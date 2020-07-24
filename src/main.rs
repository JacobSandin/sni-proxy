/*
    I might have borrowed ideas and code from these links
    https://github.com/tailhook/rotor-http/blob/master/examples/hello_world_server.rs
    https://github.com/tokio-rs/mio/blob/master/examples/tcp_server.rs#L107
    https://github.com/ctz/rustls/blob/master/rustls-mio/examples/tlsserver.rs
    //TODO: Look at https://github.com/tokio-rs/tls/blob/master/tokio-rustls/examples/server/src/main.rs
    https://stephanheijl.com/rustls_sni.html

    https://github.com/ctz/rustls/blob/master/rustls-mio/examples/tlsserver.rs

*/

//mod cert_handling;
mod connection_source;
mod sni_resolver;
use crate::connection_source::ConnectionSource;
use crate::sni_resolver::{load_certs, load_private_key, load_resolver};

use std::{collections::HashMap, error::Error, io, sync::Arc, cell::{RefCell}};

use mio::{net::TcpListener, Events, Interest, Poll, Token};

use rustls::{self, NoClientAuth};

const HTTPS_SERVER: Token = Token(0);
const HTTP_SERVER: Token = Token(1);
const SNI_TLS_CERTS: bool = true;

#[macro_use]
extern crate log;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

extern crate simplelog;
use simplelog::*;
use std::fs::File;



fn main() -> Result<(), Box<dyn Error>> {
    // Init logger
    // env_logger::Builder::from_default_env()
    //     .parse_filters("trace")
    //     .init();
    //log_enabled!(Level::Debug);

    CombinedLogger::init(
        vec![
            TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed),
            WriteLogger::new(LevelFilter::Trace, Config::default(), File::create("../trace.log").unwrap()),
        ]
    ).unwrap();


    trace!("Poll creating new");
    let mut poll = Poll::new()?;

    trace!("Events capacity 128");
    let mut events = Events::with_capacity(16192);

    trace!("Initierar connection hashmap");
    let mut connections: HashMap<Token,RefCell<ConnectionSource>>= HashMap::new();
    
    let mut forward_connections:HashMap<Token,RefCell<Token>> = HashMap::new();

    trace!("Crating unique Token with first number of 2, 0=HTTPS_SERVER 1=HTTP_SERVER");
    let mut unique_token = Token(2);

    debug!("Starting HTTPS_SERVER");
    let mut https_server = TcpListener::bind("127.0.0.1:443".parse()?)?;

    debug!("Starting HTTP_SERVER");
    let mut http_server = TcpListener::bind("127.0.0.1:80".parse()?)?;

    trace!("Adding HTTPS_SERVER to polling");
    poll.registry()
        .register(&mut https_server, HTTPS_SERVER, Interest::READABLE)?;

    trace!("Adding HTTP_SERVER to polling");
    poll.registry()
        .register(&mut http_server, HTTP_SERVER, Interest::READABLE)?;

    trace!("Creating tls config");
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());

    if SNI_TLS_CERTS {
        trace!("Loading resolver");
        let resolver = load_resolver();

        trace!("Adding cert resolver to config");
        config.cert_resolver = std::sync::Arc::new(resolver);
    } else {
        trace!("Load certificate for single cert server");
        let certs = load_certs("../certificates/icm.prod.imcode.com/fullchain.pem");
        trace!("Load cert key for single cert server");
        let privkey = load_private_key("../certificates/icm.prod.imcode.com/privkey.pem");
        trace!("Adding single cert to tls config");
        config
            .set_single_cert(certs, privkey)
            .map_err(|e| {
                error!("Bad certificates/private key {:?}", e);
                e
            })
            .unwrap();
    }
    trace!("Adding protocolls to tls config http/(1.1,1.2)");
    config.set_protocols(&[b"http/1.2".to_vec(), b"http/1.1".to_vec()]);

    debug!("Starting poll loop");
    loop {
        trace!("Polling with None as timeout");
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                HTTP_SERVER => {
                    do_server_accept(
                        "HTTP",
                        &mut http_server,
                        &mut unique_token,
                        &mut connections,
                        &mut forward_connections,
                        &mut poll,
                        &mut config,
                        false,
                    );
                }
                HTTPS_SERVER => {
                    do_server_accept(
                        "HTTPS",
                        &mut https_server,
                        &mut unique_token,
                        &mut connections,
                        &mut forward_connections,
                        &mut poll,
                        &mut config,
                        true,
                    );
                }
                token => {
                    trace!("New token action: {:?}", event);
                    let server_token = if let Some(server_token) = forward_connections.get(&token).clone() {
                        trace!("Found forward token, finding server!");
                        server_token.borrow_mut().clone()
                    } else {
                        trace!("Found no forward token, using supplied token!");
                        token
                    };
                 

                    let success: bool = if let Some(my_session) = connections.get_mut(&server_token)
                    {
                        trace!("Found session, and calling it");//: {:?}", my_session);
                        my_session.borrow_mut()
                            .handle_connection_event(poll.registry(), event, token)
                            .expect("WTF!!!!!!!!!")
                    } else {
                        false
                    };
                    if !success {
                        trace!("Removing connection with token: {}", &server_token.0);
                        if token != server_token {
                            trace!("Removing forward_connections client token: {}",token.0);
                            forward_connections.remove(&token);
                        }
                        connections.remove(&server_token);
                    }
                }
            }
        }
    }
}

fn do_server_accept(
    https_or_http: &str,
    server: &mut TcpListener,
    unique_token: &mut Token,
    connections: &mut HashMap<Token, RefCell<ConnectionSource>>,
    forward_connections: &mut HashMap<Token, RefCell<Token>>,
    poll: &mut Poll,
    config: &mut rustls::ServerConfig,
    tls: bool,
) {
    debug!("Connection to {} server", https_or_http);
    loop {
        trace!("{} loop tick", https_or_http);
        let (connection, address) = match server.accept() {
            Ok((connection, address)) => (connection, address),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                trace!("Noticing would block for {} server", https_or_http);
                break;
            }
            Err(e) => {
                panic!(
                    "Tokenloop: {} We got an error we dont know how to handle! {}",
                    https_or_http, e
                );
            }
        };

        //TODO: We need a safe token number, right now it will just grow to 18446744073709551615
        unique_token.0 += 2;
        let server_token = Token(unique_token.0 - 2);
        let forward_token = Token(unique_token.0 - 1);
        info!(
            "{} accepted connection from: {} adding token {}",
            https_or_http, address, server_token.0
        );

        let mut tls_session: Option<rustls::ServerSession> = if tls {
            Some(rustls::ServerSession::new(&Arc::new(config.clone())))
        } else {
            None
        };


        let m_session: ConnectionSource = ConnectionSource::new(connection, server_token, forward_token, tls_session);


        trace!(
            "{} created connection {:?} and inserting to connections HashMap",
            https_or_http,
            m_session
        );
        connections.insert(server_token, RefCell::new(m_session));
        forward_connections.insert(forward_token, RefCell::new(server_token));
        let my_session = connections.get(&server_token);
        if my_session.is_none() {
            error!("HTTP Unable to get session from connections HashMahp");
        } else {
            if my_session.is_none() {
                error!("HTTP my session is None");
                connections.remove(&server_token);
                connections.remove(&forward_token);
            } else {
                match my_session.unwrap().borrow_mut()
                    .init_register(poll.registry(), server_token, Interest::READABLE)
                {
                    Ok(a) => a,
                    Err(e) => {
                        error!("HTTP got error registering to poll! {:?}", e);
                        // connections.remove(&server_token);
                        // connections.remove(&forward_token);
                        break;
                    }
                };
            }

            trace!("HTTP Finished adding new session to poll, connections and everything");
        }
    }
}

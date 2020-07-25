/*
    I might have borrowed ideas and code from these links
    https://github.com/tailhook/rotor-http/blob/master/examples/hello_world_server.rs
    https://github.com/tokio-rs/mio/blob/master/examples/tcp_server.rs#L107
    https://github.com/ctz/rustls/blob/master/rustls-mio/examples/tlsserver.rs
    //TODO: Look at https://github.com/tokio-rs/tls/blob/master/tokio-rustls/examples/server/src/main.rs
    https://stephanheijl.com/rustls_sni.html

    https://github.com/ctz/rustls/blob/master/rustls-mio/examples/tlsserver.rs



    TODO: Test https://github.com/nbaksalyar/rust-streaming-http-parser/

*/

//mod cert_handling;
mod connection_source;
mod sni_resolver;
#[macro_use]
mod macros;

use crate::connection_source::ConnectionSource;
use crate::sni_resolver::{load_certs, load_private_key, load_resolver};

use std::{cell::RefCell, collections::HashMap, error::Error, io, sync::Arc};

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

    CombinedLogger::init(vec![
        TermLogger::new(LevelFilter::Debug, Config::default(), TerminalMode::Mixed),
        WriteLogger::new(
            LevelFilter::Trace,
            Config::default(),
            File::create("../trace.log").unwrap(),
        ),
    ])
    .unwrap();

    trace!(target: "0","Poll creating new");
    let mut poll = Poll::new()?;

    trace!(target: "0","Events capacity 128");
    let mut events = Events::with_capacity(16192);

    trace!(target: "0","Initierar connection hashmap");
    let mut connections: HashMap<Token, RefCell<ConnectionSource>> = HashMap::new();

    let mut forward_connections: HashMap<Token, RefCell<Token>> = HashMap::new();

    trace!(target: "0","Crating unique Token with first number of 2, 0=HTTPS_SERVER 1=HTTP_SERVER");
    let mut unique_token = Token(2);

    debug!(target: "0","Starting HTTPS_SERVER");
    let mut https_server = TcpListener::bind("127.0.0.1:443".parse()?)?;

    debug!(target: "0","Starting HTTP_SERVER");
    let mut http_server = TcpListener::bind("127.0.0.1:80".parse()?)?;

    trace!(target: "0","Adding HTTPS_SERVER to polling");
    poll.registry()
        .register(&mut https_server, HTTPS_SERVER, Interest::READABLE)?;

    trace!(target: "0","Adding HTTP_SERVER to polling");
    poll.registry()
        .register(&mut http_server, HTTP_SERVER, Interest::READABLE)?;

    trace!(target: "0","Creating tls config");
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());

    if SNI_TLS_CERTS {
        trace!(target: "0","Loading resolver");
        let resolver = load_resolver();

        trace!(target: "0","Adding cert resolver to config");
        config.cert_resolver = std::sync::Arc::new(resolver);
    } else {
        trace!(target: "0","Load certificate for single cert server");
        let certs = load_certs("../certificates/icm.prod.imcode.com/fullchain.pem");
        trace!(target: "0","Load cert key for single cert server");
        let privkey = load_private_key("../certificates/icm.prod.imcode.com/privkey.pem");
        trace!(target: "0","Adding single cert to tls config");
        config
            .set_single_cert(certs, privkey)
            .map_err(|e| {
                error!(target: "0","Bad certificates/private key {:?}", e);
                e
            })
            .unwrap();
    }
    trace!(target: "0","Adding protocolls to tls config http/(1.1,1.2)");
    config.set_protocols(&[b"http/1.2".to_vec(), b"http/1.1".to_vec()]);

    debug!(target: "0","Starting poll loop");
    loop {
        trace!(target: "0","Polling with None as timeout");
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
                    trace!(target: "0","New token action: {:?}", event);
                    let server_token =
                        if let Some(server_token) = forward_connections.get(&token).clone() {
                            trace!(target: "0","Found forward token, finding server!");
                            server_token.borrow_mut().clone()
                        } else {
                            trace!(target: "0","Found no forward token, using supplied token!");
                            token
                        };

                    let success: bool = if let Some(my_session) = connections.get_mut(&server_token)
                    {
                        trace!(target: "0","Found session, and calling it"); //: {:?}", my_session);
                        my_session
                            .borrow_mut()
                            .handle_connection_event(poll.registry(), event, token)
                            .expect("WTF!!!!!!!!!")
                    } else {
                        false
                    };
                    if !success {
                        trace!(target: "0","Removing connection with token: {}", &server_token.0);
                        if token != server_token {
                            trace!(target: "0","Removing forward_connections client token: {}", token.0);
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
    debug!(target: "0","Connection to {} server", https_or_http);
    loop {
        trace!(target: "0","{} loop tick", https_or_http);
        let (connection, address) = match server.accept() {
            Ok((connection, address)) => (connection, address),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                trace!(target: "0","Noticing would block for {} server", https_or_http);
                break;
            }
            Err(e) => {
                panic!(
                    "Token-loop: {} We got an error we dont know how to handle! {}",
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

        let tls_session: Option<rustls::ServerSession> = if tls {
            Some(rustls::ServerSession::new(&Arc::new(config.clone())))
        } else {
            None
        };

        let m_session: ConnectionSource =
            ConnectionSource::new(connection, server_token, forward_token, tls_session);

        trace!(
            "{} created connection {:?} and inserting to connections HashMap",
            https_or_http,
            m_session
        );
        connections.insert(server_token, RefCell::new(m_session));
        forward_connections.insert(forward_token, RefCell::new(server_token));
        let my_session = connections.get(&server_token);
        let mut mark_error_for_cleanup = false;
        if my_session.is_none() {
            error!(target: "0","HTTP Unable to get session from connections HashMahp");
        } else {
            if my_session.is_none() {
                error!(target: "0","HTTP my session is None");
                mark_error_for_cleanup = true;
            } else {
                match my_session.unwrap().borrow_mut().init_register(
                    poll.registry(),
                    server_token,
                    Interest::READABLE,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        error!(target: "0","HTTP got error registering to poll! {:?}", e);
                        mark_error_for_cleanup = true;
                    }
                };
            }
            if mark_error_for_cleanup {
                forward_connections.remove(&forward_token);
                connections.remove(&server_token);
            }

            trace!(target: "0","HTTP Finished adding new session to poll, connections and everything");
        }
    }
}

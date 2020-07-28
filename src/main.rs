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

//#[macro_use]
// extern crate mysql;
mod connection_source;
mod sni_resolver;
#[macro_use]
mod macros;
mod cert_database;

use crate::connection_source::ConnectionSource;
use crate::sni_resolver::{load_certs, load_private_key};

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
use cert_database::{get_all_certificates, MariaSNIResolver};
use simplelog::*;
use std::fs::File;

use dotenv;

fn main() -> Result<(), Box<dyn Error>> {
    dotenv::from_filename("improxy.env").ok();

    let mut logger: Vec<Box<dyn SharedLogger>> = Vec::new();
    if dotenv::var("TERM_LOG_LEVEL").is_ok() {
        let term_log_level: LevelFilter = dotenv::var("TERM_LOG_LEVEL").unwrap().parse().unwrap();
        logger.push(TermLogger::new(
            term_log_level,
            Config::default(),
            TerminalMode::Mixed,
        ));
    } else {
        logger.push(TermLogger::new(
            LevelFilter::Debug,
            Config::default(),
            TerminalMode::Mixed,
        ));
    }

    if dotenv::var("LOG_FILE_LEVEL").is_ok() && dotenv::var("LOG_FILE").is_ok() {
        let log_file_level: LevelFilter = dotenv::var("LOG_FILE_LEVEL").unwrap().parse().unwrap();
        let log_file = dotenv::var("LOG_FILE").unwrap();
        logger.push(WriteLogger::new(
            log_file_level,
            Config::default(),
            File::create(log_file).unwrap(),
        ));
    } else {
        logger.push(WriteLogger::new(
            LevelFilter::Trace,
            Config::default(),
            File::create("../trace.log").unwrap(),
        ));
    }

    CombinedLogger::init(logger).unwrap();

    trace!(target: "0","Poll creating new");
    let mut poll = Poll::new()?;

    trace!(target: "0","Events capacity 128");
    let mut events = Events::with_capacity(16192);

    trace!(target: "0","Initierar connection hashmap");
    let mut connections: HashMap<Token, RefCell<ConnectionSource>> = HashMap::new();
    let mut forward_connections: HashMap<Token, RefCell<Token>> = HashMap::new();

    // Import certificates and create a forwards hashmap.
    trace!(target: "0","Load forwards from database");
    let import_certificates = get_all_certificates();
    let mut forwards: HashMap<String, String> = HashMap::new();
    for cert in import_certificates
        .iter()
        .filter(|c| !c.forward.contains("127"))
    {
        if cert.domain_names.is_some() {
            for dn in cert.domain_names.as_ref().unwrap() {
                if None == forwards.insert(String::from(&dn.dn), String::from(&cert.forward)) {
                    //Hosts println!("127.0.0.1   {0}  # {0}  => {1}",dn.dn,cert.forward);
                }
            }
        }
    }
    //Debug if anyone is listening.
    //TODO we might actually shoul only do this if any debug is on
    for (f, w) in forwards.iter() {
        //        println!("127.0.0.1   {0}  # {0}  => {1}",f,w);
        debug!(target: "0","forward mapped {}  => {}",f,w);
    }

    //Create an arc of the forwards
    let forwards: Arc<HashMap<String, String>> = Arc::from(forwards);

    trace!(target: "0","Crating unique Token with first number of 2, 0=HTTPS_SERVER 1=HTTP_SERVER");
    let mut unique_token = Token(2);


    let mut http_bind=String::from("0.0.0.0:80");
    if dotenv::var("HTTP").is_ok() {
        http_bind= dotenv::var("HTTP").unwrap();
    }
    let mut https_bind=String::from("0.0.0.0:443");
    if dotenv::var("HTTPS").is_ok() {
        https_bind= dotenv::var("HTTPS").unwrap();
    }

    debug!(target: "0","Starting HTTPS_SERVER bind({})",https_bind);
    let mut https_server = TcpListener::bind(https_bind.parse()?)?;

    debug!(target: "0","Starting HTTP_SERVER bind({})",http_bind);
    let mut http_server = TcpListener::bind(http_bind.parse()?)?;

    trace!(target: "0","Adding HTTPS_SERVER to polling");
    poll.registry()
        .register(&mut https_server, HTTPS_SERVER, Interest::READABLE)?;

    trace!(target: "0","Adding HTTP_SERVER to polling");
    poll.registry()
        .register(&mut http_server, HTTP_SERVER, Interest::READABLE)?;

    trace!(target: "0","Creating tls config");
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());

    if SNI_TLS_CERTS {
        trace!(target: "0","Loading mariadb resolver");
        let mut resolver = MariaSNIResolver::new();
        resolver.populate(&import_certificates);

        //trace!(target: "0","Loading resolver");
        //let resolver = load_resolver();

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
    trace!(target: "0","Adding protocolls to tls config http/https(1.1,1.2)");
    config.set_protocols(&[b"http/1.2".to_vec(), b"http/1.1".to_vec()]);

    debug!(target: "0","Starting poll loop");
    loop {
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
                        &forwards,
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
                        &forwards,
                        &mut poll,
                        &mut config,
                        true,
                    );
                }
                token => {
                    //Too much logging  trace!(target: "0","New token action: {:?}", event);
                    let server_token =
                        if let Some(server_token) = forward_connections.get(&token).clone() {
                            //Too much logging                            trace!(target: "0","Found forward token, finding server!");
                            server_token.borrow_mut().clone()
                        } else {
                            //Too much logging                            trace!(target: "0","Found no forward token, using supplied token!");
                            token
                        };

                    let success: bool = if let Some(my_session) = connections.get_mut(&server_token)
                    {
                        //Too much logging                        trace!(target: "0","Found session, and calling it"); //: {:?}", my_session);
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
    forwards: &Arc<HashMap<String, String>>,
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

        let m_session: ConnectionSource = ConnectionSource::new(
            connection,
            server_token,
            forward_token,
            tls_session,
            Arc::clone(forwards),
        );

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
                match my_session.unwrap().borrow_mut().call_with_new_client(
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

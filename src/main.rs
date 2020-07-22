/*
    I might have borrowed ideas and code from these links
    https://github.com/tailhook/rotor-http/blob/master/examples/hello_world_server.rs
    https://github.com/tokio-rs/mio/blob/master/examples/tcp_server.rs#L107
    https://github.com/ctz/rustls/blob/master/rustls-mio/examples/tlsserver.rs
    //TODO: Look at https://github.com/tokio-rs/tls/blob/master/tokio-rustls/examples/server/src/main.rs
    https://stephanheijl.com/rustls_sni.html

*/

//mod cert_handling;
mod connection_source;
mod sni_resolver;
use crate::sni_resolver::{load_certs, load_private_key,load_resolver};
use crate::connection_source::ConnectionSource;

use std::{sync::Arc,collections::HashMap, error::Error, io};

use mio::{net::TcpListener,Events, Interest, Poll, Token};

use rustls::{self, NoClientAuth};


const HTTPS_SERVER: Token = Token(0);
const HTTP_SERVER: Token = Token(1);
const SNI_TLS_CERTS: bool = true;

fn main() -> Result<(), Box<dyn Error>> {
    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(128);
    let mut connections = HashMap::new();
    let mut unique_token = Token(3);
    let mut https_server = TcpListener::bind("127.0.0.1:443".parse()?)?;
    let mut http_server = TcpListener::bind("127.0.0.1:80".parse()?)?;
    poll.registry()
        .register(&mut https_server, HTTPS_SERVER, Interest::READABLE)?;
    poll.registry()
        .register(&mut http_server, HTTP_SERVER, Interest::READABLE)?;

    let resolver = load_resolver();
    let mut config = rustls::ServerConfig::new(NoClientAuth::new());

    if SNI_TLS_CERTS {
        config.cert_resolver = std::sync::Arc::new(resolver);
    } else {
        let certs = load_certs("../certificates/icm.prod.imcode.com/fullchain.pem");
        let privkey = load_private_key("../certificates/icm.prod.imcode.com/privkey.pem");
        config
            .set_single_cert(certs, privkey)
            .expect("bad certificates/private key");
    }

//    config.key_log = Arc::new(rustls::KeyLogFile::new());
    config.set_protocols(&[b"http/1.2".to_vec(), b"http/1.1".to_vec()]);

    loop {
        //        poll.poll(&mut events, Some(Duration::from_millis(222)))?;
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            match event.token() {
                HTTP_SERVER => {
                    loop {
                        println!("HTTP tick");
                        let (connection, address) = match http_server.accept() {
                            Ok((connection, address)) => (connection, address),
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(e) => {
                                panic!(
                                "Tokenloop: HTTP We got an error we dont know how to handle! {}",
                                e
                            );
                            }
                        };

                        println!("HTTP accepted connection from: {}", address);
                        //TODO: We need a safe token number, right now it will just grow to 18446744073709551615
                        let token = Token(unique_token.0);
                        unique_token.0 += 1;

                        let m_session: ConnectionSource = ConnectionSource {
                            server_stream: connection,
                            server_token: token,
                            server_request_body: String::new(),
                            client_stream: None,
                            client_token: None,
                            tls_session: None,
                            serve_path: None,
                            closing: false,
                            closed: false,
                            do_tls: false,
                        };

                        connections.insert(token, m_session);
                        let my_session = connections.get_mut(&token).expect("Hash not shown");
                        my_session.init_register(
                            poll.registry(),
                            token,
                            Interest::READABLE | Interest::WRITABLE,
                        )?;
                        println!("HTTP Nyt token main: {}", unique_token.0);
                    }
                }
                HTTPS_SERVER => loop {
                    println!("HTTPS tick");
                    let (connection, address) = match https_server.accept() {
                        Ok((connection, address)) => (connection, address),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => {
                            panic!(
                                "Tokenloop: HTTPS we got an error we dont know how to handle! {}",
                                e
                            );
                        }
                    };

                    println!("HTTPS accepted connection from: {}", address);
                    //TODO: We need a safe token number, right now it will just grow to 18446744073709551615
                    let token = Token(unique_token.0);
                    unique_token.0 += 1;

                    let tls_session = rustls::ServerSession::new(&Arc::new(config.clone()));

                    let m_session: ConnectionSource = ConnectionSource {
                        server_stream: connection,
                        server_token: token,
                        server_request_body: String::new(),
                        client_stream: None,
                        client_token: None,
                        tls_session: Some(tls_session),
                        serve_path: None,
                        closing: false,
                        closed: false,
                        do_tls: true,
                    };

                    connections.insert(token, m_session);
                    let my_session = connections.get_mut(&token).expect("Hash not shown");
                    my_session.init_register(
                        poll.registry(),
                        token,
                        Interest::READABLE | Interest::WRITABLE,
                    )?;
                    println!("HTTPS nyt token main: {}", unique_token.0);
                },
                token => {
                    let done: bool = if let Some(my_session) = connections.get_mut(&token) {
                        my_session
                            .handle_connection_event(poll.registry(), event, token)
                            .expect("WTF!!!!!!!!!")
                    } else {
                        false
                    };
                    if done {
                        connections.remove(&token);
                    }
                }
            }
        }
    }
}

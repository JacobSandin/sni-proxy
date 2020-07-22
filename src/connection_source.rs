
use mio::{
    event::{Event,Source},
    Interest, 
    Registry, 
    Token,
    net::TcpStream,
};

use rustls;
use rustls::Session;


//TODO: We are going to start using this
//use httparse::{Header, Request, EMPTY_HEADER};
use std::{
    io,
    io::{Read,Write},
    str::from_utf8, 
    net,
};

#[derive(Debug)]
pub struct ConnectionSource {
    pub server_stream: TcpStream,
    pub tls_session: Option<rustls::ServerSession>,
    pub server_token: Token,
    #[allow(dead_code)]
    pub client_stream: Option<std::net::TcpStream>,
    #[allow(dead_code)]
    pub client_token: Option<Token>,
    pub server_request_body: String,
    pub serve_path: Option<String>,
    pub closing: bool,
    pub closed: bool,
    pub do_tls: bool,
}

impl Source for ConnectionSource {
    //Just import from Source
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.server_stream.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.server_stream.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.server_stream.deregister(registry)
    }
}

const BODY: &[u8] = b"<html>
<body>
<h1>This is realy awsum</h1>
</body>
</html>

";

impl ConnectionSource {
    pub fn init_register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.register(registry, token, interests)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_session.as_mut().unwrap().write_tls(&mut self.server_stream);
        if rc.is_err() {
            println!("write TLS handle error failed {:?}", rc);
            self.closing = true;
            return;
        }
    }

    pub fn handle_connection_event<'a>(
        &mut self,
        registry: &Registry,
        event: &Event,
        server_token: Token,
    ) -> io::Result<bool> {
        if self.closed {
            return Ok(true);
        }

        let response = format!(
            "HTTP/1.1 200 OK\r\nServer: JS-imProxy-0.0.1\r\nContent-Length: {}\r\n\r\n{}",
            BODY.len(),
            std::str::from_utf8(BODY).unwrap().to_string()
        );

        /*

            Read/Write TLS and HTTPS

        */

        if event.is_readable() && self.do_tls && self.tls_session.as_mut().unwrap().wants_read() {
            while self.tls_session.as_mut().unwrap().wants_read() {
                match self.tls_session.as_mut().unwrap().read_tls(&mut self.server_stream) {
                    Ok(0) => {
                        match self.tls_session.as_mut().unwrap().process_new_packets() {
                            Err(e) => {
                                println!("Error processing TLS packages {:?} ", e);
                                self.do_tls_write_and_handle_error();
                                self.closing = true;
                                break;
                            }
                            _ => {}
                        }
                        break;
                    }
                    Ok(n) => {
                        println!("Read tls bytes {}", n);
                        match self.tls_session.as_mut().unwrap().process_new_packets() {
                            Err(e) => {
                                println!("Error processing TLS packages {:?} ", e);
                                //TODO: Not needed here it seem
                                // self.do_tls_write_and_handle_error();
                                // connection_closed = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        self.closing = true;
                    }

                    Err(e) => println!("Error tls read: {:?}", e),
                }
            }
            if self.tls_session.as_mut().unwrap().is_handshaking() {
                println!("Read still handshaking! +++");
            } else {
                println!("Read not handshaking! ---");
            }
        }

        if event.is_writable() && self.do_tls && self.tls_session.as_mut().unwrap().wants_write() {
            let tls_host = match self.tls_session.as_mut().unwrap().get_sni_hostname() {
                Some(s) => String::from(s),
                None => {
                    println!("Tls host None");
                    String::new()
                }
            };
            print!("TLS hostname: {}",tls_host);

            if self.tls_session.as_mut().unwrap().wants_write() {
                let ret = self.tls_session.as_mut().unwrap().write_tls(&mut self.server_stream);
                if ret.is_err() {
                    let e = ret.unwrap_err().kind();
                    match e {
                        io::ErrorKind::ConnectionAborted => {
                            self.closing = true;
                        }
                        io::ErrorKind::WouldBlock => {
                            //connection_closed=true;
                        }
                        _ => println!("new Error {:?}", e),
                    }
                } else {
                    let u = ret.ok().unwrap();
                    if u == 0 {
                        self.closing = true;
                    }
                    println!("write_tls usize: {:?} ", 0);
                }
            }

            if self.tls_session.as_mut().unwrap().is_handshaking() {
                println!("Write Still handshaking!");
            } else {
                println!("Write Not handshaking");
            }
        }

        /*

            Read/Write TLS and HTTPS

        */

        if event.is_readable() && self.do_tls && !self.tls_session.as_mut().unwrap().wants_read() {
            let mut received_data = Vec::with_capacity(4096);
            loop {
                let mut buf = [0; 256];
                match self.tls_session.as_mut().unwrap().read(&mut buf) {
                    Ok(0) => {
                        println!("Error in tls write: {:?}", io::ErrorKind::WriteZero);
                        self.closing = true;
                        break;
                    }
                    Ok(n) => received_data.extend_from_slice(&buf[..n]),
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        //   connection_closed=true;
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                        break;
                    }
                    Err(err) => return Err(err),
                }
            }

            if let Ok(str_buf) = from_utf8(&received_data) {
                println!("Received data: {}", str_buf.trim_end());
            } else {
                println!("Received (none UTF-8) data: {:?}", &received_data);
            }
        }

        if event.is_writable() && self.do_tls && !self.tls_session.as_mut().unwrap().wants_write() {

            println!("Writing tls: \r\n{}", response);
            match self.tls_session.as_mut().unwrap().write(response.as_bytes()) {
                Ok(n) if n < response.len() => {
                    println!("Error in tls write: {:?}", io::ErrorKind::WriteZero);
                    self.closing = true;
                }
                Ok(_) => registry.reregister(self, event.token(), Interest::READABLE)?,
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                    //   connection_closed=true;
                }
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                    self.handle_connection_event(registry, event, self.server_token)?;
                }
                Err(err) => return Err(err),
            }
        }

        /*

            Read/Write PLAIN (with no TLS or HTTPS)

        */

        if event.is_readable() && !self.do_tls {
            let mut received_data = Vec::with_capacity(4096);
            loop {
                if self.closing || self.closed {
                    break;
                }
                let mut buf = [0; 256];
                match self.server_stream.read(&mut buf) {
                    Ok(0) => {
                        self.closing = true;
                        break;
                    }
                    Ok(n) => received_data.extend_from_slice(&buf[..n]),
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        println!("Error no tls reading: {:?}", err);
                        self.closing = true;      
                        break;                 
                    }
                }
            }
            if let Ok(str_buf) = from_utf8(&received_data) {
                println!("Received data: {}", str_buf.trim_end());
            } else {
                println!("Received (none UTF-8) data: {:?}", &received_data);
            }
        }

        if event.is_writable() && !self.do_tls {
            //Not TLS
            println!("Writing notls: \r\n{}", response);
            match self.server_stream.write(response.as_bytes()) {
                Ok(n) if n < response.len() =>{
                    // return Err(io::ErrorKind::WriteZero.into()),
                    println!("Ok n: {}",n);
                    self.closing=true;
                },
                Ok(n) => {
                    println!("Ok n: {}",n);
                    registry.reregister(&mut self.server_stream, event.token(), Interest::READABLE)?;
                    return Ok(false);
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                    //TODO: Why
                    self.register(registry ,server_token, Interest::READABLE)?;
                    return Ok(false);
                }
                // Other errors we'll consider fatal.
                Err(err) => {
                    println!("Error no tls writing: {:?}", err);
                    self.closing = true;
                }
            }
        }

        /*

            Cleanup or reregister socket

        */

        if self.closing {
            println!("Connection closed");
            if self.do_tls {
                self.tls_session.as_mut().unwrap().send_close_notify();
            }
            let _ = self.server_stream.shutdown(net::Shutdown::Both);
            self.deregister(registry).expect("Gurka");     
            self.closed;       
            return Ok(true);
        } else {
            self.reregister(
                registry,
                self.server_token,
                Interest::READABLE | Interest::WRITABLE,
            )
            .expect("Reregister");
            println!("did we register?");
            Ok(false)
        }
    }
}

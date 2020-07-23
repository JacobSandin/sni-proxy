use mio::{
    event::{Event, Source},
    net::TcpStream,
    Interest, Registry, Token,
};

use rustls;
use rustls::{Session, TLSError};

//TODO: We{@} are going to start using this
//use httparse::{Header, Request, EMPTY_HEADER};
use std::{
    io,
    io::{Read, Write},
    net,
    str::from_utf8,
    thread::{sleep, Thread},
    time::Duration,
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
        trace!("Registering using ConnectionSource function");
        self.server_stream.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        trace!("Reregistering using ConnectionSource function");
        self.server_stream.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        trace!("Deregistering using ConnectionSource function");
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
    fn local_reader(&mut self, registry: &Registry) -> Option<bool> {
        if self.serve_path.is_some() {
            trace!("Read already given path, returning.");
            return Some(true);
        }
        trace!("Read Checking read if closed {}", self.closing);

        let mut received_data = Vec::with_capacity(4096);
        loop {
            trace!("Read Checking read if closed {}", self.closing);
            // if self.closing || self.closed {
            //     Some(false);
            // }
            let mut buf = [0; 256];

            trace!("Read Reading buffer as tls={}", self.do_tls);
            let res: Result<usize, std::io::Error> = if self.do_tls {
                trace!("Read using tls_session to read");
                self.tls_session.as_mut().unwrap().read(&mut buf)
            } else {
                trace!("Read using server_stream to read");
                self.server_stream.read(&mut buf)
            };

            trace!("Read Checking read errors");
            if res.is_err() {
                match res.unwrap_err().kind() {
                    io::ErrorKind::WouldBlock => {
                        trace!("Read Would block");
                        //   connection_closed=true;
                        break;
                    }
                    io::ErrorKind::Interrupted => {
                        trace!("Read Interupted");
                        continue;
                        //break;
                    }
                    err => {
                        trace!("Read Unknown error : {:?}", err);
                        self.closing = true;
                        return Some(false);
                    }
                }
            } else {
                trace!("Read checking OK");
                match res.unwrap() {
                    0 => {
                        trace!(
                            "Read Read Error in read: {:?} closing? {}",
                            io::ErrorKind::WriteZero,
                            self.closed || self.closing
                        );
                        break;
                        // if !self.do_tls {
                        //     self.closing = true;
                        //     return Some(false);
                        // }
                    }
                    n => {
                        trace!("Read Transfering read buffer to datacollecter received_data");
                        received_data.extend_from_slice(&buf[..n]);
                    }
                }
            }
        }

        if String::from_utf8_lossy(&received_data).contains("GET /") {
            self.serve_path = Some(String::from("/"));
        } else {
            self.serve_path = None;
        };
        debug!(
            "Read Received data: {}\r\n\r\n and using path {:?}\r\n",
            String::from_utf8_lossy(&received_data).trim_end(),
            self.serve_path
        );

        if let Ok(str_buf) = from_utf8(&received_data) {
            debug!("Read Received data: {:?}", &str_buf);
        } else {
            debug!("Read Received (none UTF-8) data: {:?}", &received_data);
        }

        if self.serve_path.is_some() && !self.closing && !self.closed {
            trace!("Read Reregistering normal write to read");
            self.reregister(registry, self.server_token, Interest::WRITABLE)
                .expect("Reregister");
        } else if self.do_tls && self.tls_session.as_mut().unwrap().wants_write() {
            trace!("Read Reregistering normal to read/write for tls");
            self.reregister(
                registry,
                self.server_token,
                Interest::READABLE | Interest::WRITABLE,
            )
            .expect("Reregister");
        } else {
            self.reregister(registry, self.server_token, Interest::WRITABLE)
                .expect("Reregister");
        }

        return Some(true);
    }

    fn local_writer(&mut self, event: &Event, registry: &Registry) -> Option<bool> {
        if self.serve_path.is_none() {
            trace!("Write path none, returning.");
            return Some(true);
        }

        trace!("Write Creating default responce");
        let response = format!(
            "HTTP/1.1 200 OK\r\nServer: JS-imProxy-0.0.1\r\nContent-Length: {}\r\n\r\n{}",
            BODY.len(),
            std::str::from_utf8(BODY).unwrap().to_string()
        );

        trace!("Write response: \r\n{}", response);

        let ret = if self.do_tls {
            self.tls_session
                .as_mut()
                .unwrap()
                .write(response.as_bytes())
        } else {
            self.server_stream.write(response.as_bytes())
        };

        match ret {
            Ok(n) if n < response.len() => {
                // return Err(io::ErrorKind::WriteZero.into()),
                trace!("Write Wrote zerro n: {}", n);
                self.closing = true;
                return Some(false);
            }
            Ok(n) => {
                trace!("Write sent {} of bytes", n);
                // self.closing = true;
                // return Some(false);
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                trace!("Write Error wouldblock ignoring");
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                //TODO: Why
                trace!("Write registering for mor write as we were interupted.");
                let res = self.register(registry, event.token(), Interest::WRITABLE);
                if res.is_err() {
                    //TODO Cleanup?
                    error!("Got error after register: {:?}", res.unwrap_err());
                    return Some(false);
                }
                return Some(true);
            }
            // Other errors we'll consider fatal.
            Err(err) => {
                error!("Unknown error no writing: {:?}", err);
                self.closing = true;
                return Some(false);
            }
        }
        if !self.closing && !self.closed {
            if self.do_tls && self.tls_session.as_mut().unwrap().wants_write() {
                trace!("Reregistering tls READ/WRITE");
                self.reregister(
                    registry,
                    self.server_token,
                    Interest::READABLE | Interest::WRITABLE,
                )
                .expect("Reregister");
            } else {
                trace!("Reregistering for READ");
                self.reregister(registry, self.server_token, Interest::READABLE)
                    .expect("Reregister");
            }
        }
        self.serve_path = None;
        return Some(true);
    }
    //  }
}

impl ConnectionSource {
    pub fn init_register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.register(registry, token, interests)
    }

    pub fn handle_connection_event<'a>(
        &mut self,
        registry: &Registry,
        event: &Event,
    ) -> Option<bool> {
        let mut success: bool = true;
        /*

            Read/Write TLS and HTTPS

        */

        if event.is_readable() && self.do_tls && self.tls_session.as_mut().unwrap().wants_read() {
            trace!("tls_session (read) Unwrapping tls_session wants_read");
            while self.tls_session.as_mut().unwrap().wants_read() {
                trace!("tls_session (read) Matching read_tls");
                match self
                    .tls_session
                    .as_mut()
                    .unwrap()
                    .read_tls(&mut self.server_stream)
                {
                    Ok(0) => {
                        trace!("tls_session (read) unwrap process_new_packages.");
                        match self.tls_session.as_mut().unwrap().process_new_packets() {
                           Err(e) if e == TLSError::AlertReceived(rustls::internal::msgs::enums::AlertDescription::CertificateUnknown) => {
                                error!("tls_session (read) 1.Certificate unknown we are ignoring for adresses without certs yet.++++++++++++++++++++++++++++++++++");
                                //panic!("wtf");
                            },
                            Err(e) => {
                                error!(
                                    "tls_session (read) Unknown error:processing TLS packages (ignoring) {:?} ",
                                    e
                                );
                                //    self.do_tls_write_and_handle_error();
                                self.closing = true;
                                break;
                            }
                            _ => {}
                        }
                        self.closing = true;
                        break;
                    }
                    Ok(n) => {
                        trace!("tls_session Read tls bytes {}", n);
                        match self.tls_session.as_mut().unwrap().process_new_packets() {
                            Err(e) if e == TLSError::AlertReceived(rustls::internal::msgs::enums::AlertDescription::CertificateUnknown) => {
                                error!("tls_session (read) 2. Certificate unknown we are ignoring for adresses without certs yet. -------------------------------");
                                //panic!("wtf");
                            },
/* TODO: CertificateUnknown
      typ: Alert,
        version: TLSv1_3,
        payload: Alert(
            AlertMessagePayload {
                level: Fatal,
                description: CertificateUnknown,
            },
        ),
    }
*/                          Err(e) => {
                                error!("tls_session (read) Error read processing TLS packages {:?} ", e);
                                //TODO: Not needed here it seem
                                // self.do_tls_write_and_handle_error();
                                self.closing = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                        trace!("tls_session (read) Connection WouldBlock breaking.");
                        break;
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                        trace!("tls_session (read) Connection interupted, continue.");
                        continue;
                    }
                    Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                        error!("tls_session (read) Connection aborted");
                        //TODO test closing again
                        //self.closing = true;
                        break;
                    }

                    Err(e) => {
                        error!("tls_session (read) Unknown error tls read: {:?}", e);
                        break;
                    }
                }
            }
            if self.tls_session.as_mut().unwrap().is_handshaking() {
                debug!("tls_session (read) still handshaking! +++");
            } else {
                debug!("tls_session (read) not handshaking! ---");
            }
            if !self.closing && !self.closed {
                if self.tls_session.as_mut().unwrap().wants_read()
                    && self.tls_session.as_mut().unwrap().wants_write()
                {
                    trace!("tls_session (read) Reregistering for READ/WRITE");
                    self.reregister(
                        registry,
                        self.server_token,
                        Interest::READABLE | Interest::WRITABLE,
                    )
                    .expect("Reregister");
                } else if self.tls_session.as_mut().unwrap().wants_read() {
                    trace!("tls_session (read) Reregistering for READ");
                    self.reregister(registry, self.server_token, Interest::READABLE)
                        .expect("Reregister");
                } else if self.tls_session.as_mut().unwrap().wants_write() {
                    trace!("tls_session (read) Reregistering for WRITE");
                    self.reregister(registry, self.server_token, Interest::WRITABLE)
                        .expect("Reregister");
                } else {
                    trace!("tls_session (read) Reregistering for WRITE");
                    self.reregister(registry, self.server_token, Interest::WRITABLE)
                        .expect("Reregister");
                }
            }
        }

        if event.is_writable() && self.do_tls && self.tls_session.as_mut().unwrap().wants_write() {
            trace!("tls_session (write) Geting SNI hostname if set.");
            let tls_host = match self.tls_session.as_mut().unwrap().get_sni_hostname() {
                Some(s) => String::from(s),
                None => {
                    trace!("tls_session (write) Tls host None");
                    String::new()
                }
            };
            debug!("tls_session (write) TLS hostname: {}", tls_host);

            trace!("Unwrapping tls_session (write) for wants_write");
            if self.tls_session.as_mut().unwrap().wants_write() {
                trace!("tls_session (write) Doing write_tls on server_stream");
                let ret = self
                    .tls_session
                    .as_mut()
                    .unwrap()
                    .write_tls(&mut self.server_stream);
                if ret.is_err() {
                    trace!("tls_session (write) We got an error writing tls");
                    let e = ret.unwrap_err().kind();
                    match e {
                        io::ErrorKind::ConnectionAborted => {
                            error!("tls_session (write) Connection aborted");
                            self.closing = true;
                            return Some(false);
                        }
                        io::ErrorKind::WouldBlock => {
                            trace!("tls_session (write) Error WouldBlock");
                            //return Some(true);
                            //connection_closed=true;
                        }
                        _ => {
                            error!("tls_session (write) Unknown error {:?}", e);
                        }
                    }
                } else {
                    let u = ret.ok().unwrap();
                    trace!("tls_session (write) Got usize {}", u);
                    if u == 0 {
                        // self.closing = true;
                        // return Some(false);
                    }
                }
            }
            if !self.closing && !self.closed {
                if self.tls_session.as_mut().unwrap().wants_read()
                    && self.tls_session.as_mut().unwrap().wants_write()
                {
                    trace!("tls_session (write) Reregistering for READ/WRITE");
                    self.reregister(
                        registry,
                        self.server_token,
                        Interest::READABLE | Interest::WRITABLE,
                    )
                    .expect("Reregister");
                } else if self.tls_session.as_mut().unwrap().wants_read() {
                    trace!("tls_session (write) Reregistering for READ");
                    self.reregister(registry, self.server_token, Interest::READABLE)
                        .expect("Reregister");
                } else if self.tls_session.as_mut().unwrap().wants_write() {
                    trace!("tls_session (write) Reregistering for WRITE");
                    self.reregister(registry, self.server_token, Interest::WRITABLE)
                        .expect("Reregister");
                } else {
                    trace!("tls_session (write) Reregistering for READ");
                    self.reregister(registry, self.server_token, Interest::READABLE)
                        .expect("Reregister");
                }
            }

            if self.tls_session.as_mut().unwrap().is_handshaking() {
                debug!("tls_session (write) Still handshaking!");
            } else {
                debug!("tls_session (write) Not handshaking");
            }
        }

        /*

            Read/Write TLS and HTTPS

        */
        if event.is_readable() {
            if self.tls_session.as_mut().is_none()
                || !self.tls_session.as_mut().unwrap().is_handshaking()
            {
                success = self.local_reader(registry).unwrap();
            }
        }

        if event.is_writable() {
            if self.tls_session.as_mut().is_none()
                || !self.tls_session.as_mut().unwrap().is_handshaking()
            {
                success = self.local_writer(event, registry).unwrap();
            }
        }

        /*

            Cleanup or reregister socket

        */

        if  !success {
            panic!("Why");
        }

        if self.closed || self.closing {
            trace!("closing connection");
            if self.do_tls {
                self.tls_session.as_mut().unwrap().send_close_notify();
            }
            let _ = self.server_stream.shutdown(net::Shutdown::Both);
            self.deregister(registry).expect("Gurka");
            self.closed = true;
            return Some(false);
        }
        return Some(true);
    }
}

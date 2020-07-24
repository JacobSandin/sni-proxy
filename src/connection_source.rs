use mio::{
    event::{Event, Source},
    net::TcpStream,
    Interest, Registry, Token,
};

use rustls;
use rustls::{Session, TLSError};

use regex::Regex;

use httparse::{Header, Request, Response};

//TODO: We{@} are going to start using this
//use httparse::{Header, Request, EMPTY_HEADER};
use cmp::min;
use io::Error;
use net::Shutdown;
use std::{
    cmp, io,
    io::{Read, Write},
    net,
    str::from_utf8,
    thread,
    time::Duration,
};

#[derive(Debug)]
pub struct ConnectionSource {
    pub server_stream: TcpStream,
    pub tls_session: Option<rustls::ServerSession>,
    pub server_token: Token,
    #[allow(dead_code)]
    pub forward_stream: Option<TcpStream>,
    #[allow(dead_code)]
    pub forward_token: Token,
    pub forward_host: String,
    pub send_to_farward: Option<Vec<u8>>,
    pub send_to_client: Option<Vec<u8>>,
    pub closing: bool,
    pub done_closing: bool,
    pub do_tls: bool,
    server_reregistered: bool,
    counter: u16,
}

impl Source for ConnectionSource {
    //Just import from Source
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        if !self.done_closing {
            if token == self.forward_token && self.forward_stream.is_some() {
                trace!("Registering forward");
                self.forward_stream
                    .as_mut()
                    .unwrap()
                    .register(registry, token, interests)
            } else {
                trace!("Registering Server");
                self.server_stream.register(registry, token, interests)
            }
        } else {
            trace!("Not registering ConnectionSource function (closing)");
            Ok(())
        }
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        if !self.done_closing {
            if token == self.forward_token && self.forward_stream.is_some() {
                trace!("Reregistering Forward using ConnectionSource function");
                self.forward_stream
                    .as_mut()
                    .unwrap()
                    .reregister(registry, token, interests)
                    .ok();
            } else {
                trace!("Reregistering Server using ConnectionSource function");
                self.server_reregistered = true;
                self.server_stream
                    .reregister(registry, token, interests)
                    .ok();
            }
        }
        Ok(())
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        trace!("Deregistering using ConnectionSource function");
        if self.forward_stream.is_some() {
            self.forward_stream
                .as_mut()
                .unwrap()
                .deregister(registry)
                .expect("Could not deregister forward stream");
        }
        self.server_stream.deregister(registry)
    }
}

impl ConnectionSource {
    pub fn new(
        connection: TcpStream,
        server_token: Token,
        forward_token: Token,
        tls_session: Option<rustls::ServerSession>,
    ) -> ConnectionSource {
        let m_session: ConnectionSource = ConnectionSource {
            server_stream: connection,
            server_token: server_token,
            forward_stream: None,
            forward_token: forward_token,
            send_to_farward: None,
            send_to_client: None,
            do_tls: tls_session.is_some(),
            tls_session: tls_session,
            closing: false,
            done_closing: false,
            server_reregistered: false,
            forward_host: String::new(),
            counter: 0,
        };
        m_session
    }
}

impl ConnectionSource {
    fn local_reader(&mut self, registry: &Registry) -> Option<bool> {
        trace!(
            "Read Checking read if shutdown ({}) returning false",
            self.done_closing
        );
        if self.done_closing {
            return Some(false);
        }
        let mut received_data = Vec::new();
        loop {
            let mut buf = [0; 512];

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
                        //                        self.closing = true;
                        trace!("Read reading zero closing:({})", self.closing);
                        break;
                    }
                    n => {
                        trace!("Read Transfering read buffer to datacollecter received_data");
                        received_data.extend_from_slice(&buf[..n]);
                    }
                }
            }
        }

        // trace!(
        //     "Read got data ------------------------------------------:\r\n{}",
        //     String::from_utf8_lossy(&received_data[..min(received_data.len(), 2048)])
        // );
        if String::from_utf8_lossy(&received_data).contains("\r\n\r\n") {
            self.send_to_farward = Some(received_data);
            //self.send_to_client = None;
            if self.forward_stream.is_none() {
                debug!("Read starting forward stream.....................................................");

                self.forward_stream = if self.tls_session.is_some()
                    && self
                        .tls_session
                        .as_mut()
                        .unwrap()
                        .get_sni_hostname()
                        .is_some()
                    && self
                        .tls_session
                        .as_mut()
                        .unwrap()
                        .get_sni_hostname()
                        .unwrap()
                        == "icm.imcode.com"
                {
                    trace!("Using forwardhost icm tomcat");
                    Some(TcpStream::connect("192.168.96.59:10132".parse().unwrap()).unwrap())
                } else {
                    trace!("Using forward host prod");
                    Some(TcpStream::connect("192.168.96.54:80".parse().unwrap()).unwrap())
                };

                //                                Some(TcpStream::connect("192.168.96.54:80".parse().unwrap()).unwrap());
                //TODO Error handling

                //Do we need to register here?
                trace!("Read Registering forward for WRITE");
                self.register(registry, self.forward_token, Interest::WRITABLE)
                    .ok();
                debug!("Read Server Created...===========================================================");
            } else {
                self.reregister(registry, self.forward_token, Interest::WRITABLE)
                    .ok();
                debug!("Read Server ReCreated==============================================================");
            }
            let len = self.send_to_farward.as_mut().unwrap().len();
            trace!(
                "Read Confirming send_to_forward has data:\r\n{}",
                String::from_utf8_lossy(&self.send_to_farward.as_mut().unwrap()[..min(len, 2048)])
            );

        //TODO Insert client?
        } else {
            //self.send_to_client = None;
        };
        // self.reregister(registry, self.server_token, Interest::WRITABLE)
        //     .ok();
        // self.reregister(registry, self.server_token,Interest::READABLE | Interest::WRITABLE)
        // .ok();

        trace!("Read DONE");
        return Some(true);
    }

    fn local_writer(&mut self, event: &Event, registry: &Registry) -> Option<bool> {
        if self.send_to_client.is_none() {
            trace!("Write nothing to send, returning adding \r\n.");
            self.register(registry, self.server_token, Interest::READABLE)
                .ok();
            return Some(true);
        }
        self.counter = 0;
        self.server_stream.flush().ok();
        //let mut buf = self.send_to_client.as_mut().unwrap().to_vec();
        //let mut response:Vec<u8> = Vec::new();
        let mut response: Vec<u8> = self.send_to_client.as_mut().unwrap().to_vec();
        self.send_to_client = None;
        debug!(
            "Write response *********************************************************************: \r\n{}",
            String::from_utf8_lossy(&response[..min(1024, response.len())])
        );
        let ret = if self.do_tls {
            self.tls_session.as_mut().unwrap().write_all(&mut response)
        } else {
            self.server_stream.write_all(&response)
        };

        match ret {
            // Ok(0) => {
            //     debug!("Write sent 0 bytes");
            // }
            // Ok(n) => {
            //     trace!("Write wrote {} bytes. breaking", { n });
            // }
            Ok(_) => {
                trace!("Write succeeded.");
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                trace!("Write Error wouldblock ignoring");
                //return Some(true);
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                //TODO: Why
                trace!("Write registering for mor write as we were interupted.");
                //We return to try closing when done writing;
                //return Some(true);
            }
            Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                error!("Write Connection aborted (breaking)");
            }
            // Other errors we'll consider fatal.
            Err(err) => {
                error!("Write Unknown error no writing: {:?}", err);
                self.closing = true;
            }
        }

        // self.server_stream.flush().ok();
        // if self.do_tls {
        //     thread::sleep(Duration::from_millis(10));
        // }
        self.send_to_client = None;
        //self.closing = true;
        trace!("Write DONE");
        return Some(true);
    }
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
        token: Token,
    ) -> Option<bool> {
        let mut success: bool = true;

        let mut forward = token == self.forward_token && self.forward_stream.is_some();

        let fwd_ok_r = forward && event.is_readable() && self.forward_stream.is_some();
        let fwd_ok_w = forward
            && event.is_writable()
            && self.forward_stream.is_some()
            && self.send_to_farward.is_some();

        let tls_ok_r = event.is_readable() && !forward && self.do_tls;
        // && self.do_tls
        // && self.tls_session.is_some()
        // && self.tls_session.as_mut().unwrap().wants_read();
        let tls_ok_w = event.is_writable()
            && !forward
            && self.do_tls
            && self.tls_session.is_some()
            && self.tls_session.as_mut().unwrap().wants_write();

        let hand_shaking = self.do_tls
            && self.tls_session.is_some()
            && self.tls_session.as_mut().unwrap().is_handshaking();
        let cli_ok_r = !forward && event.is_readable();
        let cli_ok_w = !forward && event.is_writable();


        // Workaround for not finding a way to get tls to work in MIO ekosystem statemachine environment, 
        // and seem to need read write on for the socket all the time.
        if !forward && event.is_writable() && self.send_to_client.is_none() && !tls_ok_r && !tls_ok_w {
            self.reregister(registry, token, Interest::READABLE|Interest::WRITABLE).ok();
             return Some(true);
        };

        debug!(
            "Main Is clientThread ({}) or Is forwardThread ({})",
            token == self.server_token,
            token == self.forward_token
        );

        //        trace!("Registry:\r\n{:?}\r\nToken:\r\n{:?}\r\nEvent:\r\n{:?}",registry,token,event);

        if token == self.server_token {
            self.server_reregistered = false;
        };

        if event.is_error() {
            panic!("Event is_error");
        }
        if event.is_write_closed() {
            trace!("Main Event is_write_closed");
            if forward {
                self.closing = true;
                self.forward_stream = None;
                forward = false;
            }
            self.closing = true;
        }
        if event.is_read_closed() {
            trace!("Main Event is_read_closed");
            if forward {
                self.forward_stream = None;
                self.closing = true;
                forward = false;
            } else {
                self.closing = true;
                //self.close_all(registry);
                //return Some(false);
            }
        }

        trace!(
            "Main Closing {} or Closed {} and Forward {}",
            self.closing,
            self.done_closing,
            forward
        );

        /*

            Read/Write TLS and HTTPS

        */

        if self.counter > 20 {
            self.reregister(registry, token, Interest::READABLE).ok();
        //self.closing = true;
        } else if !tls_ok_r && !tls_ok_w && !cli_ok_r && cli_ok_w && !fwd_ok_r && !fwd_ok_w {
            self.counter += 1;
        } else {
            self.counter = 0;
        }

        trace!("\r\ntls_ok_r: {}\r\ntls_ok_w: {}\r\ncli_ok_r: {}\r\ncli_ok_w: {}\r\nfwd_ok_r: {}\r\nfwd_ok_w: {}\r\nCounter: {}\r\n",
        tls_ok_r,tls_ok_w,cli_ok_r,cli_ok_w,fwd_ok_r,fwd_ok_w,self.counter);

        trace!("MAIN closing: ({})", self.closing);
        if fwd_ok_w {
            trace!("Entering FWD_W ({})", success);

            let len = min(self.send_to_farward.as_mut().unwrap().len(), 2048);
            debug!(
                "ForWrite Forwarding!!!!!!!!!!!!!!!!: \r\n{}",
                String::from_utf8_lossy(&self.send_to_farward.as_mut().unwrap()[..len])
            );
            trace!("ForWrite Reregistering for READ");
            self.reregister(registry, self.forward_token, Interest::READABLE)
                .ok();
            let stream = self.forward_stream.as_mut().expect("Forward stream");
            stream
                .write_all(self.send_to_farward.as_mut().unwrap())
                .expect("Nothing");
            stream.flush().ok();
            self.send_to_farward = None;
            trace!("Exiting FWD_W ({})", success);
        }

        trace!("MAIN closing: ({})", self.closing);
        if fwd_ok_r {
            trace!("Entering FWD_R ({})", success);
            if self.send_to_client.is_none() && self.forward_stream.is_some() {
                let mut received_data = Vec::new();
                let mut count = 1;
                loop {
                    let mut buf = [0; 2048];
                    count += 1;
                    //if count>6100{panic!("break")}
                    let res = self.forward_stream.as_mut().unwrap().read(&mut buf);
                    trace!("ForRead Checking read errors");
                    if res.is_err() {
                        match res.unwrap_err().kind() {
                            io::ErrorKind::WouldBlock => {
                                trace!("ForRead WouldBlock");
                                //   connection_closed=true;
                                break;
                            }
                            io::ErrorKind::Interrupted => {
                                trace!("ForRead Interupted");
                                continue;
                                //break;
                            }
                            err => {
                                trace!("ForRead Unknown error : {:?}", err);
                                self.closing = true;
                                return Some(false);
                            }
                        }
                    } else {
                        trace!("ForRead checking OK");
                        match res.unwrap() {
                            0 => {
                                trace!("ForRead reading zero closing:({})", self.closing);
                                break;
                            }
                            n => {
                                trace!(
                                    "ForRead Transfering read buffer to datacollecter received_data {}",
                                    n
                                );
                                received_data.extend_from_slice(&buf[..n]);
                                // self.forward_stream.as_mut().unwrap().flush().ok();
                            }
                        }
                    }
                }

                self.reregister(registry, self.server_token, Interest::WRITABLE)
                    .unwrap();

                debug!(
                    "ForRead Got data from forward host: \r\n{}",
                    String::from_utf8_lossy(&received_data[..cmp::min(received_data.len(), 256)])
                );
                self.send_to_client = Some(received_data);
                // self.forward_stream.as_mut().unwrap().deregister(registry).ok();
                // self.forward_stream.as_mut().unwrap().flush().unwrap();
                // self.forward_stream
                //     .as_mut()
                //     .unwrap()
                //     .shutdown(Shutdown::Both)
                //     .ok();
                // self.forward_stream = None;
            }

            trace!("Exiting FWD_R ({})", success);
        }
        trace!("MAIN closing: ({})", self.closing);

        if fwd_ok_r || fwd_ok_w {
            return Some(true);
        }

        trace!("MAIN closing: ({})", self.closing);
        if tls_ok_w {
            trace!("Writing tls...");
            let rc = self
                .tls_session
                .as_mut()
                .unwrap()
                .write_tls(&mut self.server_stream);
            if rc.is_err() {
                error!("write failed {:?}", rc);
                self.closing = true;
            //return;
            } else {
                trace!("Write tls: ok");
            }
            trace!("EXIT tls write.");
        }

        trace!("MAIN closing: ({})", self.closing);
        if tls_ok_r {
            trace!("New tls read: reading tls");
            // Read some TLS data.
            let rc = self
                .tls_session
                .as_mut()
                .unwrap()
                .read_tls(&mut self.server_stream);
            if rc.is_err() {
                let err = rc.unwrap_err();

                if let io::ErrorKind::WouldBlock = err.kind() {
                    trace!("New tls read: reading tls");
                    //return;
                } 

                error!("New tls read: error {:?}", err);
                //self.closing = true;
            //return;
            } else if rc.unwrap() == 0 {
                trace!("New tls read: EOF");
                self.closing = true;
            }

            // Process newly-received TLS messages.
            trace!("New tls read: processing packages");
            let processed = self.tls_session.as_mut().unwrap().process_new_packets();
            if processed.is_err() {
                error!("New tls read: cannot process packet: {:?}", processed);
                match processed.unwrap_err() {
                    TLSError::AlertReceived(rustls::internal::msgs::enums::AlertDescription::CertificateUnknown) => {
                        error!("tls_session (read) Certificate unknown we are ignoring for adresses without certs yet.");        
                    },
                    TLSError::AlertReceived(rustls::internal::msgs::enums::AlertDescription::CertificateExpired) => {
                        error!("tls_session (read) Certificate expired we are ignoring right now.");        
                    },
                    e => {
                        error!("tls_session (read) Certificate error not known terminating. {:?}",e);        
                        self.closing = true;
                    }
                }
                // last gasp write to send any alerts
            } else {
                trace!("tls_session (read) was OK");
            }
            trace!("EXIT tls read.");
        }

        /*
                if tls_ok_w {
                    trace!("Entering TLS_W");
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
                                    //Should close O think
                                    //self.closing = true;
                                    //return Some(false);
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
                    if self.tls_session.as_mut().unwrap().is_handshaking() {
                        debug!("tls_session (write) Still handshaking!");
                    } else {
                        debug!("tls_session (write) Not handshaking");
                    }
                }
        */

        /*
                if tls_ok_r {
                    trace!("Entering TLS_R");
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

                                        self.closing = true;
                                        break;
                                    }
                                    _ => {}
                                }
                                //self.closing = true;
                                break;
                            }
                            Ok(n) => {
                                trace!("tls_session (read) tls bytes {}", n);
                                match self.tls_session.as_mut().unwrap().process_new_packets() {
                                    Err(e) if e == TLSError::AlertReceived(rustls::internal::msgs::enums::AlertDescription::CertificateUnknown) => {
                                        error!("tls_session (read) 2. Certificate unknown we are ignoring for adresses without certs yet. -------------------------------");
                                        //panic!("wtf");
                                    },
                                Err(e) => {
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
                                self.closing = true;
                                break;
                            }

                            Err(e) => {
                                error!("tls_session (read) Unknown error tls read: {:?}", e);
                                self.closing = true;
                                break;
                            }
                        }
                    }
                    if self.tls_session.as_mut().unwrap().is_handshaking() {
                        debug!("tls_session (read) still handshaking! +++");
                    } else {
                        debug!("tls_session (read) not handshaking! ---");
                    }
                }
        */
        /*

            Read/Write TLS and HTTPS

        */
        trace!("MAIN closing: ({})", self.closing);
        if cli_ok_r {
            trace!("Entering CLI_R ({})", success);
            success = self.local_reader(registry).unwrap();
            trace!("Exiting CLI_R ({})", success);
        }

        trace!("MAIN closing: ({})", self.closing);
        if cli_ok_w {
            trace!("Entering CLI_W ({})", success);
            success = self.local_writer(event, registry).unwrap();
            trace!("Exiting CLI_W ({})", success);
        }

        /*

            Cleanup or reregister socket

        */

        if !success {
            trace!("Why!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        }

        if self.closing {
            trace!("Main closing connection");
            self.close_all(registry);
            return Some(false);
        } else {
            debug!("Main registry");

            if token == self.server_token && self.send_to_client.is_none() && !tls_ok_r && !tls_ok_w
            {
                trace!("Registering READ(/WRITE) but should only need READ.");
                self.reregister(registry, self.server_token, Interest::WRITABLE | Interest::READABLE)
                    .ok();
            } else if token == self.server_token && !self.server_reregistered {
                trace!("Not registered Registering READ.");
                self.reregister(
                    registry,
                    self.server_token,
                    Interest::READABLE | Interest::WRITABLE,
                )
                .ok();
            };
        }

        debug!("Main DONE");
        if self.done_closing {
            return Some(false);
        }
        return Some(true);
    }

    fn close_all(&mut self, registry: &Registry) {
        trace!("closing connection");
        if self.do_tls {
            self.tls_session.as_mut().unwrap().send_close_notify();
        }
        let _ = self.server_stream.shutdown(net::Shutdown::Both);

        if self.forward_stream.is_some() {
            let _ = self
                .forward_stream
                .as_mut()
                .unwrap()
                .shutdown(net::Shutdown::Both);
        }
        self.deregister(registry).expect("Gurka");
    }
}

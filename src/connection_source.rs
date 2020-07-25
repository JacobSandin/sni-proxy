use mio::{
    event::{Event, Source},
    net::TcpStream,
    Interest, Registry, Token,
};

use rustls;
use rustls::{Session, TLSError};

use cmp::min;
use std::{
    cmp, io,
    io::{Read, Write},
    net,
};

use crate::{read_error_handling, write_error_handling, process_error_handling};

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
                trace!(target: &self.server_token.0.to_string(),"Registering forward");
                self.forward_stream
                    .as_mut()
                    .unwrap()
                    .register(registry, token, interests)
            } else {
                trace!(target: &self.server_token.0.to_string(),"Registering Server");
                self.server_stream.register(registry, token, interests)
            }
        } else {
            trace!(target: &self.server_token.0.to_string(),"Not registering ConnectionSource function (closing)");
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
                trace!(target: &self.server_token.0.to_string(),"Reregistering Forward using ConnectionSource function");
                self.forward_stream
                    .as_mut()
                    .unwrap()
                    .reregister(registry, token, interests)
                    .ok();
            } else {
                trace!(target: &self.server_token.0.to_string(),"Reregistering Server using ConnectionSource function");
                self.server_reregistered = true;
                self.server_stream
                    .reregister(registry, token, interests)
                    .ok();
            }
        }
        Ok(())
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        trace!(target: &self.server_token.0.to_string(),"Deregistering using ConnectionSource function");
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

            trace!(target: &self.server_token.0.to_string(),"Read Reading buffer as tls={}", self.do_tls);
            let res: Result<usize, std::io::Error> = if self.do_tls {
                trace!(target: &self.server_token.0.to_string(),"Read using tls_session to read");
                self.tls_session.as_mut().unwrap().read(&mut buf)
            } else {
                trace!(target: &self.server_token.0.to_string(),"Read using server_stream to read");
                self.server_stream.read(&mut buf)
            };

            trace!(target: &self.server_token.0.to_string(),"Read Checking read errors");
            read_error_handling!(self, res, received_data, buf);
        }

        if String::from_utf8_lossy(&received_data).contains("\r\n\r\n") {
            self.send_to_farward = Some(received_data);
            if self.forward_stream.is_none() {
                debug!(target: &self.server_token.0.to_string(),"Read starting forward stream.....................................................");

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
                    trace!(target: &self.server_token.0.to_string(),"Using forwardhost icm tomcat");
                    Some(TcpStream::connect("192.168.96.59:10132".parse().unwrap()).unwrap())
                } else {
                    trace!(target: &self.server_token.0.to_string(),"Using forward host prod");
                    Some(TcpStream::connect("192.168.96.54:80".parse().unwrap()).unwrap())
                };

                //Do we need to register here?
                trace!(target: &self.server_token.0.to_string(),"Read Registering forward for WRITE");
                self.register(registry, self.forward_token, Interest::WRITABLE)
                    .ok();
                debug!(target: &self.server_token.0.to_string(),"Read Server Created...");
            } else {
                self.reregister(registry, self.forward_token, Interest::WRITABLE)
                    .ok();
                debug!(target: &self.server_token.0.to_string(),"Read Server ReCreated...");
            }
            let len = self.send_to_farward.as_mut().unwrap().len();
            trace!(
                "Read Confirming send_to_forward has data:\r\n{}",
                String::from_utf8_lossy(&self.send_to_farward.as_mut().unwrap()[..min(len, 2048)])
            );

            //TODO Insert client?
        };

        trace!(target: &self.server_token.0.to_string(),"Read DONE");
        return Some(true);
    }

    #[allow(unused_variables)]
    fn local_writer(&mut self, event: &Event, registry: &Registry) -> Option<bool> {
        if self.send_to_client.is_none() {
            trace!(target: &self.server_token.0.to_string(),"Write nothing to send, returning adding \r\n.");
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
        write_error_handling!(self, ret);

        self.send_to_client = None;
        if !self.do_tls {
            // Works for HTTP, but for HTTPS it gives ERR_CONNECTION_REFUSED
            self.closing = true;
        }
        trace!(target: &self.server_token.0.to_string(),"Write DONE");
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
        trace!(target: &self.server_token.0.to_string(),"{:?}",event);
        let mut success: bool = true;

        let mut forward = token == self.forward_token && self.forward_stream.is_some();

        let fwd_ok_r = forward && event.is_readable() && self.forward_stream.is_some();
        let fwd_ok_w = forward
            && event.is_writable()
            && self.forward_stream.is_some()
            && self.send_to_farward.is_some();

        let tls_ok_r = event.is_readable() && !forward && self.do_tls;

        let tls_ok_w = event.is_writable()
            && !forward
            && self.do_tls
            && self.tls_session.is_some()
            && self.tls_session.as_mut().unwrap().wants_write();

        let cli_ok_r = !forward && event.is_readable();
        let cli_ok_w = !forward && event.is_writable();

        // Workaround for not finding a way to get tls to work in MIO ekosystem statemachine environment,
        // and seem to need read write on for the socket all the time.
        if !forward
            && event.is_writable()
            && self.send_to_client.is_none()
            && !tls_ok_r
            && !tls_ok_w
        {
            self.reregister(registry, token, Interest::READABLE | Interest::WRITABLE)
                .ok();
            return Some(true);
        };

        debug!(
            "Main Is clientThread ({}) or Is forwardThread ({})",
            token == self.server_token,
            token == self.forward_token
        );

        if token == self.server_token {
            self.server_reregistered = false;
        };

        if event.is_error() {
            panic!("Event is_error");
        }
        if event.is_write_closed() {
            trace!(target: &self.server_token.0.to_string(),"Main Event is_write_closed");
            if forward {
                self.closing = true;
                self.forward_stream = None;
                forward = false;
            }
            self.closing = true;
        }
        if event.is_read_closed() {
            trace!(target: &self.server_token.0.to_string(),"Main Event is_read_closed");
            if forward {
                self.forward_stream = None;
                self.closing = true;
                forward = false;
            } else {
                self.closing = true;
            }
        }

        trace!(
            "Main Closing {} or Closed {} and Forward {}",
            self.closing,
            self.done_closing,
            forward
        );

        if self.counter > 20 {
            self.reregister(registry, token, Interest::READABLE).ok();
        } else if !tls_ok_r && !tls_ok_w && !cli_ok_r && cli_ok_w && !fwd_ok_r && !fwd_ok_w {
            self.counter += 1;
        } else {
            self.counter = 0;
        }

        trace!(target: &self.server_token.0.to_string(),"\r\ntls_ok_r: {}\r\ntls_ok_w: {}\r\ncli_ok_r: {}\r\ncli_ok_w: {}\r\nfwd_ok_r: {}\r\nfwd_ok_w: {}\r\nCounter: {}\r\n",
        tls_ok_r,tls_ok_w,cli_ok_r,cli_ok_w,fwd_ok_r,fwd_ok_w,self.counter);

        /*

            Read/Write FWD (HTTP)

        */
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if fwd_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Entering FWD_W ({})", success);

            let len = min(self.send_to_farward.as_mut().unwrap().len(), 2048);
            debug!(
                "ForWrite Forwarding!!!!!!!!!!!!!!!!: \r\n{}",
                String::from_utf8_lossy(&self.send_to_farward.as_mut().unwrap()[..len])
            );
            trace!(target: &self.server_token.0.to_string(),"ForWrite Reregistering for READ");
            self.reregister(registry, self.forward_token, Interest::READABLE)
                .ok();
            let stream = self.forward_stream.as_mut().expect("Forward stream");
            let ret = stream.write(self.send_to_farward.as_mut().unwrap());
            write_error_handling!(self, ret);
            stream.flush().ok();
            self.send_to_farward = None;
            trace!(target: &self.server_token.0.to_string(),"Exiting FWD_W ({})", success);
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if fwd_ok_r {
            trace!(target: &self.server_token.0.to_string(),"Entering FWD_R ({})", success);
            if self.send_to_client.is_none() && self.forward_stream.is_some() {
                let mut received_data = Vec::new();
                loop {
                    let mut buf = [0; 2048];
                    let res = self.forward_stream.as_mut().unwrap().read(&mut buf);
                    trace!(target: &self.server_token.0.to_string(),"ForRead Checking read errors");

                    read_error_handling!(self, res, received_data, buf);
                }

                self.reregister(registry, self.server_token, Interest::WRITABLE)
                    .unwrap();

                debug!(
                    "ForRead Got data from forward host: \r\n{}",
                    String::from_utf8_lossy(&received_data[..cmp::min(received_data.len(), 256)])
                );
                self.send_to_client = Some(received_data);
            }

            trace!(target: &self.server_token.0.to_string(),"Exiting FWD_R ({})", success);
        }
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);

        if fwd_ok_r || fwd_ok_w {
            self.reregister(registry, token, Interest::READABLE | Interest::WRITABLE)
                .ok();
            return Some(true);
        }

        /*

            Read/Write TLS and HTTPS

        */
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if tls_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Writing tls...");
            let rc = self
                .tls_session
                .as_mut()
                .unwrap()
                .write_tls(&mut self.server_stream);
            write_error_handling!(self, rc);
            trace!(target: &self.server_token.0.to_string(),"EXIT tls write.");
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if tls_ok_r {
            trace!(target: &self.server_token.0.to_string(),"New tls read: reading tls");
            // Read some TLS data.
            let res = self
                .tls_session
                .as_mut()
                .unwrap()
                .read_tls(&mut self.server_stream);
            read_error_handling!(self, res);

            // Process newly-received TLS messages.
            trace!(target: &self.server_token.0.to_string(),"New tls read: processing packages");
            let processed = self.tls_session.as_mut().unwrap().process_new_packets();
            error!(target: &self.server_token.0.to_string(),"New tls read: cannot process packet: {:?}", processed);
            process_error_handling!(self,processed);
        }

        /*

            Read/Write CLI

        */
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if cli_ok_r {
            trace!(target: &self.server_token.0.to_string(),"Entering CLI_R ({})", success);
            success = self.local_reader(registry).unwrap();
            trace!(target: &self.server_token.0.to_string(),"Exiting CLI_R ({})", success);
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if cli_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Entering CLI_W ({})", success);
            success = self.local_writer(event, registry).unwrap();
            trace!(target: &self.server_token.0.to_string(),"Exiting CLI_W ({})", success);
        }

        /*

            Cleanup or reregister socket

        */

        if self.closing {
            trace!(target: &self.server_token.0.to_string(),"Main closing connection");
            self.close_all(registry);
            return Some(false);
        } else {
            debug!(target: &self.server_token.0.to_string(),"Main registry");

            if token == self.server_token && self.send_to_client.is_none() && !tls_ok_r && !tls_ok_w
            {
                trace!(target: &self.server_token.0.to_string(),"Registering READ(/WRITE) but should only need READ.");
                self.reregister(
                    registry,
                    self.server_token,
                    Interest::WRITABLE | Interest::READABLE,
                )
                .ok();
            } else if token == self.server_token && !self.server_reregistered {
                trace!(target: &self.server_token.0.to_string(),"Not registered Registering READ.");
                self.reregister(
                    registry,
                    self.server_token,
                    Interest::READABLE | Interest::WRITABLE,
                )
                .ok();
            };
        }

        debug!(target: &self.server_token.0.to_string(),"Main DONE");
        if self.done_closing {
            return Some(false);
        }
        if self.do_tls {
            self.tls_session.as_mut().unwrap().flush().ok();
        } else {
            self.server_stream.flush().ok();
        }
        return Some(true);
    }

    fn close_all(&mut self, registry: &Registry) {
        trace!(target: &self.server_token.0.to_string(),"entering close_all closing connections");
        if self.do_tls {
            self.tls_session.as_mut().unwrap().send_close_notify();
            self.tls_session.as_mut().unwrap().flush().ok();
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
        trace!(target: &self.server_token.0.to_string(),"exiting close_all closing connections");
    }
}

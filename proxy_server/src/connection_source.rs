use mio::{
    event::{Event, Source},
    net::TcpStream,
    Interest, Registry, Token,
};

use rustls;
use rustls::{Session, TLSError};

//use cmp::min;
use httparse::{self, Request};
use std::{
    //    cmp,
    collections::{HashMap, VecDeque},
    io,
    io::{Read, Write},
    net,
    sync::Arc,
    time::Instant, cmp::min,
};

use crate::{
    cache_test::Cacher, http_parser::try_iterate_bytes, ok_macro, process_error_handling,
    read_error_handling, write_error_handling,
};

#[derive(Debug)] //Instant::now();
pub struct ConnectionSource {
    pub server_stream: TcpStream,
    pub tls_session: Option<rustls::ServerSession>,
    pub server_token: Token,
    pub forward_token: Token,
    pub forward_host: String,
    pub forward_lookup: Arc<HashMap<String, String>>,
    //TODO: Remove do_tls and use tls_session.is_some instead.
    pub do_tls: bool,
    request_host: String,

    forward_stream: Option<TcpStream>,
    send_to_farward: VecDeque<Vec<u8>>,
    buf_forward: Vec<u8>,
    send_to_client: VecDeque<Vec<u8>>,
    buf_client: Vec<u8>,
    closing: bool,
    done_closing: bool,
    server_reregistered: bool,
    //counter: u16,
    bytes_sent: usize,
    bytes_received: usize,
    activity_timeout: Option<Instant>,
    http_get_path: String,
}

// All functions here are needed to comply with the source implementation
// mio::event::source https://docs.rs/mio/0.7.0/mio/event/trait.Source.html
impl Source for ConnectionSource {
    // Registers the stream for the first time or after a deregister is called.
    // First we test if it is the server_stream orh the forward_stream that needs
    // registering and then we register the appropriate stream.

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
    // Reregisters the stream, to not fall out of the mio token poll loop.
    // First we test if it is the server_stream orh the forward_stream that needs
    // registering and then we reregister the appropriate stream.
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
                //To much trace!(target: &self.server_token.0.to_string(),"Reregistering Server using ConnectionSource function");
                self.server_reregistered = true;
                self.server_stream
                    .reregister(registry, token, interests)
                    .ok();
            }
        }
        Ok(())
    }

    // Removing the stream, from the mio token poll loop.
    // This will always deregister both streams if they exist or just server_stream.
    // To deregister forward_stream if needed somehow we call the deregister on the socket.
    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        trace!(target: &self.server_token.0.to_string(),"Deregistering using ConnectionSource function");
        if self.forward_stream.is_some() {
            match self.forward_stream.as_mut().unwrap().deregister(registry) {
                Ok(_) => (),
                Err(e) => error!("Error deregistering forward_stream {:?}", e),
            }
        }

        let mut server_addr = String::new();
        //        let mut sni_host="";
        let mut server_port = 0;
        if self.server_stream.peer_addr().is_ok() {
            server_addr = self.server_stream.peer_addr().unwrap().to_string()
        }
        // if self.tls_session.is_some() && self.tls_session.as_mut().unwrap().get_sni_hostname().is_some() {
        //     sni_host = self.tls_session.as_mut().unwrap().get_sni_hostname().unwrap();
        // }
        if self.server_stream.local_addr().is_ok() {
            server_port = self.server_stream.local_addr().unwrap().port();
        }

        info!(target: &self.server_token.0.to_string(),
            "Connection  {} -> {}:{} => {}  to_client:{} from_client:{}",
            server_addr,
            self.request_host,
            server_port,
            self.forward_host,
            self.bytes_received,
            self.bytes_sent,
        );

        self.server_stream.deregister(registry)
    }
}

// We have a new function so that we can have private variables.
impl ConnectionSource {
    pub fn new(
        connection: TcpStream,
        server_token: Token,
        forward_token: Token,
        tls_session: Option<rustls::ServerSession>,
        forward_lookup: Arc<HashMap<String, String>>,
    ) -> ConnectionSource {
        let m_session: ConnectionSource = ConnectionSource {
            server_stream: connection,
            server_token: server_token,
            forward_stream: None,
            forward_token: forward_token,
            forward_lookup: forward_lookup,
            send_to_farward: VecDeque::new(),
            buf_forward: Vec::new(),
            send_to_client: VecDeque::new(),
            buf_client: Vec::new(),
            do_tls: tls_session.is_some(),
            tls_session: tls_session,
            request_host: String::new(),
            closing: false,
            done_closing: false,
            server_reregistered: false,
            forward_host: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            activity_timeout: None,
            http_get_path: String::new(),
        };
        m_session
    }
}

// HTTP
impl ConnectionSource {
    fn https_reader(&mut self) -> bool {
        trace!("Entering HTTPS_READER");
        loop {
            let mut buf = [0; 256];

            match self.tls_session.as_mut().unwrap().read(&mut buf) {
                // Ok(0) => {
                //     trace!(target: &self.server_token.0.to_string(),"https_reader read 0");
                //     return true;
                // }
                Ok(n) => {
                    self.activity_timeout = None;
                    let u: usize = n.to_string().parse().unwrap();
                    self.bytes_sent = self.bytes_sent + n;
                    self.buf_forward.extend_from_slice(&buf[0..u]);
                    trace!(target: &self.server_token.0.to_string(),"https_reader read {}",n);
                    if n < buf.len() {
                        //self.activity_timeout= Instant::now();
                        return true;
                    }
                    //return None;
                }
                //Looks to be what registers when finished reading.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    trace!(target: &self.server_token.0.to_string(),"https_reader Would block\r\n{:?}",e);
                    if self.buf_forward.len() > 0 {
                        //self.activity_timeout= Instant::now();
                       
                        return true;
                    }
                    //return false;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    trace!(target: &self.server_token.0.to_string(),"https_reader Interupted\r\n{:?}",e);
                    continue;
                }
                Err(e) => {
                    error!(target: &self.server_token.0.to_string(),"https_reader Unknown error: \r\n{:?}",e);
                    return false;
                }
            }
        }
    }

    fn https_writer(&mut self) -> Option<bool> {
        while self.send_to_client.len() > 0 {
            let buf = self.send_to_client.pop_front();
            let len = &buf.clone().unwrap().len();
            let res = self
                .tls_session
                .as_mut()
                .unwrap()
                .write_all(&buf.unwrap().as_mut_slice());
            match res {
                Ok(()) => {
                    //self.activity_timeout= Instant::now();
                    self.bytes_received = self.bytes_received + len;
                    self.activity_timeout = Some(Instant::now());
                    return Some(true);
                }
                Err(e) => {
                    error!(target: &self.server_token.0.to_string(),"https_writer Unknown error: \r\n{:?}",e);
                    return Some(false);
                }
            }
        }
        Some(true)
    }

    fn http_reader(&mut self) -> bool {
        //let mut received_data: Vec<u8> = Vec::new();
        loop {
            let mut buf = [0; 2048];
            match self.server_stream.read(&mut buf) {
                // https://tokio.rs/blog/2019-12-mio-v0.7-alpha.1
                // Ok(0) => {
                //     trace!(target: &self.server_token.0.to_string(),"http_reader read 0");
                //     return true;
                // }
                Ok(n) => {
                    self.activity_timeout = None;
                    self.bytes_sent = self.bytes_sent + n;
                    self.buf_forward.extend_from_slice(&buf[0..n]);
                    trace!(target: &self.server_token.0.to_string(),"http_reader read {}",n);
                    if n < 2048 {
                        //self.activity_timeout= Instant::now();
                        return true;
                    }
                    //return None;
                }
                //Looks to be what registers when finished reading.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    trace!(target: &self.server_token.0.to_string(),"http_reader Would block\r\n{:?}",e);
                    if self.buf_forward.len() > 0 {
                        self.print_header(&self.buf_forward);
                        //self.activity_timeout= Instant::now();
                        return true;
                    }
                    return false;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    trace!(target: &self.server_token.0.to_string(),"http_reader Interupted\r\n{:?}",e);
                    continue;
                }
                Err(e) => {
                    error!(target: &self.server_token.0.to_string(),"http_reader Unknown error: \r\n{:?}",e);
                    return false;
                }
            }
        }
    }

    fn http_writer(&mut self) -> Option<bool> {
        while self.send_to_client.len() > 0 {
            let buf = self.send_to_client.pop_front();
            let len = buf.clone().unwrap().len();
            let res = self.server_stream.write_all(&buf.unwrap().as_mut_slice());
            match res {
                Ok(()) => {
                    self.bytes_received = self.bytes_received + len;
                    self.activity_timeout = Some(Instant::now());
                    return Some(true);
                }
                Err(e) => {
                    error!(target: &self.server_token.0.to_string(),"http_writer Unknown error: \r\n{:?}",e);
                    return Some(false);
                }
            }
        }
        Some(true)
    }

    fn http_fwd_reader(&mut self) -> bool {
        loop {
            let mut buf = [0; 1024];
            match self.forward_stream.as_mut().unwrap().read(&mut buf) {
                // https://tokio.rs/blog/2019-12-mio-v0.7-alpha.1
                // Ok(0) => {
                //     trace!(target: &self.server_token.0.to_string(),"http_fwd_reader read 0");
                //     return true;
                // }
                Ok(n) => {
                    if n > 0 {
                        self.buf_client.extend_from_slice(&buf[0..n]);
                    }
                    trace!(target: &self.server_token.0.to_string(),"http_fwd_reader read {}",n);
                    if n < 1024 {
                         self.print_header(&self.buf_client);
                        //self.activity_timeout= Instant::now();
                        return true;
                    }
                }
                //Looks to be what registers when finished reading.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    trace!(target: &self.server_token.0.to_string(),"http_fwd_reader Would block\r\n{:?}",e);
                    if self.buf_client.len() > 0 {
                        self.print_header(&self.buf_client);
                        return true;
                    }
                    return false;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    trace!(target: &self.server_token.0.to_string(),"http_fwd_reader Interupted\r\n{:?}",e);
                    continue;
                }
                Err(e) => {
                    error!(target: &self.server_token.0.to_string(),"http_fwd_reader Unknown error: \r\n{:?}",e);
                    return false;
                }
            }
        }
    }

    fn http_fwd_writer(&mut self) -> bool {
        while self.send_to_farward.len() > 0 {
            let buf = self.send_to_farward.pop_front();
            trace!(target: &self.server_token.0.to_string(),"http_fwd_writer data: \r\n{}",String::from_utf8_lossy(&buf.clone().unwrap().as_slice()));
            let res = self
                .forward_stream
                .as_mut()
                .unwrap()
                .write_all(&buf.unwrap().as_mut_slice());
            match res {
                Ok(()) => {
                    return true;
                }
                Err(e) => {
                    trace!(target: &self.server_token.0.to_string(),"http_fwd_writer Unknown error: \r\n{:?}",e);
                    return false;
                }
            }
        }
        return true;
    }
    
    fn print_header(&self, buf: &Vec<u8>) {
        if String::from_utf8_lossy(buf.as_slice()).contains("\r\n\r\n") {
            debug!("Headers:\r\n{}", String::from_utf8_lossy(&buf[0..min(256,buf.len())]));
        }
    }

    fn set_forward_adress(&mut self) -> bool {
        if !self.forward_host.is_empty() {
            return true;
        }
        if String::from_utf8_lossy(&self.buf_forward.as_slice()).contains("\r\n\r\n") {
            //trace!("{}", String::from_utf8_lossy(&self.buf_forward.as_slice()));
            //TODO should be a reusable struct maby.
            self.http_parse_set_host();

            return true;
        }
        true
    }

    fn http_parse_set_host(&mut self) -> bool {
        let mut headers = [httparse::EMPTY_HEADER; 200];
        let mut req = httparse::Request::new(&mut headers);
        let b: Vec<u8> = Vec::from(self.buf_forward.clone());
        match req.parse(b.as_slice()) {
            Ok(_) => (),
            Err(e) => {
                error!(target: &self.server_token.0.to_string(),"Read http-parse error unknown: {:?}",e);
                return false;
            }
        };

        //TODO is host always on index 0?
        self.request_host = format!("{}", String::from_utf8_lossy(req.headers[0].value));

        self.http_get_path = String::from(req.path.unwrap_or_else(|| ""));

        trace!(target: &self.server_token.0.to_string(),"Method: {}, Path: {}, Host: {}",
            req.method.unwrap_or(""),
            req.path.unwrap_or(""),self.request_host);
        for h in req.headers {
            trace!(target: &self.server_token.0.to_string(),"Header --> {}: {}",h.name,String::from_utf8_lossy(h.value));
        }
        return true;
    }
}

impl ConnectionSource {

    //Used by read above to start a forward_stream to handle sending along the request to
    //the backend host, and to then read the reply and send along to the server_stream that
    //then in the above write function will send it to the client.
    fn activate_forward_stream(&mut self, registry: &Registry) -> bool {
        trace!("Enter activate_forward_stream");
        //self.activity_timeout= Instant::now();
        // Did not help to prevent white pages
        // if self.forward_stream.is_some() {
        //     trace!(target: &self.server_token.0.to_string(),"Seting to none");
        //     self.forward_stream.as_mut().unwrap().shutdown(net::Shutdown::Both).ok();
        //     self.forward_stream = None;
        // }
        //We need if the forward_stream exists or not. If it does not exist we need to create
        //it, else we need to reregister.
        if self.forward_stream.is_none() {
            self.forward_stream = if !self.request_host.is_empty() {
                self.forward_host = self
                    .forward_lookup
                    .get(&self.request_host)
                    .unwrap_or(&dotenv::var("DEFAULT_FORWARD").unwrap_or(String::from("")))
                    //                    .unwrap_or(&String::from("192.168.96.54:80"))
                    .parse()
                    .expect("what2");

                info!(target: &self.server_token.0.to_string(),
                    "Connection established {} -> {}:{} => {}",
                    self.server_stream.peer_addr().expect("Peer_Addr").to_string(),
                      self.request_host, self.server_stream.local_addr().expect("ServerStream").port(),self.forward_host);

                let socket: Result<std::net::SocketAddr, _> = self.forward_host.parse();
                if socket.is_ok() {
                    Some(TcpStream::connect(socket.unwrap()).unwrap())
                } else {
                    self.closing = true;
                    error!(target: &self.server_token.0.to_string(),"We have no forwarding adress for {}",&self.request_host);
                    None
                }
            } else {
                //Anything else are assigned the following port and IP
                error!(target: &self.server_token.0.to_string(),"Could not find forward adress return with false!");
                return false;
                //TODO: fix, should either not be used or should be in config
                //Some(TcpStream::connect("192.168.96.54:80".parse().unwrap()).unwrap())
            };

            //We need to register the forward stream, as it is newly created, or recreated.
            //We only need to write as we just filled in data for it to send.
            trace!(target: &self.server_token.0.to_string(),"Forward stream set to for WRITE");
            self.register(registry, self.forward_token, Interest::WRITABLE)
                .ok();
            trace!(target: &self.server_token.0.to_string(),"Forward stream Created...");
            return true;
        } else {
            //We already have a forward_stream so lets just reregister that one.
            //We only need to write as we just filled in data for it to send.
            self.reregister(registry, self.forward_token, Interest::WRITABLE)
                .ok();
            trace!(target: &self.server_token.0.to_string(),"Write Server ReCreated...");
            return true;
        }
    }
}

impl ConnectionSource {
    // When server has a new client the struct is intitialized with this function.
    pub fn call_with_new_client(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        trace!(target: &self.server_token.0.to_string(),"New client accepted to our ConnectionSource");
        self.register(registry, token, interests)
    }

    // Handle connection for the called socket, can be either a server_stream socket or a forward_stream socket.
    // As they both will be registered to the Mio poll loop.
    pub fn handle_connection_event(
        &mut self,
        registry: &Registry,
        event: &Event,
        token: Token,
    ) -> Option<bool> {
        // if token == self.server_token {
        //     self.server_stream.deregister(registry).expect("Expected to deregister server thread on entry!");
        // }

        // if token == self.forward_token && self.forward_stream.is_some() {
        //     self.forward_stream.as_mut().unwrap().deregister(registry).expect("Expected to deregister server thread on entry!");
        // }

        // Too much trace!(target: &self.server_token.0.to_string(),"Main incomming Event: \r\n{:?}",event);
        //TODO set config for connection timout
        if self.activity_timeout.is_some()
            && self.activity_timeout.unwrap().elapsed().as_millis() > 300
        {
            self.closing = true;
        }

        //Success is used to check if thefunctions called have succeeded or not, we might
        // in the future decide closing depending on this, we will have too see.
        // And for logging to see where the code fails depending on where this changes.
        let mut success: bool = true;

        //forward is true if the thread is called to use the forward_stream
        let mut forward = token == self.forward_token && self.forward_stream.is_some();

        //if fwd_ok_r is true We are ok to read the forward stream.
        let fwd_ok_r = forward && event.is_readable() && self.forward_stream.is_some();
        //if fwd_ok_w is true We are ok to write the forward stream.
        let fwd_ok_w = forward
            && event.is_writable()
            && self.forward_stream.is_some()
            && self.send_to_farward.len() > 0;
        //&& self.do_tls;

        // let http_fwd_ok_r =
        //     forward && event.is_readable() && self.forward_stream.is_some() && !self.do_tls;

        // let http_fwd_ok_w = forward
        //     && event.is_writable()
        //     && self.forward_stream.is_some()
        //     && self.send_to_farward.len() > 0
        //     && !self.do_tls;
        //if tls_ok_r is true we have tls and we are ok to read the tls_session
        let tls_ok_r = event.is_readable() && !forward && self.do_tls;

        //if tls_ok_w is true we are ok to write to the tls_session
        let tls_ok_w = event.is_writable()
            && !forward
            && self.do_tls
            && self.tls_session.is_some()
            && self.tls_session.as_mut().unwrap().wants_write();

        //if https_ok_r is true we are ok to read from the client via server_stream
        let https_ok_r = event.is_readable() && self.do_tls;
        //if fwd_ok_w is true we are ok to write to the client via server_stream
        let https_ok_w = event.is_writable() && self.do_tls;

        let http_ok_r = event.is_readable() && !self.do_tls;
        //if fwd_ok_w is true we are ok to write to the client via server_stream
        let http_ok_w = event.is_writable() && !self.do_tls && self.send_to_client.len() > 0;

        // Workaround for not finding a way to get tls to work in MIO ekosystem statemachine environment,
        // and seem to need read write on for the socket all the time.
        if !forward
            && event.is_writable()
            && self.send_to_client.len() > 0
            && !tls_ok_r
            && !tls_ok_w
        {
            self.reregister(registry, token, Interest::READABLE | Interest::WRITABLE)
                .ok();
            return Some(true);
        };

        trace!(target: &self.server_token.0.to_string(),
            "Main Is clientThread ({}) or Is forwardThread ({})",
            token == self.server_token,
            token == self.forward_token
        );

        //We will start to set this to not registered to know if it
        //reregisters during this cycle.
        if token == self.server_token {
            self.server_reregistered = false;
        };

        //If there is a socket error in the server_stream we need to close down and
        //wait for client to reconnect. However forward_stream should be recreated
        //if it is needed.

        if forward && event.is_error() {
            ok_macro!(
                self,
                self.forward_stream
                    .as_mut()
                    .unwrap()
                    .shutdown(net::Shutdown::Both)
            );
            ok_macro!(
                self,
                self.forward_stream.as_mut().unwrap().deregister(registry)
            );
            self.forward_stream = None;
            return Some(true);
        } else if !forward && event.is_error() {
            error!(target: &self.server_token.0.to_string(),"Socket is in error state! Closing");
            self.close_all(registry);
            return Some(false);
        }

        //If there is a close event on the socket we need to free forward so it is recreated,
        //And if server_stream we need to close everything.
        if forward && event.is_write_closed() {
            ok_macro!(
                self,
                self.forward_stream
                    .as_mut()
                    .unwrap()
                    .shutdown(net::Shutdown::Both)
            );
            ok_macro!(
                self,
                self.forward_stream.as_mut().unwrap().deregister(registry)
            );
            self.forward_stream = None;
            return Some(true);
        } else if event.is_write_closed() {
            trace!(target: &self.server_token.0.to_string(),"Main Event is_write_closed");
            if forward {
                self.closing = true;
                self.forward_stream = None;
                forward = false;
            }
            self.closing = true;
        }

        //If there is a close event on the socket we need to free forward so it is recreated,
        //And if server_stream we need to close everything.
        if forward && event.is_read_closed() {
            ok_macro!(
                self,
                self.forward_stream
                    .as_mut()
                    .unwrap()
                    .shutdown(net::Shutdown::Both)
            );
            ok_macro!(
                self,
                self.forward_stream.as_mut().unwrap().deregister(registry)
            );
            self.forward_stream = None;
            return Some(true);
        } else if event.is_read_closed() {
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

        //Not realy used, its mostly to track infinite loops that we shoukd control,
        //even though we are in an infinite loop we should not process stuff when it is
        //not needed.
        // if self.counter > 20 {
        //     ok_macro!(self, self.reregister(registry, token, Interest::READABLE));
        // } else if !tls_ok_r && !tls_ok_w && !https_ok_r && https_ok_w && !fwd_ok_r && !fwd_ok_w {
        //    self.counter += 1;
        // } else {
        //     self.counter = 0;
        // }

        trace!(target: &self.server_token.0.to_string(),"tls_ok_r: {} ntls_ok_w: {} https_ok_r: {} https_ok_w: {} fwd_ok_r: {} fwd_ok_w: {}",
        tls_ok_r,tls_ok_w,https_ok_r,https_ok_w,fwd_ok_r,fwd_ok_w);

        /*

            Read/Write FWD (HTTP)

            This is for the forwarding requests to the backend server, this socket should be
            recreated if needed.

            fwd_ok_w: If a client has sent a request to the server_stream it has been collected in
            self.send_to_forward and we are therefore sending that text along to the backend
            here.

            fwd_ok_r: Will read the answer from the backend and set the self.send_to_client with
            the answer to be handled by the server_stream socket.

        */
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if fwd_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Entering FWD_W ({})", success);

            if self.http_fwd_writer() {
                ok_macro!(
                    self,
                    self.reregister(
                        registry,
                        self.forward_token,
                        Interest::READABLE | Interest::WRITABLE
                    )
                );
            }

            //self.https_forward_writer(registry);

            trace!(target: &self.server_token.0.to_string(),"Exiting FWD_W ({})", success);
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if fwd_ok_r {
            trace!(target: &self.server_token.0.to_string(),"Entering FWD_R ({})", success);

            if self.http_fwd_reader() {
                let mut c = Cacher::new();
                c.cache_this(&self.request_host, &self.forward_host, &self.http_get_path)
                     .expect("Expected cacher to cache_this");

                //try_iterate_bytes(self.buf_client.clone());

                &self.send_to_client.push_back(self.buf_client.clone());
                &self.buf_client.clear();
            } else {
                success = false;
            }
            ok_macro!(
                self,
                self.reregister(
                    registry,
                    self.forward_token,
                    Interest::READABLE | Interest::WRITABLE
                )
            );

            trace!(target: &self.server_token.0.to_string(),"Exiting FWD_R ({})", success);
        } //DONE fwd_ok_r
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);


        /*

            Read/Write TLS and HTTPS

            tls_ok_r and tls_ok_w handle the encryption and handshaking for tls(HTTPS)
            this is done using rustls.

        */
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if tls_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Writing tls...");
            //Write tls as it is needed.
            let rc = self
                .tls_session
                .as_mut()
                .unwrap()
                .write_tls(&mut self.server_stream);
            //Handle errors using macro
            write_error_handling!(self, rc);
            trace!(target: &self.server_token.0.to_string(),"EXIT tls write.");
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if tls_ok_r {
            trace!(target: &self.server_token.0.to_string(),"New tls read: reading tls");
            // Write data as this is needed.
            let res = self
                .tls_session
                .as_mut()
                .unwrap()
                .read_tls(&mut self.server_stream);
            //Handle errors with macro
            read_error_handling!(self, res);

            //Finally process messages, in the queue
            trace!(target: &self.server_token.0.to_string(),"New tls read: processing packages");
            let processed = self.tls_session.as_mut().unwrap().process_new_packets();
            //Use macro to do error handling.
            process_error_handling!(self, processed);

            // Should not be needed, we should use the request Host: header
            // if self.tls_session.is_some() && self.tls_session.unwrap().get_sni_hostname().is_some() {
            //     self.request_host = String::from(self.tls_session.unwrap().get_sni_hostname().unwrap());
            // }
        }

        /*

            Read/Write CLI

        */
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if https_ok_r {
            trace!(target: &self.server_token.0.to_string(),"Entering CLI_R ({})", success);
            if self.https_reader() {
                //Finished
                if self.set_forward_adress() {
                     let c = Cacher::new();
                     let some_cached = c.read_path(&self.request_host, &self.http_get_path);
                     if some_cached.is_ok() && some_cached.as_ref().unwrap().is_some() {
                         let cache = &some_cached.unwrap();
                         let cache = cache.clone().unwrap();
                         self.send_to_client.push_back(cache);
                         &self.buf_forward.clear();
                         //error!("GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG");
                     } else {
                        &self.send_to_farward.push_back(self.buf_forward.clone());
                        &self.buf_forward.clear();
                        self.activate_forward_stream(registry);
                    }
                }
            } else {
                success = false;
            }
            trace!(target: &self.server_token.0.to_string(),"Exiting CLI_R ({})", success);
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if https_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Entering CLI_W ({})", success);
            self.https_writer();
            //success = self.client_writer(event, registry).unwrap();
            trace!(target: &self.server_token.0.to_string(),"Exiting CLI_W ({})", success);
        }

        if http_ok_r {
            trace!(target: &self.server_token.0.to_string(),"Entering HTTP_R ({})", success);
            if self.http_reader() {
                if self.set_forward_adress() {
                    &self.send_to_farward.push_back(self.buf_forward.clone());
                    &self.buf_forward.clear();
                    self.activate_forward_stream(registry);
                }

                trace!(target: &self.server_token.0.to_string(),"HTTP_R finished reading http");
            } else {
                success = false;
            }

            trace!(target: &self.server_token.0.to_string(),"Exiting HTTP_R ({})", success);
        }

        if http_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Entering HTTP_W ({})", success);
            self.http_writer();
            trace!(target: &self.server_token.0.to_string(),"Entering HTTP_W ({})", success);
        }

        /*

            Cleanup or reregister socket

        */

        //If something has called for closing we will close everything with close_all
        //wich will set self.done_closing to true.
        if self.closing {
            trace!(target: &self.server_token.0.to_string(),"Main closing connection");
            self.close_all(registry);
            return Some(false);
        } else if self.done_closing {
            //TODO: Should we realy get here?
            trace!(target: &self.server_token.0.to_string(),"Main we are done closing, so why are we here?");
            return Some(false);
        }

        //If we are not closing we need to check that everything is registered so that we dont
        //become dead in memory.
        trace!(target: &self.server_token.0.to_string(),"Main registry");
        //IF we have a server_stream not being registered during this cycle we need to reregister
        //it or it will not be called again, and die the slow death.
        //TODO: We probably need errorhandling here.
        if self.send_to_farward.len() > 0 {
            //trace!(target: &self.server_token.0.to_string(),"Forward Registering READ.");
            //self.activate_forward_stream(registry);
        }

        if token == self.server_token && !self.server_reregistered {
            trace!(target: &self.server_token.0.to_string(),"Not registered Registering READ.");
            ok_macro!(
                self,
                self.reregister(
                    registry,
                    self.server_token,
                    Interest::READABLE | Interest::WRITABLE,
                )
            );
        };

        // Flush any active streams or tls_session
        trace!(target: &self.server_token.0.to_string(),"Main DONE");
        if self.do_tls {
            //TLS
            ok_macro!(self, self.tls_session.as_mut().unwrap().flush());
        } else {
            //Server/Client
            ok_macro!(self, self.server_stream.flush());
        }

        if self.forward_stream.is_some() {
            //Forward, handling backend connection
            ok_macro!(self, self.forward_stream.as_mut().unwrap().flush());
        }
        return Some(true);
    }

    // Closing all sockets, and sending close notify to tls_session
    //
    fn close_all(&mut self, registry: &Registry) -> Option<bool> {
        trace!(target: &self.server_token.0.to_string(),"Enter: close_all closing connections");
        trace!(target: &self.server_token.0.to_string(),"Closing all sockets!");
        //If tls then shutdown the tls_session
        if self.do_tls {
            //We do flush to send everything buffered to connections.
            ok_macro!(self, self.tls_session.as_mut().unwrap().flush());
            self.tls_session.as_mut().unwrap().send_close_notify();
        }

        //Shutdown the server_stream
        ok_macro!(self, self.server_stream.flush());
        let _ = self.server_stream.shutdown(net::Shutdown::Both);

        // Shutdown the forward_stream if it is not None
        if self.forward_stream.is_some() {
            let _ = self
                .forward_stream
                .as_mut()
                .unwrap()
                .shutdown(net::Shutdown::Both);
            drop(self.forward_stream.as_ref().unwrap());
        }

        drop(&self.server_stream);
        // Deregister server_stream and forward_stream if it exists
        ok_macro!(self, self.deregister(registry));
        trace!(target: &self.server_token.0.to_string(),"Exit: close_all closing connections");
        return Some(true);
    }
}

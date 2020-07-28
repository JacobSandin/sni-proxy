use mio::{
    event::{Event, Source},
    net::TcpStream,
    Interest, Registry, Token,
};

use rustls;
use rustls::{Session, TLSError};

use cmp::min;
use std::{
    cmp,
    collections::{HashMap, VecDeque},
    io,
    io::{Read, Write},
    net,
    sync::Arc, time::Instant,
};

use crate::{ok_macro, process_error_handling, read_error_handling, write_error_handling};

#[derive(Debug)]
pub struct ConnectionSource {
    pub server_stream: TcpStream,
    pub tls_session: Option<rustls::ServerSession>,
    pub server_token: Token,
    pub forward_token: Token,
    pub forward_host: String,
    pub forward_lookup: Arc<HashMap<String, String>>,
    //TODO: Remove do_tls and use tls_session.is_some instead.
    pub do_tls: bool,

    forward_stream: Option<TcpStream>,
    send_to_farward: VecDeque<Vec<u8>>,
    send_to_client: VecDeque<Vec<u8>>,
    closing: bool,
    done_closing: bool,
    server_reregistered: bool,
    counter: u16,
    bytes_sent: usize,
    bytes_received:usize,

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
           match self.forward_stream
                .as_mut()
                .unwrap()
                .deregister(registry) {
                    Ok(_) =>(),
                    Err(e) => error!("Error deregistering forward_stream {:?}", e),
                }
        }

        error!(target: &self.server_token.0.to_string(),
                    "Connection  {} -> {}:{} => {}  to_client:{} from_client:{}",
                    self.server_stream.peer_addr().unwrap().to_string(), 
                    self.tls_session.as_mut().unwrap().get_sni_hostname().unwrap(), 
                    self.server_stream.local_addr().unwrap().port(),
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
            send_to_client: VecDeque::new(),
            do_tls: tls_session.is_some(),
            tls_session: tls_session,
            closing: false,
            done_closing: false,
            server_reregistered: false,
            forward_host: String::new(),
            counter: 0,
            bytes_sent: 0,
            bytes_received:0,     
        };
        m_session
    }
}

impl ConnectionSource {
    // Reads the server_stream for client requests.
    fn client_reader(&mut self, registry: &Registry) -> Option<bool> {
        trace!(
            "Read Checking read if shutdown ({}) returning false",
            self.done_closing
        );
        // IF we have closed we should not be here.
        if self.done_closing {
            return Some(false);
        }
        //Setup a receiver buffer to collect read data.
        let mut received_data = Vec::new();
        //Loop untill we read all data
        loop {
            //Set up collect buffer
            let mut buf = [0; 512];
            trace!(target: &self.server_token.0.to_string(),"Read Reading buffer as tls={}", self.do_tls);
            //Chose the right stream to read depending on tls or not.
            let res: Result<usize, std::io::Error> = if self.do_tls {
                trace!(target: &self.server_token.0.to_string(),"Read using tls_session to read");
                //Use tls to read.
                self.tls_session.as_mut().unwrap().read(&mut buf)
            } else {
                trace!(target: &self.server_token.0.to_string(),"Read using server_stream to read");
                //Read unencrypted.
                self.server_stream.read(&mut buf)
            };
            trace!(target: &self.server_token.0.to_string(),"Read Checking read errors");
            //Handle errors with macro
            read_error_handling!(self, res, received_data, buf);
        }

        //If we got two linefeeds here it might actually be an html request.
        //TODO: Better parsing to decide, if it is a real request and also to add
        //proxy headers.
        self.bytes_sent += &received_data.as_slice().len();

        if String::from_utf8_lossy(&received_data).contains("\r\n\r\n") {
            self.send_to_farward.push_back(received_data);
            //= Some(received_data);
            self.activate_forward_stream(registry);
        };

        trace!(target: &self.server_token.0.to_string(),"Read DONE");
        return Some(true);
    }

    //Write response that the forward stream has collected from backend to the client
    //via the server_stream
    #[allow(unused_variables)]
    fn client_writer(&mut self, event: &Event, registry: &Registry) -> Option<bool> {
        //If we dont have anything to send, we cant realy do anything.
        if self.send_to_client.len() == 0 {
            return Some(true);
        }

        //Counter is mostly for debuging.
        //self.counter = 0;
        //Flush stream, to clear buffers.
        ok_macro!(self, self.server_stream.flush());
        //Transfer send data to local buffer, so that we can set tthe send_to_client to None for new data if there is queue.
        let res = self.send_to_client.pop_front();
        if res.is_none() {
            return Some(true);
        }
        let mut response = res.unwrap();

        trace!(target: &self.server_token.0.to_string(),
            "Write response: \r\n{}",
            String::from_utf8_lossy(&response[..min(1024, response.len())])
        );
        //Chose the right stream to send to.
        let ret = if self.do_tls {
            //Using tls/https to send data
            self.tls_session.as_mut().unwrap().write_all(&mut response)
        } else {
            //Use normal HTTP to send data.
            self.server_stream.write_all(&response)
        };
        //use Macro to fill in error handling
        write_error_handling!(self, ret);

        self.bytes_received += &response.as_slice().len();
        
        //        self.send_to_client = None;
        trace!(target: &self.server_token.0.to_string(),"Write DONE");
        if self.send_to_client.len() == 0 && self.bytes_sent >0 {
            //self.counter=0;
            // info!("Whassup");
            // self.timeout = Instant::now();
        //     self.closing =true;
        }
        return Some(true);
    }
}

impl ConnectionSource {
    fn forward_reader(&mut self, registry: &Registry) -> Option<bool> {
        // Test so that we actually have nothing in the que first, and that we have a stream to work with.
        //            if self.send_to_client.is_none() && self.forward_stream.is_some() {
        let mut received_data = Vec::new();
        //Loop to read all incomming data
        loop {
            //TODO: check that the buffer is not to small or too big, wich is normal?
            let mut buf = [0; 1280];
            let res = self.forward_stream.as_mut().unwrap().read(&mut buf);
            trace!(target: &self.server_token.0.to_string(),"ForRead Checking read errors");
            //Send along to macro for errorhandling.
            read_error_handling!(self, res, received_data, buf);
        }

        trace!(target: &self.server_token.0.to_string(),
            "ForRead Got data from forward host: \r\n{}",
            String::from_utf8_lossy(&received_data[..cmp::min(received_data.len(), 256)])
        );
        //Set data for server_stream to send to client.
        self.send_to_client.push_back(received_data);

        //Reregister the server to write the new DATA.
        self.reregister(registry, self.server_token, Interest::WRITABLE)
            .unwrap();
        //            }
        Some(true)
    }

    fn forward_writer(&mut self, registry: &Registry) -> Option<bool> {
        let send_this = self.send_to_farward.pop_front().unwrap();

        //Just for not logging too much information in debug
        let len = min(send_this.len(), 2048);
        trace!(target: &self.server_token.0.to_string(),
            "ForWrite Forwarding: \r\n{}",
            String::from_utf8_lossy(&send_this[..len])
        );

        //Sending the request collected from client to backend host.
        let stream = self
            .forward_stream
            .as_mut()
            .expect("ForWrite expecting stream");
        let ret = stream.write(&send_this);

        //Handle errors with macro
        write_error_handling!(self, ret);

        //Flush and reset
        ok_macro!(self, stream.flush());
        // self.send_to_farward = None;

        //Reregister for reading so we can collect the backend answer.
        trace!(target: &self.server_token.0.to_string(),"ForWrite Reregistering for READ");
        ok_macro!(
            self,
            self.reregister(registry, self.forward_token, Interest::READABLE)
        );

        Some(true)
    }

    //Used by read above to start a forward_stream to handle sending along the request to
    //the backend host, and to then read the reply and send along to the server_stream that
    //then in the above write function will send it to the client.
    fn activate_forward_stream(&mut self, registry: &Registry) {
        //We need if the forward_stream exists or not. If it does not exist we need to create
        //it, else we need to reregister.
        if self.forward_stream.is_none() {
            trace!(target: &self.server_token.0.to_string(),"Read starting forward stream.");
            self.forward_stream = if self.tls_session.is_some()
                && self
                    .tls_session
                    .as_mut()
                    .unwrap()
                    .get_sni_hostname()
                    .is_some()
            {
                let sni_hostname = self
                    .tls_session
                    .as_ref()
                    .unwrap()
                    .get_sni_hostname()
                    .unwrap();
                let adress = self
                    .forward_lookup
                    .get(sni_hostname)
                    .unwrap()
                    .parse()
                    .unwrap();

                info!(target: &self.server_token.0.to_string(),
                    "Connection established {} -> {}:{} => {}",
                    self.server_stream.peer_addr().unwrap().to_string(), 
                    sni_hostname, 
                    self.server_stream.local_addr().unwrap().port(),
                    adress);

                Some(TcpStream::connect(adress).unwrap())
            } else {
                //Anything else are assigned the following port and IP
                error!(target: &self.server_token.0.to_string(),"Could not find forward adress!");
                Some(TcpStream::connect("192.168.96.54:80".parse().unwrap()).unwrap())
            };

            //We need to register the forward stream, as it is newly created, or recreated.
            //We only need to write as we just filled in data for it to send.
            trace!(target: &self.server_token.0.to_string(),"Read Registering forward for WRITE");
            self.register(registry, self.forward_token, Interest::WRITABLE)
                .ok();
            trace!(target: &self.server_token.0.to_string(),"Read Server Created...");
        } else {
            //We already have a forward_stream so lets just reregister that one.
            //We only need to write as we just filled in data for it to send.
            self.reregister(registry, self.forward_token, Interest::WRITABLE)
                .ok();
            trace!(target: &self.server_token.0.to_string(),"Read Server ReCreated...");
        }
        //Getting len just for logging
        // let len = self.send_to_farward.len();
        // trace!(
        //     "Read Confirming send_to_forward has data:\r\n{}",
        //     String::from_utf8_lossy(&self.send_to_farward.as_mut().unwrap()[..min(len, 1024)])
        // );
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
        // Too much trace!(target: &self.server_token.0.to_string(),"Main incomming Event: \r\n{:?}",event);
        //self.counter += 1;
        if self.counter > 5 {
            info!("Counted enough {} ",self.counter);
            
            self.closing =true;
            self.close_all(registry);
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

        //if tls_ok_r is true we have tls and we are ok to read the tls_session
        let tls_ok_r = event.is_readable() && !forward && self.do_tls;

        //if tls_ok_w is true we are ok to write to the tls_session
        let tls_ok_w = event.is_writable()
            && !forward
            && self.do_tls
            && self.tls_session.is_some()
            && self.tls_session.as_mut().unwrap().wants_write();

        //if cli_ok_r is true we are ok to read from the client via server_stream
        let cli_ok_r = event.is_readable();
        //if fwd_ok_w is true we are ok to write to the client via server_stream
        let cli_ok_w = event.is_writable();

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
        // } else if !tls_ok_r && !tls_ok_w && !cli_ok_r && cli_ok_w && !fwd_ok_r && !fwd_ok_w {
        //    self.counter += 1;
        // } else {
        //     self.counter = 0;
        // }

        trace!(target: &self.server_token.0.to_string(),"\r\ntls_ok_r: {}\r\ntls_ok_w: {}\r\ncli_ok_r: {}\r\ncli_ok_w: {}\r\nfwd_ok_r: {}\r\nfwd_ok_w: {}\r\nCounter: {}\r\n",
        tls_ok_r,tls_ok_w,cli_ok_r,cli_ok_w,fwd_ok_r,fwd_ok_w,self.counter);

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

            self.forward_writer(registry);

            trace!(target: &self.server_token.0.to_string(),"Exiting FWD_W ({})", success);
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if fwd_ok_r {
            trace!(target: &self.server_token.0.to_string(),"Entering FWD_R ({})", success);

            self.forward_reader(registry);

            trace!(target: &self.server_token.0.to_string(),"Exiting FWD_R ({})", success);
        } //DONE fwd_ok_r
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);

        // IF we are in forward, we can stop processing here and reregister for both READ/WRITE
        // Maby we should just close it down, but lets try without the open/close overhead.
        if fwd_ok_r || fwd_ok_w {
            ok_macro!(
                self,
                self.reregister(registry, token, Interest::READABLE | Interest::WRITABLE)
            );
            return Some(true);
        }

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
        }

        /*

            Read/Write CLI

        */
        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if cli_ok_r {
            trace!(target: &self.server_token.0.to_string(),"Entering CLI_R ({})", success);
            success = self.client_reader(registry).unwrap();
            trace!(target: &self.server_token.0.to_string(),"Exiting CLI_R ({})", success);
        }

        trace!(target: &self.server_token.0.to_string(),"MAIN closing: ({})", self.closing);
        if cli_ok_w {
            trace!(target: &self.server_token.0.to_string(),"Entering CLI_W ({})", success);
            success = self.client_writer(event, registry).unwrap();
            trace!(target: &self.server_token.0.to_string(),"Exiting CLI_W ({})", success);
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
        }

        // Deregister server_stream and forward_stream if it exists
        ok_macro!(self, self.deregister(registry));
        trace!(target: &self.server_token.0.to_string(),"Exit: close_all closing connections");
        return Some(true);
    }
}

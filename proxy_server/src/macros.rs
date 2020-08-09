//Handles write errors for a socket stream.
#[macro_export]
macro_rules! write_error_handling {
    ($self:ident, $F:ident) => {
        match $F {
            Ok(a) => {
                trace!(target: &$self.server_token.0.to_string(),"MACRO Write succeeded:\r\n {:?}",a);
            },
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
               trace!(target: &$self.server_token.0.to_string(),"MACRO Write Error wouldblock ignoring \r\n{:?}",err);
            },
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                error!(target: &$self.server_token.0.to_string(),"MACRO Write registering for mor write as we were interupted.\r\n{:?}",err);
            },
            Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                error!(target: &$self.server_token.0.to_string(),"MACRO Write Connection aborted (breaking)\r\n{:?}",err);
            },
            Err(err) => {
                error!(target: &$self.server_token.0.to_string(),"MACRO Write Unknown error no writing: \r\n{:?}",err);
                $self.closing = true;
            },
        };
    }
}

//Handles read errors from socket stream
#[macro_export]
macro_rules! read_error_handling {
    // This form normal socket errors and bellow is tls
    ($self:ident, $ret:ident, $receiver:ident, $buf:ident,$wb:ident) => {

                match $ret {
                    Ok(0) => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read reading zero closing:({})", $self.closing);
                        //$self.closing =true;
                        break;
                    }
                    Ok(n) => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read Transfering read buffer to datacollecter received_data {}",n);
                        $receiver.extend_from_slice(&$buf[..n]);
                    }
                    Err(e)if e.kind() == io::ErrorKind::WouldBlock => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read Would block\r\n{:?}",e);
                        //TODO: Add a collector from client instead... so we dont halt the MIO loop or implement threading/async
                        //break;
                        if $wb.elapsed().as_millis() > 20 {
                            break;
                        }
                        continue;
                    }
                    Err(e)if e.kind() == io::ErrorKind::Interrupted => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read Interupted\r\n{:?}",e);
                        continue;
                    }
                    Err(e) => {
                        error!(target: &$self.server_token.0.to_string(),"MACRO Read Unknown error : {:?}", e);
                        $self.closing = true;
                        return false;
                    },
                }
    };
    //Her is the handling for TLS socket/session
    ($self:ident, $ret:ident) => {
            match $ret {
                Ok(0) => {
                    trace!(target: &$self.server_token.0.to_string(),"New tls read: EOF");
                    $self.closing = true;
                },
                Ok(n) => {
                    trace!(target: &$self.server_token.0.to_string(),"New tls read: bytes {}",n);
                },
                Err(e)if e.kind() == io::ErrorKind::WouldBlock => {
                    trace!(target: &$self.server_token.0.to_string(),"New tls read: Would block");
                },
                Err(e) => {
                    error!(target: &$self.server_token.0.to_string(),"New tls read: Unknown error:\r\n{:?}", e);
                }
            }
    };
}

#[macro_export]
macro_rules! req {
    ($name:ident, $buf:expr, |$arg:ident| $body:expr) => (
        req! {$name, $buf, Ok(Status::Complete($buf.len())), |$arg| $body }
    );
    ($name:ident, $buf:expr, $len:expr, |$arg:ident| $body:expr) => (
    #[test]
    fn $name() {
        let mut headers = [EMPTY_HEADER; NUM_OF_HEADERS];
        let mut req = Request::new(&mut headers[..]);
        let status = req.parse($buf.as_ref());
        assert_eq!(status, $len);
        closure(req);

        fn closure($arg: Request) {
            $body
        }
    }
    )
}

//Handle TLS process messages errors
#[macro_export]
macro_rules! process_error_handling {
    ($self:ident, $ret:ident) => {
            match $ret {
                Ok(_) => {
                    trace!(target: &$self.server_token.0.to_string(),"EXIT tls read.");
                }
                Err(e)
                    if e == TLSError::AlertReceived(
                        rustls::internal::msgs::enums::AlertDescription::CertificateUnknown,
                    ) =>
                {
                    error!(target: &$self.server_token.0.to_string(),"tls_session (read) Certificate unknown we are ignoring for adresses without certs yet:\r\n{:?}", e);
                }
                Err(e)
                    if e == TLSError::AlertReceived(
                        rustls::internal::msgs::enums::AlertDescription::CertificateExpired,
                    ) =>
                {
                    error!(target: &$self.server_token.0.to_string(),"tls_session (read) Certificate expired we are ignoring right now.:\r\n{:?}", e);
                }
                Err(e) => {
                    error!(target: &$self.server_token.0.to_string(),"tls_session (read) Certificate error not known terminating. {:?}",e);
                    $self.closing = true;
                }
            }
    }
}

//Macro for handling errors and none from Result<> and Option<>
#[macro_export]
macro_rules! ok_macro {
    ($self:ident, $ret:expr) => {
            match $ret {
                Ok(_) => {
                    trace!(target: &$self.server_token.0.to_string(),"MACRO ok_macro (OK).");
                },
                Err(e) =>
                {
                    error!(target: &$self.server_token.0.to_string(),"MACRO ok_macro returning Error:\r\n: {:?}",e);
                   // return Some(false);
                },
            }
    };
    ($self:ident, $ret:expr) => {
            match $ret {
                Some(a) => {
                    trace!(target: &$self.server_token.0.to_string(),"MACRO ok_macro Option returned (Some):\r\n {:?}.",a);
                },
                None =>
                {
                    error!(target: &$self.server_token.0.to_string(),"MACRO ok_macro Option returned (None)");
                },
            }
    };
}

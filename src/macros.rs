#[macro_export]
macro_rules! write_error_handling {
    ($self:ident, $F:ident) => {
        match $F {
            Ok(_) => {
                trace!(target: &$self.server_token.0.to_string(),"MACRO Write succeeded.");
            }
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                trace!(target: &$self.server_token.0.to_string(),"MACRO Write Error wouldblock ignoring");
            }
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {
                trace!(target: &$self.server_token.0.to_string(),"MACRO Write registering for mor write as we were interupted.");
            }
            Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
                error!(target: &$self.server_token.0.to_string(),"MACRO Write Connection aborted (breaking)");
            }
            Err(err) => {
                error!(target: &$self.server_token.0.to_string(),"MACRO Write Unknown error no writing: {:?}", err);
                $self.closing = true;
            }
        };
    }
}

#[macro_export]
macro_rules! read_error_handling {
    ($self:ident, $ret:ident, $receiver:ident, $buf:ident) => {
                match $ret {
                    Ok(0) => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read reading zero closing:({})", $self.closing);
                        break;
                    }
                    Ok(n) => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read Transfering read buffer to datacollecter received_data");
                        $receiver.extend_from_slice(&$buf[..n]);
                    }
                    Err(e)if e.kind() == io::ErrorKind::WouldBlock => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read Would block");
                        //   connection_closed=true;
                        break;
                    }
                    Err(e)if e.kind() == io::ErrorKind::Interrupted => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read Interupted");
                        continue;
                        //break;
                    }
                    Err(e) => {
                        trace!(target: &$self.server_token.0.to_string(),"MACRO Read Unknown error : {:?}", e);
                        $self.closing = true;
                        return Some(false);
                    },
                }
    };
    
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
                    error!(target: &$self.server_token.0.to_string(),"New tls read: Unknown error {:?}", e);
                }
            }
    };
}

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
                    error!(target: &$self.server_token.0.to_string(),"tls_session (read) Certificate unknown we are ignoring for adresses without certs yet.");
                }
                Err(e)
                    if e == TLSError::AlertReceived(
                        rustls::internal::msgs::enums::AlertDescription::CertificateExpired,
                    ) =>
                {
                    error!(target: &$self.server_token.0.to_string(),"tls_session (read) Certificate expired we are ignoring right now.");
                }
                Err(e) => {
                    error!(target: &$self.server_token.0.to_string(),"tls_session (read) Certificate error not known terminating. {:?}",e);
                    $self.closing = true;
                }
            }
        }
    }

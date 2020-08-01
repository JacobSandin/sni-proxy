use regex::Regex;
use rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls::sign::{RSASigningKey, SigningKey};
use rustls::{sign, ClientHello, ResolvesServerCert, TLSError};
use std::collections;
use std::fs::{self, File};
use std::io::BufReader;
use std::sync::Arc;


pub fn load_resolver() -> MyResolvesServerCertUsingSNI {
    let mut resolver = MyResolvesServerCertUsingSNI::new();
    add_certificate_to_resolver(
        "partof-path.domain.name.com",
        "domain.name.com",
        &mut resolver,
    );
    add_certificate_to_resolver(
        "partof-path.other.domain.name.com",
        "other-domain.name.com",
        &mut resolver,
    );
    //add_certificate_to_resolver("_default_", "localhost", &mut resolver);
    resolver
}


pub struct MyResolvesServerCertUsingSNI {
    by_name: collections::HashMap<String, sign::CertifiedKey>,
}


impl MyResolvesServerCertUsingSNI {
    pub fn new() -> MyResolvesServerCertUsingSNI {
        MyResolvesServerCertUsingSNI {
            by_name: collections::HashMap::new(),
        }
    }
    pub fn add(&mut self, name: &str, ck: sign::CertifiedKey) -> Result<(), TLSError> {
        if self.by_name.is_empty() {
            self.by_name.insert(String::from("__default__"), ck.clone());
        }

        self.by_name.insert(name.into(), ck);
        Ok(())
    }
}

impl ResolvesServerCert for MyResolvesServerCertUsingSNI {
    fn resolve(&self, client_hello: ClientHello) -> Option<sign::CertifiedKey> {
        if client_hello.server_name().is_none() {
            trace!("cannot look up certificate: no SNI from session");
            return None;
        }
        let name: &str = client_hello.server_name().unwrap().into();
        trace!(
            "trying to resolve name: {:?} for signature scheme: {:?}",
            name,
            client_hello.sigschemes()
        );

        if let Some(dnsname) = client_hello.server_name() {
            if self.by_name.contains_key(dnsname.into()) {
                trace!("1. lookup successfull for server name '{:?}'", dnsname);
                self.by_name.get(dnsname.into()).cloned()
            } else {
                trace!(
                    "2. could not look up a certificate for server name '{:?}' trying __default__!",
                    dnsname
                );
                self.by_name.get("__default__").cloned()
            }
        } else {
            trace!(
                "3. could not look up a certificate for server name '{:?}' trying __default__!",
                client_hello.server_name()
            );
            self.by_name.get("__default__").cloned()
            // None
        }
    }
}


pub fn add_certificate_to_resolver<'a>(
    name: &str,
    hostname: &str,
    resolver: &mut MyResolvesServerCertUsingSNI,
) {
    let cert_file = File::open(format!("../certificates/{}/fullchain.pem", name));
    if cert_file.is_err() {
        println!("error loading file: ../certificates/{}/fullchain.pem", name);
        return ();
    }
    let key_file = File::open(format!("../certificates/{}/privkey.pem", name));
    if key_file.is_err() {
        println!("error loading file: ../certificates/{}/privkey.pem", name);
        return ();
    }

    let cert = &mut BufReader::new(cert_file.unwrap());
    let cert_chain = certs(cert).unwrap();

    let (_, x509) = x509_parser::parse_x509_der(cert_chain[0].as_ref()).unwrap();
    let (_, x509) = x509.tbs_certificate.subject_alternative_name().unwrap();
    let ref mut names_vec: Vec<String> = Vec::new();
    let re = Regex::new(r#"\("(.*?)"\)"#).unwrap();
    let text = String::from(format!("{:?}", x509.general_names));
    println!("NamesHost: {}", hostname);
    for cap in re.captures_iter(text.as_str()) {
        names_vec.push((&cap[1]).to_string());
        println!("regex {}", &cap[1]);
    }

    let mut keys = rsa_private_keys(&mut BufReader::new(
        File::open(format!("../certificates/{}/privkey.pem", name)).unwrap(),
    ))
    .unwrap();

    if keys.len() == 0 {
        let key = &mut BufReader::new(
            File::open(format!("../certificates/{}/privkey.pem", name)).unwrap(),
        );
        keys = pkcs8_private_keys(key).unwrap();
    };

    let signing_key = RSASigningKey::new(&keys.remove(0)).unwrap();

    let signing_key_boxed: Arc<Box<dyn SigningKey>> = Arc::new(Box::new(signing_key));

    resolver
        .add(
            hostname,
            rustls::sign::CertifiedKey::new(cert_chain.clone(), signing_key_boxed.clone()),
        )
        .expect(&format!("Invalid certificate for {}:{}", hostname, name));
    for name in names_vec {
        resolver
            .add(
                name,
                rustls::sign::CertifiedKey::new(cert_chain.clone(), signing_key_boxed.clone()),
            )
            .expect(&format!("Invalid certificate for {}:{}", hostname, name));
    }
}


pub fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls::internal::pemfile::certs(&mut reader).unwrap()
}

pub fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::rsa_private_keys(&mut reader)
            .expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rustls::internal::pemfile::pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

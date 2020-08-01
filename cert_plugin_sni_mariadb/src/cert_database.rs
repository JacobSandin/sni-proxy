use collections::HashMap;
#[allow(unused_imports)]
use logg::{debug, error, info, trace, warn};
use mysql::{prelude::Queryable, PooledConn};
use rustls::{
    internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys},
    sign, ResolvesServerCert,
};
use sign::{RSASigningKey, SigningKey};
use std::{
    collections,
    io::{Cursor, Error},
    sync::Arc,
};
pub type Result<T> = std::result::Result<T, Error>;

pub fn get_all_certificates() -> Vec<Certificate> {
    let pool: mysql::Pool = mysql::Pool::new(dotenv::var("MARIA_URI").unwrap()).unwrap();
    let mut conn = pool.get_conn().unwrap();

    let mut selected_certificates = match conn.query_map(
        dotenv::var("SELECT_CRT_TABLE").unwrap(),
        |(id, fullchain, privkey, forward, active)| Certificate {
            id,
            fullchain,
            privkey,
            forward,
            active,
            domain_names: None,
        },
    ) {
        Ok(a) => a,
        Err(e) => {
            panic!("Error Selecting: {:?}", e);
        }
    };

    for c in &mut selected_certificates {
        c.fill_dn(&mut conn);
    }
    selected_certificates
}

#[derive(Debug, PartialEq, Eq)]
pub struct Certificate {
    pub id: i32,
    pub fullchain: String,
    pub privkey: String,
    pub forward: String,
    pub active: String,
    pub domain_names: Option<Vec<CertDomainName>>,
}

impl Certificate {
    pub fn fill_dn(&mut self, conn: &mut PooledConn) {
        let mut vars = HashMap::new();
        vars.insert("cert_id".to_string(), self.id.to_string());
        let q = strfmt::strfmt(&dotenv::var("SELECT_DN_FROM_CERT_ID").unwrap(), &vars).unwrap();

        self.domain_names = Some(
            conn.query_map(q, |(id, cert_id, dn, ca_primary)| {
                let dn = CertDomainName {
                    id,
                    cert_id,
                    dn,
                    ca_primary,
                };
                trace!("{} => {} => {}", self.id, &dn.dn, self.forward);
                dn
            })
            .unwrap(),
        );
    }

    pub fn verify_and_get_ck(&self) -> Result<sign::CertifiedKey> {
        let mut cert_bf = Cursor::new(&self.fullchain);
        let mut key_bf = Cursor::new(&self.privkey);

        let cert_chain = certs(&mut cert_bf).expect("Trying to read cert as buf");
        let mut keys = rsa_private_keys(&mut key_bf).expect("Trying to read key as buf");
        if keys.len() == 0 {
            let mut key_bf = Cursor::new(&self.privkey);
            keys = pkcs8_private_keys(&mut key_bf)
                .expect("Trying to get a key longer than 0 from pkcs8!");
        };

        let signing_key = RSASigningKey::new(&keys.remove(0)).expect("Trying to RSA Sign Key");

        let signing_key_boxed: Arc<Box<dyn SigningKey>> = Arc::new(Box::new(signing_key));

        Ok(rustls::sign::CertifiedKey::new(
            cert_chain.clone(),
            signing_key_boxed.clone(),
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CertDomainName {
    pub id: i32,
    pub cert_id: i32,
    pub dn: String,
    pub ca_primary: String,
}

#[allow(dead_code)]
pub struct MariaSNIResolver {
    default_cert: Option<sign::CertifiedKey>,
    name_to_cert_id_lookup: collections::HashMap<String, i32>,
    cert_id_to_cert_lookup: collections::HashMap<i32, sign::CertifiedKey>,
}

#[allow(dead_code)]
impl MariaSNIResolver {
    pub fn new() -> MariaSNIResolver {
        MariaSNIResolver {
            default_cert: None,
            name_to_cert_id_lookup: collections::HashMap::new(),
            cert_id_to_cert_lookup: collections::HashMap::new(),
        }
    }

    pub fn populate(&mut self, certs: &Vec<Certificate>) {
        for c in certs {
            let ck = c.verify_and_get_ck().expect("Trying to get a CK").clone();

            if dotenv::var("DEFAULT_CRT_ID").is_ok()
                && c.id.to_string() == dotenv::var("DEFAULT_CRT_ID").unwrap()
            {
                trace!("Default cert found! {}", &c.id);
                self.default_cert = Some(ck.clone());
            }

            self.cert_id_to_cert_lookup.insert(c.id, ck.clone());
            for dn in c.domain_names.as_ref().unwrap() {
                trace!("{} mapping {} => {} ", c.id, dn.dn, c.forward);
                self.name_to_cert_id_lookup.insert(dn.dn.clone(), c.id);
            }
        }
    }
}

impl ResolvesServerCert for MariaSNIResolver {
    fn resolve(&self, client_hello: rustls::ClientHello) -> Option<sign::CertifiedKey> {
        if client_hello.server_name().is_none() {
            trace!("Can't lookup db certificate: no SNI from session");
            return self.default_cert.clone();
        }
        let name: &str = client_hello.server_name().unwrap().into();
        trace!(
            "trying to resolve name: {:?} for signature scheme: {:?}",
            name,
            client_hello.sigschemes()
        );
        let opt_id = self.name_to_cert_id_lookup.get(name);
        if opt_id.is_some() {
            let id = opt_id.unwrap();
            let opt_ck = self.cert_id_to_cert_lookup.get(id).clone();
            if opt_ck.is_some() {
                trace!("Resolved name {} as CK success", &name);
                Some(opt_ck.unwrap().clone())
            } else {
                return self.default_cert.clone();
            }
        } else {
            return self.default_cert.clone();
        }
    }
}

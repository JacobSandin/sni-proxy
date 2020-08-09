//extern crate log as logg;
mod sni_resolver;
mod env_logger;
use interfaces::CertificateHandler;

use env_logger::activate_env_logger;
#[allow(unused_imports)]
use logg::{debug, error, info, trace, warn};
use std::{collections::HashMap, sync::Arc};
use sni_resolver::load_resolver;
use rustls::Certificate;

#[no_mangle]
// pub fn get_certificate_handler() -> Box<dyn CertificateHandler> {
//     activate_env_logger();
//     Box::new(CH::new())
// }
#[allow(dead_code)]
pub struct CH {
    id: String,
    import_certificates: Vec<Certificate>,
}

impl CH {
    // fn new() -> CH {
    //     let id = format!("{:08x}", rand::random::<u32>());
    //     println!("[{}] Created instance!", id);
    //     let import_certificates: Vec<Certificate>=Vec::new();// = get_all_certificates();
    //     CH {
    //         id,
    //         import_certificates,
    //     }
    // }
}

impl CertificateHandler for CH {
    fn get_forwards(&self) -> Box<Arc<HashMap<String, String>>> {
        info!(target: "0","Load forwards from database");
        let import_certificates = &self.import_certificates;
        let mut forwards: HashMap<String, String> = HashMap::new();
        // for cert in import_certificates
        //     .iter()
        //     .filter(|c| !c.forward.contains("127"))
        // {
        //     if cert.domain_names.is_some() {
        //         for dn in cert.domain_names.as_ref().unwrap() {
        //             if None == forwards.insert(String::from(&dn.dn), String::from(&cert.forward)) {
        //                 //Hosts println!("127.0.0.1   {0}  # {0}  => {1}",dn.dn,cert.forward);
        //             }
        //         }
        //     }
        // }
        // info!(target: "0","Forwards done");
        Box::new(Arc::new(forwards.clone()))
    }

    fn get_sni_resolver(&self) -> Box<Arc<dyn rustls::ResolvesServerCert>> {
        info!(target: "0","Resolver");
        
        let (resolver,forwards) = load_resolver();

        info!(target: "0","Resolver done");
        Box::new(Arc::new(resolver).clone())
    }
}

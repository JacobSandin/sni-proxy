use std::{collections::HashMap, sync::Arc};

pub trait CertificateHandler {
    fn get_forwards(&self) -> Box<Arc<HashMap<String, String>>>;
    fn get_sni_resolver(&self) -> Box<Arc<dyn rustls::ResolvesServerCert>>;
}

// pub trait Certificate {
//     fn fill_dn(&mut self, conn: &mut PooledConn);
// }

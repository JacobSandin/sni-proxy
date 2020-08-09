use std::{collections::HashMap, sync::Arc};

pub trait CertificateHandler {
    fn get_forwards(&self) -> Box<Arc<HashMap<String, String>>>;
    fn get_sni_resolver(&self) -> Box<Arc<dyn rustls::ResolvesServerCert>>;
}


pub trait Cacher {
    fn cache_update_and_test_path(&mut self, host: &str, forward: &str, http_path: &str, data: &Vec<u8>) -> std::io::Result<bool>;
    fn cache_read_path(&self, host: &str, http_path: &str) -> Box<Option<Vec<u8>>>;
}



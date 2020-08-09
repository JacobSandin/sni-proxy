mod env_logger;
mod cacher;

use interfaces::Cacher;




use env_logger::activate_env_logger;


use cacher::SNICacher;



#[no_mangle]
pub fn get_cacher() -> Box<dyn Cacher> {
    activate_env_logger();
    Box::new(SNICacher::new())
}

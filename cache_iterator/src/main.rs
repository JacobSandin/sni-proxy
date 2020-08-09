mod cache_iterator;
mod env_logger;
#[macro_use]
extern crate log;
#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

extern crate simplelog;

use env_logger::activate_env_logger;


use cache_iterator::*;


fn main() {
    activate_env_logger();
    CacheIterator::find_host_dirs();

}



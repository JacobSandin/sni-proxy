use crate::env_logger::activate_env_logger;

mod env_logger; //TODO: Make SNI with files for this plugin

#[allow(dead_code)]
pub fn call() {
    activate_env_logger();
}

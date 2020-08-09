use logg::{trace, LevelFilter};
use simplelog::{
    CombinedLogger, ConfigBuilder, SharedLogger, TermLogger, TerminalMode, WriteLogger,
};
use std::fs::File;

static LOG_FILE_NAME: &str = "sni_plugin.log";
pub fn activate_env_logger() {
    dotenv::from_filename("sni-proxy.env").unwrap_or_default();

    let log_config = ConfigBuilder::new()
        .set_time_format_str("%Y-%m-%d %T")
        .set_target_level(LevelFilter::Info)
        .set_time_to_local(true)
        .build();

    let mut logger: Vec<Box<dyn SharedLogger>> = Vec::new();

    if dotenv::var("TERM_LOG_LEVEL").is_ok() {
        let term_log_level: LevelFilter = dotenv::var("TERM_LOG_LEVEL").unwrap().parse().unwrap();
        logger.push(
            TermLogger::new(term_log_level, log_config.clone(), TerminalMode::Mixed).unwrap(),
        );
    } else {
        logger.push(
            TermLogger::new(LevelFilter::Debug, log_config.clone(), TerminalMode::Mixed).unwrap(),
        );
    }

    if dotenv::var("LOG_FILE_LEVEL").is_ok() && dotenv::var("LOG_DIR").is_ok() {
        let log_file_level: LevelFilter = dotenv::var("LOG_FILE_LEVEL").unwrap().parse().unwrap();
        let log_file = dotenv::var("LOG_DIR").unwrap();
        let log_file = format!("{}/{}", log_file, LOG_FILE_NAME);
        logger.push(WriteLogger::new(
            log_file_level.clone(),
            log_config,
            File::create(log_file).unwrap(),
        ));
    } else {
        logger.push(WriteLogger::new(
            LevelFilter::Trace,
            log_config.clone(),
            File::create("../trace_plugin_mariadb.log").unwrap(),
        ));
    }
    CombinedLogger::init(logger).unwrap();
    trace!(target: "0","Log started!");
}

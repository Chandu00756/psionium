use log::{info, error};

pub fn log_operation(op: &str, status: &str, data_size: usize) {
    match status {
        "success" => info!("Operation: {}, Status: {}, Data Size: {} bytes", op, status, data_size),
        "failure" => error!("Operation: {}, Status: {}, Data Size: {} bytes", op, status, data_size),
        _ => info!("Operation: {}, Status: {}, Data Size: {} bytes", op, status, data_size),
    }
}

pub fn init_logging() {
    env_logger::init();
}
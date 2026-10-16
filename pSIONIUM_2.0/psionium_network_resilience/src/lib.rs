#[cfg(test)]
pub mod tests;

pub mod network;

use log::info;

pub fn initialize() {
    info!("Initializing Psionium Network Resilience component");
}
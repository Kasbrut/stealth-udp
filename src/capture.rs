//! Network capture setup: interface selection and data-link channel opening.
//!
//! These functions return `Result` instead of panicking so the caller can
//! print a friendly message and exit cleanly on environment errors (missing
//! interface, insufficient privileges, ...).

use std::time::Duration;

use pnet::datalink::{self, Config, DataLinkReceiver};

/// How long a blocking read waits before returning so the capture loop can
/// check for an interrupt signal even when no packets are arriving.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// Returns the name of the first active, non-loopback interface.
pub fn default_interface() -> Result<String, String> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .map(|iface| iface.name)
        .ok_or_else(|| "No active, non-loopback network interface found".to_string())
}

/// Opens a data-link receiver on the interface named `interface_name`.
///
/// A read timeout is configured so the caller can react to interrupts even
/// while the network is idle.
pub fn open_channel(interface_name: &str) -> Result<Box<dyn DataLinkReceiver>, String> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;

    let config = Config {
        read_timeout: Some(READ_TIMEOUT),
        ..Config::default()
    };

    match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(_, rx)) => Ok(rx),
        Ok(_) => Err("Unsupported channel type (only Ethernet is supported)".to_string()),
        Err(e) => Err(format!(
            "Failed to open a capture channel on '{}': {} (are you running with the required privileges?)",
            interface_name, e
        )),
    }
}

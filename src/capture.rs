//! Network capture setup: interface selection and data-link channel opening.

use std::time::Duration;

use pnet::datalink::{self, Config, DataLinkReceiver};

/// How long a blocking read waits before returning so the capture loop can
/// check for an interrupt signal even when no packets are arriving.
const READ_TIMEOUT: Duration = Duration::from_millis(200);

/// Returns the name of the first active, non-loopback interface.
pub fn default_interface() -> String {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("No active network interface found")
        .name
}

/// Opens a data-link receiver on the interface named `interface_name`.
///
/// A read timeout is configured so the caller can react to interrupts even
/// while the network is idle.
pub fn open_channel(interface_name: &str) -> Box<dyn DataLinkReceiver> {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Interface not found");

    let config = Config {
        read_timeout: Some(READ_TIMEOUT),
        ..Config::default()
    };

    match datalink::channel(&interface, config).expect("Failed to obtain the communication channel")
    {
        datalink::Channel::Ethernet(_, rx) => rx,
        _ => panic!("Unsupported communication channel"),
    }
}

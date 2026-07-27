//! Network capture setup based on libpcap (the `pcap` crate).
//!
//! Using libpcap lets us push a BPF filter into the kernel so only the UDP
//! datagrams we care about ever reach userspace. Capture is opened in
//! non-promiscuous mode: we do not reconfigure the interface.
//!
//! These functions return `Result` instead of panicking so the caller can
//! print a friendly message and exit cleanly on environment errors (missing
//! interface, insufficient privileges, ...).

use pcap::{Active, Capture, Device, Linktype};

/// How long a blocking read waits (milliseconds) before returning so the
/// capture loop can check for an interrupt signal even when idle.
const READ_TIMEOUT_MS: i32 = 200;

/// An open capture handle that yields raw Ethernet frames.
pub struct Capturer {
    handle: Capture<Active>,
}

impl Capturer {
    /// Returns the next captured frame, `None` on read timeout, or an error
    /// string on a fatal capture error.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, String> {
        match self.handle.next_packet() {
            Ok(packet) => Ok(Some(packet.data)),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(format!("Error reading packet: {}", e)),
        }
    }
}

/// Returns the name of the first active, non-loopback interface.
pub fn default_interface() -> Result<String, String> {
    Device::list()
        .map_err(|e| format!("Failed to list network devices: {}", e))?
        .into_iter()
        .find(|d| d.flags.is_up() && !d.flags.is_loopback())
        .map(|d| d.name)
        .ok_or_else(|| "No active, non-loopback network interface found".to_string())
}

/// Opens a capture on `interface_name` with a kernel BPF filter that keeps only
/// UDP datagrams destined to `port`.
pub fn open(interface_name: &str, port: u16) -> Result<Capturer, String> {
    let device = find_device(interface_name)?;

    let mut handle = Capture::from_device(device)
        .map_err(|e| format!("Failed to select device '{}': {}", interface_name, e))?
        .promisc(false)
        .timeout(READ_TIMEOUT_MS)
        .open()
        .map_err(|e| {
            format!(
                "Failed to open a capture on '{}': {} (elevated privileges are required)",
                interface_name, e
            )
        })?;

    // Kernel-side filtering: non-matching packets are dropped before userspace.
    handle
        .filter(&format!("udp dst port {}", port), true)
        .map_err(|e| format!("Failed to set the BPF filter: {}", e))?;

    let linktype = handle.get_datalink();
    if linktype != Linktype::ETHERNET {
        let name = linktype
            .get_name()
            .unwrap_or_else(|_| format!("{:?}", linktype));
        return Err(format!(
            "Interface '{}' has link type '{}', but only Ethernet is supported",
            interface_name, name
        ));
    }

    Ok(Capturer { handle })
}

/// Looks up a libpcap device by interface name.
fn find_device(interface_name: &str) -> Result<Device, String> {
    Device::list()
        .map_err(|e| format!("Failed to list network devices: {}", e))?
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| format!("Interface '{}' not found", interface_name))
}

//! Command-line interface: parses arguments into a plain `Args` struct.

use clap::{Arg, Command};

/// The default UDP port to listen on when `--port` is not provided.
pub const DEFAULT_PORT: u16 = 12345;

/// Command-line arguments resolved at startup.
pub struct Args {
    /// Network interface to sniff on. `None` means "pick a sensible default".
    pub interface: Option<String>,
    /// UDP destination port to capture.
    pub port: u16,
}

/// Parses the process arguments into an [`Args`] value.
///
/// An invalid `--port` value is reported and falls back to [`DEFAULT_PORT`]
/// rather than aborting the program.
pub fn parse() -> Args {
    let matches = Command::new("UDP Packet Sniffer")
        .version(env!("CARGO_PKG_VERSION"))
        .about("UDP Packet Sniffer")
        .arg(
            Arg::new("iface")
                .short('i')
                .long("iface")
                .value_name("INTERFACE")
                .help("Specify the network interface"),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .value_name("PORT")
                .default_value("12345")
                .help("Specify the network port"),
        )
        .get_matches();

    let port_str = matches.get_one::<String>("port").unwrap();
    let port = port_str.parse().unwrap_or_else(|_| {
        eprintln!(
            "Invalid port '{}', falling back to {}",
            port_str, DEFAULT_PORT
        );
        DEFAULT_PORT
    });

    Args {
        interface: matches.get_one::<String>("iface").cloned(),
        port,
    }
}

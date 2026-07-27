//! Command-line interface: parses arguments (and an optional JSON config file)
//! into a plain `Args` struct. Precedence: CLI flag > config file > default.

use std::time::Duration;

use clap::parser::ValueSource;
use clap::{Arg, ArgMatches, Command};

use crate::config::{self, FileConfig};
use crate::sink::OutputFormat;

/// The default UDP port to listen on when nothing else is provided.
pub const DEFAULT_PORT: u16 = 12345;

/// The default number of seconds between periodic flushes.
pub const DEFAULT_FLUSH_SECS: u64 = 5;

/// Command-line arguments resolved at startup.
pub struct Args {
    /// Network interface to sniff on. `None` means "pick a sensible default".
    pub interface: Option<String>,
    /// UDP destination port to capture.
    pub port: u16,
    /// How captured datagrams are written out.
    pub format: OutputFormat,
    /// How often buffered data is flushed to disk.
    pub flush_interval: Duration,
}

/// Parses the process arguments (merged with the config file) into [`Args`].
pub fn parse() -> Result<Args, String> {
    let matches = command().get_matches();

    let file_cfg = match matches.get_one::<String>("config") {
        Some(path) => config::load(path)?,
        None => FileConfig::default(),
    };

    Ok(Args {
        interface: resolve_interface(&matches, &file_cfg),
        port: resolve_port(&matches, &file_cfg),
        format: resolve_format(&matches, &file_cfg)?,
        flush_interval: Duration::from_secs(resolve_flush_secs(&matches, &file_cfg)),
    })
}

fn command() -> Command {
    Command::new("UDP Packet Sniffer")
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
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .value_parser(["raw", "jsonl", "file"])
                .default_value("raw")
                .help("Output format: 'raw' appends payload bytes, 'jsonl' writes one JSON object per datagram, 'file' reassembles chunked file transfers"),
        )
        .arg(
            Arg::new("flush-interval")
                .long("flush-interval")
                .value_name("SECONDS")
                .default_value("5")
                .help("Seconds between periodic flushes to disk (0 disables periodic flushing)"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to a JSON config file (CLI flags override its values)"),
        )
}

/// Whether an argument's value came from the command line (rather than its
/// default), i.e. the user explicitly passed it.
fn set_on_cli(matches: &ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn resolve_interface(matches: &ArgMatches, file_cfg: &FileConfig) -> Option<String> {
    matches
        .get_one::<String>("iface")
        .cloned()
        .or_else(|| file_cfg.interface.clone())
}

fn resolve_port(matches: &ArgMatches, file_cfg: &FileConfig) -> u16 {
    if set_on_cli(matches, "port") {
        let raw = matches.get_one::<String>("port").unwrap();
        raw.parse().unwrap_or_else(|_| {
            eprintln!("Invalid port '{}', falling back to {}", raw, DEFAULT_PORT);
            DEFAULT_PORT
        })
    } else {
        file_cfg.port.unwrap_or(DEFAULT_PORT)
    }
}

fn resolve_format(matches: &ArgMatches, file_cfg: &FileConfig) -> Result<OutputFormat, String> {
    if set_on_cli(matches, "format") {
        // The CLI value_parser guarantees a known name here.
        Ok(OutputFormat::from_name(matches.get_one::<String>("format").unwrap()).unwrap())
    } else if let Some(name) = file_cfg.format.as_deref() {
        OutputFormat::from_name(name)
            .ok_or_else(|| format!("Invalid 'format' in config file: '{}'", name))
    } else {
        Ok(OutputFormat::Raw)
    }
}

fn resolve_flush_secs(matches: &ArgMatches, file_cfg: &FileConfig) -> u64 {
    if set_on_cli(matches, "flush-interval") {
        let raw = matches.get_one::<String>("flush-interval").unwrap();
        raw.parse().unwrap_or_else(|_| {
            eprintln!(
                "Invalid flush interval '{}', falling back to {}",
                raw, DEFAULT_FLUSH_SECS
            );
            DEFAULT_FLUSH_SECS
        })
    } else {
        file_cfg.flush_interval.unwrap_or(DEFAULT_FLUSH_SECS)
    }
}

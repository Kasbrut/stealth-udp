//! Example client for the `--format file` reassembly mode, with the server key
//! passed as an argument (for the single-file, key-embedded client see the
//! `client` binary provisioned by `stealth-udp --gen-client`).
//!
//! Usage:
//!   cargo run --example send_file -- <HOST:PORT> <FILE> \
//!       [--chunk-size N] [--server-key <HEX|FILE>]

use std::path::Path;
use std::process;

use stealth_udp::client::{send_file, DEFAULT_CHUNK_SIZE, DEFAULT_REPEAT};
use stealth_udp::crypto::{self, KEY_LEN};

const USAGE: &str =
    "usage: send_file <HOST:PORT> <FILE> [--chunk-size N] [--repeat N] [--server-key <HEX|FILE>]";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut positional = Vec::new();
    let mut chunk_size = DEFAULT_CHUNK_SIZE;
    let mut repeat = DEFAULT_REPEAT;
    let mut server_key = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chunk-size" => {
                let value = args.next().ok_or("--chunk-size needs a value")?;
                chunk_size = value.parse().map_err(|_| "--chunk-size must be a number")?;
            }
            "--repeat" => {
                let value = args.next().ok_or("--repeat needs a value")?;
                repeat = value.parse().map_err(|_| "--repeat must be a number")?;
            }
            "--server-key" => {
                let value = args.next().ok_or("--server-key needs a value")?;
                server_key = Some(load_server_key(&value)?);
            }
            other => positional.push(other.to_string()),
        }
    }

    if positional.len() != 2 {
        return Err(USAGE.to_string());
    }

    send_file(
        &positional[0],
        &positional[1],
        chunk_size,
        repeat,
        server_key,
    )
}

/// Loads a server public key from a hex string or a file containing one.
fn load_server_key(value: &str) -> Result<[u8; KEY_LEN], String> {
    let text = if Path::new(value).is_file() {
        std::fs::read_to_string(value).map_err(|e| format!("cannot read key file: {}", e))?
    } else {
        value.to_string()
    };
    crypto::from_hex(&text).ok_or_else(|| "invalid server key (expected 32-byte hex)".to_string())
}

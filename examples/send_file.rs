//! Example client for the `--format file` reassembly mode, with the server key
//! passed as an argument (for the single-file, key-embedded client see the
//! `client` binary provisioned by `stealth-udp --gen-client`).
//!
//! Usage:
//!   cargo run --example send_file -- <HOST:PORT> <FILE> \
//!       [--chunk-size N] [--repeat N] [--passes N] [--delay MICROS] \
//!       [--compress] [--fec N] [--server-key <HEX|FILE>]

use std::path::Path;
use std::process;
use std::time::Duration;

use stealth_udp::client::{parse_fec_rs, parse_fec_xor, send_file, SendOptions};
use stealth_udp::crypto::{self, KEY_LEN};
use stealth_udp::protocol::Fec;

const USAGE: &str = "usage: send_file <HOST:PORT> <FILE> [--chunk-size N] [--repeat N] \
[--passes N] [--delay MICROS] [--compress] [--fec N | --fec-rs K:M] [--server-key <HEX|FILE>]";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut positional = Vec::new();
    let mut opts = SendOptions::default();
    let mut fec_set = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chunk-size" => opts.chunk_size = parse_num(args.next(), "--chunk-size")?,
            "--repeat" => opts.repeat = parse_num(args.next(), "--repeat")?,
            "--passes" => opts.passes = parse_num(args.next(), "--passes")?,
            "--delay" => opts.delay = Duration::from_micros(parse_num(args.next(), "--delay")?),
            "--compress" => opts.compress = true,
            "--fec" => set_fec(&mut opts, &mut fec_set, parse_fec_xor(args.next())?)?,
            "--fec-rs" => set_fec(&mut opts, &mut fec_set, parse_fec_rs(args.next())?)?,
            "--server-key" => {
                let value = args.next().ok_or("--server-key needs a value")?;
                opts.server_public = Some(load_server_key(&value)?);
            }
            other => positional.push(other.to_string()),
        }
    }

    if positional.len() != 2 {
        return Err(USAGE.to_string());
    }
    send_file(&positional[0], &positional[1], &opts)
}

/// Sets the FEC scheme, rejecting a second, conflicting FEC flag.
fn set_fec(opts: &mut SendOptions, already_set: &mut bool, fec: Fec) -> Result<(), String> {
    if *already_set {
        return Err("use either --fec or --fec-rs, not both".to_string());
    }
    *already_set = true;
    opts.fec = fec;
    Ok(())
}

fn parse_num<T: std::str::FromStr>(value: Option<String>, flag: &str) -> Result<T, String> {
    value
        .ok_or_else(|| format!("{} needs a value", flag))?
        .parse()
        .map_err(|_| format!("{} must be a number", flag))
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

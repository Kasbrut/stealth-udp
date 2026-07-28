//! Provisioned file-transfer client.
//!
//! The server's public key is baked into this binary by
//! `stealth-udp --gen-client`, so a provisioned client is a single file with no
//! separate key. Run it to send a file (every packet is encrypted).
//!
//! Usage:
//!   client <HOST:PORT> <FILE> [--chunk-size N] [--repeat N] [--passes N]
//!          [--delay MICROS] [--compress] [--fec N]
//!   client --show-key            # print the embedded public key, then exit

use std::time::Duration;

use stealth_udp::client::{parse_fec_rs, parse_fec_xor, send_file, SendOptions};
use stealth_udp::crypto::to_hex;
use stealth_udp::embed::{self, SLOT_LEN};
use stealth_udp::protocol::Fec;

const USAGE: &str = "usage: client <HOST:PORT> <FILE> [--chunk-size N] [--repeat N] \
[--passes N] [--delay MICROS] [--compress] [--fec N | --fec-rs K:M]  |  client --show-key";

/// The key slot. Non-zero marker keeps it in the file image; the server patches
/// the placeholder that follows the marker.
#[used]
static EMBEDDED_KEY_SLOT: [u8; SLOT_LEN] = embed::initial_slot();

/// Reads the slot via volatile loads so the optimizer cannot fold in the
/// compile-time placeholder instead of the server-patched bytes.
fn embedded_slot() -> [u8; SLOT_LEN] {
    let mut slot = [0u8; SLOT_LEN];
    for (i, byte) in slot.iter_mut().enumerate() {
        *byte = unsafe { core::ptr::read_volatile(&EMBEDDED_KEY_SLOT[i]) };
    }
    slot
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let key = embed::read_embedded(&embedded_slot());

    let mut args = std::env::args().skip(1).peekable();
    let first = args.next().ok_or(USAGE)?;

    if first == "--show-key" {
        let key = key.ok_or("this client has no embedded key (not provisioned)")?;
        println!("{}", to_hex(&key));
        return Ok(());
    }

    let target = first;
    let path = args.next().ok_or(USAGE)?;

    let mut opts = SendOptions::default();
    let mut fec_set = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chunk-size" => opts.chunk_size = parse_num(args.next(), "--chunk-size")?,
            "--repeat" => opts.repeat = parse_num(args.next(), "--repeat")?,
            "--passes" => opts.passes = parse_num(args.next(), "--passes")?,
            "--delay" => opts.delay = Duration::from_micros(parse_num(args.next(), "--delay")?),
            "--compress" => opts.compress = true,
            "--fec" => {
                set_fec(&mut opts, &mut fec_set, parse_fec_xor(args.next())?)?;
            }
            "--fec-rs" => {
                set_fec(&mut opts, &mut fec_set, parse_fec_rs(args.next())?)?;
            }
            other => return Err(format!("unexpected argument: {}", other)),
        }
    }

    let embedded =
        key.ok_or("this client has no embedded server key; provision it with --gen-client")?;
    opts.server_public = Some(embedded);
    send_file(&target, &path, &opts)
}

fn parse_num<T: std::str::FromStr>(value: Option<String>, flag: &str) -> Result<T, String> {
    value
        .ok_or_else(|| format!("{} needs a value", flag))?
        .parse()
        .map_err(|_| format!("{} must be a number", flag))
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

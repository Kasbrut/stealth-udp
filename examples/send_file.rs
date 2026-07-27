//! Example client for the `--format file` reassembly mode.
//!
//! Splits a file into numbered chunks and sends them over UDP using the
//! protocol from `stealth_udp::protocol`. META is resent periodically so the
//! transfer survives META loss on an unstable link. With `--server-key` every
//! packet is sealed to the server's public key (see `stealth_udp::crypto`).
//!
//! Usage:
//!   cargo run --example send_file -- <HOST:PORT> <FILE> \
//!       [--chunk-size N] [--server-key <HEX|FILE>]
//!
//! Example:
//!   cargo run --example send_file -- 192.168.1.10:12345 ./photo.jpg \
//!       --server-key server.pub

use std::net::UdpSocket;
use std::path::Path;
use std::process;

use stealth_udp::crypto::{self, KEY_LEN};
use stealth_udp::protocol::{encode_data, encode_meta, MetaPacket};

/// Resend META every this many data packets so its loss is recoverable.
const META_RESEND_EVERY: usize = 50;
/// Default UDP payload chunk size, kept below a typical MTU to avoid IP
/// fragmentation.
const DEFAULT_CHUNK_SIZE: usize = 1400;

const USAGE: &str =
    "usage: send_file <HOST:PORT> <FILE> [--chunk-size N] [--server-key <HEX|FILE>]";

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

struct Options {
    target: String,
    path: String,
    chunk_size: usize,
    server_key: Option<[u8; KEY_LEN]>,
}

fn run() -> Result<(), String> {
    let opts = parse_args()?;

    let data =
        std::fs::read(&opts.path).map_err(|e| format!("cannot read '{}': {}", opts.path, e))?;
    let filename = Path::new(&opts.path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("cannot bind socket: {}", e))?;
    socket
        .connect(&opts.target)
        .map_err(|e| format!("cannot connect to '{}': {}", opts.target, e))?;

    // Optionally seal every packet to the server's public key.
    let send = |bytes: &[u8]| -> Result<(), String> {
        let packet = match &opts.server_key {
            Some(key) => crypto::seal(bytes, key),
            None => bytes.to_vec(),
        };
        socket.send(&packet).map(|_| ()).map_err(send_err)
    };

    let transfer_id = process::id();
    let meta = MetaPacket {
        transfer_id,
        file_size: data.len() as u64,
        chunk_size: opts.chunk_size as u32,
        filename,
    };
    let meta_bytes = encode_meta(&meta);

    send(&meta_bytes)?;

    let mut sent = 0usize;
    for (seq, chunk) in data.chunks(opts.chunk_size).enumerate() {
        if sent > 0 && sent.is_multiple_of(META_RESEND_EVERY) {
            send(&meta_bytes)?;
        }
        send(&encode_data(transfer_id, seq as u32, chunk))?;
        sent += 1;
    }

    // A final META so a late-starting receiver can still complete the file.
    send(&meta_bytes)?;

    println!(
        "Sent '{}' ({} bytes) as transfer {} in {} chunk(s){}.",
        meta.filename,
        meta.file_size,
        transfer_id,
        sent,
        if opts.server_key.is_some() {
            " [encrypted]"
        } else {
            ""
        }
    );
    Ok(())
}

fn parse_args() -> Result<Options, String> {
    let mut positional = Vec::new();
    let mut chunk_size = DEFAULT_CHUNK_SIZE;
    let mut server_key = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chunk-size" => {
                let value = args.next().ok_or("--chunk-size needs a value")?;
                chunk_size = value.parse().map_err(|_| "--chunk-size must be a number")?;
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
    if chunk_size == 0 {
        return Err("chunk size must be greater than zero".to_string());
    }

    Ok(Options {
        target: positional[0].clone(),
        path: positional[1].clone(),
        chunk_size,
        server_key,
    })
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

fn send_err(e: std::io::Error) -> String {
    format!("send failed: {}", e)
}

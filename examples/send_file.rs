//! Example client for the `--format file` reassembly mode.
//!
//! Splits a file into numbered chunks and sends them over UDP using the
//! protocol from `stealth_udp::protocol`. META is resent periodically so the
//! transfer survives META loss on an unstable link.
//!
//! Usage:
//!   cargo run --example send_file -- <HOST:PORT> <FILE> [CHUNK_SIZE]
//!
//! Example:
//!   cargo run --example send_file -- 192.168.1.10:12345 ./photo.jpg

use std::net::UdpSocket;
use std::path::Path;
use std::process;

use stealth_udp::protocol::{encode_data, encode_meta, MetaPacket};

/// Resend META every this many data packets so its loss is recoverable.
const META_RESEND_EVERY: usize = 50;
/// Default UDP payload chunk size, kept below a typical MTU to avoid IP
/// fragmentation.
const DEFAULT_CHUNK_SIZE: usize = 1400;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let target = args
        .next()
        .ok_or("usage: send_file <HOST:PORT> <FILE> [CHUNK_SIZE]")?;
    let path = args
        .next()
        .ok_or("usage: send_file <HOST:PORT> <FILE> [CHUNK_SIZE]")?;
    let chunk_size = match args.next() {
        Some(s) => s.parse().map_err(|_| "CHUNK_SIZE must be a number")?,
        None => DEFAULT_CHUNK_SIZE,
    };
    if chunk_size == 0 {
        return Err("CHUNK_SIZE must be greater than zero".to_string());
    }

    let data = std::fs::read(&path).map_err(|e| format!("cannot read '{}': {}", path, e))?;
    let filename = Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("cannot bind socket: {}", e))?;
    socket
        .connect(&target)
        .map_err(|e| format!("cannot connect to '{}': {}", target, e))?;

    // A transfer id unique enough for one run.
    let transfer_id = process::id();
    let meta = MetaPacket {
        transfer_id,
        file_size: data.len() as u64,
        chunk_size: chunk_size as u32,
        filename,
    };
    let meta_bytes = encode_meta(&meta);

    socket.send(&meta_bytes).map_err(send_err)?;

    let mut sent = 0usize;
    for (seq, chunk) in data.chunks(chunk_size).enumerate() {
        if sent > 0 && sent.is_multiple_of(META_RESEND_EVERY) {
            socket.send(&meta_bytes).map_err(send_err)?;
        }
        socket
            .send(&encode_data(transfer_id, seq as u32, chunk))
            .map_err(send_err)?;
        sent += 1;
    }

    // A final META so a late-starting receiver can still complete the file.
    socket.send(&meta_bytes).map_err(send_err)?;

    println!(
        "Sent '{}' ({} bytes) as transfer {} in {} chunk(s).",
        meta.filename, meta.file_size, transfer_id, sent
    );
    Ok(())
}

fn send_err(e: std::io::Error) -> String {
    format!("send failed: {}", e)
}

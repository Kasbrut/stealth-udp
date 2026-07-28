//! The file-transfer client: split a file into numbered chunks and send them
//! over UDP, with optional compression, integrity hash, forward error
//! correction (XOR or Reed-Solomon), redundancy (repeat / passes), pacing and
//! encryption.
//!
//! Shared by the `send_file` example (key passed as an argument) and the
//! `client` binary (key embedded by the server).

use std::net::UdpSocket;
use std::path::Path;
use std::time::Duration;

use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

use crate::crypto::{self, KEY_LEN};
use crate::protocol::{encode_data, encode_meta, encode_parity, Fec, MetaPacket, FLAG_COMPRESSED};

/// Default UDP payload chunk size, kept below a typical MTU to avoid IP
/// fragmentation.
pub const DEFAULT_CHUNK_SIZE: usize = 1400;

/// Default number of times each packet is sent back-to-back. The channel is
/// one-way (no retransmission), so this cheaply mitigates isolated loss; the
/// server ignores the duplicates.
pub const DEFAULT_REPEAT: usize = 2;

/// Resend META every this many data packets so its loss is recoverable on an
/// unstable link.
const META_RESEND_EVERY: usize = 50;

/// DEFLATE compression level (0-10 in miniz_oxide).
const COMPRESSION_LEVEL: u8 = 6;

/// How to send a file. Build with `SendOptions::default()` and override fields.
pub struct SendOptions {
    /// Bytes per data packet.
    pub chunk_size: usize,
    /// Times each packet is sent back-to-back.
    pub repeat: usize,
    /// Times the whole file is sent (spaced passes resist burst loss better
    /// than back-to-back repeats).
    pub passes: usize,
    /// Delay after every packet send (pacing); zero disables it.
    pub delay: Duration,
    /// Compress the file before sending.
    pub compress: bool,
    /// Forward error correction scheme.
    pub fec: Fec,
    /// Server public key to seal every packet to; `None` sends in the clear.
    pub server_public: Option<[u8; KEY_LEN]>,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            repeat: DEFAULT_REPEAT,
            passes: 1,
            delay: Duration::ZERO,
            compress: false,
            fec: Fec::None,
            server_public: None,
        }
    }
}

/// Sends `path` to `target` according to `opts`.
pub fn send_file(target: &str, path: &str, opts: &SendOptions) -> Result<(), String> {
    if opts.chunk_size == 0 {
        return Err("chunk size must be greater than zero".to_string());
    }
    let repeat = opts.repeat.max(1);
    let passes = opts.passes.max(1);

    let original = std::fs::read(path).map_err(|e| format!("cannot read '{}': {}", path, e))?;
    let original_size = original.len() as u64;
    let hash: [u8; 32] = Sha256::digest(&original).into();

    let (stream, flags) = if opts.compress {
        (
            miniz_oxide::deflate::compress_to_vec(&original, COMPRESSION_LEVEL),
            FLAG_COMPRESSED,
        )
    } else {
        (original, 0)
    };

    let filename = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("cannot bind socket: {}", e))?;
    socket
        .connect(target)
        .map_err(|e| format!("cannot connect to '{}': {}", target, e))?;

    let transfer_id = std::process::id();
    let meta = MetaPacket {
        transfer_id,
        file_size: stream.len() as u64,
        chunk_size: opts.chunk_size as u32,
        flags,
        fec: opts.fec,
        original_size,
        hash,
        filename,
    };
    let meta_bytes = encode_meta(&meta);

    let send = |bytes: &[u8]| -> Result<(), String> {
        for _ in 0..repeat {
            let packet = match &opts.server_public {
                Some(key) => crypto::seal(bytes, key),
                None => bytes.to_vec(),
            };
            socket
                .send(&packet)
                .map_err(|e| format!("send failed: {}", e))?;
            if !opts.delay.is_zero() {
                std::thread::sleep(opts.delay);
            }
        }
        Ok(())
    };

    let chunks: Vec<&[u8]> = stream.chunks(opts.chunk_size).collect();

    for _ in 0..passes {
        send(&meta_bytes)?;
        send_data(&send, &meta_bytes, transfer_id, &chunks)?;
        send_parity(&send, transfer_id, &chunks, opts.fec, opts.chunk_size)?;
        // A final META so a late-starting receiver can still complete the file.
        send(&meta_bytes)?;
    }

    println!(
        "Sent '{}' ({} bytes{}) as transfer {}: {} chunk(s), repeat x{}, passes x{}, {}{}.",
        meta.filename,
        original_size,
        if opts.compress {
            format!(", {} on the wire", stream.len())
        } else {
            String::new()
        },
        transfer_id,
        chunks.len(),
        repeat,
        passes,
        describe_fec(opts.fec),
        if opts.server_public.is_some() {
            " [encrypted]"
        } else {
            ""
        }
    );
    Ok(())
}

/// Sends one full pass of the data chunks, resending META periodically.
fn send_data(
    send: &impl Fn(&[u8]) -> Result<(), String>,
    meta_bytes: &[u8],
    transfer_id: u32,
    chunks: &[&[u8]],
) -> Result<(), String> {
    for (seq, chunk) in chunks.iter().enumerate() {
        if seq > 0 && seq.is_multiple_of(META_RESEND_EVERY) {
            send(meta_bytes)?;
        }
        send(&encode_data(transfer_id, seq as u32, chunk))?;
    }
    Ok(())
}

/// Sends the parity packets for the chosen FEC scheme.
fn send_parity(
    send: &impl Fn(&[u8]) -> Result<(), String>,
    transfer_id: u32,
    chunks: &[&[u8]],
    fec: Fec,
    chunk_size: usize,
) -> Result<(), String> {
    match fec {
        Fec::None => Ok(()),
        Fec::Xor { group } => {
            send_xor_parity(send, transfer_id, chunks, group as usize, chunk_size)
        }
        Fec::ReedSolomon { data, parity } => send_rs_parity(
            send,
            transfer_id,
            chunks,
            data as usize,
            parity as usize,
            chunk_size,
        ),
    }
}

fn send_xor_parity(
    send: &impl Fn(&[u8]) -> Result<(), String>,
    transfer_id: u32,
    chunks: &[&[u8]],
    group: usize,
    chunk_size: usize,
) -> Result<(), String> {
    if group == 0 {
        return Ok(());
    }
    for (block, group_chunks) in chunks.chunks(group).enumerate() {
        let parity = xor_parity(group_chunks, chunk_size);
        send(&encode_parity(transfer_id, block as u32, 0, &parity))?;
    }
    Ok(())
}

fn send_rs_parity(
    send: &impl Fn(&[u8]) -> Result<(), String>,
    transfer_id: u32,
    chunks: &[&[u8]],
    data: usize,
    parity: usize,
    chunk_size: usize,
) -> Result<(), String> {
    let rs = ReedSolomon::new(data, parity).map_err(|e| format!("invalid Reed-Solomon: {}", e))?;

    for (block, data_chunks) in chunks.chunks(data).enumerate() {
        // K data shards (padded to chunk_size; short/absent positions are zero)
        // followed by M zeroed parity shards, then encode.
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(data + parity);
        for i in 0..data {
            let mut shard = vec![0u8; chunk_size];
            if let Some(chunk) = data_chunks.get(i) {
                shard[..chunk.len()].copy_from_slice(chunk);
            }
            shards.push(shard);
        }
        shards.extend((0..parity).map(|_| vec![0u8; chunk_size]));

        rs.encode(&mut shards)
            .map_err(|e| format!("Reed-Solomon encode: {}", e))?;

        for (index, parity_shard) in shards[data..].iter().enumerate() {
            send(&encode_parity(
                transfer_id,
                block as u32,
                index as u16,
                parity_shard,
            ))?;
        }
    }
    Ok(())
}

/// XOR of the chunks in a group, each treated as padded to `chunk_size`.
fn xor_parity(group: &[&[u8]], chunk_size: usize) -> Vec<u8> {
    let mut parity = vec![0u8; chunk_size];
    for chunk in group {
        for (i, &byte) in chunk.iter().enumerate() {
            parity[i] ^= byte;
        }
    }
    parity
}

/// Maximum shard count for Reed-Solomon over GF(2^8).
const RS_MAX_SHARDS: usize = 256;

/// Parses the `--fec N` argument (XOR, group size N).
pub fn parse_fec_xor(value: Option<String>) -> Result<Fec, String> {
    let group: u16 = value
        .ok_or("--fec needs a value")?
        .parse()
        .map_err(|_| "--fec must be a number".to_string())?;
    if group == 0 {
        return Err("--fec must be >= 1".to_string());
    }
    Ok(Fec::Xor { group })
}

/// Parses the `--fec-rs K:M` argument (Reed-Solomon, K data, M parity).
pub fn parse_fec_rs(value: Option<String>) -> Result<Fec, String> {
    let spec = value.ok_or("--fec-rs needs K:M (e.g. 10:3)")?;
    let (k, m) = spec
        .split_once(':')
        .ok_or("--fec-rs must be K:M (e.g. 10:3)")?;
    let data: u16 = k
        .parse()
        .map_err(|_| "--fec-rs K must be a number".to_string())?;
    let parity: u16 = m
        .parse()
        .map_err(|_| "--fec-rs M must be a number".to_string())?;
    if data == 0 || parity == 0 {
        return Err("--fec-rs K and M must be >= 1".to_string());
    }
    if data as usize + parity as usize > RS_MAX_SHARDS {
        return Err("--fec-rs K+M must be <= 256".to_string());
    }
    Ok(Fec::ReedSolomon { data, parity })
}

fn describe_fec(fec: Fec) -> String {
    match fec {
        Fec::None => "no fec".to_string(),
        Fec::Xor { group } => format!("fec-xor/{}", group),
        Fec::ReedSolomon { data, parity } => format!("fec-rs {}:{}", data, parity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_parity_recovers_a_missing_chunk() {
        let a = [1u8, 2, 3, 4];
        let b = [5u8, 6, 7, 8];
        let c = [9u8, 10];
        let group: Vec<&[u8]> = vec![&a, &b, &c];
        let parity = xor_parity(&group, 4);

        let mut recovered = parity.clone();
        for chunk in [&a[..], &c[..]] {
            for (i, &byte) in chunk.iter().enumerate() {
                recovered[i] ^= byte;
            }
        }
        assert_eq!(&recovered[..b.len()], &b);
    }
}

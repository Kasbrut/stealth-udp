//! The file-transfer client: split a file into numbered chunks and send them
//! over UDP, with optional compression, integrity hash, XOR forward error
//! correction, redundancy (repeat / passes), pacing and encryption.
//!
//! Shared by the `send_file` example (key passed as an argument) and the
//! `client` binary (key embedded by the server).

use std::net::UdpSocket;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::crypto::{self, KEY_LEN};
use crate::protocol::{encode_data, encode_meta, encode_parity, MetaPacket, FLAG_COMPRESSED};

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
    /// Emit one XOR parity packet per this many data chunks; 0 disables FEC.
    pub fec_group: u16,
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
            fec_group: 0,
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
        let compressed = miniz_oxide::deflate::compress_to_vec(&original, COMPRESSION_LEVEL);
        (compressed, FLAG_COMPRESSED)
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
        fec_group: opts.fec_group,
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
        send_pass(
            &send,
            &meta_bytes,
            transfer_id,
            &chunks,
            opts.fec_group,
            opts.chunk_size,
        )?;
        // A final META so a late-starting receiver can still complete the file.
        send(&meta_bytes)?;
    }

    println!(
        "Sent '{}' ({} bytes{}) as transfer {}: {} chunk(s), repeat x{}, passes x{}{}{}.",
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
        if opts.fec_group > 0 {
            format!(", fec/{}", opts.fec_group)
        } else {
            String::new()
        },
        if opts.server_public.is_some() {
            " [encrypted]"
        } else {
            ""
        }
    );
    Ok(())
}

/// Sends one full pass over the data chunks, emitting a parity packet after
/// each complete FEC group (and a final one for a trailing partial group).
fn send_pass(
    send: &impl Fn(&[u8]) -> Result<(), String>,
    meta_bytes: &[u8],
    transfer_id: u32,
    chunks: &[&[u8]],
    fec_group: u16,
    chunk_size: usize,
) -> Result<(), String> {
    let group = fec_group as usize;

    for (seq, chunk) in chunks.iter().enumerate() {
        // Periodically resend META so a late receiver can still start.
        if seq > 0 && seq.is_multiple_of(META_RESEND_EVERY) {
            send(meta_bytes)?;
        }
        send(&encode_data(transfer_id, seq as u32, chunk))?;

        if group > 0 && (seq + 1) % group == 0 {
            let g = seq / group;
            let start = g * group;
            let parity = xor_parity(&chunks[start..=seq], chunk_size);
            send(&encode_parity(transfer_id, g as u32, &parity))?;
        }
    }

    // Trailing partial group.
    if group > 0 && !chunks.is_empty() && !chunks.len().is_multiple_of(group) {
        let g = chunks.len() / group;
        let start = g * group;
        let parity = xor_parity(&chunks[start..], chunk_size);
        send(&encode_parity(transfer_id, g as u32, &parity))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_parity_recovers_a_missing_chunk() {
        // parity ^ (all-but-one present chunks) == the missing chunk.
        let a = [1u8, 2, 3, 4];
        let b = [5u8, 6, 7, 8];
        let c = [9u8, 10]; // shorter last chunk
        let group: Vec<&[u8]> = vec![&a, &b, &c];
        let parity = xor_parity(&group, 4);

        // Reconstruct `b` from parity and the others (padded to chunk_size).
        let mut recovered = parity.clone();
        for chunk in [&a[..], &c[..]] {
            for (i, &byte) in chunk.iter().enumerate() {
                recovered[i] ^= byte;
            }
        }
        assert_eq!(&recovered[..b.len()], &b);
    }
}

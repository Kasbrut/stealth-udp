//! The file-transfer client: split a file into numbered chunks and send them
//! over UDP, with optional compression, integrity hash, forward error
//! correction (XOR or Reed-Solomon), FEC block interleaving, redundancy
//! (repeat / passes), pacing and encryption.
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

/// Default number of times each packet is sent back-to-back.
pub const DEFAULT_REPEAT: usize = 2;

/// Resend META every this many packets so its loss is recoverable.
const META_RESEND_EVERY: usize = 50;

/// DEFLATE compression level (0-10 in miniz_oxide).
const COMPRESSION_LEVEL: u8 = 6;

/// Maximum shard count for Reed-Solomon over GF(2^8).
const RS_MAX_SHARDS: usize = 256;

/// How to send a file. Build with `SendOptions::default()` and override fields.
pub struct SendOptions {
    /// Bytes per data packet.
    pub chunk_size: usize,
    /// Times each packet is sent back-to-back.
    pub repeat: usize,
    /// Times the whole file is sent.
    pub passes: usize,
    /// Delay after every packet send (pacing); zero disables it.
    pub delay: Duration,
    /// Compress the file before sending.
    pub compress: bool,
    /// Forward error correction scheme.
    pub fec: Fec,
    /// Interleave FEC blocks so a burst spreads across blocks (needs FEC).
    pub interleave: bool,
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
            interleave: false,
            server_public: None,
        }
    }
}

/// One packet to transmit, in the order the client chose.
enum Slot {
    Data(u32),
    Parity(u32, u16),
}

/// Sends `path` to `target` according to `opts`.
pub fn send_file(target: &str, path: &str, opts: &SendOptions) -> Result<(), String> {
    if opts.chunk_size == 0 {
        return Err("chunk size must be greater than zero".to_string());
    }
    if opts.interleave && opts.fec == Fec::None {
        return Err("--interleave requires --fec or --fec-rs".to_string());
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
    let parity = compute_parity_blocks(&chunks, opts.fec, opts.chunk_size)?;
    let order = packet_order(chunks.len() as u32, opts.fec, &parity, opts.interleave);

    for _ in 0..passes {
        send(&meta_bytes)?;
        for (i, slot) in order.iter().enumerate() {
            if i > 0 && i.is_multiple_of(META_RESEND_EVERY) {
                send(&meta_bytes)?;
            }
            match slot {
                Slot::Data(seq) => send(&encode_data(transfer_id, *seq, chunks[*seq as usize]))?,
                Slot::Parity(block, index) => send(&encode_parity(
                    transfer_id,
                    *block,
                    *index,
                    &parity[*block as usize][*index as usize],
                ))?,
            }
        }
        // A final META so a late-starting receiver can still complete the file.
        send(&meta_bytes)?;
    }

    println!(
        "Sent '{}' ({} bytes{}) as transfer {}: {} chunk(s), repeat x{}, passes x{}, {}{}{}.",
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
        if opts.interleave { ", interleaved" } else { "" },
        if opts.server_public.is_some() {
            " [encrypted]"
        } else {
            ""
        }
    );
    Ok(())
}

/// Computes the parity shards for every FEC block. `parity[block]` holds one
/// shard for XOR, or M shards for Reed-Solomon; empty when FEC is off.
fn compute_parity_blocks(
    chunks: &[&[u8]],
    fec: Fec,
    chunk_size: usize,
) -> Result<Vec<Vec<Vec<u8>>>, String> {
    match fec {
        Fec::None => Ok(Vec::new()),
        Fec::Xor { group } => Ok(chunks
            .chunks(group as usize)
            .map(|block| vec![xor_parity(block, chunk_size)])
            .collect()),
        Fec::ReedSolomon { data, parity } => {
            let (k, m) = (data as usize, parity as usize);
            let rs = ReedSolomon::new(k, m).map_err(|e| format!("invalid Reed-Solomon: {}", e))?;
            let mut blocks = Vec::new();
            for block in chunks.chunks(k) {
                let mut shards: Vec<Vec<u8>> = (0..k)
                    .map(|i| {
                        let mut shard = vec![0u8; chunk_size];
                        if let Some(chunk) = block.get(i) {
                            shard[..chunk.len()].copy_from_slice(chunk);
                        }
                        shard
                    })
                    .collect();
                shards.extend((0..m).map(|_| vec![0u8; chunk_size]));
                rs.encode(&mut shards)
                    .map_err(|e| format!("Reed-Solomon encode: {}", e))?;
                blocks.push(shards.split_off(k));
            }
            Ok(blocks)
        }
    }
}

/// The order in which to send DATA and PARITY packets. Without interleaving:
/// all data, then all parity. With interleaving: column-major across blocks, so
/// consecutive packets belong to different blocks and a burst spreads out.
fn packet_order(
    total_chunks: u32,
    fec: Fec,
    parity: &[Vec<Vec<u8>>],
    interleave: bool,
) -> Vec<Slot> {
    let (data_per_block, parity_per_block) = match fec {
        Fec::None => (total_chunks.max(1) as usize, 0),
        Fec::Xor { group } => (group as usize, 1),
        Fec::ReedSolomon { data, parity } => (data as usize, parity as usize),
    };
    let num_blocks = parity.len();

    let mut order = Vec::new();
    if !interleave {
        for seq in 0..total_chunks {
            order.push(Slot::Data(seq));
        }
        for (block, shards) in parity.iter().enumerate() {
            for index in 0..shards.len() {
                order.push(Slot::Parity(block as u32, index as u16));
            }
        }
        return order;
    }

    for slot in 0..data_per_block + parity_per_block {
        for block in 0..num_blocks {
            if slot < data_per_block {
                let seq = (block * data_per_block + slot) as u32;
                if seq < total_chunks {
                    order.push(Slot::Data(seq));
                }
            } else {
                let index = (slot - data_per_block) as u16;
                order.push(Slot::Parity(block as u32, index));
            }
        }
    }
    order
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

    fn describe(order: &[Slot]) -> Vec<(char, u32, u16)> {
        order
            .iter()
            .map(|s| match s {
                Slot::Data(seq) => ('d', *seq, 0),
                Slot::Parity(b, i) => ('p', *b, *i),
            })
            .collect()
    }

    #[test]
    fn non_interleaved_order_is_all_data_then_parity() {
        // 5 chunks, XOR group 2 -> 3 blocks (last block partial), 1 parity each.
        let parity = vec![vec![vec![0u8]], vec![vec![0u8]], vec![vec![0u8]]];
        let order = packet_order(5, Fec::Xor { group: 2 }, &parity, false);
        assert_eq!(
            describe(&order),
            vec![
                ('d', 0, 0),
                ('d', 1, 0),
                ('d', 2, 0),
                ('d', 3, 0),
                ('d', 4, 0),
                ('p', 0, 0),
                ('p', 1, 0),
                ('p', 2, 0),
            ]
        );
    }

    #[test]
    fn interleaved_order_spreads_blocks() {
        // Same shape, interleaved: consecutive data come from different blocks.
        let parity = vec![vec![vec![0u8]], vec![vec![0u8]], vec![vec![0u8]]];
        let order = packet_order(5, Fec::Xor { group: 2 }, &parity, true);
        assert_eq!(
            describe(&order),
            vec![
                ('d', 0, 0), // block 0, pos 0
                ('d', 2, 0), // block 1, pos 0
                ('d', 4, 0), // block 2, pos 0
                ('d', 1, 0), // block 0, pos 1
                ('d', 3, 0), // block 1, pos 1
                // block 2 has no pos-1 data chunk (partial), skipped
                ('p', 0, 0),
                ('p', 1, 0),
                ('p', 2, 0),
            ]
        );
    }

    #[test]
    fn both_orders_cover_the_same_packets() {
        let parity = vec![vec![vec![0u8], vec![0u8]], vec![vec![0u8], vec![0u8]]];
        let fec = Fec::ReedSolomon { data: 3, parity: 2 };
        let mut a = describe(&packet_order(6, fec, &parity, false));
        let mut b = describe(&packet_order(6, fec, &parity, true));
        a.sort();
        b.sort();
        assert_eq!(a, b);
    }
}

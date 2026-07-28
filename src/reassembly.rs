//! File-reassembly sink: rebuilds files from the numbered chunks defined by
//! [`crate::protocol`], tolerating out-of-order, duplicated and lost packets.
//!
//! Each chunk is written at its byte offset (`seq * chunk_size`) into a
//! `<name>.part` file. Parity packets — XOR (one per group) or Reed-Solomon
//! (M per K data chunks) — let missing chunks be reconstructed. Once every
//! chunk has arrived the stream is optionally decompressed, its integrity hash
//! verified, and it is renamed to its final name. Incomplete transfers keep
//! their `.part`; idle ones are garbage collected after a timeout.

use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

use crate::protocol::{self, DataPacket, Fec, MetaPacket, Packet, ParityPacket};
use crate::sink::DatagramSink;
use crate::writer::sanitized_ip;

/// Upper bounds that protect the server from a hostile or buggy sender.
const MAX_CONCURRENT_TRANSFERS: usize = 128;
const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB
const MAX_NAME_LEN: usize = 255;
const MAX_ORPHAN_CHUNKS: usize = 256;
const MAX_MISSING_LISTED: usize = 32;

/// Identifies a transfer: the sender plus its chosen transfer id.
type Key = (IpAddr, u32);

/// Reassembles files streamed with the chunked protocol.
pub struct FileReassemblySink {
    logs_dir: String,
    transfer_timeout: Duration,
    active: HashMap<Key, Transfer>,
    /// DATA chunks received before their META, held until META arrives.
    orphans: HashMap<Key, Vec<(u32, Vec<u8>)>>,
}

impl FileReassemblySink {
    /// Creates the sink. `transfer_timeout` bounds how long an idle incomplete
    /// transfer is kept before being garbage collected; zero disables that.
    pub fn new(logs_dir: String, transfer_timeout: Duration) -> Self {
        Self {
            logs_dir,
            transfer_timeout,
            active: HashMap::new(),
            orphans: HashMap::new(),
        }
    }

    fn on_meta(&mut self, source: IpAddr, meta: MetaPacket) -> io::Result<()> {
        let key = (source, meta.transfer_id);
        if self.active.contains_key(&key) {
            return Ok(()); // already set up; ignore the client's resent META
        }
        if meta.file_size > MAX_FILE_SIZE || meta.filename.len() > MAX_NAME_LEN {
            eprintln!(
                "Rejecting transfer {} from {}: exceeds size/name limits",
                meta.transfer_id, source
            );
            self.orphans.remove(&key);
            return Ok(());
        }
        if self.active.len() >= MAX_CONCURRENT_TRANSFERS {
            eprintln!(
                "Too many concurrent transfers; dropping {} from {}",
                meta.transfer_id, source
            );
            return Ok(());
        }

        let mut transfer = Transfer::create(&self.logs_dir, source, &meta)?;
        if let Some(pending) = self.orphans.remove(&key) {
            for (seq, chunk) in pending {
                transfer.write_chunk(seq, &chunk)?;
            }
        }
        if transfer.is_complete() {
            transfer.finalize()?;
        } else {
            self.active.insert(key, transfer);
        }
        Ok(())
    }

    fn on_data(&mut self, source: IpAddr, data: DataPacket) -> io::Result<()> {
        let key = (source, data.transfer_id);
        if let Some(transfer) = self.active.get_mut(&key) {
            transfer.touch();
            transfer.write_chunk(data.seq, &data.payload)?;
            let group = transfer.group_of(data.seq);
            transfer.try_recover(group)?;
            self.finalize_if_complete(&key)?;
        } else {
            let pending = self.orphans.entry(key).or_default();
            if pending.len() < MAX_ORPHAN_CHUNKS {
                pending.push((data.seq, data.payload));
            }
        }
        Ok(())
    }

    fn on_parity(&mut self, source: IpAddr, parity: ParityPacket) -> io::Result<()> {
        let key = (source, parity.transfer_id);
        if let Some(transfer) = self.active.get_mut(&key) {
            transfer.touch();
            transfer
                .parity
                .insert((parity.group, parity.index), parity.parity);
            transfer.try_recover(parity.group)?;
            self.finalize_if_complete(&key)?;
        }
        // Parity before META cannot be used; drop it (FEC is best-effort).
        Ok(())
    }

    fn finalize_if_complete(&mut self, key: &Key) -> io::Result<()> {
        if self.active.get(key).is_some_and(Transfer::is_complete) {
            self.active.remove(key).unwrap().finalize()?;
        }
        Ok(())
    }

    /// Drops transfers with no activity within the timeout, keeping their
    /// `.part` files.
    fn gc(&mut self) {
        if self.transfer_timeout.is_zero() {
            return;
        }
        let timeout = self.transfer_timeout;
        let stale: Vec<Key> = self
            .active
            .iter()
            .filter(|(_, t)| t.last_activity.elapsed() > timeout)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            if let Some(t) = self.active.remove(&key) {
                eprintln!(
                    "Transfer {} from {} timed out ({}/{} chunks); kept {}",
                    key.1,
                    key.0,
                    t.received.len(),
                    t.total_chunks,
                    t.part_path.display()
                );
            }
        }
    }
}

impl DatagramSink for FileReassemblySink {
    fn handle(&mut self, datagram: &crate::parser::UdpDatagram) -> io::Result<()> {
        match protocol::parse(&datagram.payload) {
            Ok(Packet::Meta(meta)) => self.on_meta(datagram.source, meta),
            Ok(Packet::Data(data)) => self.on_data(datagram.source, data),
            Ok(Packet::Parity(parity)) => self.on_parity(datagram.source, parity),
            Err(_) => Ok(()),
        }
    }

    fn flush(&mut self) {
        self.gc();
    }

    fn finish(&mut self) {
        self.gc();
        for ((source, id), transfer) in &self.active {
            eprintln!(
                "Incomplete transfer {} from {}: {}/{} chunks received, missing {}; kept {}",
                id,
                source,
                transfer.received.len(),
                transfer.total_chunks,
                transfer.summarize_missing(),
                transfer.part_path.display(),
            );
        }
    }
}

/// One in-progress file reconstruction.
struct Transfer {
    final_path: PathBuf,
    part_path: PathBuf,
    file: File,
    chunk_size: usize,
    /// Size of the transferred stream (compressed size when compressed).
    file_size: u64,
    total_chunks: u32,
    received: HashSet<u32>,
    compressed: bool,
    hash: Option<[u8; protocol::HASH_LEN]>,
    fec: Fec,
    /// Reed-Solomon codec, built only for a valid RS transfer.
    rs: Option<ReedSolomon>,
    /// Parity keyed by (group/block, parity index).
    parity: HashMap<(u32, u16), Vec<u8>>,
    last_activity: Instant,
}

impl Transfer {
    fn create(logs_dir: &str, source: IpAddr, meta: &MetaPacket) -> io::Result<Self> {
        let dir = Path::new(logs_dir).join(sanitized_ip(&source));
        create_dir_all(&dir)?;

        let name = safe_filename(&meta.filename, meta.transfer_id);
        let final_path = dir.join(&name);
        let part_path = dir.join(format!("{}.part", name));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part_path)?;

        let rs = match meta.fec {
            Fec::ReedSolomon { data, parity } => {
                match ReedSolomon::new(data as usize, parity as usize) {
                    Ok(rs) => Some(rs),
                    Err(e) => {
                        eprintln!(
                            "Transfer {}: invalid Reed-Solomon params: {}",
                            meta.transfer_id, e
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        Ok(Self {
            final_path,
            part_path,
            file,
            chunk_size: meta.chunk_size as usize,
            file_size: meta.file_size,
            total_chunks: total_chunks(meta.file_size, meta.chunk_size),
            received: HashSet::new(),
            compressed: meta.is_compressed(),
            hash: meta.has_hash().then_some(meta.hash),
            fec: meta.fec,
            rs,
            parity: HashMap::new(),
            last_activity: Instant::now(),
        })
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// The FEC group/block a data chunk belongs to.
    fn group_of(&self, seq: u32) -> u32 {
        match self.fec {
            Fec::Xor { group } => seq / group as u32,
            Fec::ReedSolomon { data, .. } => seq / data as u32,
            Fec::None => 0,
        }
    }

    /// Expected length of chunk `seq` (the last chunk may be shorter).
    fn expected_len(&self, seq: u32) -> usize {
        if self.total_chunks == 0 {
            return 0;
        }
        if seq + 1 < self.total_chunks {
            self.chunk_size
        } else {
            (self.file_size - (self.total_chunks as u64 - 1) * self.chunk_size as u64) as usize
        }
    }

    fn write_chunk(&mut self, seq: u32, chunk: &[u8]) -> io::Result<()> {
        if seq >= self.total_chunks || self.received.contains(&seq) {
            return Ok(());
        }
        let offset = seq as u64 * self.chunk_size as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(chunk)?;
        self.received.insert(seq);
        Ok(())
    }

    /// Reads a present chunk back from the `.part` file, padded to `chunk_size`.
    fn read_padded_chunk(&mut self, seq: u32) -> io::Result<Vec<u8>> {
        let offset = seq as u64 * self.chunk_size as u64;
        let len = self.expected_len(seq);
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; self.chunk_size];
        self.file.read_exact(&mut buf[..len])?;
        Ok(buf)
    }

    fn try_recover(&mut self, group: u32) -> io::Result<()> {
        match self.fec {
            Fec::None => Ok(()),
            Fec::Xor { .. } => self.try_recover_xor(group),
            Fec::ReedSolomon { .. } => self.try_recover_rs(group),
        }
    }

    /// Rebuild a single missing chunk in an XOR group.
    fn try_recover_xor(&mut self, group: u32) -> io::Result<()> {
        let group_size = match self.fec {
            Fec::Xor { group } => group as u32,
            _ => return Ok(()),
        };
        let parity = match self.parity.get(&(group, 0)) {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        let start = group * group_size;
        let end = (start + group_size).min(self.total_chunks);
        if start >= self.total_chunks {
            return Ok(());
        }

        let missing: Vec<u32> = (start..end)
            .filter(|s| !self.received.contains(s))
            .collect();
        if missing.len() != 1 {
            return Ok(());
        }
        let target = missing[0];

        let mut recovered = vec![0u8; self.chunk_size];
        for (i, &b) in parity.iter().take(self.chunk_size).enumerate() {
            recovered[i] ^= b;
        }
        for seq in start..end {
            if seq == target {
                continue;
            }
            let chunk = self.read_padded_chunk(seq)?;
            for (i, &b) in chunk.iter().enumerate() {
                recovered[i] ^= b;
            }
        }
        recovered.truncate(self.expected_len(target));
        self.write_chunk(target, &recovered)
    }

    /// Rebuild missing chunks in a Reed-Solomon block if enough shards arrived.
    fn try_recover_rs(&mut self, block: u32) -> io::Result<()> {
        let (k, m) = match self.fec {
            Fec::ReedSolomon { data, parity } => (data as usize, parity as usize),
            _ => return Ok(()),
        };
        // Take the codec out to free `self` for reading chunks.
        let rs = match self.rs.take() {
            Some(rs) => rs,
            None => return Ok(()),
        };
        let result = self.rs_reconstruct(&rs, k, m, block);
        self.rs = Some(rs);
        result
    }

    fn rs_reconstruct(
        &mut self,
        rs: &ReedSolomon,
        k: usize,
        m: usize,
        block: u32,
    ) -> io::Result<()> {
        let start = block * k as u32;
        if start >= self.total_chunks {
            return Ok(());
        }

        let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(k + m);
        let mut present = 0usize;
        let mut missing_real = false;

        for i in 0..k as u32 {
            let seq = start + i;
            if seq >= self.total_chunks {
                shards.push(Some(vec![0u8; self.chunk_size])); // known-zero phantom
                present += 1;
            } else if self.received.contains(&seq) {
                shards.push(Some(self.read_padded_chunk(seq)?));
                present += 1;
            } else {
                shards.push(None);
                missing_real = true;
            }
        }
        for j in 0..m as u16 {
            match self.parity.get(&(block, j)) {
                Some(p) => {
                    let mut shard = vec![0u8; self.chunk_size];
                    let n = p.len().min(self.chunk_size);
                    shard[..n].copy_from_slice(&p[..n]);
                    shards.push(Some(shard));
                    present += 1;
                }
                None => shards.push(None),
            }
        }

        if !missing_real || present < k {
            return Ok(()); // nothing to do, or not enough shards to reconstruct
        }
        if rs.reconstruct(&mut shards).is_err() {
            return Ok(());
        }

        for i in 0..k as u32 {
            let seq = start + i;
            if seq < self.total_chunks && !self.received.contains(&seq) {
                if let Some(shard) = shards[i as usize].take() {
                    let len = self.expected_len(seq);
                    self.write_chunk(seq, &shard[..len])?;
                }
            }
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.total_chunks
    }

    fn finalize(self) -> io::Result<()> {
        self.file.set_len(self.file_size)?;
        self.file.sync_all()?;
        drop(self.file);

        let stream = std::fs::read(&self.part_path)?;
        let data = if self.compressed {
            match miniz_oxide::inflate::decompress_to_vec(&stream) {
                Ok(data) => data,
                Err(_) => {
                    eprintln!(
                        "Transfer to {}: decompression failed; kept {}",
                        self.final_path.display(),
                        self.part_path.display()
                    );
                    return Ok(());
                }
            }
        } else {
            stream
        };

        if let Some(expected) = self.hash {
            let actual: [u8; protocol::HASH_LEN] = Sha256::digest(&data).into();
            if actual != expected {
                eprintln!(
                    "Transfer to {}: integrity check FAILED; kept {}",
                    self.final_path.display(),
                    self.part_path.display()
                );
                return Ok(());
            }
        }

        if self.compressed {
            std::fs::write(&self.final_path, &data)?;
            std::fs::remove_file(&self.part_path)?;
        } else {
            std::fs::rename(&self.part_path, &self.final_path)?;
        }
        Ok(())
    }

    fn summarize_missing(&self) -> String {
        let missing: Vec<u32> = (0..self.total_chunks)
            .filter(|seq| !self.received.contains(seq))
            .take(MAX_MISSING_LISTED)
            .collect();
        let total_missing = self.total_chunks - self.received.len() as u32;
        let listed = missing
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",");
        if total_missing as usize > missing.len() {
            format!("[{}, ...] ({} total)", listed, total_missing)
        } else {
            format!("[{}]", listed)
        }
    }
}

/// Number of chunks needed for `file_size` at `chunk_size`. `chunk_size` is
/// guaranteed non-zero by the protocol parser.
fn total_chunks(file_size: u64, chunk_size: u32) -> u32 {
    if file_size == 0 {
        return 0;
    }
    file_size.div_ceil(chunk_size as u64) as u32
}

/// Reduces an untrusted filename to a safe basename, preventing path traversal.
fn safe_filename(name: &str, transfer_id: u32) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("").trim();
    if base.is_empty() || base == "." || base == ".." {
        format!("transfer_{}", transfer_id)
    } else {
        base.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::UdpDatagram;
    use crate::protocol::{encode_data, encode_meta, encode_parity};
    use reed_solomon_erasure::galois_8::ReedSolomon;
    use std::net::Ipv4Addr;

    fn source() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))
    }

    fn datagram(payload: Vec<u8>) -> UdpDatagram {
        UdpDatagram {
            source: source(),
            payload,
        }
    }

    fn final_file(logs_dir: &str, name: &str) -> PathBuf {
        Path::new(logs_dir).join("10_0_0_9").join(name)
    }

    fn meta(transfer_id: u32, data: &[u8], chunk_size: u32, fec: Fec) -> MetaPacket {
        MetaPacket {
            transfer_id,
            file_size: data.len() as u64,
            chunk_size,
            flags: 0,
            fec,
            original_size: data.len() as u64,
            hash: Sha256::digest(data).into(),
            filename: "file.bin".to_string(),
        }
    }

    fn sink(logs_dir: &str) -> FileReassemblySink {
        FileReassemblySink::new(logs_dir.to_string(), Duration::ZERO)
    }

    #[test]
    fn reassembles_out_of_order_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        let payload = b"ABCDEFGHIJ";
        s.handle(&datagram(encode_meta(&meta(1, payload, 4, Fec::None))))
            .unwrap();
        s.handle(&datagram(encode_data(1, 2, b"IJ"))).unwrap();
        s.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();
        s.handle(&datagram(encode_data(1, 1, b"EFGH"))).unwrap();

        assert_eq!(
            std::fs::read(final_file(&logs_dir, "file.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn xor_fec_recovers_one_lost_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        let payload = b"ABCDEFGHIJ"; // 4 + 4 + 2
        let (c0, c1, c2) = (b"ABCD", b"EFGH", b"IJ");
        let mut parity = vec![0u8; 4];
        for c in [&c0[..], &c1[..], &c2[..]] {
            for (i, &b) in c.iter().enumerate() {
                parity[i] ^= b;
            }
        }

        s.handle(&datagram(encode_meta(&meta(
            1,
            payload,
            4,
            Fec::Xor { group: 3 },
        ))))
        .unwrap();
        s.handle(&datagram(encode_data(1, 0, c0))).unwrap(); // chunk 1 lost
        s.handle(&datagram(encode_data(1, 2, c2))).unwrap();
        s.handle(&datagram(encode_parity(1, 0, 0, &parity)))
            .unwrap();

        assert_eq!(
            std::fs::read(final_file(&logs_dir, "file.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn reed_solomon_recovers_two_lost_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        // 3 data chunks of 4 bytes, RS(3, 2): tolerate 2 losses.
        let payload = b"ABCDEFGHIJKL";
        let chunk_size = 4usize;
        let rs = ReedSolomon::new(3, 2).unwrap();
        let mut shards: Vec<Vec<u8>> = payload
            .chunks(chunk_size)
            .map(|c| {
                let mut s = vec![0u8; chunk_size];
                s[..c.len()].copy_from_slice(c);
                s
            })
            .collect();
        shards.push(vec![0u8; chunk_size]);
        shards.push(vec![0u8; chunk_size]);
        rs.encode(&mut shards).unwrap();

        s.handle(&datagram(encode_meta(&meta(
            1,
            payload,
            4,
            Fec::ReedSolomon { data: 3, parity: 2 },
        ))))
        .unwrap();
        // Only chunk 0 arrives; chunks 1 and 2 are lost. Both parity shards arrive.
        s.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();
        s.handle(&datagram(encode_parity(1, 0, 0, &shards[3])))
            .unwrap();
        s.handle(&datagram(encode_parity(1, 0, 1, &shards[4])))
            .unwrap();

        assert_eq!(
            std::fs::read(final_file(&logs_dir, "file.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn compressed_transfer_is_decompressed() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        let original = b"hello hello hello world world";
        let compressed = miniz_oxide::deflate::compress_to_vec(original, 6);
        let m = MetaPacket {
            transfer_id: 1,
            file_size: compressed.len() as u64,
            chunk_size: compressed.len() as u32,
            flags: crate::protocol::FLAG_COMPRESSED,
            fec: Fec::None,
            original_size: original.len() as u64,
            hash: Sha256::digest(original).into(),
            filename: "z.bin".to_string(),
        };
        s.handle(&datagram(encode_meta(&m))).unwrap();
        s.handle(&datagram(encode_data(1, 0, &compressed))).unwrap();

        assert_eq!(
            std::fs::read(final_file(&logs_dir, "z.bin")).unwrap(),
            original
        );
    }

    #[test]
    fn integrity_mismatch_keeps_part_and_skips_final() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        let mut m = meta(1, b"ABCD", 4, Fec::None);
        m.hash = [0xAB; protocol::HASH_LEN];
        s.handle(&datagram(encode_meta(&m))).unwrap();
        s.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();

        assert!(!final_file(&logs_dir, "file.bin").exists());
        assert!(Path::new(&logs_dir)
            .join("10_0_0_9")
            .join("file.bin.part")
            .exists());
    }

    #[test]
    fn safe_filename_strips_paths_and_traversal() {
        assert_eq!(safe_filename("../../etc/passwd", 1), "passwd");
        assert_eq!(safe_filename("..", 7), "transfer_7");
    }
}

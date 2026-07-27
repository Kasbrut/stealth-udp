//! File-reassembly sink: rebuilds files from the numbered chunks defined by
//! [`crate::protocol`], tolerating out-of-order, duplicated and lost packets.
//!
//! Each chunk is written at its byte offset (`seq * chunk_size`) into a
//! `<name>.part` file. XOR parity packets let a single missing chunk per FEC
//! group be reconstructed. Once every chunk has arrived the stream is optionally
//! decompressed, its integrity hash verified, and it is renamed to its final
//! name. Incomplete transfers keep their `.part`; idle ones are garbage
//! collected after a timeout, and missing chunks are logged on shutdown.

use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::protocol::{self, DataPacket, MetaPacket, Packet, ParityPacket};
use crate::sink::DatagramSink;
use crate::writer::sanitized_ip;

/// Upper bounds that protect the server from a hostile or buggy sender.
const MAX_CONCURRENT_TRANSFERS: usize = 128;
const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB
const MAX_NAME_LEN: usize = 255;
/// Max DATA chunks buffered for a transfer whose META has not arrived yet.
const MAX_ORPHAN_CHUNKS: usize = 256;
/// Max missing chunk indices listed per incomplete transfer when logging.
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
            transfer.try_recover(transfer.group_of(data.seq))?;
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
            transfer.parity.insert(parity.group, parity.parity);
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
            Err(_) => Ok(()), // non-protocol / malformed: ignore
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
    /// Integrity hash of the original file, if provided.
    hash: Option<[u8; protocol::HASH_LEN]>,
    /// Parity per FEC group; empty when FEC is unused.
    fec_group: u16,
    parity: HashMap<u32, Vec<u8>>,
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
            fec_group: meta.fec_group,
            parity: HashMap::new(),
            last_activity: Instant::now(),
        })
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// The FEC group a data chunk belongs to (meaningless when FEC is off).
    fn group_of(&self, seq: u32) -> u32 {
        if self.fec_group == 0 {
            0
        } else {
            seq / self.fec_group as u32
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

    fn read_chunk(&mut self, seq: u32) -> io::Result<Vec<u8>> {
        let offset = seq as u64 * self.chunk_size as u64;
        let len = self.expected_len(seq);
        self.file.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; len];
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// If FEC group `group` is missing exactly one chunk and its parity is
    /// present, reconstruct the missing chunk.
    fn try_recover(&mut self, group: u32) -> io::Result<()> {
        if self.fec_group == 0 {
            return Ok(());
        }
        let parity = match self.parity.get(&group) {
            Some(p) => p.clone(),
            None => return Ok(()),
        };

        let n = self.fec_group as u32;
        let start = group * n;
        let end = (start + n).min(self.total_chunks);
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

        // recovered = parity XOR (all present chunks in the group, padded).
        let mut recovered = vec![0u8; self.chunk_size];
        for (i, &b) in parity.iter().take(self.chunk_size).enumerate() {
            recovered[i] ^= b;
        }
        for seq in start..end {
            if seq == target {
                continue;
            }
            let chunk = self.read_chunk(seq)?;
            for (i, &b) in chunk.iter().enumerate() {
                recovered[i] ^= b;
            }
        }
        recovered.truncate(self.expected_len(target));
        self.write_chunk(target, &recovered)
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

    /// A short human-readable summary of the missing chunk indices.
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
/// Falls back to a name derived from the transfer id when nothing safe remains.
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
    use crate::protocol::{encode_data, encode_meta, encode_parity, HASH_LEN};
    use sha2::{Digest, Sha256};
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

    /// Builds a plain (uncompressed, no FEC) META with a correct hash.
    fn meta(transfer_id: u32, data: &[u8], chunk_size: u32, fec_group: u16) -> MetaPacket {
        MetaPacket {
            transfer_id,
            file_size: data.len() as u64,
            chunk_size,
            flags: 0,
            fec_group,
            original_size: data.len() as u64,
            hash: Sha256::digest(data).into(),
            filename: "file.bin".to_string(),
        }
    }

    fn sink(logs_dir: &str) -> FileReassemblySink {
        FileReassemblySink::new(logs_dir.to_string(), Duration::ZERO)
    }

    #[test]
    fn total_chunks_rounds_up() {
        assert_eq!(total_chunks(0, 4), 0);
        assert_eq!(total_chunks(4, 4), 1);
        assert_eq!(total_chunks(5, 4), 2);
    }

    #[test]
    fn safe_filename_strips_paths_and_traversal() {
        assert_eq!(safe_filename("../../etc/passwd", 1), "passwd");
        assert_eq!(safe_filename("a/b/c.txt", 1), "c.txt");
        assert_eq!(safe_filename("..", 7), "transfer_7");
    }

    #[test]
    fn reassembles_out_of_order_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        let payload = b"ABCDEFGHIJ";
        let m = meta(1, payload, 4, 0);
        s.handle(&datagram(encode_meta(&m))).unwrap();
        s.handle(&datagram(encode_data(1, 2, b"IJ"))).unwrap();
        s.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();
        s.handle(&datagram(encode_data(1, 1, b"EFGH"))).unwrap();

        assert_eq!(
            std::fs::read(final_file(&logs_dir, "file.bin")).unwrap(),
            payload
        );
    }

    #[test]
    fn fec_recovers_one_lost_chunk_per_group() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        // 3 chunks, one FEC group of 3; parity over all three.
        let payload = b"ABCDEFGHIJ"; // 4 + 4 + 2
        let m = meta(1, payload, 4, 3);
        let c0 = b"ABCD";
        let c1 = b"EFGH";
        let c2 = b"IJ";
        // parity padded to chunk_size 4.
        let mut parity = vec![0u8; 4];
        for c in [&c0[..], &c1[..], &c2[..]] {
            for (i, &b) in c.iter().enumerate() {
                parity[i] ^= b;
            }
        }

        s.handle(&datagram(encode_meta(&m))).unwrap();
        // Chunk 1 is "lost"; send 0, 2 and the parity.
        s.handle(&datagram(encode_data(1, 0, c0))).unwrap();
        s.handle(&datagram(encode_data(1, 2, c2))).unwrap();
        s.handle(&datagram(encode_parity(1, 0, &parity))).unwrap();

        // FEC should have rebuilt chunk 1 and completed the file.
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
            chunk_size: compressed.len() as u32, // single chunk for simplicity
            flags: crate::protocol::FLAG_COMPRESSED,
            fec_group: 0,
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

        let mut m = meta(1, b"ABCD", 4, 0);
        m.hash = [0xAB; HASH_LEN]; // wrong hash on purpose
        s.handle(&datagram(encode_meta(&m))).unwrap();
        s.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();

        assert!(!final_file(&logs_dir, "file.bin").exists());
        assert!(Path::new(&logs_dir)
            .join("10_0_0_9")
            .join("file.bin.part")
            .exists());
    }

    #[test]
    fn incomplete_transfer_keeps_part_file() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut s = sink(&logs_dir);

        let m = meta(1, b"ABCDEFGHIJKL", 4, 0); // 3 chunks
        s.handle(&datagram(encode_meta(&m))).unwrap();
        s.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();
        s.finish();

        assert!(Path::new(&logs_dir)
            .join("10_0_0_9")
            .join("file.bin.part")
            .exists());
        assert!(!final_file(&logs_dir, "file.bin").exists());
    }
}

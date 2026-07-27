//! File-reassembly sink: rebuilds files from the numbered chunks defined by
//! [`crate::protocol`], tolerating out-of-order, duplicated and lost packets.
//!
//! Each chunk is written at its byte offset (`seq * chunk_size`) into a
//! `<name>.part` file; once every chunk has arrived the file is renamed to its
//! final name. Incomplete transfers keep their `.part` file, and the missing
//! chunk ranges are logged on shutdown.

use std::collections::{HashMap, HashSet};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::protocol::{self, DataPacket, MetaPacket, Packet};
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
    active: HashMap<Key, Transfer>,
    /// DATA chunks received before their META, held until META arrives.
    orphans: HashMap<Key, Vec<(u32, Vec<u8>)>>,
}

impl FileReassemblySink {
    pub fn new(logs_dir: String) -> Self {
        Self {
            logs_dir,
            active: HashMap::new(),
            orphans: HashMap::new(),
        }
    }

    fn on_meta(&mut self, source: IpAddr, meta: MetaPacket) -> io::Result<()> {
        let key = (source, meta.transfer_id);

        // A repeated META (the client resends it for robustness) is ignored
        // once the transfer is already set up.
        if self.active.contains_key(&key) {
            return Ok(());
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

        // Replay any chunks that arrived before this META.
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
            transfer.write_chunk(data.seq, &data.payload)?;
            if transfer.is_complete() {
                // Remove first so the borrow ends, then finalize by value.
                self.active.remove(&key).unwrap().finalize()?;
            }
        } else {
            // META not seen yet: buffer the chunk, but bound the buffer.
            let pending = self.orphans.entry(key).or_default();
            if pending.len() < MAX_ORPHAN_CHUNKS {
                pending.push((data.seq, data.payload));
            }
        }
        Ok(())
    }
}

impl DatagramSink for FileReassemblySink {
    fn handle(&mut self, datagram: &crate::parser::UdpDatagram) -> io::Result<()> {
        // Non-protocol or malformed payloads are simply ignored.
        match protocol::parse(&datagram.payload) {
            Ok(Packet::Meta(meta)) => self.on_meta(datagram.source, meta),
            Ok(Packet::Data(data)) => self.on_data(datagram.source, data),
            Err(_) => Ok(()),
        }
    }

    fn flush(&mut self) {
        for ((source, id), transfer) in self.active.iter_mut() {
            let _ = transfer.file.flush();
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
    chunk_size: u32,
    file_size: u64,
    total_chunks: u32,
    received: HashSet<u32>,
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
            chunk_size: meta.chunk_size,
            file_size: meta.file_size,
            total_chunks: total_chunks(meta.file_size, meta.chunk_size),
            received: HashSet::new(),
        })
    }

    fn write_chunk(&mut self, seq: u32, chunk: &[u8]) -> io::Result<()> {
        // Ignore out-of-range indices and duplicates.
        if seq >= self.total_chunks || self.received.contains(&seq) {
            return Ok(());
        }
        let offset = seq as u64 * self.chunk_size as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(chunk)?;
        self.received.insert(seq);
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.total_chunks
    }

    fn finalize(self) -> io::Result<()> {
        self.file.set_len(self.file_size)?;
        self.file.sync_all()?;
        drop(self.file);
        std::fs::rename(&self.part_path, &self.final_path)
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
    use crate::protocol::{encode_data, encode_meta};
    use std::fs;
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

    #[test]
    fn total_chunks_rounds_up() {
        assert_eq!(total_chunks(0, 4), 0);
        assert_eq!(total_chunks(4, 4), 1);
        assert_eq!(total_chunks(5, 4), 2);
        assert_eq!(total_chunks(8, 4), 2);
    }

    #[test]
    fn safe_filename_strips_paths_and_traversal() {
        assert_eq!(safe_filename("../../etc/passwd", 1), "passwd");
        assert_eq!(safe_filename("a/b/c.txt", 1), "c.txt");
        assert_eq!(safe_filename("..", 7), "transfer_7");
        assert_eq!(safe_filename("", 7), "transfer_7");
    }

    #[test]
    fn reassembles_out_of_order_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut sink = FileReassemblySink::new(logs_dir.clone());

        let meta = MetaPacket {
            transfer_id: 1,
            file_size: 10,
            chunk_size: 4,
            filename: "hello.bin".to_string(),
        };
        // Send META, then chunks 2, 0, 1 out of order (last chunk is 2 bytes).
        sink.handle(&datagram(encode_meta(&meta))).unwrap();
        sink.handle(&datagram(encode_data(1, 2, b"IJ"))).unwrap();
        sink.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();
        sink.handle(&datagram(encode_data(1, 1, b"EFGH"))).unwrap();

        let path = final_file(&logs_dir, "hello.bin");
        assert_eq!(fs::read(&path).unwrap(), b"ABCDEFGHIJ");
        // The .part file has been renamed away.
        assert!(!path.with_extension("bin.part").exists());
    }

    #[test]
    fn buffers_data_arriving_before_meta() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut sink = FileReassemblySink::new(logs_dir.clone());

        // DATA before META must be buffered and replayed once META arrives.
        sink.handle(&datagram(encode_data(5, 0, b"ABCD"))).unwrap();
        sink.handle(&datagram(encode_data(5, 1, b"EF"))).unwrap();
        let meta = MetaPacket {
            transfer_id: 5,
            file_size: 6,
            chunk_size: 4,
            filename: "late.bin".to_string(),
        };
        sink.handle(&datagram(encode_meta(&meta))).unwrap();

        assert_eq!(
            fs::read(final_file(&logs_dir, "late.bin")).unwrap(),
            b"ABCDEF"
        );
    }

    #[test]
    fn ignores_duplicate_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut sink = FileReassemblySink::new(logs_dir.clone());

        let meta = MetaPacket {
            transfer_id: 1,
            file_size: 4,
            chunk_size: 4,
            filename: "d.bin".to_string(),
        };
        sink.handle(&datagram(encode_meta(&meta))).unwrap();
        sink.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();
        // Duplicate of the same seq must not corrupt the result.
        sink.handle(&datagram(encode_data(1, 0, b"ZZZZ"))).unwrap();

        assert_eq!(fs::read(final_file(&logs_dir, "d.bin")).unwrap(), b"ABCD");
    }

    #[test]
    fn incomplete_transfer_keeps_part_file() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut sink = FileReassemblySink::new(logs_dir.clone());

        let meta = MetaPacket {
            transfer_id: 1,
            file_size: 12,
            chunk_size: 4,
            filename: "partial.bin".to_string(),
        };
        sink.handle(&datagram(encode_meta(&meta))).unwrap();
        sink.handle(&datagram(encode_data(1, 0, b"ABCD"))).unwrap();
        // Chunks 1 and 2 never arrive.
        sink.flush();

        let part = Path::new(&logs_dir)
            .join("10_0_0_9")
            .join("partial.bin.part");
        assert!(part.exists());
        assert!(!final_file(&logs_dir, "partial.bin").exists());
    }
}

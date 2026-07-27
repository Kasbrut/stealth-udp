//! Per-IP log file writing. Owns one buffered file per source address.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::Ipv4Addr;

use crate::parser::UdpDatagram;

/// Keeps one buffered, append-only log file per source IP and writes each
/// datagram's payload to the file that belongs to its sender.
pub struct LogWriter {
    logs_dir: String,
    files: HashMap<String, BufWriter<File>>,
}

impl LogWriter {
    /// Creates a writer that stores its log files under `logs_dir`.
    pub fn new(logs_dir: String) -> Self {
        Self {
            logs_dir,
            files: HashMap::new(),
        }
    }

    /// Appends the datagram payload to its source IP's log file, opening the
    /// file on first use.
    // The `entry` API can't be used here because opening the file is fallible
    // and its `?` cannot cross the `or_insert_with` closure boundary.
    #[allow(clippy::map_entry)]
    pub fn write(&mut self, datagram: &UdpDatagram) -> io::Result<()> {
        let filename = log_filename(&datagram.source);
        if !self.files.contains_key(&filename) {
            let path = format!("{}/{}", self.logs_dir, filename);
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            self.files.insert(filename.clone(), BufWriter::new(file));
        }
        // Safe: we just inserted the entry above if it was missing.
        self.files
            .get_mut(&filename)
            .unwrap()
            .write_all(&datagram.payload)
    }

    /// Flushes every buffered log file, reporting (but not failing on) errors.
    pub fn flush_all(&mut self) {
        for (name, file) in self.files.iter_mut() {
            if let Err(e) = file.flush() {
                eprintln!("Error flushing log file {}: {}", name, e);
            }
        }
    }
}

/// Builds the per-IP log file name: `192.168.1.10` -> `192_168_1_10.log`.
pub fn log_filename(source: &Ipv4Addr) -> String {
    format!("{}.log", source.to_string().replace('.', "_"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn datagram(source: Ipv4Addr, payload: &[u8]) -> UdpDatagram {
        UdpDatagram {
            source,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn log_filename_sanitizes_dots() {
        let ip = Ipv4Addr::new(192, 168, 1, 10);
        assert_eq!(log_filename(&ip), "192_168_1_10.log");
    }

    #[test]
    fn appends_multiple_payloads_from_same_source() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut writer = LogWriter::new(logs_dir.clone());

        let source = Ipv4Addr::new(10, 0, 0, 7);
        writer.write(&datagram(source, b"abc")).unwrap();
        writer.write(&datagram(source, b"def")).unwrap();
        writer.flush_all();

        let contents = fs::read(format!("{}/10_0_0_7.log", logs_dir)).unwrap();
        assert_eq!(contents, b"abcdef");
    }

    #[test]
    fn separates_payloads_by_source_ip() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut writer = LogWriter::new(logs_dir.clone());

        writer
            .write(&datagram(Ipv4Addr::new(10, 0, 0, 1), b"one"))
            .unwrap();
        writer
            .write(&datagram(Ipv4Addr::new(10, 0, 0, 2), b"two"))
            .unwrap();
        writer.flush_all();

        assert_eq!(
            fs::read(format!("{}/10_0_0_1.log", logs_dir)).unwrap(),
            b"one"
        );
        assert_eq!(
            fs::read(format!("{}/10_0_0_2.log", logs_dir)).unwrap(),
            b"two"
        );
    }
}

//! Per-IP log file management. Owns one buffered, append-only file per name
//! and appends raw bytes to it. Sinks decide *what* bytes and *which* file.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::Ipv4Addr;

/// Keeps one buffered, append-only file per name and appends bytes to the
/// requested file, opening it on first use.
pub struct LogWriter {
    logs_dir: String,
    files: HashMap<String, BufWriter<File>>,
}

impl LogWriter {
    /// Creates a writer that stores its files under `logs_dir`.
    pub fn new(logs_dir: String) -> Self {
        Self {
            logs_dir,
            files: HashMap::new(),
        }
    }

    /// Appends `bytes` to `filename` (relative to the log directory), opening
    /// the file the first time it is seen.
    // The `entry` API can't be used here because opening the file is fallible
    // and its `?` cannot cross the `or_insert_with` closure boundary.
    #[allow(clippy::map_entry)]
    pub fn append(&mut self, filename: &str, bytes: &[u8]) -> io::Result<()> {
        if !self.files.contains_key(filename) {
            let path = format!("{}/{}", self.logs_dir, filename);
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            self.files
                .insert(filename.to_string(), BufWriter::new(file));
        }
        // Safe: we just inserted the entry above if it was missing.
        self.files.get_mut(filename).unwrap().write_all(bytes)
    }

    /// Flushes every buffered file, reporting (but not failing on) errors.
    pub fn flush_all(&mut self) {
        for (name, file) in self.files.iter_mut() {
            if let Err(e) = file.flush() {
                eprintln!("Error flushing log file {}: {}", name, e);
            }
        }
    }
}

/// Filesystem-safe form of an IPv4 address: `192.168.1.10` -> `192_168_1_10`.
pub fn sanitized_ip(source: &Ipv4Addr) -> String {
    source.to_string().replace('.', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn sanitized_ip_replaces_dots() {
        assert_eq!(
            sanitized_ip(&Ipv4Addr::new(192, 168, 1, 10)),
            "192_168_1_10"
        );
    }

    #[test]
    fn append_accumulates_into_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut writer = LogWriter::new(logs_dir.clone());

        writer.append("client.log", b"abc").unwrap();
        writer.append("client.log", b"def").unwrap();
        writer.flush_all();

        assert_eq!(
            fs::read(format!("{}/client.log", logs_dir)).unwrap(),
            b"abcdef"
        );
    }

    #[test]
    fn append_keeps_files_separate() {
        let dir = tempfile::tempdir().unwrap();
        let logs_dir = dir.path().to_str().unwrap().to_string();
        let mut writer = LogWriter::new(logs_dir.clone());

        writer.append("a.log", b"one").unwrap();
        writer.append("b.log", b"two").unwrap();
        writer.flush_all();

        assert_eq!(fs::read(format!("{}/a.log", logs_dir)).unwrap(), b"one");
        assert_eq!(fs::read(format!("{}/b.log", logs_dir)).unwrap(), b"two");
    }
}

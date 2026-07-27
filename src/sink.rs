//! Datagram sinks: pluggable destinations that decide how each captured
//! datagram is persisted. New output formats are added by implementing
//! [`DatagramSink`] and wiring them into [`build_sink`].

use std::io;

use chrono::Local;
use serde::Serialize;

use crate::parser::UdpDatagram;
use crate::writer::{sanitized_ip, LogWriter};

/// A destination for captured datagrams.
pub trait DatagramSink {
    /// Persists a single datagram.
    fn handle(&mut self, datagram: &UdpDatagram) -> io::Result<()>;
    /// Flushes any buffered data (called on shutdown).
    fn flush(&mut self);
}

/// Selectable output format, chosen on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// Append raw payload bytes to a per-IP `.log` file.
    Raw,
    /// Write one JSON object per datagram to a per-IP `.jsonl` file.
    Jsonl,
}

/// Builds the sink matching `format`, storing files under `logs_dir`. The sink
/// is `Send` so it can be moved onto the dedicated writer thread.
pub fn build_sink(format: OutputFormat, logs_dir: String) -> Box<dyn DatagramSink + Send> {
    match format {
        OutputFormat::Raw => Box::new(RawFileSink::new(logs_dir)),
        OutputFormat::Jsonl => Box::new(JsonlSink::new(logs_dir)),
    }
}

/// Appends each datagram's raw payload to a per-IP `.log` file. Suited to
/// reconstructing a file that the client streamed across multiple packets
/// (the payloads are concatenated in arrival order).
pub struct RawFileSink {
    writer: LogWriter,
}

impl RawFileSink {
    pub fn new(logs_dir: String) -> Self {
        Self {
            writer: LogWriter::new(logs_dir),
        }
    }
}

impl DatagramSink for RawFileSink {
    fn handle(&mut self, datagram: &UdpDatagram) -> io::Result<()> {
        let filename = format!("{}.log", sanitized_ip(&datagram.source));
        self.writer.append(&filename, &datagram.payload)
    }

    fn flush(&mut self) {
        self.writer.flush_all();
    }
}

/// Writes each datagram as a JSON object on its own line (JSON Lines) to a
/// per-IP `.jsonl` file. Suited to discrete messages.
pub struct JsonlSink {
    writer: LogWriter,
}

impl JsonlSink {
    pub fn new(logs_dir: String) -> Self {
        Self {
            writer: LogWriter::new(logs_dir),
        }
    }
}

impl DatagramSink for JsonlSink {
    fn handle(&mut self, datagram: &UdpDatagram) -> io::Result<()> {
        let line = json_line(datagram, &Local::now().to_rfc3339());
        let filename = format!("{}.jsonl", sanitized_ip(&datagram.source));
        self.writer.append(&filename, line.as_bytes())
    }

    fn flush(&mut self) {
        self.writer.flush_all();
    }
}

/// A single JSON Lines record. `payload_utf8` is a lossy text view (handy for
/// messages), `payload_hex` is the exact bytes (handy for binary data).
#[derive(Serialize)]
struct Record<'a> {
    timestamp: &'a str,
    source: String,
    length: usize,
    payload_utf8: String,
    payload_hex: String,
}

/// Builds one JSON Lines record for `datagram`, including the trailing newline.
fn json_line(datagram: &UdpDatagram, timestamp: &str) -> String {
    let record = Record {
        timestamp,
        source: datagram.source.to_string(),
        length: datagram.payload.len(),
        payload_utf8: String::from_utf8_lossy(&datagram.payload).into_owned(),
        payload_hex: hex::encode(&datagram.payload),
    };
    // Serializing this fixed, string/number-only struct cannot fail.
    let mut line = serde_json::to_string(&record).expect("record serialization");
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::net::{IpAddr, Ipv4Addr};

    fn datagram(payload: &[u8]) -> UdpDatagram {
        UdpDatagram {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn json_line_is_valid_json_with_expected_fields() {
        let line = json_line(&datagram(b"hi"), "2026-07-27T10:00:00+00:00");
        assert!(line.ends_with('\n'));

        let value: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(value["timestamp"], "2026-07-27T10:00:00+00:00");
        assert_eq!(value["source"], "10.0.0.5");
        assert_eq!(value["length"], 2);
        assert_eq!(value["payload_utf8"], "hi");
        assert_eq!(value["payload_hex"], "6869");
    }

    #[test]
    fn json_line_encodes_non_utf8_bytes_as_hex() {
        let line = json_line(&datagram(&[0xff, 0x00]), "2026-07-27T10:00:00+00:00");
        let value: Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(value["payload_hex"], "ff00");
        // Lossy UTF-8 keeps the record valid even for arbitrary bytes.
        assert!(value["payload_utf8"].is_string());
    }
}

//! Optional JSON configuration file.
//!
//! Every field is optional; a value set here is used only when the matching
//! command-line flag was not passed (CLI overrides the file, the file overrides
//! the built-in defaults).

use serde::Deserialize;

/// Configuration loaded from a JSON file. Unknown keys are rejected so typos
/// surface as errors instead of being silently ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub interface: Option<String>,
    pub port: Option<u16>,
    pub format: Option<String>,
    pub flush_interval: Option<u64>,
    pub transfer_timeout: Option<u64>,
}

/// Loads and parses the JSON config file at `path`.
pub fn load(path: &str) -> Result<FileConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read config file '{}': {}", path, e))?;
    serde_json::from_str(&text).map_err(|e| format!("Invalid config file '{}': {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn loads_all_fields() {
        let file = write_config(
            r#"{ "interface": "en0", "port": 9999, "format": "file", "flush_interval": 10 }"#,
        );
        let cfg = load(file.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.interface.as_deref(), Some("en0"));
        assert_eq!(cfg.port, Some(9999));
        assert_eq!(cfg.format.as_deref(), Some("file"));
        assert_eq!(cfg.flush_interval, Some(10));
    }

    #[test]
    fn missing_fields_are_none() {
        let file = write_config(r#"{ "port": 1234 }"#);
        let cfg = load(file.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.port, Some(1234));
        assert!(cfg.interface.is_none());
        assert!(cfg.format.is_none());
    }

    #[test]
    fn rejects_unknown_keys() {
        let file = write_config(r#"{ "prot": 1234 }"#);
        assert!(load(file.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(load("/no/such/config/file.json").is_err());
    }
}

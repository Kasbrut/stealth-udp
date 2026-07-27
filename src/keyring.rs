//! The server keyring: a text file holding one hex-encoded private key per
//! client, so each client can have its own key. Blank lines and lines starting
//! with `#` (used as human-readable labels) are ignored.

use std::fs::OpenOptions;
use std::io::Write;

use crate::crypto::{self, KEY_LEN};

/// Loads every private key from the keyring file at `path`.
pub fn load(path: &str) -> Result<Vec<[u8; KEY_LEN]>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read keyring '{}': {}", path, e))?;

    let mut keys = Vec::new();
    for (line_no, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = crypto::from_hex(line)
            .ok_or_else(|| format!("Invalid key on line {} of '{}'", line_no + 1, path))?;
        keys.push(key);
    }

    if keys.is_empty() {
        return Err(format!("Keyring '{}' contains no keys", path));
    }
    Ok(keys)
}

/// Appends a new client's private key (with a label comment) to the keyring,
/// creating the file if needed.
pub fn append(path: &str, label: &str, private: &[u8; KEY_LEN]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Cannot open keyring '{}': {}", path, e))?;
    writeln!(file, "# {}\n{}", label, crypto::to_hex(private))
        .map_err(|e| format!("Cannot write to keyring '{}': {}", path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[test]
    fn append_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.keys");
        let path = path.to_str().unwrap();

        let a = generate_keypair();
        let b = generate_keypair();
        append(path, "alice", &a.private).unwrap();
        append(path, "bob", &b.private).unwrap();

        let keys = load(path).unwrap();
        assert_eq!(keys, vec![a.private, b.private]);
    }

    #[test]
    fn empty_or_missing_keyring_is_an_error() {
        assert!(load("/no/such/keyring").is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.keys");
        std::fs::write(&path, "# only a comment\n\n").unwrap();
        assert!(load(path.to_str().unwrap()).is_err());
    }
}

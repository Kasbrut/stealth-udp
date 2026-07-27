//! The file-transfer client: split a file into numbered chunks and send them
//! over UDP, optionally sealing each packet to the server's public key.
//!
//! Shared by the `send_file` example (key passed as an argument) and the
//! `client` binary (key embedded by the server).

use std::net::UdpSocket;
use std::path::Path;

use crate::crypto::{self, KEY_LEN};
use crate::protocol::{encode_data, encode_meta, MetaPacket};

/// Default UDP payload chunk size, kept below a typical MTU to avoid IP
/// fragmentation.
pub const DEFAULT_CHUNK_SIZE: usize = 1400;

/// Resend META every this many data packets so its loss is recoverable on an
/// unstable link.
const META_RESEND_EVERY: usize = 50;

/// Sends `path` to `target` in chunks of `chunk_size` bytes. When
/// `server_public` is set, every packet is sealed to that key.
pub fn send_file(
    target: &str,
    path: &str,
    chunk_size: usize,
    server_public: Option<[u8; KEY_LEN]>,
) -> Result<(), String> {
    if chunk_size == 0 {
        return Err("chunk size must be greater than zero".to_string());
    }

    let data = std::fs::read(path).map_err(|e| format!("cannot read '{}': {}", path, e))?;
    let filename = Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".to_string());

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("cannot bind socket: {}", e))?;
    socket
        .connect(target)
        .map_err(|e| format!("cannot connect to '{}': {}", target, e))?;

    let send = |bytes: &[u8]| -> Result<(), String> {
        let packet = match &server_public {
            Some(key) => crypto::seal(bytes, key),
            None => bytes.to_vec(),
        };
        socket
            .send(&packet)
            .map(|_| ())
            .map_err(|e| format!("send failed: {}", e))
    };

    let transfer_id = std::process::id();
    let meta = MetaPacket {
        transfer_id,
        file_size: data.len() as u64,
        chunk_size: chunk_size as u32,
        filename,
    };
    let meta_bytes = encode_meta(&meta);

    send(&meta_bytes)?;

    let mut sent = 0usize;
    for (seq, chunk) in data.chunks(chunk_size).enumerate() {
        if sent > 0 && sent.is_multiple_of(META_RESEND_EVERY) {
            send(&meta_bytes)?;
        }
        send(&encode_data(transfer_id, seq as u32, chunk))?;
        sent += 1;
    }

    // A final META so a late-starting receiver can still complete the file.
    send(&meta_bytes)?;

    println!(
        "Sent '{}' ({} bytes) as transfer {} in {} chunk(s){}.",
        meta.filename,
        meta.file_size,
        transfer_id,
        sent,
        if server_public.is_some() {
            " [encrypted]"
        } else {
            ""
        }
    );
    Ok(())
}

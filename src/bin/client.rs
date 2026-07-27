//! Provisioned file-transfer client.
//!
//! The server's public key is baked into this binary by
//! `stealth-udp --gen-client`, so a provisioned client is a single file with no
//! separate key. Run it to send a file (every packet is encrypted).
//!
//! Usage:
//!   client <HOST:PORT> <FILE> [--chunk-size N]
//!   client --show-key            # print the embedded public key, then exit

use stealth_udp::client::{send_file, DEFAULT_CHUNK_SIZE};
use stealth_udp::crypto::to_hex;
use stealth_udp::embed::{self, SLOT_LEN};

/// The key slot. Non-zero marker keeps it in the file image; the server patches
/// the placeholder that follows the marker.
#[used]
static EMBEDDED_KEY_SLOT: [u8; SLOT_LEN] = embed::initial_slot();

/// Reads the slot via volatile loads so the optimizer cannot fold in the
/// compile-time placeholder instead of the server-patched bytes.
fn embedded_slot() -> [u8; SLOT_LEN] {
    let mut slot = [0u8; SLOT_LEN];
    for (i, byte) in slot.iter_mut().enumerate() {
        *byte = unsafe { core::ptr::read_volatile(&EMBEDDED_KEY_SLOT[i]) };
    }
    slot
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let key = embed::read_embedded(&embedded_slot());

    let mut args = std::env::args().skip(1);
    let first = args
        .next()
        .ok_or("usage: client <HOST:PORT> <FILE> [--chunk-size N]  |  client --show-key")?;

    if first == "--show-key" {
        let key = key.ok_or("this client has no embedded key (not provisioned)")?;
        println!("{}", to_hex(&key));
        return Ok(());
    }

    let target = first;
    let path = args
        .next()
        .ok_or("usage: client <HOST:PORT> <FILE> [--chunk-size N]")?;

    let mut chunk_size = DEFAULT_CHUNK_SIZE;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--chunk-size" => {
                let value = args.next().ok_or("--chunk-size needs a value")?;
                chunk_size = value.parse().map_err(|_| "--chunk-size must be a number")?;
            }
            other => return Err(format!("unexpected argument: {}", other)),
        }
    }

    let key =
        key.ok_or("this client has no embedded server key; provision it with --gen-client")?;
    send_file(&target, &path, chunk_size, Some(key))
}

//! Embedding the server public key into a pre-compiled client binary
//! ("binary patching"), so a provisioned client is a single self-contained file
//! with no separate key alongside it.
//!
//! The client template compiles a fixed slot into its image: a unique marker
//! followed by a zeroed key placeholder. The server locates the marker in the
//! template file and overwrites the following bytes with a client's public key
//! — no recompilation needed. The marker is non-zero, so the slot lands in the
//! file image (not `.bss`) and is therefore patchable.

use crate::crypto::KEY_LEN;

/// Unique marker preceding the embedded key slot. The patcher locates this
/// exact byte sequence and overwrites the `KEY_LEN` bytes that follow it.
pub const MARKER: [u8; 16] = [
    0x9e, 0x7f, 0x1a, 0x53, 0xc4, 0x2b, 0xd8, 0x66, 0x11, 0xf0, 0x3d, 0x84, 0xa9, 0x57, 0x6c, 0xe2,
];

/// Total length of the embedded slot: marker followed by the key placeholder.
pub const SLOT_LEN: usize = MARKER.len() + KEY_LEN;

/// The slot compiled into an unprovisioned client: marker + zeroed key.
pub const fn initial_slot() -> [u8; SLOT_LEN] {
    let mut slot = [0u8; SLOT_LEN];
    let mut i = 0;
    while i < MARKER.len() {
        slot[i] = MARKER[i];
        i += 1;
    }
    slot
}

/// Reads the embedded key from a slot, or `None` if it is still zeroed (the
/// client was never provisioned).
pub fn read_embedded(slot: &[u8; SLOT_LEN]) -> Option<[u8; KEY_LEN]> {
    let key: [u8; KEY_LEN] = slot[MARKER.len()..].try_into().ok()?;
    if key.iter().all(|&b| b == 0) {
        None
    } else {
        Some(key)
    }
}

/// Overwrites the single key slot in a client binary image with `public_key`.
/// Fails if the marker is absent or appears more than once.
pub fn patch(binary: &mut [u8], public_key: &[u8; KEY_LEN]) -> Result<(), String> {
    let mut positions = binary
        .windows(MARKER.len())
        .enumerate()
        .filter(|(_, window)| *window == MARKER)
        .map(|(i, _)| i);

    let first = positions
        .next()
        .ok_or("key marker not found in the client template")?;
    if positions.next().is_some() {
        return Err("key marker found more than once; the template is ambiguous".to_string());
    }

    let key_start = first + MARKER.len();
    binary[key_start..key_start + KEY_LEN].copy_from_slice(public_key);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprovisioned_slot_reads_as_none() {
        assert!(read_embedded(&initial_slot()).is_none());
    }

    #[test]
    fn patch_then_read_round_trips() {
        // Simulate a binary: junk, the slot, more junk.
        let mut binary = Vec::new();
        binary.extend_from_slice(b"....prefix....");
        binary.extend_from_slice(&initial_slot());
        binary.extend_from_slice(b"....suffix....");

        let key = [7u8; KEY_LEN];
        patch(&mut binary, &key).unwrap();

        // Extract the slot back out and read the key.
        let start = 14; // len of prefix
        let slot: [u8; SLOT_LEN] = binary[start..start + SLOT_LEN].try_into().unwrap();
        assert_eq!(read_embedded(&slot), Some(key));
    }

    #[test]
    fn patch_without_marker_fails() {
        let mut binary = vec![0u8; 200];
        assert!(patch(&mut binary, &[1u8; KEY_LEN]).is_err());
    }

    #[test]
    fn patch_with_two_markers_is_ambiguous() {
        let mut binary = Vec::new();
        binary.extend_from_slice(&initial_slot());
        binary.extend_from_slice(&initial_slot());
        assert!(patch(&mut binary, &[1u8; KEY_LEN]).is_err());
    }
}

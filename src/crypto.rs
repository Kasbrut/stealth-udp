//! Sealed-box encryption for the one-way channel.
//!
//! A sender encrypts to the recipient's X25519 public key without any
//! handshake: for every message it generates an ephemeral key pair, performs
//! ECDH against the recipient's public key, derives a symmetric key with HKDF
//! and encrypts with XChaCha20-Poly1305 (an AEAD, so tampering is detected).
//! The ephemeral public key travels with the message, so only the recipient's
//! private key can derive the same secret and decrypt. Per-message ephemeral
//! keys give forward secrecy.
//!
//! Wire format of a sealed message:
//! ```text
//!   [recipient_id 4][ephemeral_public 32][nonce 24][ciphertext + tag]
//! ```
//! `recipient_id` lets a server holding several private keys pick the right one
//! in O(1) before attempting to decrypt.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

/// Length in bytes of an X25519 public or private key.
pub const KEY_LEN: usize = 32;

const ID_LEN: usize = 4;
const EPUB_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = ID_LEN + EPUB_LEN + NONCE_LEN;

/// HKDF context string, binding derived keys to this protocol and version.
const HKDF_INFO: &[u8] = b"stealth-udp sealed box v1";

/// An X25519 key pair.
pub struct Keypair {
    pub private: [u8; KEY_LEN],
    pub public: [u8; KEY_LEN],
}

/// Generates a fresh random key pair.
pub fn generate_keypair() -> Keypair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    Keypair {
        private: secret.to_bytes(),
        public: public.to_bytes(),
    }
}

/// Derives the public key corresponding to a private key.
pub fn public_from_private(private: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

/// A short, non-secret identifier for a public key, used to route a sealed
/// message to the matching private key.
pub fn key_id(public: &[u8; KEY_LEN]) -> [u8; ID_LEN] {
    let digest = Sha256::digest(public);
    digest[..ID_LEN].try_into().unwrap()
}

/// Encrypts `plaintext` to `recipient_public`, producing a sealed message.
pub fn seal(plaintext: &[u8], recipient_public: &[u8; KEY_LEN]) -> Vec<u8> {
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*recipient_public));
    let key = derive_key(shared.as_bytes(), &ephemeral_public);

    let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .expect("encryption cannot fail for a valid key/nonce");

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&key_id(recipient_public));
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypts a sealed message with `recipient_private`, or returns `None` if it
/// is not addressed to this key, is malformed, or fails authentication.
pub fn open(sealed: &[u8], recipient_private: &[u8; KEY_LEN]) -> Option<Vec<u8>> {
    if sealed.len() < HEADER_LEN {
        return None;
    }
    let our_public = public_from_private(recipient_private);
    if sealed[..ID_LEN] != key_id(&our_public) {
        return None; // not addressed to us
    }

    let ephemeral_public: [u8; EPUB_LEN] = sealed[ID_LEN..ID_LEN + EPUB_LEN].try_into().ok()?;
    let nonce = &sealed[ID_LEN + EPUB_LEN..HEADER_LEN];
    let ciphertext = &sealed[HEADER_LEN..];

    let shared =
        StaticSecret::from(*recipient_private).diffie_hellman(&PublicKey::from(ephemeral_public));
    let key = derive_key(shared.as_bytes(), &ephemeral_public);

    let cipher = XChaCha20Poly1305::new_from_slice(&key).ok()?;
    cipher.decrypt(XNonce::from_slice(nonce), ciphertext).ok()
}

/// The recipient key id carried by a sealed message, for keyring routing.
pub fn recipient_id(sealed: &[u8]) -> Option<[u8; ID_LEN]> {
    sealed.get(..ID_LEN).map(|s| s.try_into().unwrap())
}

/// Serializes a key as a lowercase hex string.
pub fn to_hex(key: &[u8; KEY_LEN]) -> String {
    hex::encode(key)
}

/// Parses a 32-byte key from a hex string (whitespace trimmed).
pub fn from_hex(text: &str) -> Option<[u8; KEY_LEN]> {
    let bytes = hex::decode(text.trim()).ok()?;
    bytes.try_into().ok()
}

fn derive_key(shared_secret: &[u8], ephemeral_public: &[u8; EPUB_LEN]) -> [u8; 32] {
    // Salt with the ephemeral public key so the derived key is unique even if
    // the same shared secret were ever reused.
    let hkdf = Hkdf::<Sha256>::new(Some(ephemeral_public), shared_secret);
    let mut key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trips() {
        let kp = generate_keypair();
        let sealed = seal(b"secret message", &kp.public);
        assert_eq!(open(&sealed, &kp.private).unwrap(), b"secret message");
    }

    #[test]
    fn wrong_private_key_cannot_open() {
        let recipient = generate_keypair();
        let attacker = generate_keypair();
        let sealed = seal(b"secret", &recipient.public);
        assert!(open(&sealed, &attacker.private).is_none());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let kp = generate_keypair();
        let mut sealed = seal(b"secret", &kp.public);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&sealed, &kp.private).is_none());
    }

    #[test]
    fn two_seals_differ_thanks_to_ephemeral_keys() {
        let kp = generate_keypair();
        let a = seal(b"same", &kp.public);
        let b = seal(b"same", &kp.public);
        assert_ne!(a, b);
        assert_eq!(open(&a, &kp.private).unwrap(), b"same");
        assert_eq!(open(&b, &kp.private).unwrap(), b"same");
    }

    #[test]
    fn recipient_id_matches_the_key() {
        let kp = generate_keypair();
        let sealed = seal(b"x", &kp.public);
        assert_eq!(recipient_id(&sealed).unwrap(), key_id(&kp.public));
    }

    #[test]
    fn public_from_private_is_consistent() {
        let kp = generate_keypair();
        assert_eq!(public_from_private(&kp.private), kp.public);
    }

    #[test]
    fn hex_round_trips() {
        let kp = generate_keypair();
        assert_eq!(from_hex(&to_hex(&kp.private)).unwrap(), kp.private);
        assert!(from_hex("not hex").is_none());
        assert!(from_hex("ab").is_none()); // wrong length
    }

    #[test]
    fn garbage_does_not_open() {
        let kp = generate_keypair();
        assert!(open(b"too short", &kp.private).is_none());
        assert!(open(&[0u8; 100], &kp.private).is_none());
    }
}

//! End-to-end test: a client seals chunked file-transfer packets to the
//! server's public key; the DecryptingSink decrypts them and the
//! FileReassemblySink rebuilds the original file. Exercises the crypto and
//! reassembly paths together without any networking.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use sha2::{Digest, Sha256};
use stealth_udp::crypto;
use stealth_udp::parser::UdpDatagram;
use stealth_udp::protocol::{encode_data, encode_meta, Fec, MetaPacket};
use stealth_udp::reassembly::FileReassemblySink;
use stealth_udp::sink::{DatagramSink, DecryptingSink};

fn datagram(payload: Vec<u8>) -> UdpDatagram {
    UdpDatagram {
        source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)),
        payload,
    }
}

fn meta(transfer_id: u32, data: &[u8], chunk_size: u32, filename: &str) -> MetaPacket {
    MetaPacket {
        transfer_id,
        file_size: data.len() as u64,
        chunk_size,
        flags: 0,
        fec: Fec::None,
        original_size: data.len() as u64,
        hash: Sha256::digest(data).into(),
        filename: filename.to_string(),
    }
}

#[test]
fn sealed_chunks_are_decrypted_and_reassembled() {
    let dir = tempfile::tempdir().unwrap();
    let logs_dir = dir.path().to_str().unwrap().to_string();

    let server = crypto::generate_keypair();

    let inner = Box::new(FileReassemblySink::new(logs_dir.clone(), Duration::ZERO));
    let mut sink = DecryptingSink::new(vec![server.private], inner);

    let meta = meta(99, b"ABCDEFGHIJ", 4, "secret.bin");

    // The client seals every packet to the server's public key. Send chunks
    // out of order to also exercise reassembly.
    let seal = |bytes: Vec<u8>| datagram(crypto::seal(&bytes, &server.public));
    sink.handle(&seal(encode_meta(&meta))).unwrap();
    sink.handle(&seal(encode_data(99, 2, b"IJ"))).unwrap();
    sink.handle(&seal(encode_data(99, 0, b"ABCD"))).unwrap();
    sink.handle(&seal(encode_data(99, 1, b"EFGH"))).unwrap();

    let path = std::path::Path::new(&logs_dir)
        .join("10_0_0_42")
        .join("secret.bin");
    assert_eq!(std::fs::read(path).unwrap(), b"ABCDEFGHIJ");
}

#[test]
fn packets_for_an_unknown_key_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let logs_dir = dir.path().to_str().unwrap().to_string();

    let server = crypto::generate_keypair();
    let stranger = crypto::generate_keypair();

    let inner = Box::new(FileReassemblySink::new(logs_dir.clone(), Duration::ZERO));
    let mut sink = DecryptingSink::new(vec![server.private], inner);

    let meta = meta(1, b"ABCD", 4, "nope.bin");
    // Sealed to a key the server does not hold: must be ignored.
    sink.handle(&datagram(crypto::seal(
        &encode_meta(&meta),
        &stranger.public,
    )))
    .unwrap();
    sink.handle(&datagram(crypto::seal(
        &encode_data(1, 0, b"ABCD"),
        &stranger.public,
    )))
    .unwrap();

    assert!(!std::path::Path::new(&logs_dir).join("10_0_0_42").exists());
}

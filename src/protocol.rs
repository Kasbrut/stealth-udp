//! The file-transfer wire protocol carried inside UDP payloads.
//!
//! Because the capture channel is one-way (no acknowledgements are ever sent
//! back), the protocol is designed to tolerate reordering, duplication and
//! loss: a client announces a transfer with a META packet and then sends
//! independently-numbered DATA packets. The server places each chunk at its
//! offset, so chunks may arrive in any order.
//!
//! Wire format (all integers big-endian). Common 8-byte header:
//!
//! ```text
//!   0: magic "SU" (2)   2: version (1)   3: type (1)   4: transfer_id (4)
//! ```
//!
//! META body (type 0): file_size (8), chunk_size (4), name_len (2), filename.
//! DATA body (type 1): seq (4), then the chunk bytes.

/// Protocol magic, identifying our packets among unrelated UDP traffic.
pub const MAGIC: [u8; 2] = *b"SU";
/// Protocol version.
pub const VERSION: u8 = 1;

const TYPE_META: u8 = 0;
const TYPE_DATA: u8 = 1;

const HEADER_LEN: usize = 8;
const META_FIXED_LEN: usize = HEADER_LEN + 8 + 4 + 2;
const DATA_FIXED_LEN: usize = HEADER_LEN + 4;

/// A transfer announcement: which file the following DATA packets rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaPacket {
    pub transfer_id: u32,
    pub file_size: u64,
    pub chunk_size: u32,
    pub filename: String,
}

/// A single numbered chunk of a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    pub transfer_id: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// A parsed protocol packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Meta(MetaPacket),
    Data(DataPacket),
}

/// Why a payload is not a valid protocol packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Fewer bytes than the packet type requires.
    TooShort,
    /// Missing or wrong magic (not one of our packets).
    BadMagic,
    /// A version this build does not understand.
    UnsupportedVersion(u8),
    /// A packet type this build does not understand.
    UnknownType(u8),
    /// A declared length that does not fit the buffer, or a zero chunk size.
    BadLength,
}

/// Parses a UDP payload into a protocol [`Packet`].
pub fn parse(payload: &[u8]) -> Result<Packet, ProtocolError> {
    if payload.len() < HEADER_LEN {
        return Err(ProtocolError::TooShort);
    }
    if payload[0..2] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    let version = payload[2];
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let transfer_id = read_u32(&payload[4..8]);

    match payload[3] {
        TYPE_META => parse_meta(payload, transfer_id),
        TYPE_DATA => parse_data(payload, transfer_id),
        other => Err(ProtocolError::UnknownType(other)),
    }
}

fn parse_meta(payload: &[u8], transfer_id: u32) -> Result<Packet, ProtocolError> {
    if payload.len() < META_FIXED_LEN {
        return Err(ProtocolError::TooShort);
    }
    let file_size = read_u64(&payload[8..16]);
    let chunk_size = read_u32(&payload[16..20]);
    let name_len = read_u16(&payload[20..22]) as usize;

    if chunk_size == 0 {
        return Err(ProtocolError::BadLength);
    }
    if payload.len() < META_FIXED_LEN + name_len {
        return Err(ProtocolError::BadLength);
    }

    let filename =
        String::from_utf8_lossy(&payload[META_FIXED_LEN..META_FIXED_LEN + name_len]).into_owned();

    Ok(Packet::Meta(MetaPacket {
        transfer_id,
        file_size,
        chunk_size,
        filename,
    }))
}

fn parse_data(payload: &[u8], transfer_id: u32) -> Result<Packet, ProtocolError> {
    if payload.len() < DATA_FIXED_LEN {
        return Err(ProtocolError::TooShort);
    }
    let seq = read_u32(&payload[8..12]);
    Ok(Packet::Data(DataPacket {
        transfer_id,
        seq,
        payload: payload[DATA_FIXED_LEN..].to_vec(),
    }))
}

/// Serializes a META packet.
pub fn encode_meta(meta: &MetaPacket) -> Vec<u8> {
    let name = meta.filename.as_bytes();
    let mut buf = Vec::with_capacity(META_FIXED_LEN + name.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(TYPE_META);
    buf.extend_from_slice(&meta.transfer_id.to_be_bytes());
    buf.extend_from_slice(&meta.file_size.to_be_bytes());
    buf.extend_from_slice(&meta.chunk_size.to_be_bytes());
    buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
    buf.extend_from_slice(name);
    buf
}

/// Serializes a DATA packet for `chunk` at index `seq`.
pub fn encode_data(transfer_id: u32, seq: u32, chunk: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(DATA_FIXED_LEN + chunk.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(TYPE_DATA);
    buf.extend_from_slice(&transfer_id.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(chunk);
    buf
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().unwrap())
}
fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().unwrap())
}
fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_round_trips() {
        let meta = MetaPacket {
            transfer_id: 0xDEADBEEF,
            file_size: 1_000_000,
            chunk_size: 1400,
            filename: "report.pdf".to_string(),
        };
        let bytes = encode_meta(&meta);
        assert_eq!(parse(&bytes).unwrap(), Packet::Meta(meta));
    }

    #[test]
    fn data_round_trips() {
        let bytes = encode_data(7, 42, b"chunk-bytes");
        let expected = Packet::Data(DataPacket {
            transfer_id: 7,
            seq: 42,
            payload: b"chunk-bytes".to_vec(),
        });
        assert_eq!(parse(&bytes).unwrap(), expected);
    }

    #[test]
    fn empty_chunk_is_valid_data() {
        let bytes = encode_data(1, 0, b"");
        match parse(&bytes).unwrap() {
            Packet::Data(d) => assert!(d.payload.is_empty()),
            _ => panic!("expected DATA"),
        }
    }

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(
            parse(b"XXideotheader").unwrap_err(),
            ProtocolError::BadMagic
        );
    }

    #[test]
    fn rejects_short_payload() {
        assert_eq!(parse(b"SU").unwrap_err(), ProtocolError::TooShort);
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut bytes = encode_data(1, 0, b"x");
        bytes[2] = 99;
        assert_eq!(
            parse(&bytes).unwrap_err(),
            ProtocolError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn rejects_unknown_type() {
        let mut bytes = encode_data(1, 0, b"x");
        bytes[3] = 200;
        assert_eq!(parse(&bytes).unwrap_err(), ProtocolError::UnknownType(200));
    }

    #[test]
    fn rejects_meta_with_truncated_name() {
        let mut bytes = encode_meta(&MetaPacket {
            transfer_id: 1,
            file_size: 10,
            chunk_size: 4,
            filename: "abcdefgh".to_string(),
        });
        bytes.truncate(META_FIXED_LEN + 2); // claims 8-byte name, only 2 present
        assert_eq!(parse(&bytes).unwrap_err(), ProtocolError::BadLength);
    }

    #[test]
    fn rejects_zero_chunk_size() {
        let bytes = encode_meta(&MetaPacket {
            transfer_id: 1,
            file_size: 10,
            chunk_size: 0,
            filename: "x".to_string(),
        });
        assert_eq!(parse(&bytes).unwrap_err(), ProtocolError::BadLength);
    }
}

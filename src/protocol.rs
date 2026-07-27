//! The file-transfer wire protocol carried inside UDP payloads (version 2).
//!
//! Because the capture channel is one-way (no acknowledgements are ever sent
//! back), the protocol is designed to tolerate reordering, duplication and
//! loss: a client announces a transfer with a META packet and then sends
//! independently-numbered DATA packets. The server places each chunk at its
//! offset, so chunks may arrive in any order. Optional PARITY packets carry XOR
//! forward-error-correction so a single lost chunk per group can be rebuilt.
//!
//! Wire format (all integers big-endian). Common 8-byte header:
//!
//! ```text
//!   0: magic "SU" (2)   2: version (1)   3: type (1)   4: transfer_id (4)
//! ```
//!
//! META body (type 0): file_size (8), chunk_size (4), flags (1),
//!   fec_group (2), original_size (8), hash (32), name_len (2), filename.
//! DATA body (type 1): seq (4), then the chunk bytes.
//! PARITY body (type 2): group (4), then the XOR parity bytes.

/// Protocol magic, identifying our packets among unrelated UDP traffic.
pub const MAGIC: [u8; 2] = *b"SU";
/// Protocol version.
pub const VERSION: u8 = 2;

/// META flag: the transferred stream is DEFLATE-compressed.
pub const FLAG_COMPRESSED: u8 = 0x01;

const TYPE_META: u8 = 0;
const TYPE_DATA: u8 = 1;
const TYPE_PARITY: u8 = 2;

const HEADER_LEN: usize = 8;
const META_FIXED_LEN: usize = HEADER_LEN + 8 + 4 + 1 + 2 + 8 + 32 + 2;
const DATA_FIXED_LEN: usize = HEADER_LEN + 4;
const PARITY_FIXED_LEN: usize = HEADER_LEN + 4;

/// Length in bytes of the integrity hash (SHA-256).
pub const HASH_LEN: usize = 32;

/// A transfer announcement: which file the following DATA packets rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaPacket {
    pub transfer_id: u32,
    /// Size of the transferred stream (the compressed size when compressed).
    pub file_size: u64,
    pub chunk_size: u32,
    pub flags: u8,
    /// Emit one parity packet per this many data chunks; 0 disables FEC.
    pub fec_group: u16,
    /// Size of the original (pre-compression) file.
    pub original_size: u64,
    /// SHA-256 of the original file; all-zero means "no integrity check".
    pub hash: [u8; HASH_LEN],
    pub filename: String,
}

impl MetaPacket {
    /// Whether the transferred stream is compressed.
    pub fn is_compressed(&self) -> bool {
        self.flags & FLAG_COMPRESSED != 0
    }
    /// Whether an integrity hash is present.
    pub fn has_hash(&self) -> bool {
        self.hash != [0u8; HASH_LEN]
    }
}

/// A single numbered chunk of a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacket {
    pub transfer_id: u32,
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// XOR parity over the data chunks of one FEC group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityPacket {
    pub transfer_id: u32,
    pub group: u32,
    pub parity: Vec<u8>,
}

/// A parsed protocol packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Meta(MetaPacket),
    Data(DataPacket),
    Parity(ParityPacket),
}

/// Why a payload is not a valid protocol packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    TooShort,
    BadMagic,
    UnsupportedVersion(u8),
    UnknownType(u8),
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
        TYPE_PARITY => parse_parity(payload, transfer_id),
        other => Err(ProtocolError::UnknownType(other)),
    }
}

fn parse_meta(payload: &[u8], transfer_id: u32) -> Result<Packet, ProtocolError> {
    if payload.len() < META_FIXED_LEN {
        return Err(ProtocolError::TooShort);
    }
    let file_size = read_u64(&payload[8..16]);
    let chunk_size = read_u32(&payload[16..20]);
    let flags = payload[20];
    let fec_group = read_u16(&payload[21..23]);
    let original_size = read_u64(&payload[23..31]);
    let hash: [u8; HASH_LEN] = payload[31..63].try_into().unwrap();
    let name_len = read_u16(&payload[63..65]) as usize;

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
        flags,
        fec_group,
        original_size,
        hash,
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

fn parse_parity(payload: &[u8], transfer_id: u32) -> Result<Packet, ProtocolError> {
    if payload.len() < PARITY_FIXED_LEN {
        return Err(ProtocolError::TooShort);
    }
    let group = read_u32(&payload[8..12]);
    Ok(Packet::Parity(ParityPacket {
        transfer_id,
        group,
        parity: payload[PARITY_FIXED_LEN..].to_vec(),
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
    buf.push(meta.flags);
    buf.extend_from_slice(&meta.fec_group.to_be_bytes());
    buf.extend_from_slice(&meta.original_size.to_be_bytes());
    buf.extend_from_slice(&meta.hash);
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

/// Serializes a PARITY packet for FEC `group`.
pub fn encode_parity(transfer_id: u32, group: u32, parity: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PARITY_FIXED_LEN + parity.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(TYPE_PARITY);
    buf.extend_from_slice(&transfer_id.to_be_bytes());
    buf.extend_from_slice(&group.to_be_bytes());
    buf.extend_from_slice(parity);
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

    fn sample_meta() -> MetaPacket {
        MetaPacket {
            transfer_id: 0xDEADBEEF,
            file_size: 1_000_000,
            chunk_size: 1400,
            flags: FLAG_COMPRESSED,
            fec_group: 8,
            original_size: 2_000_000,
            hash: [9u8; HASH_LEN],
            filename: "report.pdf".to_string(),
        }
    }

    #[test]
    fn meta_round_trips() {
        let meta = sample_meta();
        assert_eq!(parse(&encode_meta(&meta)).unwrap(), Packet::Meta(meta));
    }

    #[test]
    fn meta_flags_and_hash_helpers() {
        let meta = sample_meta();
        assert!(meta.is_compressed());
        assert!(meta.has_hash());

        let plain = MetaPacket {
            flags: 0,
            hash: [0u8; HASH_LEN],
            ..sample_meta()
        };
        assert!(!plain.is_compressed());
        assert!(!plain.has_hash());
    }

    #[test]
    fn data_round_trips() {
        let bytes = encode_data(7, 42, b"chunk-bytes");
        assert_eq!(
            parse(&bytes).unwrap(),
            Packet::Data(DataPacket {
                transfer_id: 7,
                seq: 42,
                payload: b"chunk-bytes".to_vec(),
            })
        );
    }

    #[test]
    fn parity_round_trips() {
        let bytes = encode_parity(7, 3, b"parity");
        assert_eq!(
            parse(&bytes).unwrap(),
            Packet::Parity(ParityPacket {
                transfer_id: 7,
                group: 3,
                parity: b"parity".to_vec(),
            })
        );
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
        let mut bytes = encode_meta(&sample_meta());
        bytes.truncate(META_FIXED_LEN + 2); // claims a longer name than present
        assert_eq!(parse(&bytes).unwrap_err(), ProtocolError::BadLength);
    }

    #[test]
    fn rejects_zero_chunk_size() {
        let bytes = encode_meta(&MetaPacket {
            chunk_size: 0,
            ..sample_meta()
        });
        assert_eq!(parse(&bytes).unwrap_err(), ProtocolError::BadLength);
    }
}

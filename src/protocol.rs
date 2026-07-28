//! The file-transfer wire protocol carried inside UDP payloads (version 3).
//!
//! Because the capture channel is one-way (no acknowledgements are ever sent
//! back), the protocol tolerates reordering, duplication and loss: a client
//! announces a transfer with a META packet and then sends independently
//! numbered DATA packets. The server places each chunk at its offset, so chunks
//! may arrive in any order. Optional PARITY packets carry forward error
//! correction — either XOR (one parity per group, recovers one loss per group)
//! or Reed-Solomon (M parity per K data chunks, recovers up to M losses).
//!
//! Wire format (all integers big-endian). Common 8-byte header:
//!
//! ```text
//!   0: magic "SU" (2)   2: version (1)   3: type (1)   4: transfer_id (4)
//! ```
//!
//! META body (type 0): file_size (8), chunk_size (4), flags (1),
//!   fec_mode (1), fec_a (2), fec_b (2), original_size (8), hash (32),
//!   name_len (2), filename.
//! DATA body (type 1): seq (4), then the chunk bytes.
//! PARITY body (type 2): group (4), index (2), then the parity bytes.

/// Protocol magic, identifying our packets among unrelated UDP traffic.
pub const MAGIC: [u8; 2] = *b"SU";
/// Protocol version.
pub const VERSION: u8 = 3;

/// META flag: the transferred stream is DEFLATE-compressed.
pub const FLAG_COMPRESSED: u8 = 0x01;

const TYPE_META: u8 = 0;
const TYPE_DATA: u8 = 1;
const TYPE_PARITY: u8 = 2;

const FEC_NONE: u8 = 0;
const FEC_XOR: u8 = 1;
const FEC_RS: u8 = 2;

const HEADER_LEN: usize = 8;
const META_FIXED_LEN: usize = HEADER_LEN + 8 + 4 + 1 + 1 + 2 + 2 + 8 + 32 + 2;
const DATA_FIXED_LEN: usize = HEADER_LEN + 4;
const PARITY_FIXED_LEN: usize = HEADER_LEN + 4 + 2;

/// Length in bytes of the integrity hash (SHA-256).
pub const HASH_LEN: usize = 32;

/// Forward-error-correction scheme announced by a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fec {
    /// No FEC.
    None,
    /// One XOR parity packet per `group` data chunks (recovers one loss/group).
    Xor { group: u16 },
    /// `parity` Reed-Solomon parity chunks per `data` chunks (recovers up to
    /// `parity` losses per block).
    ReedSolomon { data: u16, parity: u16 },
}

impl Fec {
    fn to_wire(self) -> (u8, u16, u16) {
        match self {
            Fec::None => (FEC_NONE, 0, 0),
            Fec::Xor { group } => (FEC_XOR, group, 0),
            Fec::ReedSolomon { data, parity } => (FEC_RS, data, parity),
        }
    }

    /// Decodes the wire form, normalising nonsensical parameters to `None`.
    fn from_wire(mode: u8, a: u16, b: u16) -> Fec {
        match mode {
            FEC_XOR if a >= 1 => Fec::Xor { group: a },
            FEC_RS if a >= 1 && b >= 1 => Fec::ReedSolomon { data: a, parity: b },
            _ => Fec::None,
        }
    }
}

/// A transfer announcement: which file the following DATA packets rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetaPacket {
    pub transfer_id: u32,
    /// Size of the transferred stream (the compressed size when compressed).
    pub file_size: u64,
    pub chunk_size: u32,
    pub flags: u8,
    pub fec: Fec,
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

/// A parity chunk for one FEC group/block. `index` is 0 for XOR and the parity
/// shard index for Reed-Solomon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParityPacket {
    pub transfer_id: u32,
    pub group: u32,
    pub index: u16,
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
    let fec = Fec::from_wire(
        payload[21],
        read_u16(&payload[22..24]),
        read_u16(&payload[24..26]),
    );
    let original_size = read_u64(&payload[26..34]);
    let hash: [u8; HASH_LEN] = payload[34..66].try_into().unwrap();
    let name_len = read_u16(&payload[66..68]) as usize;

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
        fec,
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
    let index = read_u16(&payload[12..14]);
    Ok(Packet::Parity(ParityPacket {
        transfer_id,
        group,
        index,
        parity: payload[PARITY_FIXED_LEN..].to_vec(),
    }))
}

/// Serializes a META packet.
pub fn encode_meta(meta: &MetaPacket) -> Vec<u8> {
    let name = meta.filename.as_bytes();
    let (mode, a, b) = meta.fec.to_wire();
    let mut buf = Vec::with_capacity(META_FIXED_LEN + name.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(TYPE_META);
    buf.extend_from_slice(&meta.transfer_id.to_be_bytes());
    buf.extend_from_slice(&meta.file_size.to_be_bytes());
    buf.extend_from_slice(&meta.chunk_size.to_be_bytes());
    buf.push(meta.flags);
    buf.push(mode);
    buf.extend_from_slice(&a.to_be_bytes());
    buf.extend_from_slice(&b.to_be_bytes());
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

/// Serializes a PARITY packet for FEC `group`, parity shard `index`.
pub fn encode_parity(transfer_id: u32, group: u32, index: u16, parity: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PARITY_FIXED_LEN + parity.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(TYPE_PARITY);
    buf.extend_from_slice(&transfer_id.to_be_bytes());
    buf.extend_from_slice(&group.to_be_bytes());
    buf.extend_from_slice(&index.to_be_bytes());
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

    fn sample_meta(fec: Fec) -> MetaPacket {
        MetaPacket {
            transfer_id: 0xDEADBEEF,
            file_size: 1_000_000,
            chunk_size: 1400,
            flags: FLAG_COMPRESSED,
            fec,
            original_size: 2_000_000,
            hash: [9u8; HASH_LEN],
            filename: "report.pdf".to_string(),
        }
    }

    #[test]
    fn meta_round_trips_for_each_fec() {
        for fec in [
            Fec::None,
            Fec::Xor { group: 8 },
            Fec::ReedSolomon {
                data: 10,
                parity: 3,
            },
        ] {
            let meta = sample_meta(fec);
            assert_eq!(parse(&encode_meta(&meta)).unwrap(), Packet::Meta(meta));
        }
    }

    #[test]
    fn invalid_fec_params_normalise_to_none() {
        let meta = MetaPacket {
            fec: Fec::Xor { group: 0 },
            ..sample_meta(Fec::None)
        };
        if let Packet::Meta(parsed) = parse(&encode_meta(&meta)).unwrap() {
            assert_eq!(parsed.fec, Fec::None);
        } else {
            panic!("expected META");
        }
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
        let bytes = encode_parity(7, 3, 1, b"parity");
        assert_eq!(
            parse(&bytes).unwrap(),
            Packet::Parity(ParityPacket {
                transfer_id: 7,
                group: 3,
                index: 1,
                parity: b"parity".to_vec(),
            })
        );
    }

    #[test]
    fn rejects_bad_magic() {
        assert_eq!(
            parse(b"XXideoheader!").unwrap_err(),
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
    fn rejects_zero_chunk_size() {
        let bytes = encode_meta(&MetaPacket {
            chunk_size: 0,
            ..sample_meta(Fec::None)
        });
        assert_eq!(parse(&bytes).unwrap_err(), ProtocolError::BadLength);
    }
}

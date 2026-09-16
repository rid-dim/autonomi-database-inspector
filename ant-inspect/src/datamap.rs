//! Parsing and analysis of self-encryption DataMaps.
//!
//! A DataMap is the retrieval metadata self-encryption produces for a file:
//! one `ChunkInfo` per chunk with the chunk's network address (`dst_hash`,
//! the BLAKE3 hash of the *encrypted* chunk), the hash of the plaintext
//! chunk (`src_hash`) and the plaintext size (`src_size`). Large files get a
//! *shrunk* DataMap: the serialized root DataMap is itself self-encrypted and
//! the resulting (small) DataMap carries `child = Some(level)`.
//!
//! Wire formats that occur in the wild:
//!
//! - **MessagePack, current** — what the autonomi client stores on the network
//!   as a public DataMap chunk and writes to `.datamap` files
//!   (`rmp_serde::to_vec(&DataMap)`): the array `[version = 1,
//!   chunk_identifiers, child]`. `self_encryption` 0.36 prepends the version
//!   byte in its `Serialize` impl for binary formats.
//! - **MessagePack, legacy** — the old autonomi client wrapped the pre-0.34
//!   DataMap in a `DataMapLevel::{First, Additional}` enum, which serializes as
//!   the map `{"First": [chunk_infos]}`.
//! - **bincode** — `DataMap::to_bytes()`; used *inside* the shrinking
//!   process (the bytes that get encrypted into a child level) and by some
//!   tooling. Fixed-width little-endian integers.
//! - **JSON** — legacy `ant-gui` `.datamap` files; the struct
//!   `{"chunk_identifiers": [...], "child": ...}` with hashes as 32-int arrays.
//!
//! Every parse is followed by a plausibility check (non-empty, contiguous
//! indices, sane sizes, whole input consumed), so random or self-encrypted
//! bytes essentially never pass as a DataMap.

use self_encryption::{ChunkInfo, DataMap};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use xor_name::XorName;

/// Upper bound accepted for a chunk's plaintext size. The protocol caps a
/// chunk at 4 MiB (ant-protocol `MAX_CHUNK_SIZE`); self-encryption itself uses
/// 4 MiB − 4 KiB to leave room for compression growth. Older clients used the
/// full 4 MiB, so the looser bound is the right one for validation.
pub const MAX_SRC_SIZE: usize = 4 * 1024 * 1024;

/// Deepest shrink level we accept. `get_root_data_map` in self_encryption
/// refuses to recurse deeper than 100 levels; a real file never needs more
/// than a handful.
pub const MAX_CHILD_LEVEL: usize = 100;

/// Largest input we try to parse as a DataMap. A root DataMap for a file at
/// the 4 MiB chunk limit with ~1,200 chunks is ~150 KiB serialized; anything
/// larger gets shrunk by the client. A generous cap keeps the parse attempts
/// off multi-megabyte data chunks.
pub const MAX_PARSE_LEN: usize = 1024 * 1024;

/// How the bytes were encoded.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum WireFormat {
    /// `rmp_serde` array `[1, chunk_identifiers, child]` (current network format).
    MsgpackV1,
    /// `rmp_serde` map `{"First"|"Additional": [chunk_infos]}` (legacy client).
    MsgpackLegacy,
    /// `bincode` fixint encoding with leading version byte (`DataMap::to_bytes`).
    Bincode,
    /// JSON struct (legacy `ant-gui` `.datamap` files).
    Json,
}

impl WireFormat {
    pub fn label(self) -> &'static str {
        match self {
            WireFormat::MsgpackV1 => "msgpack (current network format, version 1)",
            WireFormat::MsgpackLegacy => "msgpack (legacy DataMapLevel wrapper)",
            WireFormat::Bincode => "bincode (DataMap::to_bytes, version 1)",
            WireFormat::Json => "json (legacy ant-gui .datamap)",
        }
    }
}

/// A successfully parsed and validated DataMap.
#[derive(Clone, Debug)]
pub struct ParsedDataMap {
    pub format: WireFormat,
    pub data_map: DataMap,
    /// Length of the serialized input in bytes.
    pub serialized_len: usize,
}

/// Per-chunk row for reports.
#[derive(Serialize, Clone)]
pub struct ChunkRow {
    pub index: usize,
    /// Network address of the encrypted chunk (BLAKE3 of its content).
    pub address: String,
    /// BLAKE3 of the plaintext chunk.
    pub src_hash: String,
    /// Plaintext size in bytes.
    pub src_size: usize,
}

/// Aggregate statistics over a DataMap.
#[derive(Serialize, Clone)]
pub struct DataMapStats {
    pub chunk_count: usize,
    /// Sum of `src_size`: the plaintext size this DataMap describes. For a
    /// root DataMap that is the file size; for a shrunk (child) DataMap it is
    /// the size of the serialized parent DataMap.
    pub content_bytes: u64,
    pub min_src_size: usize,
    pub max_src_size: usize,
    pub mean_src_size: u64,
    /// Number of distinct chunk addresses (duplicates are possible for
    /// repeated plaintext).
    pub distinct_addresses: usize,
}

impl ParsedDataMap {
    pub fn infos(&self) -> &[ChunkInfo] {
        self.data_map.infos()
    }

    pub fn child(&self) -> Option<usize> {
        self.data_map.child()
    }

    pub fn is_child(&self) -> bool {
        self.data_map.is_child()
    }

    pub fn rows(&self) -> Vec<ChunkRow> {
        self.infos()
            .iter()
            .map(|c| ChunkRow {
                index: c.index,
                address: hex::encode(c.dst_hash),
                src_hash: hex::encode(c.src_hash),
                src_size: c.src_size,
            })
            .collect()
    }

    pub fn stats(&self) -> DataMapStats {
        let infos = self.infos();
        let sizes: Vec<usize> = infos.iter().map(|c| c.src_size).collect();
        let total: u64 = sizes.iter().map(|&s| s as u64).sum();
        let mut addrs: Vec<XorName> = infos.iter().map(|c| c.dst_hash).collect();
        addrs.sort_unstable();
        addrs.dedup();
        DataMapStats {
            chunk_count: infos.len(),
            content_bytes: total,
            min_src_size: sizes.iter().copied().min().unwrap_or(0),
            max_src_size: sizes.iter().copied().max().unwrap_or(0),
            mean_src_size: if sizes.is_empty() { 0 } else { total / sizes.len() as u64 },
            distinct_addresses: addrs.len(),
        }
    }
}

/// Try every known wire format and return the first that parses *and* passes
/// the plausibility check.
pub fn parse(bytes: &[u8]) -> Option<ParsedDataMap> {
    if bytes.len() < 4 || bytes.len() > MAX_PARSE_LEN {
        return None;
    }
    let first = bytes[0];

    // JSON is unambiguous from the first byte.
    if first == b'{' {
        return parse_json(bytes);
    }

    // bincode starts with the version byte 0x01 followed by a u64 LE length;
    // a MessagePack array starts with 0x9x / 0xdc / 0xdd. 0x01 is a positive
    // fixint in MessagePack and can never start a valid DataMap there, so
    // there is no ambiguity.
    if first == 0x01 {
        return parse_bincode(bytes);
    }

    if let Some(p) = parse_msgpack_current(bytes) {
        return Some(p);
    }
    parse_msgpack_legacy(bytes)
}

/// Current network format: `rmp_serde` of `self_encryption::DataMap`
/// (`[version, chunk_identifiers, child]`). Uses the real crate's
/// `Deserialize` impl, which enforces `version == 1`.
fn parse_msgpack_current(bytes: &[u8]) -> Option<ParsedDataMap> {
    let mut de = rmp_serde::Deserializer::new(Cursor::new(bytes));
    let dm = DataMap::deserialize(&mut de).ok()?;
    let consumed = de.get_ref().position() as usize;
    if consumed != bytes.len() {
        return None;
    }
    plausible(&dm).then_some(ParsedDataMap {
        format: WireFormat::MsgpackV1,
        data_map: dm,
        serialized_len: bytes.len(),
    })
}

/// Mirror of the pre-0.34 `ChunkInfo` (identical field layout).
#[derive(Deserialize)]
struct LegacyChunkInfo {
    index: usize,
    dst_hash: XorName,
    src_hash: XorName,
    src_size: usize,
}

/// Mirror of the old autonomi client's `DataMapLevel` enum wrapping the old
/// `DataMap(Vec<ChunkInfo>)` newtype, which serializes as the bare list.
#[derive(Deserialize)]
enum LegacyDataMapLevel {
    First(Vec<LegacyChunkInfo>),
    Additional(Vec<LegacyChunkInfo>),
}

fn parse_msgpack_legacy(bytes: &[u8]) -> Option<ParsedDataMap> {
    let mut de = rmp_serde::Deserializer::new(Cursor::new(bytes));
    let level = LegacyDataMapLevel::deserialize(&mut de).ok()?;
    if de.get_ref().position() as usize != bytes.len() {
        return None;
    }
    let (infos, child) = match level {
        LegacyDataMapLevel::First(c) => (c, None),
        // The legacy client did not record the level; `Additional` only says
        // "not the root". Report it as level 1 so callers see `is_child()`.
        LegacyDataMapLevel::Additional(c) => (c, Some(1)),
    };
    let infos: Vec<ChunkInfo> = infos
        .into_iter()
        .map(|c| ChunkInfo {
            index: c.index,
            dst_hash: c.dst_hash,
            src_hash: c.src_hash,
            src_size: c.src_size,
        })
        .collect();
    let dm = match child {
        Some(level) => DataMap::with_child(infos, level),
        None => DataMap::new(infos),
    };
    plausible(&dm).then_some(ParsedDataMap {
        format: WireFormat::MsgpackLegacy,
        data_map: dm,
        serialized_len: bytes.len(),
    })
}

/// `DataMap::to_bytes()` output: bincode 1.x fixint encoding of
/// `VersionedDataMap { version: u8, chunk_identifiers: Vec<ChunkInfo>, child: Option<usize> }`.
///
/// The exact byte length is fully determined by the chunk count and the
/// `child` tag, so the check is exact rather than "parses somehow".
fn parse_bincode(bytes: &[u8]) -> Option<ParsedDataMap> {
    let dm = DataMap::from_bytes(bytes).ok()?;
    let n = dm.len();
    let expected = 1 + 8 + n * (8 + 32 + 32 + 8) + 1 + if dm.is_child() { 8 } else { 0 };
    if expected != bytes.len() {
        return None;
    }
    plausible(&dm).then_some(ParsedDataMap {
        format: WireFormat::Bincode,
        data_map: dm,
        serialized_len: bytes.len(),
    })
}

fn parse_json(bytes: &[u8]) -> Option<ParsedDataMap> {
    let dm: DataMap = serde_json::from_slice(bytes).ok()?;
    plausible(&dm).then_some(ParsedDataMap {
        format: WireFormat::Json,
        data_map: dm,
        serialized_len: bytes.len(),
    })
}

/// Structural sanity: non-empty, indices run `0..N` in order, every plaintext
/// size is within the chunk limit, and the shrink level (if any) is sane.
pub fn plausible(dm: &DataMap) -> bool {
    let infos = dm.infos();
    if infos.is_empty() {
        return false;
    }
    if let Some(level) = dm.child() {
        if level == 0 || level > MAX_CHILD_LEVEL {
            return false;
        }
    }
    infos
        .iter()
        .enumerate()
        .all(|(i, c)| c.index == i && c.src_size >= 1 && c.src_size <= MAX_SRC_SIZE)
}

/// Re-encode a DataMap in the current network format. Used to report the
/// address a DataMap would have as a public chunk (`BLAKE3` of these bytes),
/// which for a DataMap read from a `.datamap` file or resolved from a child
/// level is not otherwise known.
pub fn to_network_bytes(dm: &DataMap) -> Vec<u8> {
    rmp_serde::to_vec(dm).expect("DataMap serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live network bytes: the public DataMap chunk at
    /// `9f8ea63f705b75916548e2477c4a90022e9e9a31e01e85d99e987fc81b56130a`
    /// (ubuntu-20.10-desktop-amd64.iso, 2.8 GB), fetched with
    /// `ant chunk get` on 2026-09-16. A shrunk (child = 1) DataMap with 3 entries.
    const LIVE_UBUNTU_ISO: &[u8] = include_bytes!(
        "../../samples/live-store/chunks/0a/9f8ea63f705b75916548e2477c4a90022e9e9a31e01e85d99e987fc81b56130a"
    );

    /// Ground truth produced by `self_encryption` 0.34.3 + `rmp_serde` (the
    /// current array form) for a 3-chunk root DataMap.
    const REAL_DATAMAP_NEW: &str = "9301939400dc002015cc95cc9accb9ccf655cc934d66ccf6cc912eccb15e15\
3847ccbcccd4cca90bcc94cce549520dcc8e51cce8cccdccf2ccc8dc0020372077ccac20022ccc94ccbcccce5d0dcce3cc\
c8ccdd6149cce1ccd5ccc5ccdccc93cc934fccac2725671365673bcd27109401dc0020cc9acca9ccd62a4a3a2416cc8e55\
1e21ccf96c52ccf51761ccc30755ccb82dccedccb3cca53e62cc8d665accafdc00202029787a6acc83594eccd576cccdcc\
c442cce3756dccb5151ecc8339ccae5dccc4ccff57cce5ccc51e4fcc88ccbbcd27109402dc002034744012cce0ccaccca0\
29ccaf4e62cc955dccacccf76809ccce17712c275343ccaa49280f750756cca9dc00201bcc94cceb2251cce62d1636ccf0\
ccec52cc88ccbaccab5248ccfa71ccca5bcc802fcced10ccc230ccf3cc9acce10fccabcd2710c0";

    /// Ground truth for the legacy `DataMapLevel::First(DataMap)` form,
    /// produced by `self_encryption` 0.30.0 + `rmp_serde`.
    const REAL_DATAMAP_OLD: &str = "81a54669727374939400dc002015cc95cc9accb9ccf655cc934d66ccf6cc912e\
ccb15e153847ccbcccd4cca90bcc94cce549520dcc8e51cce8cccdccf2ccc8dc0020372077ccac20022ccc94ccbcccce5d\
0dcce3ccc8ccdd6149cce1ccd5ccc5ccdccc93cc934fccac2725671365673bcd27109401dc0020cc9acca9ccd62a4a3a24\
16cc8e551e21ccf96c52ccf51761ccc30755ccb82dccedccb3cca53e62cc8d665accafdc00202029787a6acc83594eccd5\
76cccdccc442cce3756dccb5151ecc8339ccae5dccc4ccff57cce5ccc51e4fcc88ccbbcd27109402dc002034744012cce0\
ccaccca029ccaf4e62cc955dccacccf76809ccce17712c275343ccaa49280f750756cca9dc00201bcc94cceb2251cce62d\
1636ccf0ccec52cc88ccbaccab5248ccfa71ccca5bcc802fcced10ccc230ccf3cc9acce10fccabcd2710";

    fn sample_infos(n: usize) -> Vec<ChunkInfo> {
        (0..n)
            .map(|i| ChunkInfo {
                index: i,
                dst_hash: XorName(blake3::hash(format!("dst{i}").as_bytes()).into()),
                src_hash: XorName(blake3::hash(format!("src{i}").as_bytes()).into()),
                src_size: 1000 * (i + 1),
            })
            .collect()
    }

    #[test]
    fn parses_ground_truth_current_format() {
        let bytes = hex::decode(REAL_DATAMAP_NEW).unwrap();
        let p = parse(&bytes).expect("parses");
        assert_eq!(p.format, WireFormat::MsgpackV1);
        assert_eq!(p.infos().len(), 3);
        assert_eq!(p.child(), None);
        assert_eq!(p.stats().content_bytes, 3 * 10_000);
    }

    #[test]
    fn parses_ground_truth_legacy_format() {
        let bytes = hex::decode(REAL_DATAMAP_OLD).unwrap();
        let p = parse(&bytes).expect("parses");
        assert_eq!(p.format, WireFormat::MsgpackLegacy);
        assert_eq!(p.infos().len(), 3);
        assert!(!p.is_child());
    }

    #[test]
    fn parses_live_network_datamap() {
        let bytes = LIVE_UBUNTU_ISO;
        // The chunk's network address is the BLAKE3 hash of its bytes.
        assert_eq!(
            hex::encode(blake3::hash(bytes).as_bytes()),
            "9f8ea63f705b75916548e2477c4a90022e9e9a31e01e85d99e987fc81b56130a"
        );
        let p = parse(bytes).expect("parses");
        assert_eq!(p.format, WireFormat::MsgpackV1);
        assert_eq!(p.child(), Some(1));
        assert_eq!(p.infos().len(), 3);
        assert_eq!(
            hex::encode(p.infos()[0].dst_hash),
            "e7f1a5a60d39268a6e54d45772e7cf90c1ead6fbd278d57f6abef99ded4ad8cc"
        );
        assert_eq!(p.stats().content_bytes, 56_250);
    }

    #[test]
    fn round_trips_current_bincode_and_json() {
        let dm = DataMap::with_child(sample_infos(4), 2);

        let mp = rmp_serde::to_vec(&dm).unwrap();
        let p = parse(&mp).expect("msgpack");
        assert_eq!(p.format, WireFormat::MsgpackV1);
        assert_eq!(p.data_map, dm);

        let bc = dm.to_bytes().unwrap();
        let p = parse(&bc).expect("bincode");
        assert_eq!(p.format, WireFormat::Bincode);
        assert_eq!(p.data_map, dm);

        let js = serde_json::to_vec(&dm).unwrap();
        let p = parse(&js).expect("json");
        assert_eq!(p.format, WireFormat::Json);
        assert_eq!(p.data_map, dm);

        // A root map (no child) in bincode has a shorter tail.
        let root = DataMap::new(sample_infos(2));
        let p = parse(&root.to_bytes().unwrap()).expect("bincode root");
        assert_eq!(p.child(), None);
    }

    #[test]
    fn rejects_impostors() {
        let bytes = hex::decode(REAL_DATAMAP_NEW).unwrap();
        // Truncated.
        assert!(parse(&bytes[..bytes.len() - 40]).is_none());
        // Trailing garbage must not be silently ignored.
        let mut longer = bytes.clone();
        longer.push(0x00);
        assert!(parse(&longer).is_none());
        // Wrong version byte.
        let mut wrong = bytes.clone();
        wrong[1] = 0x02;
        assert!(parse(&wrong).is_none());
        // Random-ish bytes.
        let random: Vec<u8> = (0..300u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        assert!(parse(&random).is_none());
        // Plaintext.
        assert!(parse(&b"hello world, this is not a datamap".repeat(4)).is_none());
        // Empty chunk list is not a DataMap.
        assert!(parse(&rmp_serde::to_vec(&DataMap::new(vec![])).unwrap()).is_none());
        // Non-contiguous indices.
        let mut infos = sample_infos(3);
        infos[2].index = 7;
        let dm = DataMap { chunk_identifiers: infos, child: None };
        assert!(parse(&rmp_serde::to_vec(&dm).unwrap()).is_none());
        // Bincode with trailing byte.
        let mut bc = DataMap::new(sample_infos(2)).to_bytes().unwrap();
        bc.push(0);
        assert!(parse(&bc).is_none());
    }
}

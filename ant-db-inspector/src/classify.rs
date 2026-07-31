//! Content classification for stored chunks.
//!
//! A node's chunk store holds opaque bytes: the only protocol rule is
//! `BLAKE3(content) == address` (see ant-node handler.rs). Self-encryption is
//! a client-side convention, so a node can hold both self-encrypted data
//! chunks *and* plaintext chunks (anyone can PUT raw bytes via the low-level
//! `chunk_put`). This module guesses what a chunk most likely is, purely from
//! its bytes:
//!
//! - **DataMap**: the retrieval metadata self-encryption produces. For public
//!   data it is stored *unencrypted* as a chunk, so it is structurally
//!   detectable (see [`parse_datamap`]).
//! - **Media / known format**: recognized by magic bytes (PNG, PDF, ZIP, …).
//!   Implies unencrypted content.
//! - **Text**: mostly printable bytes with low entropy.
//! - **High-entropy**: entropy near 8 bit/byte — the expected shape of a
//!   self-encrypted (or compressed) data chunk.
//! - **Other**: structured binary that matches none of the above.
//!
//! None of this is authoritative — self-encrypted output is by design
//! indistinguishable from random data, so "high-entropy" cannot prove
//! encryption, and a plaintext file that happens to be compressed also lands
//! there. The DataMap and magic-byte detectors, by contrast, are precise.

use serde::Serialize;

/// Maximum chunk size on the network (ant-protocol MAX_CHUNK_SIZE, 4 MiB).
/// Used to bound `src_size` when validating a candidate DataMap.
const MAX_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Bytes sampled from the start of a value for entropy/printable estimates.
/// Keeps classification O(1) per chunk on very large databases; magic bytes
/// and the DataMap parse look at their own (small / exact) ranges.
const SAMPLE_LEN: usize = 64 * 1024;

/// What a chunk's bytes most likely are.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    /// Empty value (e.g. a paid-list membership record).
    Empty,
    /// A self-encryption DataMap stored unencrypted (public retrieval metadata).
    DataMap,
    /// A recognized file format (magic bytes) — unencrypted content.
    Media,
    /// Mostly printable, low-entropy bytes.
    Text,
    /// Entropy near maximal — likely self-encrypted or compressed.
    HighEntropy,
    /// Structured binary matching none of the above.
    Other,
}

impl ContentClass {
    /// Stable key used to aggregate the distribution.
    pub fn key(self) -> &'static str {
        match self {
            ContentClass::Empty => "empty",
            ContentClass::DataMap => "datamap",
            ContentClass::Media => "media",
            ContentClass::Text => "text",
            ContentClass::HighEntropy => "high_entropy",
            ContentClass::Other => "other",
        }
    }

    /// Short tag for the per-record list column.
    pub fn tag(self) -> &'static str {
        match self {
            ContentClass::Empty => "-",
            ContentClass::DataMap => "datamap",
            ContentClass::Media => "media",
            ContentClass::Text => "text",
            ContentClass::HighEntropy => "enc?",
            ContentClass::Other => "bin",
        }
    }

    /// Longer, human-readable description for the distribution legend.
    pub fn description(self) -> &'static str {
        match self {
            ContentClass::Empty => "empty value",
            ContentClass::DataMap => "public DataMap (unencrypted retrieval metadata)",
            ContentClass::Media => "recognized file format (magic bytes) — unencrypted",
            ContentClass::Text => "mostly printable text — unencrypted",
            ContentClass::HighEntropy => "high entropy — likely self-encrypted or compressed",
            ContentClass::Other => "structured binary, unrecognized",
        }
    }
}

/// Full classification detail for one chunk.
#[derive(Serialize, Clone)]
pub struct Classification {
    pub class: ContentClass,
    /// Shannon entropy over the sampled bytes, bit/byte (0.0..=8.0).
    pub entropy_bits: f64,
    /// Detected format label when `class == Media`, e.g. "PNG".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
    /// Number of chunk entries when `class == DataMap`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datamap_entries: Option<u64>,
}

/// Classify a chunk value.
pub fn classify(content: &[u8]) -> Classification {
    if content.is_empty() {
        return Classification {
            class: ContentClass::Empty,
            entropy_bits: 0.0,
            format: None,
            datamap_entries: None,
        };
    }

    // Precise detectors first: a positive here is trustworthy.
    if let Some(entries) = parse_datamap(content) {
        return Classification {
            class: ContentClass::DataMap,
            entropy_bits: shannon_entropy(&content[..content.len().min(SAMPLE_LEN)]),
            format: None,
            datamap_entries: Some(entries),
        };
    }
    if let Some(fmt) = magic_format(content) {
        return Classification {
            class: ContentClass::Media,
            entropy_bits: shannon_entropy(&content[..content.len().min(SAMPLE_LEN)]),
            format: Some(fmt),
            datamap_entries: None,
        };
    }

    // Heuristic fallback: entropy + printable ratio over a sample.
    let sample = &content[..content.len().min(SAMPLE_LEN)];
    let entropy = shannon_entropy(sample);
    let printable = printable_ratio(sample);

    let class = if entropy >= 7.90 {
        ContentClass::HighEntropy
    } else if printable >= 0.85 && entropy < 6.0 {
        ContentClass::Text
    } else {
        ContentClass::Other
    };

    Classification {
        class,
        entropy_bits: entropy,
        format: None,
        datamap_entries: None,
    }
}

/// Shannon entropy in bits per byte over `data` (0.0 for empty).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Fraction of bytes that are printable ASCII (incl. tab/newline/CR).
fn printable_ratio(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
        .count();
    printable as f64 / data.len() as f64
}

/// Return a format label if the content starts with a known magic signature.
fn magic_format(data: &[u8]) -> Option<&'static str> {
    // (offset, signature, label)
    const SIGS: &[(usize, &[u8], &str)] = &[
        (0, b"\x89PNG\r\n\x1a\n", "PNG"),
        (0, b"\xff\xd8\xff", "JPEG"),
        (0, b"GIF87a", "GIF"),
        (0, b"GIF89a", "GIF"),
        (0, b"%PDF-", "PDF"),
        (0, b"PK\x03\x04", "ZIP"),
        (0, b"PK\x05\x06", "ZIP (empty)"),
        (0, b"\x1f\x8b", "GZIP"),
        (0, b"BZh", "BZIP2"),
        (0, b"\x28\xb5\x2f\xfd", "ZSTD"),
        (0, b"\xfd7zXZ\x00", "XZ"),
        (0, b"7z\xbc\xaf\x27\x1c", "7Z"),
        (0, b"Rar!\x1a\x07", "RAR"),
        (0, b"\x7fELF", "ELF"),
        (0, b"\x00asm", "WASM"),
        (0, b"OggS", "OGG"),
        (0, b"fLaC", "FLAC"),
        (0, b"ID3", "MP3"),
        (0, b"RIFF", "RIFF (WAV/AVI/WEBP)"),
        (0, b"\x25\x21PS", "PostScript"),
        (0, b"SQLite format 3\x00", "SQLite"),
        (0, b"\xca\xfe\xba\xbe", "Java class"),
        (4, b"ftyp", "MP4/MOV"),
        (257, b"ustar", "TAR"),
    ];
    for (off, sig, label) in SIGS {
        if data.len() >= off + sig.len() && &data[*off..off + sig.len()] == *sig {
            return Some(label);
        }
    }
    None
}

/// Try to parse `content` as a bincode-serialized self-encryption `DataMap`
/// (v1 versioned format) and return the number of chunk entries on success.
///
/// Layout (bincode 1.x default: fixint, little-endian):
///
/// ```text
/// version : u8 = 0x01
/// len     : u64                       (number of ChunkInfo entries, N)
/// N × ChunkInfo {
///     index    : u64
///     dst_hash : [u8; 32]
///     src_hash : [u8; 32]
///     src_size : u64
/// }                                   (80 bytes each)
/// child   : Option<usize>             (0x00 | 0x01 + u64)
/// ```
///
/// Validation is strict — the whole-chunk length must match exactly, the
/// version byte must be 1, the embedded length must equal the derived N,
/// indices must run 0..N, and every `src_size` must be in `1..=MAX_CHUNK_SIZE`.
/// Random or self-encrypted bytes effectively never satisfy all of these at
/// once, so a positive result is trustworthy. Note this only detects DataMaps
/// stored *directly* (the common public case); a re-encrypted / shrunk
/// DataMap is indistinguishable from a normal chunk and will not match.
pub fn parse_datamap(content: &[u8]) -> Option<u64> {
    const HEADER: usize = 1 + 8; // version + vec length
    const ENTRY: usize = 8 + 32 + 32 + 8; // 80
    let len = content.len();
    if len < HEADER + 1 {
        return None;
    }

    // Derive N from the total length, for child = None (1 byte) or Some (9).
    let body = len - HEADER;
    let (n, child_some) = if body >= 1 && (body - 1).is_multiple_of(ENTRY) {
        ((body - 1) / ENTRY, false)
    } else if body >= 9 && (body - 9).is_multiple_of(ENTRY) {
        ((body - 9) / ENTRY, true)
    } else {
        return None;
    };
    if n == 0 {
        return None;
    }

    if content[0] != 0x01 {
        return None;
    }
    let vec_len = read_u64(content, 1)?;
    if vec_len != n as u64 {
        return None;
    }

    for i in 0..n {
        let base = HEADER + i * ENTRY;
        let index = read_u64(content, base)?;
        if index != i as u64 {
            return None;
        }
        let src_size = read_u64(content, base + 8 + 32 + 32)?;
        if src_size == 0 || src_size > MAX_CHUNK_SIZE {
            return None;
        }
    }

    // Validate the child tag against the length we assumed.
    let child_tag = content[HEADER + n * ENTRY];
    match (child_tag, child_some) {
        (0, false) => {}
        (1, true) => {}
        _ => return None,
    }

    Some(n as u64)
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|s| u64::from_le_bytes(s.try_into().expect("checked length")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize a DataMap exactly like bincode 1.x would, to prove the parser
    /// accepts the real format.
    fn encode_datamap(indices_sizes: &[(u64, u64)], child: Option<u64>) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x01); // version
        out.extend_from_slice(&(indices_sizes.len() as u64).to_le_bytes());
        for (i, (index, src_size)) in indices_sizes.iter().enumerate() {
            assert_eq!(*index, i as u64);
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&[0xAB; 32]); // dst_hash
            out.extend_from_slice(&[0xCD; 32]); // src_hash
            out.extend_from_slice(&src_size.to_le_bytes());
        }
        match child {
            None => out.push(0x00),
            Some(v) => {
                out.push(0x01);
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        out
    }

    #[test]
    fn detects_real_datamap_root() {
        let bytes = encode_datamap(&[(0, 1000), (1, 1_048_576), (2, 512)], None);
        assert_eq!(parse_datamap(&bytes), Some(3));
        assert_eq!(classify(&bytes).class, ContentClass::DataMap);
    }

    #[test]
    fn detects_datamap_with_child() {
        let bytes = encode_datamap(&[(0, 100), (1, 200)], Some(1));
        assert_eq!(parse_datamap(&bytes), Some(2));
    }

    #[test]
    fn rejects_datamap_impostors() {
        // Right length but wrong version byte.
        let mut bytes = encode_datamap(&[(0, 100), (1, 200)], None);
        bytes[0] = 0x02;
        assert_eq!(parse_datamap(&bytes), None);

        // Right length, wrong index sequence.
        let mut bytes = encode_datamap(&[(0, 100), (1, 200)], None);
        bytes[1 + 8] = 5; // first index = 5 instead of 0
        assert_eq!(parse_datamap(&bytes), None);

        // src_size out of range (huge) — like random data would have.
        let bytes = encode_datamap(&[(0, u64::MAX)], None);
        assert_eq!(parse_datamap(&bytes), None);

        // Random bytes essentially never parse.
        let random: Vec<u8> = (0..250u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        assert_eq!(parse_datamap(&random), None);
    }

    #[test]
    fn entropy_bounds() {
        // All-identical bytes → 0 entropy.
        assert!(shannon_entropy(&[7u8; 4096]) < 0.001);
        // Uniformly distributed 0..=255 → ~8 bit/byte.
        let uniform: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!(shannon_entropy(&uniform) > 7.99);
    }

    #[test]
    fn classifies_text_and_media() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
        assert_eq!(classify(&text).class, ContentClass::Text);

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0u8; 100]);
        let c = classify(&png);
        assert_eq!(c.class, ContentClass::Media);
        assert_eq!(c.format, Some("PNG"));
    }

    #[test]
    fn classifies_high_entropy_as_encrypted() {
        // A pseudo-random blob stands in for a self-encrypted chunk.
        let blob: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 15) as u8)
            .collect();
        assert_eq!(classify(&blob).class, ContentClass::HighEntropy);
    }
}

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
    /// `None` when the payload was not scanned (a large chunk assumed
    /// self-encrypted — see [`classify`]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_bits: Option<f64>,
    /// Detected format label when `class == Media`, e.g. "PNG".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
    /// Number of chunk entries when `class == DataMap`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datamap_entries: Option<u64>,
    /// True when the class was assumed from the size alone, without reading
    /// the payload.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub assumed: bool,
}

/// Classify a chunk value.
///
/// `assume_encrypted_above` is a fast-path threshold: a chunk at least that
/// large that isn't caught by the cheap magic-byte check is classified as
/// [`ContentClass::HighEntropy`] *without* scanning its payload. On a real
/// node this skips faulting in gigabytes of full-size chunks, which are
/// virtually always self-encrypted data. Set it to `u64::MAX` to always
/// scan. A rare large public DataMap (metadata for a very large file) would
/// be assumed-encrypted rather than detected under this shortcut.
pub fn classify(content: &[u8], assume_encrypted_above: u64) -> Classification {
    if content.is_empty() {
        return Classification {
            class: ContentClass::Empty,
            entropy_bits: None,
            format: None,
            datamap_entries: None,
            assumed: false,
        };
    }

    // Magic bytes are cheap (first few hundred bytes, one page) and catch a
    // large unencrypted media file uploaded as a plaintext chunk, so run this
    // even before the size shortcut.
    if let Some(fmt) = magic_format(content) {
        return Classification {
            class: ContentClass::Media,
            entropy_bits: Some(shannon_entropy(&content[..content.len().min(SAMPLE_LEN)])),
            format: Some(fmt),
            datamap_entries: None,
            assumed: false,
        };
    }

    // Size shortcut: assume a large chunk is self-encrypted without reading it.
    if content.len() as u64 >= assume_encrypted_above {
        return Classification {
            class: ContentClass::HighEntropy,
            entropy_bits: None,
            format: None,
            datamap_entries: None,
            assumed: true,
        };
    }

    // Precise DataMap detector (small chunks only): a positive is trustworthy.
    if let Some(entries) = parse_datamap(content) {
        return Classification {
            class: ContentClass::DataMap,
            entropy_bits: Some(shannon_entropy(&content[..content.len().min(SAMPLE_LEN)])),
            format: None,
            datamap_entries: Some(entries),
            assumed: false,
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
        entropy_bits: Some(entropy),
        format: None,
        datamap_entries: None,
        assumed: false,
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

/// Largest chunk we attempt to parse as a DataMap. Real root DataMaps are a
/// few hundred bytes to a few KiB (self-encryption shrinks larger ones), so a
/// generous cap keeps the rmp-serde attempt off multi-megabyte data chunks.
const DATAMAP_MAX_TRY: usize = 512 * 1024;

/// One chunk entry as it appears on the wire inside a DataMap: a 4-element
/// MessagePack array `[index, dst_hash, src_hash, src_size]`. The 32-byte
/// hashes are encoded as arrays of 32 integers (serde `[u8; 32]`).
#[derive(serde::Deserialize)]
struct WireChunkInfo {
    index: u64,
    #[allow(dead_code)]
    dst_hash: [u8; 32],
    #[allow(dead_code)]
    src_hash: [u8; 32],
    src_size: u64,
}

/// Current self-encryption DataMap wire form (autonomi `wrap_data_map`):
/// `rmp_serde` of `[version, chunk_identifiers, child]`.
#[derive(serde::Deserialize)]
struct WireDataMapNew {
    version: u8,
    chunk_identifiers: Vec<WireChunkInfo>,
    #[allow(dead_code)]
    child: Option<u64>,
}

/// Legacy wire form: `rmp_serde` of the `DataMapLevel` enum wrapping the old
/// self-encryption DataMap, which serializes as a bare list of chunk infos.
#[derive(serde::Deserialize)]
enum WireDataMapLevel {
    First(Vec<WireChunkInfo>),
    Additional(Vec<WireChunkInfo>),
}

/// Try to parse `content` as a public self-encryption DataMap chunk and return
/// the number of chunk entries on success.
///
/// Autonomi stores a public DataMap as the `rmp_serde` (MessagePack)
/// serialization of the self-encryption DataMap (see the autonomi client's
/// `memory_encryption.rs::wrap_data_map`). Two forms occur in the wild:
///
/// - **current**: `[version:1, chunk_identifiers, child]`
/// - **legacy**: the `DataMapLevel::First/Additional` enum → a MessagePack map
///   `{"First": [chunk_infos]}`
///
/// Both are deserialized with `rmp-serde` into mirror structs, then validated:
/// non-empty, contiguous indices `0..N`, and every `src_size` in
/// `1..=MAX_CHUNK_SIZE`. Random or self-encrypted bytes essentially never
/// deserialize into this nested shape *and* pass the checks, so a positive
/// result is trustworthy.
pub fn parse_datamap(content: &[u8]) -> Option<u64> {
    if content.len() < 4 || content.len() > DATAMAP_MAX_TRY {
        return None;
    }

    // Current format: top-level array [version, chunks, child].
    if let Ok(dm) = rmp_serde::from_slice::<WireDataMapNew>(content) {
        if dm.version == 1 && plausible_chunks(&dm.chunk_identifiers) {
            return Some(dm.chunk_identifiers.len() as u64);
        }
    }

    // Legacy format: DataMapLevel enum map {"First"|"Additional": [chunks]}.
    if let Ok(level) = rmp_serde::from_slice::<WireDataMapLevel>(content) {
        let chunks = match &level {
            WireDataMapLevel::First(c) | WireDataMapLevel::Additional(c) => c,
        };
        if plausible_chunks(chunks) {
            return Some(chunks.len() as u64);
        }
    }

    None
}

/// A chunk-info list is a plausible DataMap: non-empty, indices run `0..N`,
/// and every `src_size` is a sane chunk size.
fn plausible_chunks(chunks: &[WireChunkInfo]) -> bool {
    !chunks.is_empty()
        && chunks
            .iter()
            .enumerate()
            .all(|(i, c)| c.index == i as u64 && c.src_size >= 1 && c.src_size <= MAX_CHUNK_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real wire bytes of a public DataMap for a 3-chunk file, produced by the
    /// actual `self_encryption` 0.34.3 crate serialized with `rmp_serde`
    /// exactly as the autonomi client does (current format). Ground truth —
    /// not generated by this codebase, so the test is not circular.
    const REAL_DATAMAP_NEW: &str = "9301939400dc002015cc95cc9accb9ccf655cc934d66ccf6cc912eccb15e15\
3847ccbcccd4cca90bcc94cce549520dcc8e51cce8cccdccf2ccc8dc0020372077ccac20022ccc94ccbcccce5d0dcce3cc\
c8ccdd6149cce1ccd5ccc5ccdccc93cc934fccac2725671365673bcd27109401dc0020cc9acca9ccd62a4a3a2416cc8e55\
1e21ccf96c52ccf51761ccc30755ccb82dccedccb3cca53e62cc8d665accafdc00202029787a6acc83594eccd576cccdcc\
c442cce3756dccb5151ecc8339ccae5dccc4ccff57cce5ccc51e4fcc88ccbbcd27109402dc002034744012cce0ccaccca0\
29ccaf4e62cc955dccacccf76809ccce17712c275343ccaa49280f750756cca9dc00201bcc94cceb2251cce62d1636ccf0\
ccec52cc88ccbaccab5248ccfa71ccca5bcc802fcced10ccc230ccf3cc9acce10fccabcd2710c0";

    /// Real wire bytes of the legacy `DataMapLevel::First(DataMap)` form,
    /// produced by `self_encryption` 0.30.0 + `rmp_serde`. Ground truth.
    const REAL_DATAMAP_OLD: &str = "81a54669727374939400dc002015cc95cc9accb9ccf655cc934d66ccf6cc912e\
ccb15e153847ccbcccd4cca90bcc94cce549520dcc8e51cce8cccdccf2ccc8dc0020372077ccac20022ccc94ccbcccce5d\
0dcce3ccc8ccdd6149cce1ccd5ccc5ccdccc93cc934fccac2725671365673bcd27109401dc0020cc9acca9ccd62a4a3a24\
16cc8e551e21ccf96c52ccf51761ccc30755ccb82dccedccb3cca53e62cc8d665accafdc00202029787a6acc83594eccd5\
76cccdccc442cce3756dccb5151ecc8339ccae5dccc4ccff57cce5ccc51e4fcc88ccbbcd27109402dc002034744012cce0\
ccaccca029ccaf4e62cc955dccacccf76809ccce17712c275343ccaa49280f750756cca9dc00201bcc94cceb2251cce62d\
1636ccf0ccec52cc88ccbaccab5248ccfa71ccca5bcc802fcced10ccc230ccf3cc9acce10fccabcd2710";

    /// Threshold that never triggers the size shortcut in these small tests.
    const NO_SHORTCUT: u64 = u64::MAX;

    #[test]
    fn detects_real_datamap_current_format() {
        let bytes = hex::decode(REAL_DATAMAP_NEW).unwrap();
        assert_eq!(parse_datamap(&bytes), Some(3));
        assert_eq!(classify(&bytes, NO_SHORTCUT).class, ContentClass::DataMap);
    }

    #[test]
    fn detects_real_datamap_legacy_format() {
        let bytes = hex::decode(REAL_DATAMAP_OLD).unwrap();
        assert_eq!(parse_datamap(&bytes), Some(3));
        assert_eq!(classify(&bytes, NO_SHORTCUT).class, ContentClass::DataMap);
    }

    #[test]
    fn rejects_datamap_impostors() {
        // A truncated DataMap must not parse.
        let bytes = hex::decode(REAL_DATAMAP_NEW).unwrap();
        assert_eq!(parse_datamap(&bytes[..bytes.len() - 40]), None);

        // Flipping the version byte (offset 1) breaks the current-format check.
        let mut bytes = hex::decode(REAL_DATAMAP_NEW).unwrap();
        bytes[1] = 0x02;
        assert_eq!(parse_datamap(&bytes), None);

        // Random bytes essentially never deserialize into the nested shape.
        let random: Vec<u8> = (0..300u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        assert_eq!(parse_datamap(&random), None);

        // Plaintext is not a DataMap.
        assert_eq!(parse_datamap(&b"hello world, this is not a datamap".repeat(4)), None);
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
        assert_eq!(classify(&text, NO_SHORTCUT).class, ContentClass::Text);

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0u8; 100]);
        let c = classify(&png, NO_SHORTCUT);
        assert_eq!(c.class, ContentClass::Media);
        assert_eq!(c.format, Some("PNG"));
    }

    #[test]
    fn classifies_high_entropy_as_encrypted() {
        // A pseudo-random blob stands in for a self-encrypted chunk.
        let blob: Vec<u8> = (0..8192u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 15) as u8)
            .collect();
        assert_eq!(classify(&blob, NO_SHORTCUT).class, ContentClass::HighEntropy);
    }

    #[test]
    fn size_shortcut_assumes_encrypted_without_scan() {
        // A large low-entropy (all-zero) chunk: a real scan would call it
        // text/other, but above the threshold it is assumed high-entropy and
        // not scanned (no entropy computed).
        let big = vec![0u8; 100_000];
        let c = classify(&big, 64 * 1024);
        assert_eq!(c.class, ContentClass::HighEntropy);
        assert!(c.assumed);
        assert_eq!(c.entropy_bits, None);

        // Magic bytes still win over the shortcut for large media.
        let mut big_png = b"\x89PNG\r\n\x1a\n".to_vec();
        big_png.resize(100_000, 0);
        let c = classify(&big_png, 64 * 1024);
        assert_eq!(c.class, ContentClass::Media);
        assert!(!c.assumed);

        // Below the threshold the payload is scanned as usual.
        let small = vec![0u8; 1000];
        let c = classify(&small, 64 * 1024);
        assert!(!c.assumed);
        assert!(c.entropy_bits.is_some());
    }
}

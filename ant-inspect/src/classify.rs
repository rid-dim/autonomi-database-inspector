//! Content classification for chunks.
//!
//! A node's chunk store holds opaque bytes: the only protocol rule is
//! `BLAKE3(content) == address`. Self-encryption is a client-side convention,
//! so a node can hold self-encrypted data chunks, public DataMaps *and*
//! plaintext chunks (anyone can PUT raw bytes with `ant chunk put`). This
//! module guesses what a chunk most likely is, purely from its bytes:
//!
//! - **DataMap**: a public DataMap is stored unencrypted, so it is
//!   structurally detectable — precisely — by deserializing it (see
//!   [`crate::datamap::parse`]).
//! - **Media / known format**: recognized by magic bytes (PNG, PDF, ZIP, …).
//!   Implies unencrypted content.
//! - **Text**: mostly printable bytes with low entropy. An approximation:
//!   "probably human-readable text".
//! - **High-entropy**: entropy near 8 bit/byte — the expected shape of a
//!   self-encrypted (or compressed/encrypted-elsewhere) chunk.
//! - **Other**: structured binary that matches none of the above.
//!
//! Only the DataMap and magic-byte detectors are authoritative. Self-encrypted
//! output is by design indistinguishable from random data, so "high-entropy"
//! cannot *prove* encryption, and compressed plaintext lands there too.

use crate::datamap;
use serde::Serialize;

/// Bytes sampled from the start of a value for entropy/printable estimates.
const SAMPLE_LEN: usize = 64 * 1024;

/// What a chunk's bytes most likely are.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ContentClass {
    /// A self-encryption DataMap stored unencrypted (public retrieval metadata).
    DataMap,
    /// A recognized file format (magic bytes) — unencrypted content.
    Media,
    /// Mostly printable, low-entropy bytes — probably plaintext.
    Text,
    /// Entropy near maximal — most likely self-encrypted.
    HighEntropy,
    /// Structured binary matching none of the above.
    Other,
    /// Empty file.
    Empty,
}

impl ContentClass {
    /// Stable key used in JSON and to aggregate the distribution.
    pub fn key(self) -> &'static str {
        match self {
            ContentClass::DataMap => "datamap",
            ContentClass::Media => "media",
            ContentClass::Text => "text",
            ContentClass::HighEntropy => "encrypted",
            ContentClass::Other => "binary",
            ContentClass::Empty => "empty",
        }
    }

    /// Short tag for list columns (fixed width 9).
    pub fn tag(self) -> &'static str {
        match self {
            ContentClass::DataMap => "datamap",
            ContentClass::Media => "media",
            ContentClass::Text => "text",
            ContentClass::HighEntropy => "encrypted",
            ContentClass::Other => "binary",
            ContentClass::Empty => "empty",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            ContentClass::DataMap => "public DataMap (unencrypted retrieval metadata)",
            ContentClass::Media => "recognized file format by magic bytes — unencrypted",
            ContentClass::Text => "mostly printable text — probably unencrypted (heuristic)",
            ContentClass::HighEntropy => "high entropy — most likely self-encrypted (heuristic)",
            ContentClass::Other => "structured binary, unrecognized",
            ContentClass::Empty => "empty file",
        }
    }

    pub fn all() -> [ContentClass; 6] {
        [
            ContentClass::DataMap,
            ContentClass::HighEntropy,
            ContentClass::Media,
            ContentClass::Text,
            ContentClass::Other,
            ContentClass::Empty,
        ]
    }
}

/// Full classification detail for one chunk.
#[derive(Serialize, Clone)]
pub struct Classification {
    pub class: ContentClass,
    /// Shannon entropy over the sampled bytes, bit/byte (0.0..=8.0).
    /// `None` when the payload was not scanned (size shortcut).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_bits: Option<f64>,
    /// Detected format label when `class == Media`, e.g. "PNG".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
    /// Number of chunk entries when `class == DataMap`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datamap_chunks: Option<usize>,
    /// Shrink level when `class == DataMap` and the map is a child.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datamap_child: Option<usize>,
    /// True when the class was assumed from the size alone.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub assumed: bool,
}

impl Classification {
    fn plain(class: ContentClass, entropy: Option<f64>) -> Self {
        Classification {
            class,
            entropy_bits: entropy,
            format: None,
            datamap_chunks: None,
            datamap_child: None,
            assumed: false,
        }
    }
}

/// Classify a chunk's bytes.
///
/// `assume_encrypted_above` is a fast path: a chunk at least that large that
/// is not caught by the cheap magic-byte check is classified as
/// [`ContentClass::HighEntropy`] without scanning the payload. Set it to
/// `u64::MAX` to always scan.
pub fn classify(content: &[u8], assume_encrypted_above: u64) -> Classification {
    if content.is_empty() {
        return Classification::plain(ContentClass::Empty, None);
    }
    let sample = &content[..content.len().min(SAMPLE_LEN)];

    if let Some(fmt) = magic_format(content) {
        let mut c = Classification::plain(ContentClass::Media, Some(shannon_entropy(sample)));
        c.format = Some(fmt);
        return c;
    }

    if content.len() as u64 >= assume_encrypted_above {
        let mut c = Classification::plain(ContentClass::HighEntropy, None);
        c.assumed = true;
        return c;
    }

    if let Some(dm) = datamap::parse(content) {
        let mut c = Classification::plain(ContentClass::DataMap, Some(shannon_entropy(sample)));
        c.datamap_chunks = Some(dm.infos().len());
        c.datamap_child = dm.child();
        return c;
    }

    let entropy = shannon_entropy(sample);
    let printable = printable_ratio(sample);
    let class = if looks_random(entropy, sample.len()) {
        ContentClass::HighEntropy
    } else if printable >= 0.85 && entropy < 6.0 {
        ContentClass::Text
    } else {
        ContentClass::Other
    };
    Classification::plain(class, Some(entropy))
}

/// Whether `entropy` (bit/byte) over a sample of `len` bytes is as high as
/// random data gets. A sample shorter than 256 bytes cannot reach 8 bit/byte
/// (it has at most `len` distinct values), so for small samples the bar is a
/// fraction of the achievable maximum `log2(len)`; a 130-byte encrypted chunk
/// lands at ~6.5 bit/byte, plaintext of that length at ~4.5.
fn looks_random(entropy: f64, len: usize) -> bool {
    if len >= 4096 {
        return entropy >= 7.90;
    }
    if len < 16 {
        return false;
    }
    let max_possible = (len as f64).log2().min(8.0);
    entropy >= 0.88 * max_possible
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
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
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
        (0, b"<svg", "SVG"),
        (0, b"<?xml", "XML"),
        (4, b"ftyp", "MP4/MOV"),
        (257, b"ustar", "TAR"),
    ];
    SIGS.iter()
        .find(|(off, sig, _)| data.len() >= off + sig.len() && &data[*off..off + sig.len()] == *sig)
        .map(|(_, _, label)| *label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use self_encryption::{ChunkInfo, DataMap};
    use xor_name::XorName;

    const NO_SHORTCUT: u64 = u64::MAX;

    #[test]
    fn detects_datamap() {
        let infos: Vec<ChunkInfo> = (0..3)
            .map(|i| ChunkInfo {
                index: i,
                dst_hash: XorName(blake3::hash(format!("d{i}").as_bytes()).into()),
                src_hash: XorName(blake3::hash(format!("s{i}").as_bytes()).into()),
                src_size: 4096,
            })
            .collect();
        let bytes = rmp_serde::to_vec(&DataMap::with_child(infos, 2)).unwrap();
        let c = classify(&bytes, NO_SHORTCUT);
        assert_eq!(c.class, ContentClass::DataMap);
        assert_eq!(c.datamap_chunks, Some(3));
        assert_eq!(c.datamap_child, Some(2));
    }

    #[test]
    fn entropy_bounds() {
        assert!(shannon_entropy(&[7u8; 4096]) < 0.001);
        let uniform: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!(shannon_entropy(&uniform) > 7.99);
    }

    #[test]
    fn classifies_text_media_and_encrypted() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
        assert_eq!(classify(&text, NO_SHORTCUT).class, ContentClass::Text);

        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[0u8; 100]);
        let c = classify(&png, NO_SHORTCUT);
        assert_eq!(c.class, ContentClass::Media);
        assert_eq!(c.format, Some("PNG"));

        let blob: Vec<u8> = (0..8192u32).map(|i| (i.wrapping_mul(2654435761) >> 15) as u8).collect();
        assert_eq!(classify(&blob, NO_SHORTCUT).class, ContentClass::HighEntropy);

        assert_eq!(classify(&[], NO_SHORTCUT).class, ContentClass::Empty);
    }

    #[test]
    fn small_random_chunks_still_count_as_encrypted() {
        // Real 130-byte encrypted chunk of BegBlag.mp3's shrunk DataMap level.
        let real: &[u8] = include_bytes!(
            "../../samples/live-store/chunks/3b/70a0b43add6a8584198334d9bf6856c098d0b143e4523f7f644ccc0b1176063b"
        );
        assert_eq!(real.len(), 130);
        assert_eq!(classify(real, NO_SHORTCUT).class, ContentClass::HighEntropy);

        // Pseudo-random samples of assorted small lengths.
        for len in [40usize, 130, 300, 1000, 3000] {
            let blob: Vec<u8> = (0..len as u32)
                .map(|i| (i.wrapping_mul(2654435761).wrapping_add(len as u32) >> 13) as u8)
                .collect();
            assert_eq!(classify(&blob, NO_SHORTCUT).class, ContentClass::HighEntropy, "len {len}");
        }

        // Short text and structured binary must not.
        let text = b"Beg, Blag and Steal - a short line of text for the test.\n".repeat(2);
        assert_eq!(classify(&text, NO_SHORTCUT).class, ContentClass::Text);
        let structured: Vec<u8> = (0..200u8).map(|i| i % 7).collect();
        assert_eq!(classify(&structured, NO_SHORTCUT).class, ContentClass::Other);
    }

    #[test]
    fn size_shortcut_assumes_encrypted_without_scan() {
        let big = vec![0u8; 100_000];
        let c = classify(&big, 64 * 1024);
        assert_eq!(c.class, ContentClass::HighEntropy);
        assert!(c.assumed);
        assert_eq!(c.entropy_bits, None);

        let mut big_png = b"\x89PNG\r\n\x1a\n".to_vec();
        big_png.resize(100_000, 0);
        let c = classify(&big_png, 64 * 1024);
        assert_eq!(c.class, ContentClass::Media);
        assert!(!c.assumed);
    }
}

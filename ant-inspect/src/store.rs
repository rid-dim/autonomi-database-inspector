//! Scanning of ant-node file-based chunk stores and generic chunk directories.
//!
//! Since ADR-0014 ant-node keeps one immutable file per chunk
//! (`src/storage/file_store.rs`):
//!
//! ```text
//! {root}/chunks/                     store root
//! {root}/chunks/layout.json          versioned layout marker
//! {root}/chunks/.lock                advisory single-process guard
//! {root}/chunks/<xy>/<64-hex>        xy = the LAST two hex characters of the address
//! {root}/chunks/<xy>/.tmp.<pid>.<n>  an in-flight write, in the destination directory
//! {root}/chunks/<xy>/<name>.not-a-chunk   an entry the node quarantined (case-folded twin)
//! ```
//!
//! The filename *is* the address (BLAKE3 of the content, lowercase hex, all
//! 64 characters), so a directory listing recovers the whole key set and a
//! `find` over the tree recovers the store even without the shard layer.
//!
//! Beside the store a node root also holds `paid_list.mdb/` (still LMDB),
//! `migration-state.json` (the LMDB → files migration marker) and, until
//! retirement completes, the legacy `chunks.mdb/` environment (or
//! `chunks.mdb.retired/` while it is being deleted).
//!
//! This module only reads: directory entries, `stat`, and — where asked —
//! file contents. Nothing is ever created, renamed or removed.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use xor_name::XorName;

pub const CHUNKS_DIR_NAME: &str = "chunks";
pub const LAYOUT_FILE_NAME: &str = "layout.json";
pub const LOCK_FILE_NAME: &str = ".lock";
pub const TEMP_PREFIX: &str = ".tmp.";
pub const QUARANTINE_SUFFIX: &str = ".not-a-chunk";
pub const MIGRATION_STATE_FILE: &str = "migration-state.json";
pub const LEGACY_ENV_DIR: &str = "chunks.mdb";
pub const RETIRED_ENV_DIR: &str = "chunks.mdb.retired";
pub const RETIRED_MARKER: &str = "RETIRED";
pub const PAID_LIST_DIR: &str = "paid_list.mdb";
pub const SHARD_COUNT: usize = 256;
pub const CHUNK_NAME_LEN: usize = 64;

/// The on-disk layout marker (`layout.json`), mirrored from ant-node's
/// `StoreLayout`. Unknown fields are kept in `extra` so a newer marker still
/// prints in full.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreLayout {
    pub schema: u32,
    pub scheme: String,
    pub shard_chars: u8,
    pub depth: u8,
    pub name_encoding: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl StoreLayout {
    /// The one layout this build (and ant-node today) implements.
    pub fn is_current(&self) -> bool {
        self.schema == 1
            && self.scheme == "suffix-hex"
            && self.shard_chars == 2
            && self.depth == 1
            && self.name_encoding == "lower-hex"
    }
}

/// What the given path turned out to be.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// A node root directory: contains `chunks/`.
    NodeRoot,
    /// The `chunks/` store directory itself (has `layout.json` or shard dirs).
    ChunkStore,
    /// A single shard directory `<xy>/` inside a store.
    ShardDir,
    /// Any other directory: every regular file below it is a chunk candidate.
    GenericDir,
}

impl TargetKind {
    pub fn label(self) -> &'static str {
        match self {
            TargetKind::NodeRoot => "node root directory",
            TargetKind::ChunkStore => "chunk store directory",
            TargetKind::ShardDir => "shard directory",
            TargetKind::GenericDir => "generic directory (recursive scan)",
        }
    }
}

/// One chunk file.
#[derive(Clone, Debug)]
pub struct ChunkEntry {
    pub path: PathBuf,
    /// Address decoded from the filename when it is 64 hex characters.
    pub name_address: Option<XorName>,
    /// Address computed from the content (set by [`Scan::resolve_addresses`]
    /// or `verify`).
    pub computed_address: Option<XorName>,
    /// Apparent size (`st_size`).
    pub size: u64,
    /// Allocated size on disk (`st_blocks × 512`), Unix only.
    pub allocated: Option<u64>,
    /// Filename was hex but not lowercase (the node would ignore it).
    pub uppercase_name: bool,
}

impl ChunkEntry {
    /// Best-known address: from the filename, else computed.
    pub fn address(&self) -> Option<XorName> {
        self.name_address.or(self.computed_address)
    }

    pub fn read(&self) -> io::Result<Vec<u8>> {
        fs::read(&self.path)
    }
}

/// Facts about a node root beside the chunk store.
#[derive(Serialize, Clone, Debug, Default)]
pub struct NodeRootInfo {
    /// Parsed `migration-state.json`, schema-agnostic.
    pub migration_state: Option<serde_json::Value>,
    pub migration_state_error: Option<String>,
    /// Legacy LMDB environment `chunks.mdb/` still present, with its size.
    pub legacy_env_bytes: Option<u64>,
    /// `chunks.mdb.retired/` present (retirement in progress), with its size.
    pub retired_env_bytes: Option<u64>,
    /// The `RETIRED` marker was found inside the legacy directory.
    pub legacy_env_marked_retired: bool,
    /// `paid_list.mdb/` size.
    pub paid_list_bytes: Option<u64>,
    /// Every top-level entry of the node root (names), for orientation.
    pub entries: Vec<String>,
}

/// Result of scanning a target path.
#[derive(Debug)]
pub struct Scan {
    pub kind: TargetKind,
    /// The path the user gave.
    pub target: PathBuf,
    /// Where the chunk files live (`{root}/chunks` for a node root).
    pub chunks_dir: PathBuf,
    /// Parsed `layout.json`, or the error reading it, or `None` if absent.
    pub layout: Option<Result<StoreLayout, String>>,
    pub lock_present: bool,
    /// Number of shard directories found (`00`..`ff`).
    pub shards_present: usize,
    /// Chunk files per shard index (256 entries; only meaningful for stores).
    pub per_shard: Vec<u64>,
    pub chunks: Vec<ChunkEntry>,
    pub temp_files: Vec<PathBuf>,
    pub quarantined: Vec<PathBuf>,
    /// Entries that are neither chunk files nor known store artifacts.
    pub unexpected: Vec<PathBuf>,
    /// Directories that could not be read (permissions etc.).
    pub errors: Vec<String>,
    pub node: Option<NodeRootInfo>,
    index: Option<HashMap<XorName, usize>>,
}

impl Scan {
    /// Detect what `path` is and scan it.
    #[allow(clippy::self_named_constructors)]
    pub fn scan(path: &Path) -> io::Result<Scan> {
        let meta = fs::metadata(path)?;
        if !meta.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a directory"));
        }
        let kind = detect_kind(path);
        let chunks_dir = match kind {
            TargetKind::NodeRoot => path.join(CHUNKS_DIR_NAME),
            _ => path.to_path_buf(),
        };
        let mut scan = Scan {
            kind,
            target: path.to_path_buf(),
            chunks_dir: chunks_dir.clone(),
            layout: None,
            lock_present: false,
            shards_present: 0,
            per_shard: vec![0; SHARD_COUNT],
            chunks: Vec::new(),
            temp_files: Vec::new(),
            quarantined: Vec::new(),
            unexpected: Vec::new(),
            errors: Vec::new(),
            node: None,
            index: None,
        };
        match kind {
            TargetKind::NodeRoot | TargetKind::ChunkStore => {
                scan.layout = read_layout(&chunks_dir);
                scan.lock_present = chunks_dir.join(LOCK_FILE_NAME).is_file();
                scan.scan_store_top(&chunks_dir);
                if kind == TargetKind::NodeRoot {
                    scan.node = Some(read_node_root(path));
                }
            }
            TargetKind::ShardDir => {
                let shard = shard_index_from_name(path).unwrap_or(0);
                scan.scan_shard(path, shard);
                scan.shards_present = 1;
            }
            TargetKind::GenericDir => scan.scan_generic(path, 0),
        }
        scan.chunks.sort_by(|a, b| a.address().cmp(&b.address()).then(a.path.cmp(&b.path)));
        Ok(scan)
    }

    fn scan_store_top(&mut self, dir: &Path) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                self.errors.push(format!("{}: {e}", dir.display()));
                return;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                self.unexpected.push(entry.path());
                continue;
            };
            if name == LAYOUT_FILE_NAME || name == LOCK_FILE_NAME {
                continue;
            }
            if name.starts_with(TEMP_PREFIX) {
                self.temp_files.push(entry.path());
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if name.len() == 2 && is_lower_hex(name) && is_dir {
                let shard = u8::from_str_radix(name, 16).unwrap_or(0);
                self.shards_present += 1;
                self.scan_shard(&entry.path(), shard);
                continue;
            }
            self.unexpected.push(entry.path());
        }
    }

    fn scan_shard(&mut self, dir: &Path, shard: u8) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                self.errors.push(format!("{}: {e}", dir.display()));
                return;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                self.unexpected.push(entry.path());
                continue;
            };
            if name.starts_with(TEMP_PREFIX) {
                self.temp_files.push(entry.path());
                continue;
            }
            if name.ends_with(QUARANTINE_SUFFIX) {
                self.quarantined.push(entry.path());
                continue;
            }
            let Some((addr, upper)) = decode_chunk_name(name) else {
                self.unexpected.push(entry.path());
                continue;
            };
            let Ok(meta) = entry.metadata() else {
                self.errors.push(format!("{}: cannot stat", entry.path().display()));
                continue;
            };
            if !meta.is_file() {
                self.unexpected.push(entry.path());
                continue;
            }
            self.per_shard[shard as usize] += 1;
            self.chunks.push(ChunkEntry {
                path: entry.path(),
                name_address: Some(addr),
                computed_address: None,
                size: meta.len(),
                allocated: allocated_bytes(&meta),
                uppercase_name: upper,
            });
        }
    }

    /// Recursive scan of an arbitrary directory: every regular file is a
    /// chunk candidate. Hidden entries (leading `.`) are skipped.
    fn scan_generic(&mut self, dir: &Path, depth: usize) {
        if depth > 64 {
            self.errors.push(format!("{}: directory nesting too deep", dir.display()));
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                self.errors.push(format!("{}: {e}", dir.display()));
                return;
            }
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                self.errors.push(format!("{}: cannot stat", entry.path().display()));
                continue;
            };
            if meta.is_dir() {
                self.scan_generic(&entry.path(), depth + 1);
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            let decoded = decode_chunk_name(&name);
            if let Some(addr) = decoded.map(|(a, _)| a) {
                self.per_shard[addr[31] as usize] += 1;
            }
            self.chunks.push(ChunkEntry {
                path: entry.path(),
                name_address: decoded.map(|(a, _)| a),
                computed_address: None,
                size: meta.len(),
                allocated: allocated_bytes(&meta),
                uppercase_name: decoded.map(|(_, u)| u).unwrap_or(false),
            });
        }
    }

    /// Compute the content address of every entry whose filename did not
    /// carry one (generic directories). Reads those files.
    pub fn resolve_addresses(&mut self) -> io::Result<()> {
        let mut changed = false;
        for entry in &mut self.chunks {
            if entry.address().is_none() {
                let bytes = fs::read(&entry.path)?;
                entry.computed_address = Some(XorName(*blake3::hash(&bytes).as_bytes()));
                changed = true;
            }
        }
        if changed {
            self.index = None;
            self.chunks.sort_by(|a, b| a.address().cmp(&b.address()).then(a.path.cmp(&b.path)));
        }
        Ok(())
    }

    fn ensure_index(&mut self) {
        if self.index.is_none() {
            let mut idx = HashMap::with_capacity(self.chunks.len());
            for (i, c) in self.chunks.iter().enumerate() {
                if let Some(a) = c.address() {
                    idx.entry(a).or_insert(i);
                }
            }
            self.index = Some(idx);
        }
    }

    /// Find the chunk with this address.
    pub fn locate(&mut self, address: &XorName) -> Option<&ChunkEntry> {
        self.ensure_index();
        let i = *self.index.as_ref()?.get(address)?;
        self.chunks.get(i)
    }

    /// The path a chunk with this address would have in a store of the
    /// current layout, whether or not it exists.
    pub fn expected_path(&self, address: &XorName) -> PathBuf {
        self.chunks_dir
            .join(format!("{:02x}", address[31]))
            .join(hex::encode(address))
    }

    pub fn total_bytes(&self) -> u64 {
        self.chunks.iter().map(|c| c.size).sum()
    }

    pub fn allocated_bytes(&self) -> Option<u64> {
        self.chunks.iter().map(|c| c.allocated).sum()
    }
}

/// Decide what kind of directory `path` is.
pub fn detect_kind(path: &Path) -> TargetKind {
    let chunks = path.join(CHUNKS_DIR_NAME);
    if chunks.is_dir() && (chunks.join(LAYOUT_FILE_NAME).is_file() || has_shard_dirs(&chunks)) {
        return TargetKind::NodeRoot;
    }
    if path.join(LAYOUT_FILE_NAME).is_file() || has_shard_dirs(path) {
        return TargetKind::ChunkStore;
    }
    if shard_index_from_name(path).is_some() && has_chunk_files(path) {
        return TargetKind::ShardDir;
    }
    TargetKind::GenericDir
}

fn has_shard_dirs(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_type().map(|t| t.is_dir()).unwrap_or(false)
            && e.file_name().to_str().is_some_and(|n| n.len() == 2 && is_lower_hex(n))
    })
}

fn has_chunk_files(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name().to_str().is_some_and(|n| decode_chunk_name(n).is_some()))
}

fn shard_index_from_name(path: &Path) -> Option<u8> {
    let name = path.file_name()?.to_str()?;
    (name.len() == 2 && is_lower_hex(name))
        .then(|| u8::from_str_radix(name, 16).ok())
        .flatten()
}

fn read_layout(chunks_dir: &Path) -> Option<Result<StoreLayout, String>> {
    let path = chunks_dir.join(LAYOUT_FILE_NAME);
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(e.to_string())),
    };
    Some(serde_json::from_slice::<StoreLayout>(&bytes).map_err(|e| e.to_string()))
}

fn read_node_root(root: &Path) -> NodeRootInfo {
    let mut info = NodeRootInfo::default();
    if let Ok(entries) = fs::read_dir(root) {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| {
                let mut n = e.file_name().to_string_lossy().into_owned();
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    n.push('/');
                }
                n
            })
            .collect();
        names.sort();
        info.entries = names;
    }
    let state = root.join(MIGRATION_STATE_FILE);
    if state.is_file() {
        match fs::read(&state).map_err(|e| e.to_string()).and_then(|b| {
            serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| e.to_string())
        }) {
            Ok(v) => info.migration_state = Some(v),
            Err(e) => info.migration_state_error = Some(e),
        }
    }
    let legacy = root.join(LEGACY_ENV_DIR);
    if legacy.is_dir() {
        info.legacy_env_bytes = Some(dir_size(&legacy));
        info.legacy_env_marked_retired = legacy.join(RETIRED_MARKER).is_file();
    }
    let retired = root.join(RETIRED_ENV_DIR);
    if retired.is_dir() {
        info.retired_env_bytes = Some(dir_size(&retired));
    }
    let paid = root.join(PAID_LIST_DIR);
    if paid.is_dir() {
        info.paid_list_bytes = Some(dir_size(&paid));
    }
    info
}

/// Apparent size of every regular file below `dir` (one level is enough for
/// LMDB environments, but recurse anyway).
pub fn dir_size(dir: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Ok(m) = e.metadata() {
                if m.is_dir() {
                    total += dir_size(&e.path());
                } else if m.is_file() {
                    total += m.len();
                }
            }
        }
    }
    total
}

/// Decode a chunk filename into its address. Returns `(address, was_uppercase)`;
/// the node itself only accepts lowercase, so uppercase is flagged.
pub fn decode_chunk_name(name: &str) -> Option<(XorName, bool)> {
    if name.len() != CHUNK_NAME_LEN || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(name).ok()?;
    let addr = XorName(<[u8; 32]>::try_from(bytes.as_slice()).ok()?);
    let upper = name.bytes().any(|b| b.is_ascii_uppercase());
    Some((addr, upper))
}

pub fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Parse a 64-hex address from the command line (either case, optional `0x`).
pub fn parse_address(s: &str) -> Result<XorName, String> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != CHUNK_NAME_LEN {
        return Err(format!("expected 64 hex characters, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map(XorName)
        .map_err(|_| "not a 32-byte address".to_string())
}

#[cfg(unix)]
fn allocated_bytes(meta: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(meta.blocks() * 512)
}

#[cfg(not(unix))]
fn allocated_bytes(_meta: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_chunk(chunks_dir: &Path, content: &[u8]) -> XorName {
        let addr = XorName(*blake3::hash(content).as_bytes());
        let shard = chunks_dir.join(format!("{:02x}", addr[31]));
        fs::create_dir_all(&shard).unwrap();
        fs::write(shard.join(hex::encode(addr)), content).unwrap();
        addr
    }

    #[test]
    fn scans_a_node_root_in_ant_node_layout() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let chunks = root.join("chunks");
        fs::create_dir_all(&chunks).unwrap();
        fs::write(
            chunks.join("layout.json"),
            r#"{"schema":1,"scheme":"suffix-hex","shard_chars":2,"depth":1,"name_encoding":"lower-hex"}"#,
        )
        .unwrap();
        fs::write(chunks.join(".lock"), b"").unwrap();
        let a = write_chunk(&chunks, b"chunk one");
        let b = write_chunk(&chunks, b"chunk two");
        // Node artifacts the scan must ignore or report, never count.
        fs::write(chunks.join("ab").join(".tmp.123.deadbeef.1"), b"partial").unwrap_or_else(|_| {
            fs::create_dir_all(chunks.join("ab")).unwrap();
            fs::write(chunks.join("ab").join(".tmp.123.deadbeef.1"), b"partial").unwrap();
        });
        fs::write(chunks.join("ab").join("junk.not-a-chunk"), b"x").unwrap();
        fs::write(chunks.join("ab").join("notes.txt"), b"x").unwrap();
        fs::write(root.join("migration-state.json"), r#"{"schema":1,"phase":"files_only"}"#).unwrap();
        fs::create_dir_all(root.join("paid_list.mdb")).unwrap();
        fs::write(root.join("paid_list.mdb").join("data.mdb"), vec![0u8; 1000]).unwrap();

        let mut scan = Scan::scan(root).unwrap();
        assert_eq!(scan.kind, TargetKind::NodeRoot);
        assert!(scan.layout.as_ref().unwrap().as_ref().unwrap().is_current());
        assert!(scan.lock_present);
        assert_eq!(scan.chunks.len(), 2);
        assert_eq!(scan.temp_files.len(), 1);
        assert_eq!(scan.quarantined.len(), 1);
        assert_eq!(scan.unexpected.len(), 1);
        assert!(scan.locate(&a).is_some());
        assert!(scan.locate(&b).is_some());
        assert!(scan.locate(&XorName([9u8; 32])).is_none());
        let node = scan.node.as_ref().unwrap();
        assert_eq!(node.paid_list_bytes, Some(1000));
        assert_eq!(node.migration_state.as_ref().unwrap()["phase"], "files_only");
        assert_eq!(node.legacy_env_bytes, None);

        // The store directory itself is recognized too.
        let inner = Scan::scan(&chunks).unwrap();
        assert_eq!(inner.kind, TargetKind::ChunkStore);
        assert_eq!(inner.chunks.len(), 2);

        // And a single shard.
        let shard = Scan::scan(&chunks.join(format!("{:02x}", a[31]))).unwrap();
        assert_eq!(shard.kind, TargetKind::ShardDir);
        assert!(!shard.chunks.is_empty());
    }

    #[test]
    fn generic_directory_hashes_unnamed_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("whatever.bin"), b"payload").unwrap();
        // A chunk-named file directly in the directory (no shard layer).
        let named = XorName(*blake3::hash(b"named").as_bytes());
        fs::write(dir.path().join(hex::encode(named)), b"named").unwrap();
        let mut scan = Scan::scan(dir.path()).unwrap();
        assert_eq!(scan.kind, TargetKind::GenericDir);
        assert_eq!(scan.chunks.len(), 2);
        scan.resolve_addresses().unwrap();
        let computed = XorName(*blake3::hash(b"payload").as_bytes());
        assert!(scan.locate(&computed).is_some());
        assert!(scan.locate(&named).is_some());
    }

    #[test]
    fn decodes_names_and_addresses() {
        let lower = "00".repeat(32);
        assert_eq!(decode_chunk_name(&lower), Some((XorName([0u8; 32]), false)));
        let upper = "AB".repeat(32);
        assert!(decode_chunk_name(&upper).unwrap().1);
        assert!(decode_chunk_name("zz").is_none());
        assert!(parse_address(&format!("0x{lower}")).is_ok());
        assert!(parse_address("abc").is_err());
    }
}

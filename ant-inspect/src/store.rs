//! Scanning of chunk directories: ant-node file stores and anything else.
//!
//! Two modes, chosen by what the path is:
//!
//! - **Store mode** — a node root (has `chunks/`) or a directory with
//!   `layout.json`. The scan applies ant-node's own rules from
//!   `src/storage/file_store.rs` (ADR-0014):
//!
//!   ```text
//!   {root}/chunks/                     store root
//!   {root}/chunks/layout.json          versioned layout marker
//!   {root}/chunks/.lock                advisory single-process guard
//!   {root}/chunks/<xy>/<64-hex>        xy = the LAST two hex characters of the address
//!   {root}/chunks/<xy>/.tmp.<pid>.<n>  an in-flight write, in the destination directory
//!   {root}/chunks/<xy>/<name>.not-a-chunk   an entry the node quarantined
//!   ```
//!
//!   A chunk the node would *not* index (wrong shard, wrong depth, uppercase
//!   name, not a regular file) is reported as such, because the node's read
//!   path only ever looks at `chunks/<last two hex>/<address>`.
//!
//! - **Directory mode** — any other directory. It is walked recursively and
//!   every regular file is a chunk candidate, whatever the subdirectory
//!   structure (flat, sharded on a prefix or suffix of any length, nested).
//!   No layout is assumed; the structure actually found is reported.
//!
//! The filename is the address when it is 64 hex characters; otherwise the
//! address is computed from the content on demand.
//!
//! Big stores: directories are walked in parallel, entries are kept compact
//! (~80 bytes per chunk) and looked up by binary search, so millions of
//! chunks fit comfortably in memory. Nothing is ever written.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
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
pub const CHUNK_NAME_LEN: usize = 64;

/// Directory nesting we follow before giving up on a subtree.
const MAX_DEPTH: usize = 32;

/// The on-disk layout marker (`layout.json`), mirrored from ant-node's
/// `StoreLayout`. Unknown fields are kept in `extra`.
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
    /// The one layout ant-node implements today.
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
    /// A node root directory: contains `chunks/`. Store mode.
    NodeRoot,
    /// A store directory with `layout.json`. Store mode.
    ChunkStore,
    /// Any other directory: walked recursively, no layout assumed.
    Directory,
}

impl TargetKind {
    pub fn label(self) -> &'static str {
        match self {
            TargetKind::NodeRoot => "node root directory (ant-node store rules apply)",
            TargetKind::ChunkStore => "chunk store directory (ant-node store rules apply)",
            TargetKind::Directory => "directory (recursive scan, any structure)",
        }
    }

    pub fn is_store(self) -> bool {
        !matches!(self, TargetKind::Directory)
    }
}

/// One chunk file. Compact: the path is reconstructed from the directory
/// table and the address, so a store with millions of files stays small.
#[derive(Clone, Debug)]
pub struct ChunkEntry {
    /// Index into [`Scan::dirs`].
    pub dir: u32,
    /// Filename, kept only when it is not the lowercase hex of `name_address`.
    name: Option<Box<str>>,
    /// Address decoded from the filename when it is 64 hex characters.
    pub name_address: Option<XorName>,
    /// Address computed from the content (see [`Scan::resolve_addresses`]).
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

    pub fn file_name(&self) -> String {
        match (&self.name, self.name_address) {
            (Some(n), _) => n.to_string(),
            (None, Some(a)) => hex::encode(a),
            (None, None) => String::new(),
        }
    }
}

/// How the chunk files are actually arranged below the scanned directory,
/// inferred from the files themselves (not from `layout.json`).
#[derive(Serialize, Clone, Debug, Default)]
pub struct Structure {
    /// Directories that hold at least one chunk file.
    pub dirs_with_chunks: usize,
    pub files_per_dir_min: u64,
    pub files_per_dir_max: u64,
    pub files_per_dir_mean: f64,
    /// Shallowest / deepest chunk file, in directory levels below the root.
    pub depth_min: usize,
    pub depth_max: usize,
    /// Sharding scheme the majority of files follow: "flat", "prefix-hex",
    /// "suffix-hex" or "other".
    pub scheme: String,
    /// Hex characters of the address used per directory level (for
    /// prefix/suffix schemes).
    pub shard_chars: usize,
    /// Files whose location matches `scheme`.
    pub matching: usize,
    /// Files that do not.
    pub off_scheme: usize,
}

/// Facts about a node root beside the chunk store.
#[derive(Serialize, Clone, Debug, Default)]
pub struct NodeRootInfo {
    pub migration_state: Option<serde_json::Value>,
    pub migration_state_error: Option<String>,
    pub legacy_env_bytes: Option<u64>,
    pub retired_env_bytes: Option<u64>,
    pub legacy_env_marked_retired: bool,
    pub paid_list_bytes: Option<u64>,
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
    /// Every directory visited; index 0 is `chunks_dir`.
    pub dirs: Vec<PathBuf>,
    /// Chunk files per directory (parallel to `dirs`).
    pub dir_counts: Vec<u64>,
    /// Sorted by address (entries without a known address first).
    pub chunks: Vec<ChunkEntry>,
    pub temp_files: Vec<PathBuf>,
    pub quarantined: Vec<PathBuf>,
    /// Store mode only: chunk-named files the node would not index because
    /// they are not at `chunks/<last two hex>/<address>`.
    pub misfiled: Vec<PathBuf>,
    /// Store mode: entries that are neither chunk files nor known artifacts.
    pub unexpected: Vec<PathBuf>,
    pub errors: Vec<String>,
    pub node: Option<NodeRootInfo>,
    pub structure: Structure,
    sorted: bool,
}

/// Per-thread scan output, merged into the `Scan` afterwards.
#[derive(Default)]
struct Partial {
    dirs: Vec<PathBuf>,
    dir_counts: Vec<u64>,
    chunks: Vec<ChunkEntry>,
    temp_files: Vec<PathBuf>,
    quarantined: Vec<PathBuf>,
    unexpected: Vec<PathBuf>,
    errors: Vec<String>,
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
            dirs: vec![chunks_dir.clone()],
            dir_counts: vec![0],
            chunks: Vec::new(),
            temp_files: Vec::new(),
            quarantined: Vec::new(),
            misfiled: Vec::new(),
            unexpected: Vec::new(),
            errors: Vec::new(),
            node: None,
            structure: Structure::default(),
            sorted: false,
        };
        if kind.is_store() {
            scan.layout = read_layout(&chunks_dir);
            scan.lock_present = chunks_dir.join(LOCK_FILE_NAME).is_file();
        }
        if kind == TargetKind::NodeRoot {
            scan.node = Some(read_node_root(path));
        }

        scan.walk_parallel();
        if kind.is_store() {
            scan.check_store_rules();
        }
        scan.infer_structure();
        scan.sort();
        Ok(scan)
    }

    /// Walk the root directory; its subdirectories are handed to a pool of
    /// worker threads, each walking one subtree at a time.
    fn walk_parallel(&mut self) {
        let store_mode = self.kind.is_store();
        let root = self.chunks_dir.clone();
        let entries = match fs::read_dir(&root) {
            Ok(e) => e,
            Err(e) => {
                self.errors.push(format!("{}: {e}", root.display()));
                return;
            }
        };

        // Files directly in the root are handled here; subdirectories go to
        // the work queue.
        let mut root_partial = Partial::default();
        root_partial.dirs.push(root.clone());
        root_partial.dir_counts.push(0);
        let mut subdirs: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if store_mode && (name == LEGACY_ENV_DIR || name == PAID_LIST_DIR) {
                    continue;
                }
                if name.starts_with('.') {
                    continue;
                }
                subdirs.push(entry.path());
            } else {
                classify_entry(&entry, 0, store_mode, true, &mut root_partial);
            }
        }
        // Root files: fold into the scan's dir 0.
        self.dir_counts[0] = root_partial.dir_counts[0];
        self.chunks.extend(root_partial.chunks);
        self.temp_files.extend(root_partial.temp_files);
        self.quarantined.extend(root_partial.quarantined);
        self.unexpected.extend(root_partial.unexpected);
        self.errors.extend(root_partial.errors);

        subdirs.sort();
        let progress = Progress::new();
        let queue = Mutex::new(subdirs);
        let results: Mutex<Vec<Partial>> = Mutex::new(Vec::new());
        let workers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, 16);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| {
                    let mut partial = Partial::default();
                    loop {
                        let next = queue.lock().unwrap().pop();
                        let Some(dir) = next else { break };
                        walk_dir(&dir, 1, store_mode, &mut partial, &progress);
                    }
                    results.lock().unwrap().push(partial);
                });
            }
        });
        progress.finish();

        let mut partials = results.into_inner().unwrap();
        // Deterministic merge order regardless of thread timing.
        partials.sort_by(|a, b| a.dirs.first().cmp(&b.dirs.first()));
        for partial in partials {
            let offset = self.dirs.len() as u32;
            self.dirs.extend(partial.dirs);
            self.dir_counts.extend(partial.dir_counts);
            self.chunks.extend(partial.chunks.into_iter().map(|mut c| {
                c.dir += offset;
                c
            }));
            self.temp_files.extend(partial.temp_files);
            self.quarantined.extend(partial.quarantined);
            self.unexpected.extend(partial.unexpected);
            self.errors.extend(partial.errors);
        }
        self.temp_files.sort();
        self.quarantined.sort();
        self.unexpected.sort();
    }

    /// Work out how the files are arranged: depth, files per directory, and
    /// whether directory names are a prefix or suffix of the addresses.
    fn infer_structure(&mut self) {
        let counts: Vec<u64> = self.dir_counts.iter().copied().filter(|&c| c > 0).collect();
        let mut st = Structure {
            dirs_with_chunks: counts.len(),
            files_per_dir_min: counts.iter().copied().min().unwrap_or(0),
            files_per_dir_max: counts.iter().copied().max().unwrap_or(0),
            files_per_dir_mean: if counts.is_empty() {
                0.0
            } else {
                self.chunks.len() as f64 / counts.len() as f64
            },
            ..Default::default()
        };
        if self.chunks.is_empty() {
            st.scheme = "empty".into();
            self.structure = st;
            return;
        }

        // Relative directory components per distinct directory (cached).
        let rel: Vec<Vec<String>> = self
            .dirs
            .iter()
            .map(|d| {
                d.strip_prefix(&self.chunks_dir)
                    .map(|r| r.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect())
                    .unwrap_or_default()
            })
            .collect();

        let mut depth_min = usize::MAX;
        let mut depth_max = 0;
        let mut flat = 0usize;
        let mut prefix = 0usize;
        let mut suffix = 0usize;
        let mut prefix_chars = 0usize;
        let mut suffix_chars = 0usize;
        let mut named = 0usize;
        for c in &self.chunks {
            let comps = &rel[c.dir as usize];
            depth_min = depth_min.min(comps.len());
            depth_max = depth_max.max(comps.len());
            let Some(addr) = c.name_address else { continue };
            named += 1;
            if comps.is_empty() {
                flat += 1;
                continue;
            }
            let hex = hex::encode(addr);
            let joined: String = comps.concat().to_ascii_lowercase();
            if hex.starts_with(&joined) {
                prefix += 1;
                prefix_chars = joined.len();
            } else if comps.len() == 1 && hex.ends_with(&joined) {
                suffix += 1;
                suffix_chars = joined.len();
            }
        }
        st.depth_min = if depth_min == usize::MAX { 0 } else { depth_min };
        st.depth_max = depth_max;
        let (scheme, chars, matching) = if named == 0 {
            ("other", 0, 0)
        } else if flat * 2 > named {
            ("flat", 0, flat)
        } else if prefix >= suffix && prefix * 2 > named {
            ("prefix-hex", prefix_chars, prefix)
        } else if suffix * 2 > named {
            ("suffix-hex", suffix_chars, suffix)
        } else {
            ("other", 0, 0)
        };
        st.scheme = scheme.into();
        st.shard_chars = chars;
        st.matching = matching;
        st.off_scheme = named.saturating_sub(matching);
        self.structure = st;
    }

    /// Store mode: move every chunk the node would not find into `misfiled`.
    /// Only the current layout (`suffix-hex`, 2 chars, depth 1) is known;
    /// under an unknown `layout.json` nothing is judged.
    fn check_store_rules(&mut self) {
        let judge = match &self.layout {
            Some(Ok(l)) => l.is_current(),
            // No marker: the node adopts the current scheme.
            None => true,
            Some(Err(_)) => false,
        };
        if !judge {
            return;
        }
        let rel: Vec<Option<String>> = self
            .dirs
            .iter()
            .map(|d| {
                let r = d.strip_prefix(&self.chunks_dir).ok()?;
                let mut comps = r.components();
                let first = comps.next()?.as_os_str().to_string_lossy().into_owned();
                comps.next().is_none().then_some(first)
            })
            .collect();
        let mut kept = Vec::with_capacity(self.chunks.len());
        for c in std::mem::take(&mut self.chunks) {
            let ok = match (c.name_address, &rel[c.dir as usize]) {
                (Some(addr), Some(shard)) => !c.uppercase_name && *shard == format!("{:02x}", addr[31]),
                _ => false,
            };
            if ok {
                kept.push(c);
            } else {
                self.dir_counts[c.dir as usize] = self.dir_counts[c.dir as usize].saturating_sub(1);
                self.misfiled.push(self.path_of(&c));
            }
        }
        self.chunks = kept;
        self.misfiled.sort();
    }

    fn sort(&mut self) {
        self.chunks.sort_by(|a, b| a.address().cmp(&b.address()).then(a.dir.cmp(&b.dir)));
        self.sorted = true;
    }

    /// Full path of an entry.
    pub fn path_of(&self, entry: &ChunkEntry) -> PathBuf {
        self.dirs[entry.dir as usize].join(entry.file_name())
    }

    /// Compute the content address of every entry whose filename did not
    /// carry one. Reads those files.
    pub fn resolve_addresses(&mut self) -> io::Result<()> {
        let mut changed = false;
        for i in 0..self.chunks.len() {
            if self.chunks[i].address().is_none() {
                let path = self.path_of(&self.chunks[i]);
                let bytes = fs::read(&path)?;
                self.chunks[i].computed_address = Some(XorName(*blake3::hash(&bytes).as_bytes()));
                changed = true;
            }
        }
        if changed {
            self.sort();
        }
        Ok(())
    }

    /// Find the chunk with this address (binary search over the sorted list).
    pub fn locate(&self, address: &XorName) -> Option<&ChunkEntry> {
        debug_assert!(self.sorted);
        let i = self.chunks.partition_point(|c| c.address() < Some(*address));
        self.chunks.get(i).filter(|c| c.address() == Some(*address))
    }

    /// Where the node would look for this address (current layout only).
    pub fn expected_path(&self, address: &XorName) -> Option<PathBuf> {
        let current = match &self.layout {
            Some(Ok(l)) => l.is_current(),
            None => self.kind.is_store(),
            Some(Err(_)) => false,
        };
        current.then(|| self.chunks_dir.join(format!("{:02x}", address[31])).join(hex::encode(address)))
    }

    pub fn total_bytes(&self) -> u64 {
        self.chunks.iter().map(|c| c.size).sum()
    }

    pub fn allocated_bytes(&self) -> Option<u64> {
        self.chunks.iter().map(|c| c.allocated).sum()
    }

    pub fn read(&self, entry: &ChunkEntry) -> io::Result<Vec<u8>> {
        fs::read(self.path_of(entry))
    }
}

/// Recursive walk of one subtree into `partial`.
fn walk_dir(dir: &Path, depth: usize, store_mode: bool, partial: &mut Partial, progress: &Progress) {
    if depth > MAX_DEPTH {
        partial.errors.push(format!("{}: nested too deep, skipped", dir.display()));
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            partial.errors.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    let dir_index = partial.dirs.len();
    partial.dirs.push(dir.to_path_buf());
    partial.dir_counts.push(0);
    for entry in entries.flatten() {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            walk_dir(&entry.path(), depth + 1, store_mode, partial, progress);
            continue;
        }
        classify_entry(&entry, dir_index, store_mode, false, partial);
        progress.tick();
    }
}

/// Sort one non-directory entry into the partial result.
fn classify_entry(entry: &fs::DirEntry, dir_index: usize, store_mode: bool, at_root: bool, partial: &mut Partial) {
    let name_os = entry.file_name();
    let name = name_os.to_string_lossy();
    if store_mode && at_root && (name == LAYOUT_FILE_NAME || name == LOCK_FILE_NAME || name == MIGRATION_STATE_FILE) {
        return;
    }
    if name.starts_with(TEMP_PREFIX) {
        partial.temp_files.push(entry.path());
        return;
    }
    if name.ends_with(QUARANTINE_SUFFIX) {
        partial.quarantined.push(entry.path());
        return;
    }
    if name.starts_with('.') {
        if store_mode {
            partial.unexpected.push(entry.path());
        }
        return;
    }
    let decoded = decode_chunk_name(&name);
    if store_mode && decoded.is_none() {
        partial.unexpected.push(entry.path());
        return;
    }
    let meta = match entry.metadata() {
        Ok(m) => m,
        Err(e) => {
            partial.errors.push(format!("{}: {e}", entry.path().display()));
            return;
        }
    };
    if !meta.is_file() {
        if store_mode {
            partial.unexpected.push(entry.path());
        }
        return;
    }
    let (name_address, uppercase) = match decoded {
        Some((a, u)) => (Some(a), u),
        None => (None, false),
    };
    let keep_name = name_address.is_none() || uppercase;
    partial.dir_counts[dir_index] += 1;
    partial.chunks.push(ChunkEntry {
        dir: dir_index as u32,
        name: keep_name.then(|| name.into_owned().into_boxed_str()),
        name_address,
        computed_address: None,
        size: meta.len(),
        allocated: allocated_bytes(&meta),
        uppercase_name: uppercase,
    });
}

/// Progress on stderr for big stores (only when stderr is a terminal).
struct Progress {
    files: AtomicU64,
    enabled: bool,
    last_len: AtomicUsize,
}

impl Progress {
    fn new() -> Self {
        Progress { files: AtomicU64::new(0), enabled: io::stderr().is_terminal(), last_len: AtomicUsize::new(0) }
    }

    fn tick(&self) {
        if !self.enabled {
            return;
        }
        let n = self.files.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_multiple_of(50_000) {
            let msg = format!("\rscanning… {n} files");
            self.last_len.store(msg.len(), Ordering::Relaxed);
            let mut e = io::stderr().lock();
            let _ = e.write_all(msg.as_bytes());
            let _ = e.flush();
        }
    }

    fn finish(&self) {
        if self.enabled && self.last_len.load(Ordering::Relaxed) > 0 {
            let mut e = io::stderr().lock();
            let _ = write!(e, "\r{}\r", " ".repeat(self.last_len.load(Ordering::Relaxed)));
            let _ = e.flush();
        }
    }
}

/// Decide what kind of directory `path` is.
pub fn detect_kind(path: &Path) -> TargetKind {
    let chunks = path.join(CHUNKS_DIR_NAME);
    if chunks.is_dir() && (chunks.join(LAYOUT_FILE_NAME).is_file() || has_suffix_shard_dirs(&chunks)) {
        return TargetKind::NodeRoot;
    }
    if path.join(LAYOUT_FILE_NAME).is_file() {
        return TargetKind::ChunkStore;
    }
    TargetKind::Directory
}

/// A `chunks/` directory without `layout.json` still counts as a node store
/// when it holds `<xy>/` shards (the node adopts the current layout on open).
fn has_suffix_shard_dirs(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        e.file_type().map(|t| t.is_dir()).unwrap_or(false)
            && e.file_name().to_str().is_some_and(|n| n.len() == 2 && is_lower_hex(n))
    })
}

/// True when the directory name looks like a shard name (short hex).
pub fn looks_like_shard_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| (1..=8).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// True when the directory holds at least one chunk-named file.
pub fn has_chunk_files(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries
        .flatten()
        .any(|e| e.file_name().to_str().is_some_and(|n| decode_chunk_name(n).is_some()))
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
        match fs::read(&state)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).map_err(|e| e.to_string()))
        {
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

/// Apparent size of every regular file below `dir`.
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

/// Decode a chunk filename into its address. Returns `(address, was_uppercase)`.
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

    fn addr_of(content: &[u8]) -> XorName {
        XorName(*blake3::hash(content).as_bytes())
    }

    /// Write a chunk under the ant-node layout (last two hex chars).
    fn write_suffix(chunks_dir: &Path, content: &[u8]) -> XorName {
        let addr = addr_of(content);
        let shard = chunks_dir.join(format!("{:02x}", addr[31]));
        fs::create_dir_all(&shard).unwrap();
        fs::write(shard.join(hex::encode(addr)), content).unwrap();
        addr
    }

    /// Write a chunk under a prefix layout with `n` hex chars.
    fn write_prefix(dir: &Path, content: &[u8], n: usize) -> XorName {
        let addr = addr_of(content);
        let hex = hex::encode(addr);
        let shard = dir.join(&hex[..n]);
        fs::create_dir_all(&shard).unwrap();
        fs::write(shard.join(&hex), content).unwrap();
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
        let a = write_suffix(&chunks, b"chunk one");
        let b = write_suffix(&chunks, b"chunk two");
        fs::create_dir_all(chunks.join("ab")).unwrap();
        fs::write(chunks.join("ab").join(".tmp.123.deadbeef.1"), b"partial").unwrap();
        fs::write(chunks.join("ab").join("junk.not-a-chunk"), b"x").unwrap();
        fs::write(chunks.join("ab").join("notes.txt"), b"x").unwrap();
        // A real chunk name in the wrong shard: the node cannot find it.
        let misfiled = addr_of(b"misfiled");
        assert_ne!(misfiled[31], 0xab);
        fs::write(chunks.join("ab").join(hex::encode(misfiled)), b"misfiled").unwrap();
        // A chunk nested one level too deep, and one directly in chunks/.
        let deep = addr_of(b"deep");
        let deep_dir = chunks.join(format!("{:02x}", deep[31])).join("extra");
        fs::create_dir_all(&deep_dir).unwrap();
        fs::write(deep_dir.join(hex::encode(deep)), b"deep").unwrap();
        let top = addr_of(b"top");
        fs::write(chunks.join(hex::encode(top)), b"top").unwrap();
        fs::write(root.join("migration-state.json"), r#"{"schema":1,"phase":"files_only"}"#).unwrap();
        fs::create_dir_all(root.join("paid_list.mdb")).unwrap();
        fs::write(root.join("paid_list.mdb").join("data.mdb"), vec![0u8; 1000]).unwrap();

        let scan = Scan::scan(root).unwrap();
        assert_eq!(scan.kind, TargetKind::NodeRoot);
        assert!(scan.layout.as_ref().unwrap().as_ref().unwrap().is_current());
        assert!(scan.lock_present);
        assert_eq!(scan.chunks.len(), 2);
        assert_eq!(scan.temp_files.len(), 1);
        assert_eq!(scan.quarantined.len(), 1);
        assert_eq!(scan.unexpected.len(), 1, "{:?}", scan.unexpected);
        assert_eq!(scan.misfiled.len(), 3, "{:?}", scan.misfiled);
        assert!(scan.locate(&a).is_some());
        assert!(scan.locate(&b).is_some());
        assert!(scan.locate(&misfiled).is_none());
        assert!(scan.locate(&XorName([9u8; 32])).is_none());
        assert_eq!(scan.path_of(scan.locate(&a).unwrap()), chunks.join(format!("{:02x}", a[31])).join(hex::encode(a)));
        assert_eq!(scan.expected_path(&a), Some(scan.path_of(scan.locate(&a).unwrap())));
        assert_eq!(scan.structure.scheme, "suffix-hex");
        assert_eq!(scan.structure.shard_chars, 2);
        let node = scan.node.as_ref().unwrap();
        assert_eq!(node.paid_list_bytes, Some(1000));
        assert_eq!(node.migration_state.as_ref().unwrap()["phase"], "files_only");
        assert_eq!(node.legacy_env_bytes, None);

        // The store directory itself is recognized too.
        let inner = Scan::scan(&chunks).unwrap();
        assert_eq!(inner.kind, TargetKind::ChunkStore);
        assert_eq!(inner.chunks.len(), 2);
    }

    #[test]
    fn any_directory_structure_is_accepted_without_judgement() {
        // A big store sharded on the first three hex characters, plus one
        // file deeper down and one with a non-hex name.
        let dir = tempfile::tempdir().unwrap();
        let mut addrs = Vec::new();
        for i in 0..20u8 {
            addrs.push(write_prefix(dir.path(), &[i; 100], 3));
        }
        let nested = dir.path().join("zzz").join("more");
        fs::create_dir_all(&nested).unwrap();
        let deep = addr_of(b"deep");
        fs::write(nested.join(hex::encode(deep)), b"deep").unwrap();
        fs::write(nested.join("whatever.bin"), b"payload").unwrap();

        let mut scan = Scan::scan(dir.path()).unwrap();
        assert_eq!(scan.kind, TargetKind::Directory);
        assert_eq!(scan.chunks.len(), 22);
        assert!(scan.misfiled.is_empty());
        assert!(scan.unexpected.is_empty());
        assert_eq!(scan.structure.scheme, "prefix-hex");
        assert_eq!(scan.structure.shard_chars, 3);
        assert_eq!(scan.structure.matching, 20);
        assert_eq!(scan.structure.off_scheme, 1);
        assert_eq!(scan.structure.depth_max, 2);
        assert_eq!(scan.expected_path(&addrs[0]), None);
        for a in &addrs {
            assert!(scan.locate(a).is_some());
        }
        assert!(scan.locate(&deep).is_some());

        scan.resolve_addresses().unwrap();
        let computed = addr_of(b"payload");
        let e = scan.locate(&computed).unwrap();
        assert_eq!(scan.path_of(e), nested.join("whatever.bin"));
    }

    #[test]
    fn prefix_two_is_not_mistaken_for_a_node_store() {
        // Same-looking "<xy>/" directories, but sharded on the FIRST two
        // characters and without layout.json: directory mode, nothing misfiled.
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10u8 {
            write_prefix(dir.path(), &[i; 50], 2);
        }
        let scan = Scan::scan(dir.path()).unwrap();
        assert_eq!(scan.kind, TargetKind::Directory);
        assert_eq!(scan.chunks.len(), 10);
        assert!(scan.misfiled.is_empty());
        assert_eq!(scan.structure.scheme, "prefix-hex");
        assert_eq!(scan.structure.shard_chars, 2);
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

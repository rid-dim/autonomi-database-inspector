//! ant-inspect — inspect ant-node file-based chunk stores and DataMaps.
//!
//! Give it an absolute path and it works out what it is:
//!
//! - a **node root** (`…/nodes/<peer-id>/`, contains `chunks/`)
//! - a **chunk store** (`chunks/` with `layout.json` and `<xy>/` shards)
//! - a **shard directory** or any **directory of chunk files**
//! - a **single file**: a chunk, a public DataMap chunk, a `.datamap` file
//!
//! and prints a report: layout, counts, sizes, statistics, content
//! classification (DataMap / self-encrypted / plaintext), and — for a
//! DataMap — the chunk addresses in order, with a check of which of them the
//! local store holds. Everything is strictly read-only.

mod classify;
mod datamap;
mod store;

use classify::{classify, Classification, ContentClass};
use clap::{Parser, ValueEnum};
use datamap::{ChunkRow, DataMapStats, ParsedDataMap, WireFormat};
use self_encryption::DataMap;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use store::{Scan, TargetKind};
use xor_name::XorName;

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_VERIFY_FAILED: u8 = 2;
const EXIT_NOT_FOUND: u8 = 3;

#[derive(Parser)]
#[command(
    name = "ant-inspect",
    version,
    about = "Inspect ant-node chunk stores and self-encryption DataMaps (read-only)",
    long_about = "Inspect ant-node chunk stores and self-encryption DataMaps (read-only).\n\n\
        PATH may be:\n  \
        - a node root directory (contains chunks/)\n  \
        - a chunk store directory (chunks/ with layout.json and <xy>/ shards)\n  \
        - a shard directory or any directory holding chunk files (scanned recursively)\n  \
        - a single file: a chunk, a public DataMap chunk, or a .datamap file\n\n\
        Exit codes: 0 ok · 1 error · 2 verification failures · 3 not a DataMap / not found"
)]
struct Args {
    /// Path to inspect (node root, chunks/ dir, any directory, or a file)
    path: PathBuf,

    /// Emit the report as JSON
    #[arg(long)]
    json: bool,

    /// Print one line per chunk (store: address, size[, class]; DataMap: index,
    /// address, src size[, src hash][, local]). Tab-separated.
    #[arg(long, short = 'l')]
    list: bool,

    /// Print only chunk addresses, one per line, nothing else. For a DataMap
    /// these are its chunk addresses in order. Exit 3 if PATH is not a DataMap.
    #[arg(long, short = 'a')]
    addresses: bool,

    /// Sort order for --list / --addresses on a store
    #[arg(long, value_enum, default_value_t = SortOrder::Addr)]
    sort: SortOrder,

    /// Cap the list at N entries (0 = all)
    #[arg(long, default_value_t = 0)]
    limit: usize,

    /// Recompute BLAKE3 over every chunk file and compare with its filename.
    /// Exit 2 on any mismatch.
    #[arg(long)]
    verify: bool,

    /// Classify every chunk's content (DataMap / encrypted / media / text /
    /// binary) and print the distribution. Reads every file.
    #[arg(long, short = 'c')]
    classify: bool,

    /// Find every public DataMap in the store and report its stats and how
    /// many of its chunks the store holds. Reads every file up to 1 MiB.
    #[arg(long, short = 'd')]
    datamaps: bool,

    /// With --classify: assume chunks at least this large are self-encrypted
    /// and skip scanning their payload (0 = scan everything). Default 3.5 MiB.
    #[arg(long, value_name = "BYTES", default_value_t = 3_670_016)]
    assume_encrypted_above: u64,

    /// Inspect one chunk of the store by its address (64 hex)
    #[arg(long, value_name = "ADDR")]
    chunk: Option<String>,

    /// Print the path of the chunk with this address inside the store and
    /// exit (3 if absent)
    #[arg(long, value_name = "ADDR")]
    locate: Option<String>,

    /// Chunk store / directory to check DataMap chunks against and to resolve
    /// from (default: the store the file lives in, if any)
    #[arg(long, short = 's', value_name = "DIR")]
    store: Option<PathBuf>,

    /// For a shrunk (child) DataMap: decrypt the parent level(s) from local
    /// chunks down to the root DataMap and report each level
    #[arg(long, short = 'r')]
    resolve: bool,

    /// Reconstruct the file described by the (root) DataMap from local chunks
    /// and write it here. Implies --resolve.
    #[arg(long, value_name = "FILE")]
    decrypt: Option<PathBuf>,

    /// Exit 0 if PATH is a DataMap, 3 otherwise. Prints nothing.
    #[arg(long)]
    is_datamap: bool,

    /// In DataMap lists, also print the plaintext hash (src_hash)
    #[arg(long)]
    src: bool,

    /// Suppress the report; print only the requested list
    #[arg(long, short = 'q')]
    quiet: bool,
}

#[derive(Copy, Clone, ValueEnum, PartialEq, Eq)]
enum SortOrder {
    /// Ascending by address
    Addr,
    /// Descending by size
    Size,
}

// ───────────────────────────── report model ─────────────────────────────

#[derive(Serialize)]
struct FileReport {
    path: String,
    size_bytes: u64,
    /// BLAKE3 of the content: the address this file has as a chunk.
    address: String,
    /// Address decoded from the filename, if it is one.
    name_address: Option<String>,
    /// Whether content hash and filename agree.
    name_matches: Option<bool>,
    classification: Classification,
    datamap: Option<DataMapReport>,
    /// Parent levels decrypted with --resolve, from the given map's parent
    /// down to the root (last entry).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    resolved: Vec<DataMapReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolve_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decrypted: Option<DecryptReport>,
}

#[derive(Serialize)]
struct DecryptReport {
    output: String,
    bytes: u64,
    /// The plaintext of each chunk was checked against `src_hash`.
    verified: bool,
}

#[derive(Serialize, Clone)]
struct DataMapReport {
    format: WireFormat,
    /// Shrink level; `None` for a root DataMap.
    child: Option<usize>,
    serialized_bytes: usize,
    /// Address this DataMap has (or would have) as a public chunk: BLAKE3 of
    /// its current-format MessagePack encoding.
    network_address: String,
    stats: DataMapStats,
    chunks: Vec<ChunkRowLocal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<CoverageReport>,
}

#[derive(Serialize, Clone)]
struct ChunkRowLocal {
    #[serde(flatten)]
    row: ChunkRow,
    /// Present in the local store (None when no store is known).
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<bool>,
    /// Size of the stored (encrypted) chunk file when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    local_size: Option<u64>,
}

#[derive(Serialize, Clone)]
struct CoverageReport {
    store: String,
    present: usize,
    total: usize,
    /// Bytes of the present chunk files.
    present_bytes: u64,
    complete: bool,
}

#[derive(Serialize)]
struct StoreReport {
    kind: TargetKind,
    target: String,
    chunks_dir: String,
    layout: Option<store::StoreLayout>,
    layout_error: Option<String>,
    layout_is_current: Option<bool>,
    lock_present: bool,
    shards_present: usize,
    shard_fill: Option<ShardFill>,
    chunk_count: usize,
    total_bytes: u64,
    allocated_bytes: Option<u64>,
    uppercase_names: usize,
    temp_files: Vec<String>,
    quarantined: Vec<String>,
    unexpected: Vec<String>,
    errors: Vec<String>,
    address_spread: Option<AddressSpread>,
    node: Option<store::NodeRootInfo>,
    statistics: Option<StatsReport>,
    content_distribution: Option<Vec<ClassBucket>>,
    datamaps: Option<Vec<DataMapSummary>>,
    verification: Option<VerifyReport>,
    records: Option<Vec<RecordReport>>,
    records_truncated_at: Option<usize>,
}

#[derive(Serialize)]
struct ShardFill {
    min: u64,
    max: u64,
    mean: f64,
    /// Shards (of 256) that hold at least one chunk.
    non_empty: usize,
}

/// How the stored addresses spread over the XOR space. A node's holdings
/// cluster around its own ID (it stores what it is close to), so the leading
/// bits are shared while the trailing bits are uniform.
#[derive(Serialize)]
struct AddressSpread {
    /// Number of leading bits every stored address has in common.
    common_prefix_bits: u32,
    /// Distinct values of the first address byte.
    distinct_first_bytes: usize,
    /// Distinct values of the last address byte (= shards used).
    distinct_last_bytes: usize,
}

#[derive(Serialize)]
struct StatsReport {
    total_bytes: u64,
    min_bytes: u64,
    max_bytes: u64,
    mean_bytes: u64,
    median_bytes: u64,
    p90_bytes: u64,
    p99_bytes: u64,
    histogram: Vec<HistogramBucket>,
}

#[derive(Serialize)]
struct HistogramBucket {
    label: String,
    upper_bound_bytes: Option<u64>,
    count: u64,
}

#[derive(Serialize)]
struct ClassBucket {
    class: ContentClass,
    description: String,
    count: u64,
    bytes: u64,
    percent: f64,
}

#[derive(Serialize)]
struct DataMapSummary {
    address: String,
    path: String,
    format: WireFormat,
    child: Option<usize>,
    chunk_count: usize,
    content_bytes: u64,
    local_present: usize,
}

#[derive(Serialize)]
struct VerifyReport {
    checked: u64,
    ok: u64,
    failed: u64,
    unreadable: u64,
    failures: Vec<VerifyFailure>,
}

#[derive(Serialize)]
struct VerifyFailure {
    path: String,
    expected: String,
    computed: String,
}

#[derive(Serialize)]
struct RecordReport {
    address: String,
    size_bytes: u64,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<Classification>,
}

// ───────────────────────────── entry point ─────────────────────────────

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(args: &Args) -> Result<u8, String> {
    let path = &args.path;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;

    if meta.is_file() {
        let store_scan = match &args.store {
            Some(dir) => Some(scan_dir(dir)?),
            None => find_store_for_file(path).map(|d| scan_dir(&d)).transpose()?,
        };
        return inspect_file(args, path, store_scan);
    }
    if !meta.is_dir() {
        return Err(format!("{}: neither a file nor a directory", path.display()));
    }

    let mut scan = scan_dir(path)?;

    if let Some(addr) = &args.locate {
        let addr = store::parse_address(addr)?;
        scan.resolve_addresses().map_err(|e| e.to_string())?;
        return Ok(match scan.locate(&addr) {
            Some(entry) => {
                println!("{}", entry.path.display());
                EXIT_OK
            }
            None => {
                if !args.quiet {
                    eprintln!("not found: {} (expected at {})", hex::encode(addr), scan.expected_path(&addr).display());
                }
                EXIT_NOT_FOUND
            }
        });
    }

    if let Some(addr) = &args.chunk {
        let addr = store::parse_address(addr)?;
        scan.resolve_addresses().map_err(|e| e.to_string())?;
        let Some(entry) = scan.locate(&addr) else {
            eprintln!("not found: {} (expected at {})", hex::encode(addr), scan.expected_path(&addr).display());
            return Ok(EXIT_NOT_FOUND);
        };
        let file = entry.path.clone();
        return inspect_file(args, &file, Some(scan));
    }

    inspect_store(args, scan)
}

fn scan_dir(dir: &Path) -> Result<Scan, String> {
    Scan::scan(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// For a file inside a store (`…/chunks/<xy>/<addr>`, `…/chunks/<addr>` or any
/// directory of chunk files), find the store directory to check against.
fn find_store_for_file(file: &Path) -> Option<PathBuf> {
    let abs = std::fs::canonicalize(file).ok()?;
    let mut dir = abs.parent()?;
    for _ in 0..3 {
        let kind = store::detect_kind(dir);
        match kind {
            TargetKind::ChunkStore | TargetKind::NodeRoot => return Some(dir.to_path_buf()),
            TargetKind::ShardDir => {}
            TargetKind::GenericDir => {}
        }
        dir = dir.parent()?;
    }
    // Not inside a recognizable store: fall back to the file's own directory
    // when it holds other chunk-named files (a dump directory).
    let parent = abs.parent()?;
    if store::detect_kind(parent) == TargetKind::ShardDir {
        return Some(parent.to_path_buf());
    }
    let has_siblings = std::fs::read_dir(parent).ok()?.flatten().any(|e| {
        e.path() != abs && e.file_name().to_str().is_some_and(|n| store::decode_chunk_name(n).is_some())
    });
    has_siblings.then(|| parent.to_path_buf())
}

// ───────────────────────────── single file ─────────────────────────────

fn inspect_file(args: &Args, path: &Path, mut store_scan: Option<Scan>) -> Result<u8, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let address = XorName(*blake3::hash(&bytes).as_bytes());
    let name_address = path
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(store::decode_chunk_name)
        .map(|(a, _)| a);

    let parsed = datamap::parse(&bytes);

    if args.is_datamap {
        return Ok(if parsed.is_some() { EXIT_OK } else { EXIT_NOT_FOUND });
    }

    let classification = classify(&bytes, u64::MAX);
    let mut report = FileReport {
        path: path.display().to_string(),
        size_bytes: bytes.len() as u64,
        address: hex::encode(address),
        name_address: name_address.map(hex::encode),
        name_matches: name_address.map(|n| n == address),
        classification,
        datamap: None,
        resolved: Vec::new(),
        resolve_error: None,
        decrypted: None,
    };

    let Some(parsed) = parsed else {
        if args.addresses {
            return Ok(EXIT_NOT_FOUND);
        }
        if args.json {
            println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
        } else if !args.quiet {
            print_file_header(&report);
            println!();
            println!("Not a DataMap.");
        }
        return Ok(EXIT_OK);
    };

    let mut levels: Vec<ParsedDataMap> = vec![parsed];
    let want_resolve = args.resolve || args.decrypt.is_some();
    if want_resolve {
        match &mut store_scan {
            Some(scan) => loop {
                let current = levels.last().unwrap();
                if !current.is_child() {
                    break;
                }
                match decrypt_level(&current.data_map, scan) {
                    Ok(parent_bytes) => match datamap::parse(&parent_bytes) {
                        Some(parent) => levels.push(parent),
                        None => {
                            report.resolve_error =
                                Some("decrypted parent level is not a valid DataMap".to_string());
                            break;
                        }
                    },
                    Err(e) => {
                        report.resolve_error = Some(e);
                        break;
                    }
                }
            },
            None => {
                report.resolve_error = Some(
                    "no local chunk store known (file is not inside a store; pass --store DIR)".to_string(),
                );
            }
        }
    }

    let mut reports: Vec<DataMapReport> = levels
        .iter()
        .map(|p| datamap_report(p, store_scan.as_mut()))
        .collect();
    report.datamap = Some(reports.remove(0));
    report.resolved = reports;

    if let Some(out) = &args.decrypt {
        let root = levels.last().unwrap();
        if root.is_child() {
            report.resolve_error.get_or_insert_with(|| "could not reach the root DataMap".to_string());
        } else {
            let scan = store_scan.as_mut().ok_or("no local chunk store known for --decrypt")?;
            let plain = decrypt_content(&root.data_map, scan)?;
            std::fs::write(out, &plain).map_err(|e| format!("{}: {e}", out.display()))?;
            report.decrypted = Some(DecryptReport {
                output: out.display().to_string(),
                bytes: plain.len() as u64,
                verified: true,
            });
        }
    }

    if args.addresses {
        let map = if want_resolve { report.resolved.last().unwrap_or(report.datamap.as_ref().unwrap()) } else { report.datamap.as_ref().unwrap() };
        let mut out = io::stdout().lock();
        for row in map.chunks.iter().take(limit_or_all(args.limit, map.chunks.len())) {
            writeln!(out, "{}", row.row.address).map_err(|e| e.to_string())?;
        }
        return Ok(if report.resolve_error.is_some() { EXIT_NOT_FOUND } else { EXIT_OK });
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
        return Ok(EXIT_OK);
    }

    if !args.quiet {
        print_file_header(&report);
        println!();
        print_datamap_section(report.datamap.as_ref().unwrap(), "DataMap", args);
        for (i, lvl) in report.resolved.iter().enumerate() {
            println!();
            let title = if lvl.child.is_none() {
                "Root DataMap (resolved)".to_string()
            } else {
                format!("Parent level {} (resolved)", i + 1)
            };
            print_datamap_section(lvl, &title, args);
        }
        if let Some(e) = &report.resolve_error {
            println!();
            println!("Resolve: FAILED — {e}");
        }
        if let Some(d) = &report.decrypted {
            println!();
            println!("Decrypted {} to {} (every chunk's plaintext hash verified)", fmt_bytes(d.bytes), d.output);
        }
    } else if args.list {
        let map = report.resolved.last().unwrap_or(report.datamap.as_ref().unwrap());
        print_datamap_rows(map, args);
    }
    Ok(if report.resolve_error.is_some() { EXIT_NOT_FOUND } else { EXIT_OK })
}

fn datamap_report(parsed: &ParsedDataMap, scan: Option<&mut Scan>) -> DataMapReport {
    let network_bytes = datamap::to_network_bytes(&parsed.data_map);
    let rows = parsed.rows();
    let mut chunks: Vec<ChunkRowLocal> = rows
        .into_iter()
        .map(|row| ChunkRowLocal { row, local: None, local_size: None })
        .collect();
    let mut local = None;
    if let Some(scan) = scan {
        let _ = scan.resolve_addresses();
        let mut present = 0;
        let mut present_bytes = 0;
        for (info, c) in parsed.infos().iter().zip(chunks.iter_mut()) {
            match scan.locate(&info.dst_hash) {
                Some(entry) => {
                    c.local = Some(true);
                    c.local_size = Some(entry.size);
                    present += 1;
                    present_bytes += entry.size;
                }
                None => c.local = Some(false),
            }
        }
        local = Some(CoverageReport {
            store: scan.chunks_dir.display().to_string(),
            present,
            total: chunks.len(),
            present_bytes,
            complete: present == chunks.len(),
        });
    }
    DataMapReport {
        format: parsed.format,
        child: parsed.child(),
        serialized_bytes: parsed.serialized_len,
        network_address: hex::encode(blake3::hash(&network_bytes).as_bytes()),
        stats: parsed.stats(),
        chunks,
        local,
    }
}

/// Decrypt one shrink level: read the child map's chunks from the local
/// store, decrypt each with self_encryption and concatenate — the result is
/// the bincode-serialized parent DataMap.
fn decrypt_level(dm: &DataMap, scan: &mut Scan) -> Result<Vec<u8>, String> {
    let level = dm.child().ok_or("not a child DataMap")?;
    decrypt_chunks(dm, level, scan)
}

/// Decrypt the file content described by a root DataMap from local chunks.
fn decrypt_content(dm: &DataMap, scan: &mut Scan) -> Result<Vec<u8>, String> {
    if dm.is_child() {
        return Err("not a root DataMap".into());
    }
    decrypt_chunks(dm, 0, scan)
}

fn decrypt_chunks(dm: &DataMap, level: usize, scan: &mut Scan) -> Result<Vec<u8>, String> {
    let src_hashes: Vec<XorName> = dm.infos().iter().map(|c| c.src_hash).collect();
    let mut out = Vec::with_capacity(dm.original_file_size());
    for info in dm.infos() {
        let addr = hex::encode(info.dst_hash);
        let entry = scan
            .locate(&info.dst_hash)
            .ok_or_else(|| format!("chunk {} of {} ({addr}) is not in the local store", info.index, dm.len()))?;
        let bytes = entry.read().map_err(|e| format!("{}: {e}", entry.path.display()))?;
        if blake3::hash(&bytes).as_bytes() != &info.dst_hash.0 {
            return Err(format!("{}: content does not hash to its address", entry.path.display()));
        }
        let plain = self_encryption::decrypt_chunk(info.index, &bytes.into(), &src_hashes, level)
            .map_err(|e| format!("chunk {} ({addr}): decryption failed: {e}", info.index))?;
        if blake3::hash(&plain).as_bytes() != &info.src_hash.0 {
            return Err(format!("chunk {} ({addr}): plaintext does not match src_hash", info.index));
        }
        if plain.len() != info.src_size {
            return Err(format!(
                "chunk {} ({addr}): plaintext is {} bytes, DataMap says {}",
                info.index,
                plain.len(),
                info.src_size
            ));
        }
        out.extend_from_slice(&plain);
    }
    Ok(out)
}

fn print_file_header(r: &FileReport) {
    println!("File       : {}  ({})", r.path, fmt_bytes(r.size_bytes));
    let name_note = match r.name_matches {
        Some(true) => "  — matches filename",
        Some(false) => "  — DOES NOT MATCH filename",
        None => "",
    };
    println!("Address    : {}  (BLAKE3 of content){name_note}", r.address);
    if let Some(false) = r.name_matches {
        println!("Filename   : {}", r.name_address.as_deref().unwrap_or(""));
    }
    let c = &r.classification;
    let mut detail = Vec::new();
    if let Some(f) = c.format {
        detail.push(f.to_string());
    }
    if let Some(e) = c.entropy_bits {
        detail.push(format!("entropy {e:.2} bit/B"));
    }
    let detail = if detail.is_empty() { String::new() } else { format!("  [{}]", detail.join(", ")) };
    println!("Content    : {}{detail}", c.class.description());
}

fn print_datamap_section(m: &DataMapReport, title: &str, args: &Args) {
    println!("{title}");
    println!("  format         : {}", m.format.label());
    match m.child {
        Some(level) => println!(
            "  level          : child {level} (shrunk — entries describe the encrypted parent DataMap, not file data)"
        ),
        None => println!("  level          : root (entries are the file's data chunks)"),
    }
    println!("  chunks         : {} ({} distinct addresses)", fmt_num(m.stats.chunk_count as u64), fmt_num(m.stats.distinct_addresses as u64));
    let what = if m.child.is_some() { "parent DataMap size" } else { "file size" };
    println!("  content size   : {}  [sum of src_size = {what}]", fmt_bytes(m.stats.content_bytes));
    println!("  serialized     : {}", fmt_bytes(m.serialized_bytes as u64));
    println!("  network address: {}  (BLAKE3 of the msgpack encoding = its address as a public chunk)", m.network_address);
    println!(
        "  chunk src size : min {} / max {} / mean {}",
        fmt_num(m.stats.min_src_size as u64),
        fmt_num(m.stats.max_src_size as u64),
        fmt_num(m.stats.mean_src_size)
    );
    if let Some(l) = &m.local {
        let status = if l.complete { "complete" } else { "INCOMPLETE" };
        println!(
            "  local store    : {} of {} chunks present in {} ({} on disk) — {status}",
            l.present,
            l.total,
            l.store,
            fmt_bytes(l.present_bytes)
        );
    }
    println!();
    let mut header = String::from("  Chunks (index · address · src size");
    if args.src {
        header.push_str(" · src hash");
    }
    if m.local.is_some() {
        header.push_str(" · local");
    }
    header.push(')');
    println!("{header}");
    let shown = limit_or_all(args.limit, m.chunks.len());
    for c in m.chunks.iter().take(shown) {
        let mut line = format!("  {:>5}  {}  {:>11} B", c.row.index, c.row.address, fmt_num(c.row.src_size as u64));
        if args.src {
            line.push_str(&format!("  {}", c.row.src_hash));
        }
        match (c.local, c.local_size) {
            (Some(true), Some(sz)) => line.push_str(&format!("  present ({} B)", fmt_num(sz))),
            (Some(false), _) => line.push_str("  MISSING"),
            _ => {}
        }
        println!("{line}");
    }
    if shown < m.chunks.len() {
        println!("  … {} more (--limit)", m.chunks.len() - shown);
    }
}

fn print_datamap_rows(m: &DataMapReport, args: &Args) {
    let mut out = io::stdout().lock();
    for c in m.chunks.iter().take(limit_or_all(args.limit, m.chunks.len())) {
        let mut line = format!("{}\t{}\t{}", c.row.index, c.row.address, c.row.src_size);
        if args.src {
            line.push('\t');
            line.push_str(&c.row.src_hash);
        }
        if let Some(l) = c.local {
            line.push('\t');
            line.push_str(if l { "present" } else { "missing" });
        }
        let _ = writeln!(out, "{line}");
    }
}

// ───────────────────────────── directories ─────────────────────────────

fn inspect_store(args: &Args, mut scan: Scan) -> Result<u8, String> {
    let need_content = args.verify || args.classify || args.datamaps;
    if scan.kind == TargetKind::GenericDir || args.addresses || args.list {
        scan.resolve_addresses().map_err(|e| e.to_string())?;
    }

    // Fast path: bare address list.
    if args.addresses {
        let order = sorted_indices(&scan, args.sort);
        let mut out = io::stdout().lock();
        for &i in order.iter().take(limit_or_all(args.limit, order.len())) {
            if let Some(a) = scan.chunks[i].address() {
                writeln!(out, "{}", hex::encode(a)).map_err(|e| e.to_string())?;
            }
        }
        return Ok(EXIT_OK);
    }

    let (layout, layout_error, layout_is_current) = match &scan.layout {
        Some(Ok(l)) => (Some(l.clone()), None, Some(l.is_current())),
        Some(Err(e)) => (None, Some(e.clone()), None),
        None => (None, None, None),
    };

    let is_store = matches!(scan.kind, TargetKind::NodeRoot | TargetKind::ChunkStore);
    let shard_fill = is_store.then(|| {
        let non_empty = scan.per_shard.iter().filter(|&&c| c > 0).count();
        ShardFill {
            min: scan.per_shard.iter().copied().min().unwrap_or(0),
            max: scan.per_shard.iter().copied().max().unwrap_or(0),
            mean: scan.chunks.len() as f64 / store::SHARD_COUNT as f64,
            non_empty,
        }
    });

    // Per-chunk content pass (classification, DataMap discovery, verification).
    let mut classifications: Vec<Option<Classification>> = vec![None; scan.chunks.len()];
    let mut datamap_hits: Vec<(usize, ParsedDataMap)> = Vec::new();
    let mut verify = args.verify.then(|| VerifyReport { checked: 0, ok: 0, failed: 0, unreadable: 0, failures: Vec::new() });
    if need_content {
        let assume = if args.assume_encrypted_above == 0 { u64::MAX } else { args.assume_encrypted_above };
        #[allow(clippy::needless_range_loop)]
        for i in 0..scan.chunks.len() {
            let entry = &scan.chunks[i];
            let small_enough = entry.size as usize <= datamap::MAX_PARSE_LEN;
            let want_read = args.verify || args.classify || (args.datamaps && small_enough);
            if !want_read {
                continue;
            }
            let bytes = match entry.read() {
                Ok(b) => b,
                Err(e) => {
                    if let Some(v) = &mut verify {
                        v.unreadable += 1;
                    }
                    scan.errors.push(format!("{}: {e}", entry.path.display()));
                    continue;
                }
            };
            if let Some(v) = &mut verify {
                if let Some(expected) = entry.name_address {
                    let computed = XorName(*blake3::hash(&bytes).as_bytes());
                    v.checked += 1;
                    if computed == expected {
                        v.ok += 1;
                    } else {
                        v.failed += 1;
                        if v.failures.len() < 20 {
                            v.failures.push(VerifyFailure {
                                path: entry.path.display().to_string(),
                                expected: hex::encode(expected),
                                computed: hex::encode(computed),
                            });
                        }
                    }
                }
            }
            if args.classify {
                let c = classify(&bytes, assume);
                if c.class == ContentClass::DataMap && args.datamaps {
                    if let Some(p) = datamap::parse(&bytes) {
                        datamap_hits.push((i, p));
                    }
                }
                classifications[i] = Some(c);
            } else if args.datamaps && small_enough {
                if let Some(p) = datamap::parse(&bytes) {
                    datamap_hits.push((i, p));
                }
            }
        }
    }

    let content_distribution = args.classify.then(|| {
        let mut buckets: BTreeMap<ContentClass, (u64, u64)> = BTreeMap::new();
        for (c, e) in classifications.iter().zip(scan.chunks.iter()) {
            if let Some(c) = c {
                let b = buckets.entry(c.class).or_insert((0, 0));
                b.0 += 1;
                b.1 += e.size;
            }
        }
        let total = scan.chunks.len().max(1) as f64;
        ContentClass::all()
            .iter()
            .filter_map(|cls| {
                buckets.get(cls).map(|&(count, bytes)| ClassBucket {
                    class: *cls,
                    description: cls.description().to_string(),
                    count,
                    bytes,
                    percent: count as f64 * 100.0 / total,
                })
            })
            .collect()
    });

    let datamaps = args.datamaps.then(|| {
        let mut list = Vec::new();
        for (i, p) in &datamap_hits {
            let present = p.infos().iter().filter(|c| scan.locate(&c.dst_hash).is_some()).count();
            let entry = &scan.chunks[*i];
            list.push(DataMapSummary {
                address: entry.address().map(hex::encode).unwrap_or_default(),
                path: entry.path.display().to_string(),
                format: p.format,
                child: p.child(),
                chunk_count: p.infos().len(),
                content_bytes: p.stats().content_bytes,
                local_present: present,
            });
        }
        list
    });

    let statistics = (!scan.chunks.is_empty()).then(|| compute_stats(&scan));
    let address_spread = compute_spread(&scan);

    let (records, records_truncated_at) = if args.list {
        let order = sorted_indices(&scan, args.sort);
        let shown = limit_or_all(args.limit, order.len());
        let recs: Vec<RecordReport> = order
            .iter()
            .take(shown)
            .map(|&i| {
                let e = &scan.chunks[i];
                RecordReport {
                    address: e.address().map(hex::encode).unwrap_or_default(),
                    size_bytes: e.size,
                    path: e.path.display().to_string(),
                    classification: classifications[i].clone(),
                }
            })
            .collect();
        (Some(recs), (shown < order.len()).then_some(shown))
    } else {
        (None, None)
    };

    const LIST_CAP: usize = 50;
    let report = StoreReport {
        kind: scan.kind,
        target: scan.target.display().to_string(),
        chunks_dir: scan.chunks_dir.display().to_string(),
        layout,
        layout_error,
        layout_is_current,
        lock_present: scan.lock_present,
        shards_present: scan.shards_present,
        shard_fill,
        chunk_count: scan.chunks.len(),
        total_bytes: scan.total_bytes(),
        allocated_bytes: scan.allocated_bytes(),
        uppercase_names: scan.chunks.iter().filter(|c| c.uppercase_name).count(),
        temp_files: paths_to_strings(&scan.temp_files, LIST_CAP),
        quarantined: paths_to_strings(&scan.quarantined, LIST_CAP),
        unexpected: paths_to_strings(&scan.unexpected, LIST_CAP),
        errors: scan.errors.clone(),
        address_spread,
        node: scan.node.clone(),
        statistics,
        content_distribution,
        datamaps,
        verification: verify,
        records,
        records_truncated_at,
    };

    let exit = match &report.verification {
        Some(v) if v.failed > 0 || v.unreadable > 0 => EXIT_VERIFY_FAILED,
        _ => EXIT_OK,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
        return Ok(exit);
    }
    if args.quiet {
        if let Some(recs) = &report.records {
            print_record_rows(recs);
        }
        return Ok(exit);
    }
    print_store_report(&report, args);
    Ok(exit)
}

fn paths_to_strings(paths: &[PathBuf], cap: usize) -> Vec<String> {
    paths.iter().take(cap).map(|p| p.display().to_string()).collect()
}

fn sorted_indices(scan: &Scan, order: SortOrder) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..scan.chunks.len()).collect();
    match order {
        SortOrder::Addr => idx.sort_by(|&a, &b| scan.chunks[a].address().cmp(&scan.chunks[b].address())),
        SortOrder::Size => idx.sort_by(|&a, &b| {
            scan.chunks[b].size.cmp(&scan.chunks[a].size).then(scan.chunks[a].address().cmp(&scan.chunks[b].address()))
        }),
    }
    idx
}

fn compute_stats(scan: &Scan) -> StatsReport {
    let mut sizes: Vec<u64> = scan.chunks.iter().map(|c| c.size).collect();
    sizes.sort_unstable();
    let n = sizes.len();
    let total: u64 = sizes.iter().sum();
    let pct = |p: f64| -> u64 {
        let rank = ((n as f64 - 1.0) * p).round() as usize;
        sizes[rank.min(n - 1)]
    };
    let bounds: [(&str, Option<u64>); 15] = [
        ("< 1 KiB", Some(1 << 10)),
        ("1–2 KiB", Some(2 << 10)),
        ("2–4 KiB", Some(4 << 10)),
        ("4–8 KiB", Some(8 << 10)),
        ("8–16 KiB", Some(16 << 10)),
        ("16–32 KiB", Some(32 << 10)),
        ("32–64 KiB", Some(64 << 10)),
        ("64–128 KiB", Some(128 << 10)),
        ("128–256 KiB", Some(256 << 10)),
        ("256–512 KiB", Some(512 << 10)),
        ("512 KiB–1 MiB", Some(1 << 20)),
        ("1–2 MiB", Some(2 << 20)),
        ("2–3 MiB", Some(3 << 20)),
        ("3–4 MiB", Some(4 << 20)),
        ("> 4 MiB", None),
    ];
    let mut histogram: Vec<HistogramBucket> = bounds
        .iter()
        .map(|(label, ub)| HistogramBucket { label: label.to_string(), upper_bound_bytes: *ub, count: 0 })
        .collect();
    for &s in &sizes {
        let i = bounds.iter().position(|(_, ub)| ub.is_none_or(|u| s < u)).unwrap_or(bounds.len() - 1);
        histogram[i].count += 1;
    }
    StatsReport {
        total_bytes: total,
        min_bytes: sizes[0],
        max_bytes: sizes[n - 1],
        mean_bytes: total / n as u64,
        median_bytes: pct(0.5),
        p90_bytes: pct(0.9),
        p99_bytes: pct(0.99),
        histogram,
    }
}

fn compute_spread(scan: &Scan) -> Option<AddressSpread> {
    let addrs: Vec<XorName> = scan.chunks.iter().filter_map(|c| c.address()).collect();
    if addrs.is_empty() {
        return None;
    }
    let first = addrs[0];
    let mut common = 256u32;
    for a in &addrs[1..] {
        let mut bits = 0u32;
        for (x, y) in first.0.iter().zip(a.0.iter()) {
            let d = x ^ y;
            if d == 0 {
                bits += 8;
            } else {
                bits += d.leading_zeros();
                break;
            }
        }
        common = common.min(bits);
        if common == 0 {
            break;
        }
    }
    let mut firsts = [false; 256];
    let mut lasts = [false; 256];
    for a in &addrs {
        firsts[a[0] as usize] = true;
        lasts[a[31] as usize] = true;
    }
    Some(AddressSpread {
        common_prefix_bits: if addrs.len() == 1 { 0 } else { common },
        distinct_first_bytes: firsts.iter().filter(|&&b| b).count(),
        distinct_last_bytes: lasts.iter().filter(|&&b| b).count(),
    })
}

fn print_store_report(r: &StoreReport, args: &Args) {
    println!("Target: {}  — {}", r.target, r.kind.label());
    println!("{}", "═".repeat(72));
    println!();
    println!("Store");
    println!("  chunks dir    : {}", r.chunks_dir);
    match (&r.layout, &r.layout_error) {
        (Some(l), _) => {
            let ok = if r.layout_is_current == Some(true) { "current" } else { "UNKNOWN LAYOUT" };
            println!(
                "  layout.json   : schema {}, scheme {}, {} hex chars, depth {}, names {}  [{ok}]",
                l.schema, l.scheme, l.shard_chars, l.depth, l.name_encoding
            );
        }
        (None, Some(e)) => println!("  layout.json   : UNREADABLE — {e}"),
        (None, None) => println!("  layout.json   : absent"),
    }
    if matches!(r.kind, TargetKind::NodeRoot | TargetKind::ChunkStore) {
        println!("  lock file     : {}", if r.lock_present { "present (.lock)" } else { "absent" });
        if let Some(f) = &r.shard_fill {
            println!(
                "  shards        : {} of 256 directories present, {} non-empty; files per shard min {} / max {} / mean {:.2}",
                r.shards_present, f.non_empty, f.min, f.max, f.mean
            );
        }
    }
    println!("  chunk files   : {}", fmt_num(r.chunk_count as u64));
    println!("  total size    : {}", fmt_bytes(r.total_bytes));
    if let Some(a) = r.allocated_bytes {
        println!("  on disk       : {}  (allocated blocks)", fmt_bytes(a));
    }
    let mut other = Vec::new();
    if !r.temp_files.is_empty() {
        other.push(format!("{} in-flight temp file(s) (.tmp.*)", r.temp_files.len()));
    }
    if !r.quarantined.is_empty() {
        other.push(format!("{} quarantined (*.not-a-chunk)", r.quarantined.len()));
    }
    if !r.unexpected.is_empty() {
        other.push(format!("{} unexpected entr(ies)", r.unexpected.len()));
    }
    if r.uppercase_names > 0 {
        other.push(format!("{} uppercase-named file(s) the node would ignore", r.uppercase_names));
    }
    println!("  other entries : {}", if other.is_empty() { "none".to_string() } else { other.join(", ") });
    for p in r.temp_files.iter().chain(r.quarantined.iter()).chain(r.unexpected.iter()).take(20) {
        println!("                  {p}");
    }
    for e in &r.errors {
        println!("  ERROR         : {e}");
    }
    if let Some(s) = &r.address_spread {
        println!(
            "  address spread: {} leading bits shared by all addresses; {} distinct first bytes, {} distinct last bytes (shards)",
            s.common_prefix_bits, s.distinct_first_bytes, s.distinct_last_bytes
        );
    }

    if let Some(node) = &r.node {
        println!();
        println!("Node root");
        println!("  entries       : {}", node.entries.join("  "));
        match (&node.migration_state, &node.migration_state_error) {
            (Some(v), _) => {
                let phase = v.get("phase").and_then(|p| p.as_str()).unwrap_or("?");
                let shed = v.get("shed_key_count").and_then(|p| p.as_u64()).unwrap_or(0);
                let kept = v.get("kept_key_count").and_then(|p| p.as_u64()).unwrap_or(0);
                let first = v.get("first_start_unix").and_then(|p| p.as_u64()).unwrap_or(0);
                println!(
                    "  migration     : phase {phase}, first start {} (unix {first}), kept {kept} keys, shed {shed} keys",
                    fmt_unix(first)
                );
            }
            (None, Some(e)) => println!("  migration     : migration-state.json UNREADABLE — {e}"),
            (None, None) => println!("  migration     : no migration-state.json (fresh file-only node or pre-migration build)"),
        }
        match node.legacy_env_bytes {
            Some(b) => println!(
                "  legacy LMDB   : chunks.mdb/ present, {}{}",
                fmt_bytes(b),
                if node.legacy_env_marked_retired { " — marked RETIRED (will be deleted)" } else { " — not yet retired" }
            ),
            None => println!("  legacy LMDB   : chunks.mdb/ absent (retired)"),
        }
        if let Some(b) = node.retired_env_bytes {
            println!("  retiring      : chunks.mdb.retired/ present, {} (deletion in progress)", fmt_bytes(b));
        }
        match node.paid_list_bytes {
            Some(b) => println!("  paid list     : paid_list.mdb/ {}", fmt_bytes(b)),
            None => println!("  paid list     : paid_list.mdb/ absent"),
        }
    }

    if let Some(s) = &r.statistics {
        println!();
        println!("Statistics (chunk file sizes)");
        println!("  total         : {}", fmt_bytes(s.total_bytes));
        println!("  min / max     : {} / {}", fmt_bytes(s.min_bytes), fmt_bytes(s.max_bytes));
        println!("  mean / median : {} / {}", fmt_bytes(s.mean_bytes), fmt_bytes(s.median_bytes));
        println!("  p90 / p99     : {} / {}", fmt_bytes(s.p90_bytes), fmt_bytes(s.p99_bytes));
        println!();
        println!("  Size histogram");
        let max = s.histogram.iter().map(|b| b.count).max().unwrap_or(0).max(1);
        for b in &s.histogram {
            let bar = (b.count * 40 / max) as usize;
            println!("  {:>15} │{:<40} {}", b.label, "█".repeat(bar), b.count);
        }
    }

    if let Some(dist) = &r.content_distribution {
        println!();
        println!("Content classification");
        for b in dist {
            println!(
                "  {:<10} {:>8}  {:>5.1}%  {:>12}   {}",
                b.class.tag(),
                fmt_num(b.count),
                b.percent,
                fmt_short(b.bytes),
                b.description
            );
        }
        if args.assume_encrypted_above > 0 {
            println!(
                "  (chunks ≥ {} assumed encrypted without scanning; --assume-encrypted-above 0 scans all)",
                fmt_bytes(args.assume_encrypted_above)
            );
        }
    }

    if let Some(dms) = &r.datamaps {
        println!();
        println!("Public DataMaps in store: {}", dms.len());
        if !dms.is_empty() {
            println!("  ADDRESS                                                           LEVEL    CHUNKS     CONTENT  LOCAL");
            for d in dms {
                let level = d.child.map(|c| format!("child {c}")).unwrap_or_else(|| "root".into());
                println!(
                    "  {}  {:<7} {:>7}  {:>10}  {}/{}",
                    d.address,
                    level,
                    fmt_num(d.chunk_count as u64),
                    fmt_short(d.content_bytes),
                    d.local_present,
                    d.chunk_count
                );
            }
            println!("  (inspect one with: ant-inspect <store> --chunk <ADDRESS>)");
        }
    }

    if let Some(v) = &r.verification {
        println!();
        println!("Verification (BLAKE3(content) == filename)");
        println!("  checked: {}   ok: {}   failed: {}   unreadable: {}", v.checked, v.ok, v.failed, v.unreadable);
        for f in &v.failures {
            println!("  FAIL {}", f.path);
            println!("       expected {}  computed {}", f.expected, f.computed);
        }
    }

    if let Some(recs) = &r.records {
        println!();
        let cls = if args.classify { " · class" } else { "" };
        println!("Chunks (address · size{cls})");
        for rec in recs {
            let mut line = format!("  {}  {:>13} B", rec.address, fmt_num(rec.size_bytes));
            if let Some(c) = &rec.classification {
                line.push_str(&format!("  {:<9}", c.class.tag()));
            }
            println!("{line}");
        }
        if let Some(n) = r.records_truncated_at {
            println!("  … list truncated at {n} of {} (--limit)", r.chunk_count);
        }
    }
}

fn print_record_rows(recs: &[RecordReport]) {
    let mut out = io::stdout().lock();
    for rec in recs {
        let mut line = format!("{}\t{}", rec.address, rec.size_bytes);
        if let Some(c) = &rec.classification {
            line.push('\t');
            line.push_str(c.class.key());
        }
        let _ = writeln!(out, "{line}");
    }
}

// ───────────────────────────── formatting ─────────────────────────────

fn limit_or_all(limit: usize, len: usize) -> usize {
    if limit == 0 { len } else { limit.min(len) }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Compact size for table columns ("1.43 MiB", "410 B").
fn fmt_short(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.2} {}", UNITS[u])
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.2} {} ({} B)", UNITS[u], fmt_num(n))
}

fn fmt_unix(secs: u64) -> String {
    if secs == 0 {
        return "-".into();
    }
    // Civil-from-days (Howard Hinnant), UTC.
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, (rem % 3600) / 60, rem % 60)
}

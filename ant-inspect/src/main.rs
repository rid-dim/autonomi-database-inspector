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
use self_encryption::{ChunkInfo, DataMap};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::process::Command;
use store::{ChunkEntry, Scan, TargetKind};
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

    /// Fetch chunks that are not available locally from the network with the
    /// `ant` CLI (`ant chunk get`) into --fetch-dir and use them. Applies to
    /// every DataMap level touched (with --resolve / --decrypt).
    #[arg(long)]
    fetch: bool,

    /// Where --fetch puts downloaded chunks (flat, one file per address).
    /// Chunks already there are reused.
    #[arg(long, value_name = "DIR", default_value = "./fetched-chunks")]
    fetch_dir: PathBuf,

    /// The ant CLI binary used by --fetch
    #[arg(long, value_name = "PATH", default_value = "ant")]
    ant_bin: String,

    /// Extra arguments for the ant CLI, placed before the subcommand, e.g.
    /// "-b 1.2.3.4:10000,5.6.7.8:10000" (one string, split on whitespace)
    #[arg(long, value_name = "ARGS", allow_hyphen_values = true)]
    ant_args: Option<String>,

    /// Parallel readers for --verify / --classify / --datamaps (default: CPU
    /// count, at most 8). Raise it on network storage, lower it on a single
    /// spinning disk.
    #[arg(long, short = 'j', value_name = "N")]
    jobs: Option<usize>,

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
    fetch_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decrypted: Option<DecryptReport>,
}

/// Where chunks may come from: the store the file lives in (or --store),
/// plus the --fetch-dir once it exists.
#[derive(Default)]
struct Sources {
    scans: Vec<Scan>,
    /// Index of the fetch-dir scan in `scans`, if present.
    fetch_index: Option<usize>,
}

impl Sources {
    fn locate(&self, address: &XorName) -> Option<(&Scan, &ChunkEntry)> {
        self.scans.iter().find_map(|s| s.locate(address).map(|e| (s, e)))
    }

    fn is_empty(&self) -> bool {
        self.scans.is_empty()
    }

    fn describe(&self) -> String {
        self.scans.iter().map(|s| s.chunks_dir.display().to_string()).collect::<Vec<_>>().join(", ")
    }

    fn set_fetch_dir(&mut self, scan: Scan) {
        match self.fetch_index {
            Some(i) => self.scans[i] = scan,
            None => {
                self.scans.push(scan);
                self.fetch_index = Some(self.scans.len() - 1);
            }
        }
    }
}

/// Downloads missing chunks with the `ant` CLI.
struct Fetcher {
    bin: String,
    args: Vec<String>,
    dir: PathBuf,
}

impl Fetcher {
    fn from_args(args: &Args) -> Option<Fetcher> {
        args.fetch.then(|| Fetcher {
            bin: args.ant_bin.clone(),
            args: args.ant_args.as_deref().unwrap_or("").split_whitespace().map(str::to_string).collect(),
            dir: args.fetch_dir.clone(),
        })
    }

    /// Fetch every chunk of `infos` that no source holds, then rescan the
    /// fetch directory into `sources`. Returns how many were fetched.
    fn ensure(&self, infos: &[ChunkInfo], sources: &mut Sources) -> Result<usize, String> {
        let missing: Vec<XorName> = infos
            .iter()
            .map(|c| c.dst_hash)
            .filter(|a| sources.locate(a).is_none())
            .collect();
        if missing.is_empty() {
            return Ok(0);
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let mut failed = Vec::new();
        let mut fetched = 0;
        for (i, addr) in missing.iter().enumerate() {
            let hex = hex::encode(addr);
            let out_path = self.dir.join(&hex);
            eprintln!("fetching {}/{} {hex} …", i + 1, missing.len());
            let output = Command::new(&self.bin)
                .args(&self.args)
                .args(["chunk", "get", &hex, "-o"])
                .arg(&out_path)
                .output()
                .map_err(|e| format!("cannot run `{}`: {e} (install the ant CLI or pass --ant-bin)", self.bin))?;
            let good = output.status.success() && out_path.is_file()
                && std::fs::read(&out_path).map(|b| blake3::hash(&b).as_bytes() == &addr.0).unwrap_or(false);
            if good {
                fetched += 1;
            } else {
                let _ = std::fs::remove_file(&out_path);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let reason = stderr.lines().last().unwrap_or("no output").trim().to_string();
                failed.push(format!("{hex}: {reason}"));
            }
        }
        if fetched > 0 {
            let scan = Scan::scan(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
            sources.set_fetch_dir(scan);
        }
        if failed.is_empty() {
            Ok(fetched)
        } else {
            Err(format!("{} of {} chunk(s) could not be fetched: {}", failed.len(), missing.len(), failed.join("; ")))
        }
    }
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
    /// Directory structure as actually found (inferred from the files).
    structure: store::Structure,
    chunk_count: usize,
    total_bytes: u64,
    allocated_bytes: Option<u64>,
    uppercase_names: usize,
    /// 0-byte files with chunk names: interrupted writes, never valid.
    empty_files: Vec<String>,
    empty_file_count: usize,
    temp_files: Vec<String>,
    quarantined: Vec<String>,
    /// Chunk-named files in the wrong shard directory (invisible to the node).
    misfiled: Vec<String>,
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
    /// Failures that are 0-byte files (a subset of `failed`).
    empty: u64,
    unreadable: u64,
    failures: Vec<VerifyFailure>,
}

#[derive(Serialize)]
struct VerifyFailure {
    path: String,
    expected: String,
    computed: String,
    /// Set for failures with an obvious cause, e.g. "empty file (0 bytes)".
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
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
        let mut sources = Sources::default();
        let store_dir = match &args.store {
            Some(dir) => Some(dir.clone()),
            None => find_store_for_file(path),
        };
        if let Some(dir) = store_dir {
            sources.scans.push(scan_dir(&dir)?);
        }
        add_fetch_dir(args, &mut sources)?;
        return inspect_file(args, path, sources);
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
                println!("{}", scan.path_of(entry).display());
                EXIT_OK
            }
            None => {
                if !args.quiet {
                    eprintln!("{}", not_found_message(&scan, &addr));
                }
                EXIT_NOT_FOUND
            }
        });
    }

    if let Some(addr) = &args.chunk {
        let addr = store::parse_address(addr)?;
        scan.resolve_addresses().map_err(|e| e.to_string())?;
        let Some(entry) = scan.locate(&addr) else {
            eprintln!("{}", not_found_message(&scan, &addr));
            return Ok(EXIT_NOT_FOUND);
        };
        let file = scan.path_of(entry);
        let mut sources = Sources { scans: vec![scan], fetch_index: None };
        add_fetch_dir(args, &mut sources)?;
        return inspect_file(args, &file, sources);
    }

    inspect_store(args, scan)
}

/// With --fetch, chunks downloaded by an earlier run are picked up again.
fn add_fetch_dir(args: &Args, sources: &mut Sources) -> Result<(), String> {
    if args.fetch && args.fetch_dir.is_dir() {
        sources.set_fetch_dir(scan_dir(&args.fetch_dir)?);
    }
    Ok(())
}

fn not_found_message(scan: &Scan, addr: &XorName) -> String {
    match scan.expected_path(addr) {
        Some(p) => format!("not found: {} (the node would look at {})", hex::encode(addr), p.display()),
        None => format!("not found: {}", hex::encode(addr)),
    }
}

fn scan_dir(dir: &Path) -> Result<Scan, String> {
    Scan::scan(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// For a file inside a store, find the directory to check its DataMap
/// chunks against: the nearest ancestor that is a node root or has
/// `layout.json`, else the top of the hex-named shard directories the file
/// sits in, else its own directory when that holds other chunk files.
fn find_store_for_file(file: &Path) -> Option<PathBuf> {
    let abs = std::fs::canonicalize(file).ok()?;
    let parent = abs.parent()?;
    // 1. A real store above us (up to a few levels).
    let mut dir = parent;
    for _ in 0..4 {
        if store::detect_kind(dir).is_store() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
    // 2. Climb out of shard-named directories (prefix or suffix sharding of
    //    any depth) to the directory that holds the whole structure.
    let mut top = parent;
    while store::looks_like_shard_dir(top) {
        top = top.parent()?;
    }
    if top != parent {
        return Some(top.to_path_buf());
    }
    // 3. A flat dump directory.
    store::has_chunk_files(parent).then(|| parent.to_path_buf())
}

// ───────────────────────────── single file ─────────────────────────────

fn inspect_file(args: &Args, path: &Path, mut sources: Sources) -> Result<u8, String> {
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
        fetch_error: None,
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
    for scan in &mut sources.scans {
        scan.resolve_addresses().map_err(|e| e.to_string())?;
    }
    let fetcher = Fetcher::from_args(args);
    if let Some(f) = &fetcher {
        if let Err(e) = f.ensure(levels[0].infos(), &mut sources) {
            report.fetch_error = Some(e);
        }
    }
    if want_resolve {
        if sources.is_empty() {
            report.resolve_error = Some(
                "no local chunks known (file is not inside a chunk directory; pass --store DIR, or --fetch)".to_string(),
            );
        } else {
            loop {
                let current = levels.last().unwrap();
                if !current.is_child() {
                    break;
                }
                match decrypt_level(&current.data_map, &sources) {
                    Ok(parent_bytes) => match datamap::parse(&parent_bytes) {
                        Some(parent) => {
                            if let Some(f) = &fetcher {
                                if let Err(e) = f.ensure(parent.infos(), &mut sources) {
                                    report.fetch_error = Some(e);
                                }
                            }
                            levels.push(parent);
                        }
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
            }
        }
    }

    let mut reports: Vec<DataMapReport> = levels
        .iter()
        .map(|p| datamap_report(p, &sources))
        .collect();
    report.datamap = Some(reports.remove(0));
    report.resolved = reports;

    if let Some(out) = &args.decrypt {
        let root = levels.last().unwrap();
        if root.is_child() {
            report.resolve_error.get_or_insert_with(|| "could not reach the root DataMap".to_string());
        } else {
            if sources.is_empty() {
                return Err("no local chunks known for --decrypt (pass --store DIR or --fetch)".into());
            }
            let plain = decrypt_content(&root.data_map, &sources)?;
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
        if let Some(e) = &report.fetch_error {
            println!();
            println!("Fetch: FAILED — {e}");
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

fn datamap_report(parsed: &ParsedDataMap, sources: &Sources) -> DataMapReport {
    let network_bytes = datamap::to_network_bytes(&parsed.data_map);
    let rows = parsed.rows();
    let mut chunks: Vec<ChunkRowLocal> = rows
        .into_iter()
        .map(|row| ChunkRowLocal { row, local: None, local_size: None })
        .collect();
    let mut local = None;
    if !sources.is_empty() {
        let mut present = 0;
        let mut present_bytes = 0;
        for (info, c) in parsed.infos().iter().zip(chunks.iter_mut()) {
            match sources.locate(&info.dst_hash) {
                Some((_, entry)) => {
                    c.local = Some(true);
                    c.local_size = Some(entry.size);
                    present += 1;
                    present_bytes += entry.size;
                }
                None => c.local = Some(false),
            }
        }
        local = Some(CoverageReport {
            store: sources.describe(),
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
fn decrypt_level(dm: &DataMap, sources: &Sources) -> Result<Vec<u8>, String> {
    let level = dm.child().ok_or("not a child DataMap")?;
    decrypt_chunks(dm, level, sources)
}

/// Decrypt the file content described by a root DataMap from local chunks.
fn decrypt_content(dm: &DataMap, sources: &Sources) -> Result<Vec<u8>, String> {
    if dm.is_child() {
        return Err("not a root DataMap".into());
    }
    decrypt_chunks(dm, 0, sources)
}

fn decrypt_chunks(dm: &DataMap, level: usize, sources: &Sources) -> Result<Vec<u8>, String> {
    let src_hashes: Vec<XorName> = dm.infos().iter().map(|c| c.src_hash).collect();
    let mut out = Vec::with_capacity(dm.original_file_size());
    for info in dm.infos() {
        let addr = hex::encode(info.dst_hash);
        let (scan, entry) = sources
            .locate(&info.dst_hash)
            .ok_or_else(|| format!("chunk {} of {} ({addr}) is not available locally (try --store DIR or --fetch)", info.index, dm.len()))?;
        let path = scan.path_of(entry);
        let bytes = scan.read(entry).map_err(|e| format!("{}: {e}", path.display()))?;
        if blake3::hash(&bytes).as_bytes() != &info.dst_hash.0 {
            return Err(format!("{}: content does not hash to its address", path.display()));
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
    if r.size_bytes == 0 {
        println!("WARNING    : EMPTY FILE (0 bytes) — an interrupted or failed write; it can never be a valid chunk");
    }
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
    if scan.kind == TargetKind::Directory || args.addresses || args.list {
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

    // Per-chunk content pass (classification, DataMap discovery, verification).
    // Files are read by a pool of workers; results are merged in index order
    // so the report is deterministic whatever the thread timing.
    let mut classifications: Vec<Option<Classification>> = vec![None; scan.chunks.len()];
    let mut datamap_hits: Vec<(usize, ParsedDataMap)> = Vec::new();
    let mut verify = args.verify.then(|| VerifyReport { checked: 0, ok: 0, failed: 0, empty: 0, unreadable: 0, failures: Vec::new() });
    let mut read_errors: Vec<String> = Vec::new();
    if need_content {
        let assume = if args.assume_encrypted_above == 0 { u64::MAX } else { args.assume_encrypted_above };
        let todo: Vec<usize> = (0..scan.chunks.len())
            .filter(|&i| {
                let small_enough = scan.chunks[i].size as usize <= datamap::MAX_PARSE_LEN;
                args.verify || args.classify || (args.datamaps && small_enough)
            })
            .collect();
        let total_bytes: u64 = todo.iter().map(|&i| scan.chunks[i].size).sum();
        let what = if args.verify { "verifying" } else { "reading" };
        let progress = ContentProgress::new(what, todo.len(), total_bytes);
        let jobs = args
            .jobs
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).min(8))
            .max(1);
        let next = std::sync::atomic::AtomicUsize::new(0);
        let outcomes: std::sync::Mutex<Vec<ContentOutcome>> = std::sync::Mutex::new(Vec::with_capacity(todo.len()));
        let scan_ref = &scan;
        std::thread::scope(|sc| {
            for _ in 0..jobs {
                sc.spawn(|| {
                    let mut local = Vec::new();
                    loop {
                        let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(&i) = todo.get(k) else { break };
                        let entry = &scan_ref.chunks[i];
                        let mut out = ContentOutcome { index: i, computed: None, classification: None, datamap: None, error: None };
                        match scan_ref.read(entry) {
                            Ok(bytes) => {
                                if args.verify && entry.name_address.is_some() {
                                    out.computed = Some(XorName(*blake3::hash(&bytes).as_bytes()));
                                }
                                if args.classify {
                                    let c = classify(&bytes, assume);
                                    if c.class == ContentClass::DataMap && args.datamaps {
                                        out.datamap = datamap::parse(&bytes);
                                    }
                                    out.classification = Some(c);
                                } else if args.datamaps && bytes.len() <= datamap::MAX_PARSE_LEN {
                                    out.datamap = datamap::parse(&bytes);
                                }
                                progress.tick(bytes.len() as u64);
                            }
                            Err(e) => {
                                out.error = Some(format!("{}: {e}", scan_ref.path_of(entry).display()));
                                progress.tick(0);
                            }
                        }
                        local.push(out);
                        if local.len() >= 1024 {
                            outcomes.lock().unwrap().append(&mut local);
                        }
                    }
                    outcomes.lock().unwrap().append(&mut local);
                });
            }
        });
        progress.finish();

        let mut outcomes = outcomes.into_inner().unwrap();
        outcomes.sort_by_key(|o| o.index);
        for out in outcomes {
            let i = out.index;
            if let Some(e) = out.error {
                if let Some(v) = &mut verify {
                    v.unreadable += 1;
                }
                read_errors.push(e);
                continue;
            }
            if let (Some(v), Some(computed), Some(expected)) = (&mut verify, out.computed, scan.chunks[i].name_address) {
                v.checked += 1;
                if computed == expected {
                    v.ok += 1;
                } else {
                    v.failed += 1;
                    let empty = scan.chunks[i].size == 0;
                    if empty {
                        v.empty += 1;
                    }
                    if v.failures.len() < 20 || empty && v.failures.len() < 40 {
                        v.failures.push(VerifyFailure {
                            path: scan.path_of(&scan.chunks[i]).display().to_string(),
                            expected: hex::encode(expected),
                            computed: hex::encode(computed),
                            note: empty.then(|| "empty file (0 bytes) — an interrupted or failed write, never a valid chunk".to_string()),
                        });
                    }
                }
            }
            if let Some(p) = out.datamap {
                datamap_hits.push((i, p));
            }
            classifications[i] = out.classification;
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
                path: scan.path_of(entry).display().to_string(),
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
                    path: scan.path_of(e).display().to_string(),
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
        structure: scan.structure.clone(),
        chunk_count: scan.chunks.len(),
        total_bytes: scan.total_bytes(),
        allocated_bytes: scan.allocated_bytes(),
        uppercase_names: scan.chunks.iter().filter(|c| c.uppercase_name).count(),
        empty_files: scan
            .chunks
            .iter()
            .filter(|c| c.size == 0)
            .take(LIST_CAP)
            .map(|c| scan.path_of(c).display().to_string())
            .collect(),
        empty_file_count: scan.chunks.iter().filter(|c| c.size == 0).count(),
        temp_files: paths_to_strings(&scan.temp_files, LIST_CAP),
        quarantined: paths_to_strings(&scan.quarantined, LIST_CAP),
        misfiled: paths_to_strings(&scan.misfiled, LIST_CAP),
        unexpected: paths_to_strings(&scan.unexpected, LIST_CAP),
        errors: scan.errors.iter().cloned().chain(read_errors).collect(),
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
    if r.kind.is_store() {
        println!("  lock file     : {}", if r.lock_present { "present (.lock)" } else { "absent" });
    }
    let st = &r.structure;
    let scheme = match st.scheme.as_str() {
        "flat" => "flat (files directly in the directory)".to_string(),
        "prefix-hex" => format!("sharded on the FIRST {} hex chars of the address", st.shard_chars),
        "suffix-hex" => format!("sharded on the LAST {} hex chars of the address", st.shard_chars),
        "empty" => "no chunk files".to_string(),
        _ => "no single scheme (mixed / unrecognized)".to_string(),
    };
    let depth = if st.depth_min == st.depth_max { format!("depth {}", st.depth_min) } else { format!("depth {}–{}", st.depth_min, st.depth_max) };
    println!("  structure     : {scheme}; {depth}; {} directories with chunks", fmt_num(st.dirs_with_chunks as u64));
    if st.dirs_with_chunks > 0 {
        let mut line = format!(
            "  files per dir : min {} / max {} / mean {:.1}",
            fmt_num(st.files_per_dir_min),
            fmt_num(st.files_per_dir_max),
            st.files_per_dir_mean
        );
        if st.off_scheme > 0 {
            line.push_str(&format!("; {} file(s) outside the {} scheme", fmt_num(st.off_scheme as u64), st.scheme));
        }
        println!("{line}");
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
    if !r.misfiled.is_empty() {
        other.push(format!("{} chunk file(s) NOT at chunks/<last two hex>/<address> — the node ignores them", r.misfiled.len()));
    }
    if !r.unexpected.is_empty() {
        other.push(format!("{} unexpected entr(ies)", r.unexpected.len()));
    }
    if r.uppercase_names > 0 {
        other.push(format!("{} uppercase-named file(s) the node would ignore", r.uppercase_names));
    }
    if r.empty_file_count > 0 {
        other.push(format!(
            "{} EMPTY (0-byte) file(s) — interrupted writes, never valid chunks",
            r.empty_file_count
        ));
    }
    println!("  other entries : {}", if other.is_empty() { "none".to_string() } else { other.join(", ") });
    for p in r.empty_files.iter().chain(r.temp_files.iter()).chain(r.quarantined.iter()).chain(r.misfiled.iter()).chain(r.unexpected.iter()).take(20) {
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
        println!(
            "  checked: {}   ok: {}   failed: {} (of which {} empty 0-byte files)   unreadable: {}",
            v.checked, v.ok, v.failed, v.empty, v.unreadable
        );
        for f in &v.failures {
            match &f.note {
                Some(note) => println!("  FAIL {}  — {note}", f.path),
                None => {
                    println!("  FAIL {}", f.path);
                    println!("       expected {}  computed {}", f.expected, f.computed);
                }
            }
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

/// What one worker found out about one chunk file.
struct ContentOutcome {
    index: usize,
    computed: Option<XorName>,
    classification: Option<Classification>,
    datamap: Option<ParsedDataMap>,
    error: Option<String>,
}

/// Progress line on stderr for the content pass (only when stderr is a
/// terminal), refreshed at most twice a second.
struct ContentProgress {
    what: &'static str,
    total_files: usize,
    total_bytes: u64,
    files: std::sync::atomic::AtomicUsize,
    bytes: std::sync::atomic::AtomicU64,
    started: std::time::Instant,
    last: std::sync::Mutex<std::time::Instant>,
    enabled: bool,
    printed: std::sync::atomic::AtomicBool,
}

impl ContentProgress {
    fn new(what: &'static str, total_files: usize, total_bytes: u64) -> Self {
        use std::io::IsTerminal;
        let now = std::time::Instant::now();
        ContentProgress {
            what,
            total_files,
            total_bytes,
            files: std::sync::atomic::AtomicUsize::new(0),
            bytes: std::sync::atomic::AtomicU64::new(0),
            started: now,
            last: std::sync::Mutex::new(now),
            enabled: io::stderr().is_terminal() && total_files > 0,
            printed: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn tick(&self, bytes: u64) {
        use std::sync::atomic::Ordering;
        let files = self.files.fetch_add(1, Ordering::Relaxed) + 1;
        let done = self.bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if !self.enabled {
            return;
        }
        let Ok(mut last) = self.last.try_lock() else { return };
        if last.elapsed().as_millis() < 500 && files < self.total_files {
            return;
        }
        *last = std::time::Instant::now();
        let secs = self.started.elapsed().as_secs_f64().max(0.001);
        let rate = done as f64 / secs;
        let eta = if rate > 0.0 && self.total_bytes > done {
            let s = ((self.total_bytes - done) as f64 / rate) as u64;
            format!(", ~{}m{:02}s left", s / 60, s % 60)
        } else {
            String::new()
        };
        let msg = format!(
            "\r{}… {} / {} files, {} of {} read ({}/s{eta})   ",
            self.what,
            fmt_num(files as u64),
            fmt_num(self.total_files as u64),
            fmt_short(done),
            fmt_short(self.total_bytes),
            fmt_short(rate as u64),
        );
        let mut e = io::stderr().lock();
        let _ = e.write_all(msg.as_bytes());
        let _ = e.flush();
        self.printed.store(true, Ordering::Relaxed);
    }

    fn finish(&self) {
        if self.printed.load(std::sync::atomic::Ordering::Relaxed) {
            let mut e = io::stderr().lock();
            let _ = write!(e, "\r{}\r", " ".repeat(100));
            let _ = e.flush();
        }
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

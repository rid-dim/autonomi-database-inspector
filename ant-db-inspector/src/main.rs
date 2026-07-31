//! Inspector for ant-node LMDB databases.
//!
//! ant-node (WithAutonomi/ant-node) persists two LMDB environments under a
//! node's root directory, both via `heed` 0.22:
//!
//! - `chunks.mdb/` (src/storage/lmdb.rs) — the chunk store:
//!   one unnamed database, key = 32-byte XorName = BLAKE3 hash of the chunk
//!   content, value = raw chunk bytes.
//! - `paid_list.mdb/` (src/replication/paid_list.rs) — paid-authorization set:
//!   one unnamed database, key = 32-byte XorName, value = empty.
//!
//! This tool opens the databases strictly read-only and prints everything the
//! files contain: environment metadata, raw LMDB meta pages (both
//! generations), freelist and space accounting, tables with B-tree stats,
//! key/value schema with a format check, record counts, all XOR addresses
//! with sizes, size statistics, and optionally a content-integrity check
//! (BLAKE3(value) == key) and a hex preview of stored values.

mod meta;

use clap::{Parser, ValueEnum};
use heed::types::Bytes;
use heed::{Database, Env, EnvFlags, EnvOpenOptions, RoTxn};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Cap for named-database enumeration. ant-node only uses the unnamed
/// default database; enumeration exists so the tool stays useful for
/// arbitrary LMDB files.
const MAX_NAMED_DBS: u32 = 64;

/// Size of the `MDB_db` record by which sub-database entries in the main
/// database are recognized (LMDB internal, stable since LMDB 0.9).
const MDB_DB_RECORD_SIZE: usize = 48;

/// Expected key length of an ant-node record (XorName).
const XORNAME_LEN: usize = 32;

#[derive(Parser)]
#[command(
    name = "ant-db-inspector",
    version,
    about = "Inspect ant-node LMDB databases (chunk store, paid list)",
    long_about = "Inspect ant-node LMDB databases (chunk store, paid list).\n\n\
        PATH may be:\n  \
        - a node root directory (all *.mdb environments in it are inspected)\n  \
        - a single LMDB environment directory (e.g. chunks.mdb/)\n  \
        - the data.mdb file inside it\n  \
        - any standalone LMDB file (opened with NO_SUB_DIR)\n\n\
        Databases are always opened read-only."
)]
struct Args {
    /// Path to inspect (node root dir, *.mdb env dir, or data.mdb file)
    path: PathBuf,

    /// Emit the full report as JSON instead of human-readable text
    #[arg(long)]
    json: bool,

    /// Verify content addressing: recompute BLAKE3(value) and compare to key
    #[arg(long)]
    verify: bool,

    /// Do not print the per-record address list (summary and stats only)
    #[arg(long)]
    no_chunks: bool,

    /// Limit the record list to the first N entries per database (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    limit: usize,

    /// Sort order of the record list
    #[arg(long, value_enum, default_value_t = SortOrder::Addr)]
    sort: SortOrder,

    /// Show a hex preview of the first N value bytes for each record
    #[arg(long, default_value_t = 0, value_name = "N")]
    preview: usize,

    /// Open without the LMDB lock file (for snapshots on read-only media;
    /// never use while a node is writing to the database)
    #[arg(long)]
    no_lock: bool,
}

#[derive(Copy, Clone, ValueEnum)]
enum SortOrder {
    /// Ascending by XOR address (LMDB natural key order)
    Addr,
    /// Descending by value size
    Size,
}

// ────────────────────────────── report data model ──────────────────────────

#[derive(Serialize)]
struct Report {
    environments: Vec<EnvironmentReport>,
}

#[derive(Serialize)]
struct EnvironmentReport {
    environment: EnvReport,
    meta: meta::MetaReport,
    space: SpaceReport,
    tables: Vec<TableReport>,
    schema: SchemaReport,
    record_count: u64,
    records: Vec<RecordReport>,
    records_truncated_at: Option<usize>,
    statistics: Option<StatsReport>,
    verification: Option<VerifyReport>,
}

#[derive(Serialize)]
struct EnvReport {
    /// Short label, e.g. "chunks.mdb" or "paid_list.mdb".
    label: String,
    env_path: String,
    data_file: String,
    data_file_bytes: u64,
    lock_file_present: bool,
    no_sub_dir_mode: bool,
    page_size: u32,
    map_size: usize,
    last_txn_id: usize,
    last_page_number: usize,
    readers_used: u32,
    readers_max: u32,
}

/// Space accounting derived from the freelist and page counts.
#[derive(Serialize)]
struct SpaceReport {
    /// data.mdb size on the filesystem.
    file_bytes: u64,
    /// Pages ever touched: (last_page_number + 1) × page size.
    used_span_bytes: u64,
    /// Bytes in live (non-free) pages, from walking the freelist.
    live_bytes: u64,
    /// Reclaimable bytes: pages on the freelist (reused before the file grows).
    free_bytes: u64,
    /// live / used span, in percent.
    utilization_percent: f64,
    /// Sum of all stored value bytes (payload).
    payload_bytes: u64,
    /// live − payload: B-tree, page headers, keys, slack.
    structural_overhead_bytes: u64,
}

#[derive(Serialize)]
struct TableReport {
    name: String,
    entries: u64,
    btree_depth: u32,
    branch_pages: usize,
    leaf_pages: usize,
    overflow_pages: usize,
    /// Bytes occupied by this table (page count × page size).
    used_bytes: u64,
}

/// Classification of what an unnamed ant-node database holds.
#[derive(Serialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum StoreKind {
    /// 32-byte keys, non-empty values: chunk store (key = BLAKE3(value)).
    ChunkStore,
    /// 32-byte keys, all values empty: paid-authorization set.
    PaidList,
    /// Anything else.
    Generic,
    /// No entries.
    Empty,
}

#[derive(Serialize)]
struct SchemaReport {
    store_kind: StoreKind,
    key_description: String,
    value_description: String,
    /// key length → number of entries. A healthy ant-node database has
    /// exactly the entry {32: n}.
    key_length_distribution: BTreeMap<usize, u64>,
    matches_ant_node_format: bool,
}

#[derive(Serialize)]
struct RecordReport {
    xor_address: String,
    size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    preview_hex: Option<String>,
}

#[derive(Serialize)]
struct StatsReport {
    total_payload_bytes: u64,
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
struct VerifyReport {
    checked: u64,
    ok: u64,
    failed: u64,
    /// Entries whose key is not a 32-byte XorName.
    skipped_non_xorname_keys: u64,
    /// Entries with empty values (paid-list membership records).
    skipped_empty_values: u64,
    /// Up to 10 failing addresses (expected ↔ computed).
    failures: Vec<VerifyFailure>,
}

#[derive(Serialize)]
struct VerifyFailure {
    xor_address: String,
    computed_blake3: String,
    size_bytes: u64,
}

// ─────────────────────────────── path resolution ───────────────────────────

/// One LMDB environment to inspect.
struct EnvTarget {
    label: String,
    env_path: PathBuf,
    no_sub_dir: bool,
}

fn target_for_env_dir(env_dir: &Path) -> EnvTarget {
    let label = env_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| env_dir.display().to_string());
    EnvTarget {
        label,
        env_path: env_dir.to_path_buf(),
        no_sub_dir: false,
    }
}

/// Resolve the user-supplied path to one or more LMDB environments.
fn resolve_targets(input: &Path) -> Result<Vec<EnvTarget>, String> {
    if input.is_file() {
        if input.file_name().is_some_and(|n| n == "data.mdb") {
            let parent = input
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            return Ok(vec![target_for_env_dir(&parent)]);
        }
        // Arbitrarily named standalone LMDB file (e.g. a copied snapshot).
        return Ok(vec![EnvTarget {
            label: input
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| input.display().to_string()),
            env_path: input.to_path_buf(),
            no_sub_dir: true,
        }]);
    }

    if input.is_dir() {
        // The directory itself is an environment.
        if input.join("data.mdb").is_file() {
            return Ok(vec![target_for_env_dir(input)]);
        }

        // Node root: collect every *.mdb environment directory in it,
        // chunks.mdb first, the rest alphabetically.
        let mut env_dirs: Vec<PathBuf> = std::fs::read_dir(input)
            .map_err(|e| format!("cannot read directory {}: {e}", input.display()))?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.is_dir() && p.join("data.mdb").is_file())
            .collect();
        env_dirs.sort_by_key(|p| {
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned());
            (name.as_deref() != Some("chunks.mdb"), name)
        });

        if env_dirs.is_empty() {
            return Err(format!(
                "no LMDB environment found under {}: expected data.mdb or *.mdb/data.mdb",
                input.display()
            ));
        }
        return Ok(env_dirs.iter().map(|p| target_for_env_dir(p)).collect());
    }

    Err(format!("path does not exist: {}", input.display()))
}

/// Open an environment read-only.
///
/// The map size is derived from the file size (rounded up to the OS page
/// size); if the meta page records a larger map, LMDB uses that instead.
fn open_env(target: &EnvTarget, no_lock: bool) -> Result<Env, String> {
    let data_file = data_file_path(target);
    let file_len = std::fs::metadata(&data_file)
        .map_err(|e| format!("cannot stat {}: {e}", data_file.display()))?
        .len();

    let page = page_size::get() as u64;
    let map_size = usize::try_from(file_len.div_ceil(page) * page)
        .unwrap_or(usize::MAX)
        .max(10 * 1024 * 1024);

    let mut flags = EnvFlags::READ_ONLY;
    if target.no_sub_dir {
        flags |= EnvFlags::NO_SUB_DIR;
    }
    if no_lock {
        flags |= EnvFlags::NO_LOCK;
    }

    let mut opts = EnvOpenOptions::new();
    opts.map_size(map_size).max_dbs(MAX_NAMED_DBS);

    // SAFETY: READ_ONLY rules out any mutation. NO_LOCK is only set on
    // explicit user request (snapshot inspection); the flag's documentation
    // warns against concurrent writers.
    let env = unsafe {
        opts.flags(flags)
            .open(&target.env_path)
            .map_err(|e| format!("cannot open LMDB env {}: {e}", target.env_path.display()))?
    };
    Ok(env)
}

fn data_file_path(target: &EnvTarget) -> PathBuf {
    if target.no_sub_dir {
        target.env_path.clone()
    } else {
        target.env_path.join("data.mdb")
    }
}

fn lock_file_path(target: &EnvTarget) -> PathBuf {
    if target.no_sub_dir {
        let mut os = target.env_path.as_os_str().to_os_string();
        os.push("-lock");
        PathBuf::from(os)
    } else {
        target.env_path.join("lock.mdb")
    }
}

// ─────────────────────────────── inspection ────────────────────────────────

struct RawEntry {
    key: Vec<u8>,
    value_len: u64,
    preview: Option<Vec<u8>>,
    verified: Option<Result<(), [u8; 32]>>,
}

fn table_report(name: &str, db: Database<Bytes, Bytes>, rtxn: &RoTxn) -> Result<TableReport, String> {
    let stat = db
        .stat(rtxn)
        .map_err(|e| format!("stat failed for table {name}: {e}"))?;
    let pages = (stat.branch_pages + stat.leaf_pages + stat.overflow_pages) as u64;
    Ok(TableReport {
        name: name.to_string(),
        entries: stat.entries as u64,
        btree_depth: stat.depth,
        branch_pages: stat.branch_pages,
        leaf_pages: stat.leaf_pages,
        overflow_pages: stat.overflow_pages,
        used_bytes: pages * u64::from(stat.page_size),
    })
}

fn classify(entries: &[RawEntry], key_lengths: &BTreeMap<usize, u64>) -> StoreKind {
    if entries.is_empty() {
        return StoreKind::Empty;
    }
    if key_lengths.keys().all(|&l| l == XORNAME_LEN) {
        if entries.iter().all(|e| e.value_len == 0) {
            return StoreKind::PaidList;
        }
        if entries.iter().all(|e| e.value_len > 0) {
            return StoreKind::ChunkStore;
        }
    }
    StoreKind::Generic
}

fn inspect_env(target: &EnvTarget, args: &Args) -> Result<EnvironmentReport, String> {
    let env = open_env(target, args.no_lock)?;

    let rtxn = env
        .read_txn()
        .map_err(|e| format!("cannot open read txn: {e}"))?;
    let main_db: Database<Bytes, Bytes> = env
        .open_database(&rtxn, None)
        .map_err(|e| format!("cannot open main database: {e}"))?
        .ok_or("main database not found")?;

    // ── walk the main database ──────────────────────────────────────────
    // Entries that look like sub-database records (value = 48-byte MDB_db
    // struct, key = valid UTF-8 name) are probed as named databases; only
    // on a successful open do they count as a table instead of a record.
    let mut entries: Vec<RawEntry> = Vec::new();
    let mut named_tables: Vec<TableReport> = Vec::new();

    let iter = main_db
        .iter(&rtxn)
        .map_err(|e| format!("cannot iterate: {e}"))?;
    for item in iter {
        let (key, value) = item.map_err(|e| format!("read error while iterating: {e}"))?;

        if value.len() == MDB_DB_RECORD_SIZE {
            if let Ok(name) = std::str::from_utf8(key) {
                if !name.contains('\0') && (named_tables.len() as u32) < MAX_NAMED_DBS {
                    if let Ok(Some(sub)) = env.open_database::<Bytes, Bytes>(&rtxn, Some(name)) {
                        named_tables.push(table_report(name, sub, &rtxn)?);
                        continue;
                    }
                }
            }
        }

        let verified = if args.verify && key.len() == XORNAME_LEN && !value.is_empty() {
            let computed: [u8; 32] = *blake3::hash(value).as_bytes();
            Some(if computed == key { Ok(()) } else { Err(computed) })
        } else {
            None
        };

        entries.push(RawEntry {
            key: key.to_vec(),
            value_len: value.len() as u64,
            preview: (args.preview > 0 && !value.is_empty())
                .then(|| value[..value.len().min(args.preview)].to_vec()),
            verified,
        });
    }

    // ── tables ──────────────────────────────────────────────────────────
    let mut tables = vec![table_report("(main)", main_db, &rtxn)?];
    tables.extend(named_tables);

    // ── environment metadata ────────────────────────────────────────────
    let info = env.info();
    let main_stat = main_db
        .stat(&rtxn)
        .map_err(|e| format!("stat failed: {e}"))?;
    let data_file = data_file_path(target);
    let data_file_bytes = std::fs::metadata(&data_file).map(|m| m.len()).unwrap_or(0);

    let environment = EnvReport {
        label: target.label.clone(),
        env_path: target.env_path.display().to_string(),
        data_file: data_file.display().to_string(),
        data_file_bytes,
        lock_file_present: lock_file_path(target).exists(),
        no_sub_dir_mode: target.no_sub_dir,
        page_size: main_stat.page_size,
        map_size: info.map_size,
        last_txn_id: info.last_txn_id,
        last_page_number: info.last_page_number,
        readers_used: info.number_of_readers,
        readers_max: info.maximum_number_of_readers,
    };

    // ── raw meta pages and space accounting ─────────────────────────────
    let meta_report = meta::parse_meta(&data_file)?;
    let payload_bytes: u64 = entries.iter().map(|e| e.value_len).sum();
    let space = {
        let active = meta_report.active();
        let psize = u64::from(meta_report.page_size);
        let used_span = (active.last_page + 1) * psize;
        // Live pages = touched span minus pages parked on the freelist and
        // minus the freelist's own B-tree pages... the freelist B-tree IS
        // live data, so only the *listed free pages* are subtracted. The
        // number of free pages is the sum of the freelist values, which
        // LMDB does not expose through stats — derive it from the page
        // counts instead: every touched page is either a meta page, part
        // of a B-tree (main, freelist, sub-DBs), or free.
        let btree_pages: u64 = {
            let f = active.freelist_db;
            let m = active.main_db;
            (f.branch_pages + f.leaf_pages + f.overflow_pages)
                + (m.branch_pages + m.leaf_pages + m.overflow_pages)
                + tables
                    .iter()
                    .skip(1) // (main) is already counted via the meta record
                    .map(|t| (t.branch_pages + t.leaf_pages + t.overflow_pages) as u64)
                    .sum::<u64>()
        };
        let live = (2 + btree_pages) * psize; // + 2 meta pages
        let free = used_span.saturating_sub(live);
        SpaceReport {
            file_bytes: data_file_bytes,
            used_span_bytes: used_span,
            live_bytes: live,
            free_bytes: free,
            utilization_percent: if used_span > 0 {
                live as f64 / used_span as f64 * 100.0
            } else {
                0.0
            },
            payload_bytes,
            structural_overhead_bytes: live.saturating_sub(payload_bytes),
        }
    };

    drop(rtxn);

    // ── schema ──────────────────────────────────────────────────────────
    let mut key_lengths: BTreeMap<usize, u64> = BTreeMap::new();
    for e in &entries {
        *key_lengths.entry(e.key.len()).or_insert(0) += 1;
    }
    let store_kind = classify(&entries, &key_lengths);
    let (key_description, value_description) = match store_kind {
        StoreKind::ChunkStore => (
            format!("{XORNAME_LEN}-byte XOR address (BLAKE3 hash of chunk content)"),
            "raw chunk bytes (no wrapper, no metadata)".to_string(),
        ),
        StoreKind::PaidList => (
            format!("{XORNAME_LEN}-byte XOR address of a paid-authorized key"),
            "empty (set membership only)".to_string(),
        ),
        StoreKind::Generic | StoreKind::Empty => (
            "raw bytes".to_string(),
            "raw bytes".to_string(),
        ),
    };
    let schema = SchemaReport {
        store_kind,
        key_description,
        value_description,
        key_length_distribution: key_lengths,
        matches_ant_node_format: matches!(store_kind, StoreKind::ChunkStore | StoreKind::PaidList),
    };

    // ── verification ────────────────────────────────────────────────────
    let verification = args.verify.then(|| {
        let mut ok = 0u64;
        let mut failed = 0u64;
        let mut skipped_key = 0u64;
        let mut skipped_empty = 0u64;
        let mut failures = Vec::new();
        for e in &entries {
            match &e.verified {
                Some(Ok(())) => ok += 1,
                Some(Err(computed)) => {
                    failed += 1;
                    if failures.len() < 10 {
                        failures.push(VerifyFailure {
                            xor_address: hex::encode(&e.key),
                            computed_blake3: hex::encode(computed),
                            size_bytes: e.value_len,
                        });
                    }
                }
                None if e.value_len == 0 => skipped_empty += 1,
                None => skipped_key += 1,
            }
        }
        VerifyReport {
            checked: ok + failed,
            ok,
            failed,
            skipped_non_xorname_keys: skipped_key,
            skipped_empty_values: skipped_empty,
            failures,
        }
    });

    // ── statistics ──────────────────────────────────────────────────────
    let statistics = (!entries.is_empty() && store_kind != StoreKind::PaidList).then(|| {
        let mut sizes: Vec<u64> = entries.iter().map(|e| e.value_len).collect();
        sizes.sort_unstable();
        StatsReport {
            total_payload_bytes: sizes.iter().sum(),
            min_bytes: sizes[0],
            max_bytes: *sizes.last().unwrap_or(&0),
            mean_bytes: sizes.iter().sum::<u64>() / sizes.len() as u64,
            median_bytes: percentile(&sizes, 50.0),
            p90_bytes: percentile(&sizes, 90.0),
            p99_bytes: percentile(&sizes, 99.0),
            histogram: histogram(&sizes),
        }
    });

    // ── record list ─────────────────────────────────────────────────────
    match args.sort {
        SortOrder::Addr => entries.sort_by(|a, b| a.key.cmp(&b.key)),
        SortOrder::Size => {
            entries.sort_by(|a, b| b.value_len.cmp(&a.value_len).then(a.key.cmp(&b.key)));
        }
    }
    let record_count = entries.len() as u64;
    let truncate = args.limit > 0 && entries.len() > args.limit;
    let records_truncated_at = truncate.then_some(args.limit);
    let records: Vec<RecordReport> = entries
        .iter()
        .take(if truncate { args.limit } else { entries.len() })
        .map(|e| RecordReport {
            xor_address: hex::encode(&e.key),
            size_bytes: e.value_len,
            preview_hex: e.preview.as_deref().map(hex::encode),
        })
        .collect();

    Ok(EnvironmentReport {
        environment,
        meta: meta_report,
        space,
        tables,
        schema,
        record_count,
        records,
        records_truncated_at,
        statistics,
        verification,
    })
}

// ─────────────────────────────── statistics ────────────────────────────────

/// Nearest-rank percentile on an ascending sorted slice.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn histogram(sizes: &[u64]) -> Vec<HistogramBucket> {
    // 4 MiB is a legal chunk size (ant-protocol MAX_CHUNK_SIZE), so the top
    // bounded bucket is upper-inclusive; the overflow bucket only catches
    // protocol violations.
    const MAX_CHUNK: u64 = 4 * 1024 * 1024;
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * 1024;
    const BOUNDS: [(u64, &str); 14] = [
        (KIB, "< 1 KiB"),
        (2 * KIB, "1–2 KiB"),
        (4 * KIB, "2–4 KiB"),
        (8 * KIB, "4–8 KiB"),
        (16 * KIB, "8–16 KiB"),
        (32 * KIB, "16–32 KiB"),
        (64 * KIB, "32–64 KiB"),
        (128 * KIB, "64–128 KiB"),
        (256 * KIB, "128–256 KiB"),
        (512 * KIB, "256–512 KiB"),
        (MIB, "512 KiB–1 MiB"),
        (2 * MIB, "1–2 MiB"),
        (3 * MIB, "2–3 MiB"),
        (4 * MIB, "3–4 MiB"),
    ];
    let mut buckets: Vec<HistogramBucket> = BOUNDS
        .iter()
        .map(|(ub, label)| HistogramBucket {
            label: (*label).to_string(),
            upper_bound_bytes: Some(*ub),
            count: 0,
        })
        .collect();
    buckets.push(HistogramBucket {
        label: "> 4 MiB".to_string(),
        upper_bound_bytes: None,
        count: 0,
    });

    for &s in sizes {
        let idx = if s > MAX_CHUNK {
            BOUNDS.len()
        } else {
            // s == 4 MiB finds no smaller bound and lands in "3–4 MiB".
            BOUNDS
                .iter()
                .position(|(ub, _)| s < *ub)
                .unwrap_or(BOUNDS.len() - 1)
        };
        buckets[idx].count += 1;
    }
    buckets
}

// ─────────────────────────────── formatting ────────────────────────────────

/// Thousands separator: 4194304 → "4,194,304".
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Human-readable size: 4194304 → "4.00 MiB".
fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

fn size_cell(bytes: u64) -> String {
    format!("{} ({} B)", human_size(bytes), thousands(bytes))
}

fn store_kind_label(kind: StoreKind) -> &'static str {
    match kind {
        StoreKind::ChunkStore => "chunk store",
        StoreKind::PaidList => "paid list",
        StoreKind::Generic => "generic LMDB",
        StoreKind::Empty => "empty",
    }
}

fn print_db_record(name: &str, r: &meta::DbRecord) {
    println!(
        "  {:<12}: root page {}  depth {}  branch/leaf/overflow {}/{}/{}  entries {}",
        name,
        r.root_page.map_or("-".to_string(), |p| p.to_string()),
        r.depth,
        r.branch_pages,
        r.leaf_pages,
        r.overflow_pages,
        thousands(r.entries),
    );
}

fn print_environment(rep: &EnvironmentReport, args: &Args) {
    let e = &rep.environment;
    println!();
    println!(
        "Database: {} — {}",
        e.label,
        store_kind_label(rep.schema.store_kind)
    );
    println!("{}", "═".repeat(72));

    println!("\nEnvironment");
    println!(
        "  env path      : {}{}",
        e.env_path,
        if e.no_sub_dir_mode { "  [NO_SUB_DIR]" } else { "" }
    );
    println!("  data file     : {}  {}", e.data_file, size_cell(e.data_file_bytes));
    println!(
        "  lock file     : {}",
        if e.lock_file_present { "present" } else { "absent" }
    );
    println!("  page size     : {} B", e.page_size);
    println!("  map size      : {}", size_cell(e.map_size as u64));
    println!("  last txn id   : {}", e.last_txn_id);
    println!("  last page     : {}", e.last_page_number);
    println!("  readers       : {} / {}", e.readers_used, e.readers_max);

    let m = &rep.meta;
    println!("\nLMDB meta pages (raw, both generations)");
    println!(
        "  format        : magic ok, version {}, page size {} B, env flags 0x{:04x}",
        m.active().format_version,
        m.page_size,
        m.env_flags
    );
    for (i, page) in m.meta_pages.iter().enumerate() {
        println!(
            "  meta {}        : txn id {}  last page {}  map size on disk {}{}",
            i,
            page.txn_id,
            page.last_page,
            human_size(page.map_size_on_disk),
            if i == m.active_meta { "  [active]" } else { "" }
        );
    }
    print_db_record("freelist DB", &m.active().freelist_db);
    print_db_record("main DB", &m.active().main_db);

    let s = &rep.space;
    println!("\nSpace accounting");
    println!("  file size     : {}", size_cell(s.file_bytes));
    println!("  touched span  : {}", size_cell(s.used_span_bytes));
    println!(
        "  live pages    : {}  ({:.1}% of span)",
        size_cell(s.live_bytes),
        s.utilization_percent
    );
    println!("  reclaimable   : {}", size_cell(s.free_bytes));
    println!("  payload       : {}", size_cell(s.payload_bytes));
    println!("  struct. overhead: {}", size_cell(s.structural_overhead_bytes));

    println!("\nTables (LMDB databases)");
    println!(
        "  {:<10} {:>10} {:>6} {:>8} {:>7} {:>9} {:>14}",
        "NAME", "ENTRIES", "DEPTH", "BRANCH", "LEAF", "OVERFLOW", "USED"
    );
    for t in &rep.tables {
        println!(
            "  {:<10} {:>10} {:>6} {:>8} {:>7} {:>9} {:>14}",
            t.name,
            thousands(t.entries),
            t.btree_depth,
            t.branch_pages,
            t.leaf_pages,
            t.overflow_pages,
            human_size(t.used_bytes)
        );
    }

    let sc = &rep.schema;
    println!("\nSchema (main)");
    println!("  key           : {}", sc.key_description);
    println!("  value         : {}", sc.value_description);
    let dist: Vec<String> = sc
        .key_length_distribution
        .iter()
        .map(|(len, n)| format!("{} × {len} B", thousands(*n)))
        .collect();
    println!(
        "  key lengths   : {}",
        if dist.is_empty() {
            "(empty database)".to_string()
        } else {
            dist.join(", ")
        }
    );
    println!(
        "  format check  : {}",
        if sc.matches_ant_node_format {
            format!(
                "OK — matches the ant-node {} format",
                store_kind_label(sc.store_kind)
            )
        } else {
            "no match with a known ant-node format".to_string()
        }
    );

    println!("\nRecords: {}", thousands(rep.record_count));

    if let Some(v) = &rep.verification {
        println!("\nContent verification (BLAKE3(value) == key)");
        println!(
            "  checked: {}   ok: {}   failed: {}   skipped: {} empty-value, {} non-XorName-key",
            thousands(v.checked),
            thousands(v.ok),
            thousands(v.failed),
            thousands(v.skipped_empty_values),
            thousands(v.skipped_non_xorname_keys)
        );
        for f in &v.failures {
            println!(
                "  FAIL {}  ({} B) — computed {}",
                f.xor_address,
                thousands(f.size_bytes),
                f.computed_blake3
            );
        }
        if v.failed > v.failures.len() as u64 {
            println!("  … {} more failures not shown", v.failed - v.failures.len() as u64);
        }
    }

    if !args.no_chunks && !rep.records.is_empty() {
        println!("\nRecords (XOR address · size)");
        for r in &rep.records {
            print!("  {}  {:>12}", r.xor_address, format!("{} B", thousands(r.size_bytes)));
            if let Some(p) = &r.preview_hex {
                print!("  {p}…");
            }
            println!();
        }
        if let Some(limit) = rep.records_truncated_at {
            println!(
                "  … list truncated at {} of {} records (--limit)",
                limit,
                thousands(rep.record_count)
            );
        }
    }

    if let Some(st) = &rep.statistics {
        println!("\nStatistics (value sizes)");
        println!("  total payload : {}", size_cell(st.total_payload_bytes));
        println!("  min / max     : {} / {}", size_cell(st.min_bytes), size_cell(st.max_bytes));
        println!(
            "  mean / median : {} / {}",
            size_cell(st.mean_bytes),
            size_cell(st.median_bytes)
        );
        println!("  p90 / p99     : {} / {}", size_cell(st.p90_bytes), size_cell(st.p99_bytes));
        println!("\n  Size histogram");
        let max_count = st.histogram.iter().map(|b| b.count).max().unwrap_or(1).max(1);
        for b in &st.histogram {
            let bar_len = ((b.count as f64 / max_count as f64) * 40.0).round() as usize;
            println!(
                "  {:>14} │{:<40} {}",
                b.label,
                "█".repeat(bar_len),
                thousands(b.count)
            );
        }
    }
}

fn main() {
    let args = Args::parse();

    let targets = match resolve_targets(&args.path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let mut environments = Vec::new();
    let mut had_error = false;
    for target in &targets {
        match inspect_env(target, &args) {
            Ok(rep) => environments.push(rep),
            Err(e) => {
                eprintln!("error: {}: {e}", target.label);
                had_error = true;
            }
        }
    }

    if environments.is_empty() {
        std::process::exit(1);
    }

    let report = Report { environments };
    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("error: failed to serialize report: {e}");
                std::process::exit(1);
            }
        }
    } else {
        println!("ant-node database inspector — {}", args.path.display());
        for rep in &report.environments {
            print_environment(rep, &args);
        }
    }

    // Verification failures surface in the exit code so the tool can serve
    // as an integrity check in scripts/CI.
    if report
        .environments
        .iter()
        .any(|r| r.verification.as_ref().is_some_and(|v| v.failed > 0))
    {
        std::process::exit(2);
    }
    if had_error {
        std::process::exit(1);
    }
}

// ──────────────────────────────────── tests ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vector from ant-node/src/storage/lmdb.rs (test_compute_address).
    #[test]
    fn blake3_matches_ant_node_compute_address() {
        assert_eq!(
            hex::encode(blake3::hash(b"hello world").as_bytes()),
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
    }

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 50.0), 50);
        assert_eq!(percentile(&v, 90.0), 90);
        assert_eq!(percentile(&v, 99.0), 99);
        assert_eq!(percentile(&v, 100.0), 100);
        assert_eq!(percentile(&[7], 50.0), 7);
        assert_eq!(percentile(&[], 50.0), 0);
    }

    #[test]
    fn histogram_buckets_cover_all_sizes() {
        let sizes = [10, 2048, 5000, 20_000, 100_000, 300_000, 600_000, 2_000_000, 4_194_304, 8_000_000];
        let h = histogram(&sizes);
        assert_eq!(h.iter().map(|b| b.count).sum::<u64>(), sizes.len() as u64);

        let count_of = |label: &str| h.iter().find(|b| b.label == label).unwrap().count;
        assert_eq!(count_of("256–512 KiB"), 1); // 300_000
        assert_eq!(count_of("512 KiB–1 MiB"), 1); // 600_000
        // Exactly MAX_CHUNK_SIZE is legal and must not land in the overflow bucket.
        assert_eq!(count_of("3–4 MiB"), 1); // 4_194_304
        assert_eq!(count_of("> 4 MiB"), 1); // 8_000_000 (protocol violation)
    }

    #[test]
    fn thousands_formatting() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(4_194_304), "4,194,304");
    }

    #[test]
    fn human_size_formatting() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(4_194_304), "4.00 MiB");
    }

    fn entry(key_len: usize, value_len: u64) -> RawEntry {
        RawEntry {
            key: vec![0xAA; key_len],
            value_len,
            preview: None,
            verified: None,
        }
    }

    #[test]
    fn store_classification() {
        let dist32: BTreeMap<usize, u64> = [(32usize, 2u64)].into_iter().collect();
        assert!(matches!(
            classify(&[entry(32, 100), entry(32, 5)], &dist32),
            StoreKind::ChunkStore
        ));
        assert!(matches!(
            classify(&[entry(32, 0), entry(32, 0)], &dist32),
            StoreKind::PaidList
        ));
        assert!(matches!(
            classify(&[entry(32, 0), entry(32, 5)], &dist32),
            StoreKind::Generic
        ));
        let dist_mixed: BTreeMap<usize, u64> = [(32usize, 1u64), (5, 1)].into_iter().collect();
        assert!(matches!(
            classify(&[entry(32, 9), entry(5, 9)], &dist_mixed),
            StoreKind::Generic
        ));
        assert!(matches!(classify(&[], &BTreeMap::new()), StoreKind::Empty));
    }

    #[test]
    fn resolve_paths() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path();

        // Node root with two environments: chunks.mdb and paid_list.mdb.
        for name in ["paid_list.mdb", "chunks.mdb"] {
            let env_dir = root.join(name);
            std::fs::create_dir_all(&env_dir).unwrap();
            std::fs::write(env_dir.join("data.mdb"), b"x").unwrap();
        }

        let targets = resolve_targets(root).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].label, "chunks.mdb"); // chunks.mdb sorts first
        assert_eq!(targets[1].label, "paid_list.mdb");
        assert!(!targets[0].no_sub_dir);

        let env_dir = root.join("chunks.mdb");
        let targets = resolve_targets(&env_dir).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].env_path, env_dir);

        let targets = resolve_targets(&env_dir.join("data.mdb")).unwrap();
        assert_eq!(targets[0].env_path, env_dir);
        assert!(!targets[0].no_sub_dir);

        // Standalone file with an arbitrary name → NO_SUB_DIR.
        let snapshot = root.join("backup.mdb");
        std::fs::write(&snapshot, b"x").unwrap();
        let targets = resolve_targets(&snapshot).unwrap();
        assert_eq!(targets[0].env_path, snapshot);
        assert!(targets[0].no_sub_dir);

        assert!(resolve_targets(&root.join("missing")).is_err());
    }
}

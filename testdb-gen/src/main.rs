//! Generates a test database set in the exact ant-node storage format.
//!
//! Layout matches `WithAutonomi/ant-node`:
//!
//! ```text
//! {out}/chunks.mdb/      chunk store   (src/storage/lmdb.rs)
//! {out}/paid_list.mdb/   paid list     (src/replication/paid_list.rs)
//! ```
//!
//! Both are LMDB environments with a single unnamed database:
//!
//! - chunk store: key = 32-byte XorName = BLAKE3 hash of the content,
//!   value = raw chunk bytes (no wrapper, no metadata)
//! - paid list: key = 32-byte XorName, value = empty (set membership)
//!
//! Chunk sizes are a realistic mix: a few tiny chunks, log-uniform mid-range
//! sizes, and one chunk at `MAX_CHUNK_SIZE` (4 MiB, see ant-protocol). With a
//! fixed `--seed` the databases are reproducible bit for bit.

use clap::Parser;
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// One chunk entry inside a `DataMap`, matching self_encryption's `ChunkInfo`
/// (`[index, dst_hash, src_hash, src_size]` on the wire).
#[derive(Serialize)]
struct ChunkInfo {
    index: usize,
    dst_hash: [u8; 32],
    src_hash: [u8; 32],
    src_size: usize,
}

/// self_encryption's versioned DataMap wire form: `[version:1, chunks, child]`.
/// Serialized with `rmp_serde` (MessagePack) this is byte-for-byte what the
/// autonomi client stores as a public DataMap chunk (see the client's
/// `memory_encryption.rs::wrap_data_map`).
#[derive(Serialize)]
struct VersionedDataMap {
    version: u8,
    chunk_identifiers: Vec<ChunkInfo>,
    child: Option<usize>,
}

/// Maximum chunk size on the Autonomi network (ant-protocol: `MAX_CHUNK_SIZE`).
const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Map size for the chunk-store test environment — generous; irrelevant for
/// the file format (data.mdb only grows with actual data).
const CHUNKS_MAP_SIZE: usize = 1024 * 1024 * 1024;

/// Map size ant-node uses for the paid list (paid_list.rs: DEFAULT_MAP_SIZE).
const PAID_LIST_MAP_SIZE: usize = 256 * 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "testdb-gen",
    about = "Generate a test database set (chunk store + paid list) in the ant-node LMDB format"
)]
struct Args {
    /// Output root directory (environments are created at {out}/chunks.mdb/
    /// and {out}/paid_list.mdb/)
    #[arg(short, long, default_value = "testdata")]
    out: PathBuf,

    /// Number of chunks to generate
    #[arg(short, long, default_value_t = 100)]
    count: usize,

    /// Extra paid-list keys without a stored chunk (paid, not yet uploaded)
    #[arg(long, default_value_t = 5)]
    extra_paid: usize,

    /// Additional plaintext (readable text) chunks — unencrypted content that
    /// the inspector's --classify should flag as "text"
    #[arg(long, default_value_t = 4)]
    plaintext: usize,

    /// Additional public DataMap chunks (real rmp-serde/MessagePack wire
    /// format) that --classify should detect as "datamap"
    #[arg(long, default_value_t = 2)]
    datamaps: usize,

    /// RNG seed (same seed → identical databases)
    #[arg(short, long, default_value_t = 42)]
    seed: u64,
}

/// A short, readable, low-entropy text payload of roughly `target` bytes.
fn plaintext_payload(target: usize, index: usize) -> Vec<u8> {
    let sentence = format!(
        "Chunk {index}: the quick brown fox jumps over the lazy dog. \
         Autonomi stores content-addressed chunks; BLAKE3(content) is the address. "
    );
    let mut out = String::new();
    while out.len() < target {
        out.push_str(&sentence);
    }
    out.truncate(target.max(sentence.len()));
    out.into_bytes()
}

/// Serialize a public DataMap referencing `refs` (real stored addresses and
/// their sizes) in self_encryption's exact rmp-serde/MessagePack wire format.
fn build_datamap(refs: &[([u8; 32], usize)], rng: &mut StdRng) -> Vec<u8> {
    let chunk_identifiers = refs
        .iter()
        .enumerate()
        .map(|(index, (dst_hash, size))| {
            let mut src_hash = [0u8; 32];
            rng.fill_bytes(&mut src_hash);
            ChunkInfo {
                index,
                dst_hash: *dst_hash,
                src_hash,
                // Pre-encryption source size, bounded to a realistic ≤ 1 MiB.
                src_size: (*size).clamp(1, 1024 * 1024),
            }
        })
        .collect();
    let dm = VersionedDataMap {
        version: 1,
        chunk_identifiers,
        child: None,
    };
    rmp_serde::to_vec(&dm).expect("DataMap serialization")
}

/// Deterministic, realistic size distribution:
/// - index 0: exactly `MAX_CHUNK_SIZE` (the network edge case)
/// - first ~5%: tiny chunks (32 B – 1 KiB)
/// - rest: log-uniform between 1 KiB and 512 KiB
fn chunk_size(index: usize, count: usize, rng: &mut StdRng) -> usize {
    if index == 0 {
        return MAX_CHUNK_SIZE;
    }
    if index <= count / 20 {
        return rng.gen_range(32..=1024);
    }
    let log_min = (1024f64).ln();
    let log_max = (512.0 * 1024.0f64).ln();
    let log_size = rng.gen_range(log_min..log_max);
    log_size.exp() as usize
}

/// Open (create) an environment exactly like ant-node does: `max_dbs(1)`,
/// one unnamed database.
fn create_env(dir: &Path, map_size: usize) -> Result<(Env, Database<Bytes, Bytes>), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    // SAFETY: no other process opens this freshly created directory.
    let env = unsafe {
        EnvOpenOptions::new()
            .map_size(map_size)
            .max_dbs(1)
            .open(dir)?
    };
    let mut wtxn = env.write_txn()?;
    let db: Database<Bytes, Bytes> = env.create_database(&mut wtxn, None)?;
    wtxn.commit()?;
    Ok((env, db))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Self-check of the address computation against the test vector from
    // ant-node/src/storage/lmdb.rs (test_compute_address).
    assert_eq!(
        hex::encode(blake3::hash(b"hello world").as_bytes()),
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24",
        "BLAKE3 test vector does not match ant-node"
    );

    let mut rng = StdRng::seed_from_u64(args.seed);

    // ── chunk store ─────────────────────────────────────────────────────
    let chunks_dir = args.out.join("chunks.mdb");
    let (chunks_env, chunks_db) = create_env(&chunks_dir, CHUNKS_MAP_SIZE)?;

    let mut wtxn = chunks_env.write_txn()?;
    let mut addresses: Vec<[u8; 32]> = Vec::with_capacity(args.count);
    // (address, size) of the random data chunks — referenced by the DataMaps.
    let mut data_refs: Vec<([u8; 32], usize)> = Vec::with_capacity(args.count);
    let mut total_bytes = 0u64;

    // ── random "data" chunks (stand in for self-encrypted, high-entropy) ─
    for i in 0..args.count {
        let size = chunk_size(i, args.count, &mut rng);
        let mut content = vec![0u8; size];
        rng.fill_bytes(&mut content);

        // Address = BLAKE3(content), like LmdbStorage::compute_address().
        let address: [u8; 32] = *blake3::hash(&content).as_bytes();
        chunks_db.put(&mut wtxn, &address, &content)?;
        addresses.push(address);
        data_refs.push((address, size));
        total_bytes += size as u64;

        if i < 3 || i == args.count - 1 {
            println!("  chunk {:>3}: {} ({} bytes)", i, hex::encode(address), size);
        } else if i == 3 {
            println!("  ...");
        }
    }

    // ── plaintext chunks (unencrypted, low entropy → classified "text") ──
    for i in 0..args.plaintext {
        let content = plaintext_payload(rng.gen_range(200..4000), i);
        let address: [u8; 32] = *blake3::hash(&content).as_bytes();
        chunks_db.put(&mut wtxn, &address, &content)?;
        addresses.push(address);
        total_bytes += content.len() as u64;
    }

    // ── public DataMap chunks (real MessagePack wire format → "datamap") ─
    let datamaps = if data_refs.is_empty() { 0 } else { args.datamaps };
    for i in 0..datamaps {
        // Reference a growing slice of real data chunks (≥3, like a root map).
        let n = (3 + i * 2).clamp(1, data_refs.len());
        let content = build_datamap(&data_refs[..n], &mut rng);
        let address: [u8; 32] = *blake3::hash(&content).as_bytes();
        chunks_db.put(&mut wtxn, &address, &content)?;
        addresses.push(address);
        total_bytes += content.len() as u64;
    }
    wtxn.commit()?;

    let total_chunks = args.count + args.plaintext + datamaps;

    // ── paid list ───────────────────────────────────────────────────────
    // A real node tracks the keys it considers paid-authorized: the stored
    // chunks plus keys that were paid for but not (yet) uploaded.
    let paid_dir = args.out.join("paid_list.mdb");
    let (paid_env, paid_db) = create_env(&paid_dir, PAID_LIST_MAP_SIZE)?;

    let mut wtxn = paid_env.write_txn()?;
    for address in &addresses {
        paid_db.put(&mut wtxn, address, &[])?;
    }
    for _ in 0..args.extra_paid {
        let mut address = [0u8; 32];
        rng.fill_bytes(&mut address);
        paid_db.put(&mut wtxn, &address, &[])?;
    }
    wtxn.commit()?;

    // ── recheck entry counts straight from the LMDB metadata ────────────
    let rtxn = chunks_env.read_txn()?;
    let chunk_entries = chunks_db.stat(&rtxn)?.entries;
    drop(rtxn);
    let rtxn = paid_env.read_txn()?;
    let paid_entries = paid_db.stat(&rtxn)?.entries;
    drop(rtxn);

    println!();
    println!(
        "Created {} chunks ({} bytes payload) in {}",
        chunk_entries,
        total_bytes,
        chunks_dir.display()
    );
    println!(
        "  {} data + {} plaintext + {} datamap",
        args.count, args.plaintext, datamaps
    );
    println!(
        "Created {} paid-list keys ({} stored + {} paid-only) in {}",
        paid_entries,
        addresses.len(),
        args.extra_paid,
        paid_dir.display()
    );
    assert_eq!(chunk_entries, total_chunks, "chunk entry count mismatch after commit");
    assert_eq!(
        paid_entries,
        total_chunks + args.extra_paid,
        "paid-list entry count mismatch after commit"
    );

    Ok(())
}

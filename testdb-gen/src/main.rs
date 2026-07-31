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
use std::path::{Path, PathBuf};

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

    /// RNG seed (same seed → identical databases)
    #[arg(short, long, default_value_t = 42)]
    seed: u64,
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
    let mut total_bytes = 0u64;

    for i in 0..args.count {
        let size = chunk_size(i, args.count, &mut rng);
        let mut content = vec![0u8; size];
        rng.fill_bytes(&mut content);

        // Address = BLAKE3(content), like LmdbStorage::compute_address().
        let address: [u8; 32] = *blake3::hash(&content).as_bytes();
        chunks_db.put(&mut wtxn, &address, &content)?;
        addresses.push(address);
        total_bytes += size as u64;

        if i < 3 || i == args.count - 1 {
            println!("  chunk {:>3}: {} ({} bytes)", i, hex::encode(address), size);
        } else if i == 3 {
            println!("  ...");
        }
    }
    wtxn.commit()?;

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
        "Created {} paid-list keys ({} stored + {} paid-only) in {}",
        paid_entries,
        addresses.len(),
        args.extra_paid,
        paid_dir.display()
    );
    assert_eq!(chunk_entries, args.count, "chunk entry count mismatch after commit");
    assert_eq!(
        paid_entries,
        args.count + args.extra_paid,
        "paid-list entry count mismatch after commit"
    );

    Ok(())
}

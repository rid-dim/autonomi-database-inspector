//! teststore-gen — build a test chunk store in the exact ant-node file layout.
//!
//! The store is populated the way a real node's store gets populated: files
//! are self-encrypted with the real `self_encryption` crate (the same version
//! the autonomi client uses), every resulting encrypted chunk is written to
//! `chunks/<xy>/<blake3-hex>`, and each file's DataMap is stored as a public
//! DataMap chunk in the client's wire format (`rmp_serde`). One file is large
//! enough that its DataMap gets *shrunk* (child level), so the store contains
//! a real multi-level DataMap whose parent can be resolved from local chunks.
//! A few plaintext and media chunks stand in for raw `ant chunk put` uploads.
//!
//! Deterministic for a given `--seed`; nothing is random at runtime.

use clap::Parser;
use self_encryption::{bytes::Bytes, encrypt, shrink_data_map, DataMap, EncryptedChunk};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "teststore-gen", version, about = "Generate a test chunk store in the ant-node file layout")]
struct Args {
    /// Output directory (becomes a node root: <out>/chunks/… plus node markers)
    #[arg(long, short)]
    out: PathBuf,

    /// Plaintext sizes of the files to self-encrypt and store publicly, in
    /// bytes, comma-separated. At least one should exceed 4 chunks (> ~16 MiB
    /// of incompressible data) to produce a shrunk DataMap.
    #[arg(long, value_delimiter = ',', default_value = "5000,100000,1500000,9000000,20000000")]
    file_sizes: Vec<usize>,

    /// Number of additional private files (chunks stored, DataMap written to
    /// <out>/private/*.datamap instead of the store)
    #[arg(long, default_value_t = 1)]
    private: usize,

    /// Number of plaintext text chunks
    #[arg(long, default_value_t = 3)]
    plaintext: usize,

    /// Number of media chunks (PNG header + payload)
    #[arg(long, default_value_t = 1)]
    media: usize,

    /// Number of standalone random chunks (orphans without a DataMap)
    #[arg(long, default_value_t = 20)]
    orphans: usize,

    /// PRNG seed
    #[arg(long, default_value_t = 42)]
    seed: u64,

    /// Also drop an in-flight temp file and a quarantined entry into a shard
    #[arg(long)]
    with_junk: bool,
}

/// xorshift64* — small, deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0u8; n];
        self.fill(&mut v);
        v
    }
}

struct Store {
    chunks_dir: PathBuf,
    written: usize,
    bytes: u64,
}

impl Store {
    fn new(root: &Path) -> std::io::Result<Self> {
        let chunks_dir = root.join("chunks");
        fs::create_dir_all(&chunks_dir)?;
        // Exactly what ant-node writes at store creation (StoreLayout::default(),
        // serde_json::to_vec_pretty).
        let layout = serde_json::json!({
            "schema": 1,
            "scheme": "suffix-hex",
            "shard_chars": 2,
            "depth": 1,
            "name_encoding": "lower-hex"
        });
        fs::write(chunks_dir.join("layout.json"), serde_json::to_vec_pretty(&layout)?)?;
        Ok(Store { chunks_dir, written: 0, bytes: 0 })
    }

    /// Write `content` under its BLAKE3 address, sharded on the last byte.
    fn put(&mut self, content: &[u8]) -> std::io::Result<String> {
        let hash = blake3::hash(content);
        let addr = hex::encode(hash.as_bytes());
        let shard = self.chunks_dir.join(&addr[62..]);
        fs::create_dir_all(&shard)?;
        let path = shard.join(&addr);
        if !path.exists() {
            fs::write(&path, content)?;
            self.written += 1;
            self.bytes += content.len() as u64;
        }
        Ok(addr)
    }

    fn put_all(&mut self, chunks: &[EncryptedChunk]) -> std::io::Result<()> {
        for c in chunks {
            self.put(&c.content)?;
        }
        Ok(())
    }
}

fn self_encrypt(plain: Vec<u8>, store: &mut Store) -> Result<DataMap, String> {
    let (data_map, chunks) = encrypt(Bytes::from(plain)).map_err(|e| e.to_string())?;
    store.put_all(&chunks).map_err(|e| e.to_string())?;
    // Shrink exactly like the client does (self_encryption::shrink_data_map
    // loops while len > 3), storing the intermediate chunks too.
    let mut stored: Vec<(Vec<u8>,)> = Vec::new();
    let (final_map, _) = shrink_data_map(data_map, |_addr, content| {
        stored.push((content.to_vec(),));
        Ok(())
    })
    .map_err(|e| e.to_string())?;
    for (c,) in stored {
        store.put(&c).map_err(|e| e.to_string())?;
    }
    Ok(final_map)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse();
    let mut rng = Rng(args.seed | 1);
    let root = &args.out;
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let mut store = Store::new(root).map_err(|e| e.to_string())?;

    println!("Generating test store at {}", root.display());
    println!();

    // Public files: chunks + DataMap chunk in the store.
    println!("Public files (DataMap stored as a chunk):");
    for (i, &size) in args.file_sizes.iter().enumerate() {
        let plain = rng.bytes(size);
        let plain_hash = hex::encode(blake3::hash(&plain).as_bytes());
        let dm = self_encrypt(plain, &mut store)?;
        let wire = rmp_serde::to_vec(&dm).map_err(|e| e.to_string())?;
        let addr = store.put(&wire).map_err(|e| e.to_string())?;
        let level = dm.child().map(|c| format!("child {c}")).unwrap_or_else(|| "root".into());
        println!(
            "  file {i}: {size:>10} B  datamap {addr}  ({level}, {} chunks, plaintext blake3 {plain_hash})",
            dm.len()
        );
    }

    // Private files: chunks in the store, DataMap only as a .datamap file.
    if args.private > 0 {
        let private_dir = root.join("private");
        fs::create_dir_all(&private_dir).map_err(|e| e.to_string())?;
        println!();
        println!("Private files (DataMap written to <out>/private/*.datamap):");
        for i in 0..args.private {
            let size = 200_000 + (rng.next_u64() % 800_000) as usize;
            let plain = rng.bytes(size);
            let dm = self_encrypt(plain, &mut store)?;
            let wire = rmp_serde::to_vec(&dm).map_err(|e| e.to_string())?;
            let path = private_dir.join(format!("private-{i}.bin.datamap"));
            fs::write(&path, &wire).map_err(|e| e.to_string())?;
            println!("  {}  ({} chunks, {size} B)", path.display(), dm.len());
        }
    }

    // Plaintext chunks (as `ant chunk put` of a text file would store them).
    let text = "Autonomi test chunk. The quick brown fox jumps over the lazy dog. \
                Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    for i in 0..args.plaintext {
        let body = format!("# plaintext chunk {i}\n{}", text.repeat(20 + i * 7));
        store.put(body.as_bytes()).map_err(|e| e.to_string())?;
    }

    // Media chunks: PNG signature followed by pseudo-random payload.
    for _ in 0..args.media {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(rng.bytes(30_000));
        store.put(&png).map_err(|e| e.to_string())?;
    }

    // Orphan encrypted-looking chunks (a node mostly holds chunks of files
    // whose DataMaps it does not have).
    for _ in 0..args.orphans {
        let size = 1000 + (rng.next_u64() % 400_000) as usize;
        let blob = rng.bytes(size);
        store.put(&blob).map_err(|e| e.to_string())?;
    }

    if args.with_junk {
        let shard = store.chunks_dir.join("ab");
        fs::create_dir_all(&shard).map_err(|e| e.to_string())?;
        fs::write(shard.join(".tmp.4242.0badf00d.1"), b"interrupted write").map_err(|e| e.to_string())?;
        fs::write(shard.join("stray.not-a-chunk"), b"quarantined").map_err(|e| e.to_string())?;
    }

    // Node-root markers beside the store.
    let state = serde_json::json!({
        "schema": 1,
        "phase": "files_only",
        "first_start_unix": 1_756_100_000u64,
        "committed_at_unix": null,
        "rebuilds_since_commit": 0,
        "shed_key_count": 0,
        "kept_key_count": store.written
    });
    fs::write(root.join("migration-state.json"), serde_json::to_vec_pretty(&state).unwrap())
        .map_err(|e| e.to_string())?;
    fs::create_dir_all(root.join("paid_list.mdb")).map_err(|e| e.to_string())?;

    println!();
    println!("Wrote {} chunk files, {} bytes, to {}", store.written, store.bytes, store.chunks_dir.display());
    Ok(())
}

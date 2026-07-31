# autonomi-database-inspector

Terminal tool for inspecting [ant-node](https://github.com/WithAutonomi/ant-node) LMDB databases — built for observability and statistical analysis, without ever touching the node's data (strictly read-only).

## Quickstart

```console
# build
cargo build --release

# generate a realistic test database set (100 chunks + paid list)
cargo run --release -p testdb-gen -- --out testdata

# inspect it
cargo run --release -p ant-db-inspector -- testdata --verify

# or point it at a real node root / a single database
ant-db-inspector /path/to/node-root
ant-db-inspector /path/to/node-root/chunks.mdb
ant-db-inspector /path/to/chunks.mdb/data.mdb
ant-db-inspector copied-snapshot.mdb --no-lock
```

## What ant-node stores (background)

ant-node persists two LMDB environments (via `heed` 0.22) under a node's root
directory. Each contains exactly **one unnamed database**:

| Environment | Source | Key | Value |
|---|---|---|---|
| `chunks.mdb/` | `src/storage/lmdb.rs` | 32-byte **XorName** = **BLAKE3** hash of the content | raw chunk bytes (no wrapper) |
| `paid_list.mdb/` | `src/replication/paid_list.rs` | 32-byte XorName of a paid-authorized key | empty (set membership) |

Maximum chunk size is 4 MiB (`ant-protocol::MAX_CHUNK_SIZE`).

## ant-db-inspector

Opens every database strictly read-only and prints everything the files
contain:

- **Environment**: file sizes, page size, map size, last transaction id, readers
- **Raw LMDB meta pages**: both generations with txn ids, active meta, on-disk
  map size, freelist/main B-tree records — data the normal LMDB API doesn't expose
- **Space accounting**: touched span, live pages, reclaimable pages, payload
  vs. structural overhead
- **Tables**: entries, B-tree depth, branch/leaf/overflow pages, used bytes
  (named sub-databases are enumerated too, for generic LMDB files)
- **Schema**: key/value description, key-length distribution, and a format
  check that classifies the database (chunk store / paid list / generic)
- **Records**: count plus all XOR addresses with their sizes
- **Statistics**: total/min/max/mean/median/p90/p99 and a size histogram
- **Content classification** (`--classify`): per-chunk guess of what the bytes
  are, plus a distribution with the share of public **DataMaps** (see below)
- `--verify`: recomputes BLAKE3 over every chunk and compares it to the key
- `--extract` / `--dump-all`: write raw chunk bytes to a file or directory
- `--preview N`: hex preview of the first N value bytes per record

| Option | Effect |
|---|---|
| `--json` | full report as JSON (for scripts and analysis pipelines) |
| `--verify` | integrity check: `BLAKE3(value) == key` for every chunk |
| `--classify` | classify each chunk (DataMap / media / text / high-entropy) and print a distribution; reads every value, so it is opt-in |
| `--assume-encrypted-above <BYTES>` | with `--classify`, assume any chunk this large is self-encrypted and skip scanning its payload (default 3.5 MiB; `0` scans all) |
| `--extract <XOR_HEX>` | write one chunk's raw bytes to stdout (or `--output FILE`) |
| `--dump-all <DIR>` | write every chunk to `<DIR>/<xor-address>.bin` |
| `--export-textfiles <DIR>` | write only the plaintext-text chunks to `<DIR>/<xor-address>.txt` (the unencrypted, human-readable content on a node) |
| `--no-chunks` | suppress the per-record address list |
| `--limit N` | cap the record list at N entries per database (0 = all) |
| `--sort addr\|size` | list order: address ascending / size descending |
| `--preview N` | show first N value bytes as hex per record |
| `--no-lock` | open without the LMDB lock file (snapshots on read-only media; never while a node is writing) |

### Data at rest & content classification

A node's chunk store holds **opaque bytes**. The only rule the node enforces on
a PUT is `content.len() <= 4 MiB` and `BLAKE3(content) == address` — there is no
encryption in the node and no `self_encryption` dependency (verified against
`ant-node`'s source). Self-encryption is a **client-side** convention:

- The normal file-upload path encrypts client-side, so most stored chunks are
  **self-encrypted** — indistinguishable from random data (entropy ≈ 8 bit/byte).
  A single node can never recover the original plaintext: that needs the
  **DataMap** and the file's other chunks, which a lone node does not have.
- But the low-level `chunk_put(bytes)` API stores whatever bytes you give it, so
  a node can also hold **plaintext** chunks (the `ant-node` example literally
  does `chunk_put("hello world")`).

`--extract`/`--dump-all` therefore emit the stored bytes **as-is** — the
self-encrypted chunk for a normal upload, not file plaintext.

`--classify` guesses what each chunk is, purely from its bytes:

- **datamap** — a public DataMap (self-encryption's retrieval metadata) is stored
  *unencrypted*. The autonomi client serializes it with `rmp-serde` (MessagePack);
  the inspector deserializes candidate chunks back into mirror structs (current
  `[version, chunks, child]` form and the legacy `DataMapLevel` form) and
  validates them (contiguous indices, bounded `src_size`). This is how you spot
  public data and count it as a share of the store.
- **media** — recognized by magic bytes (PNG, PDF, ZIP, gzip, …): unencrypted.
- **text** — mostly printable, low entropy: unencrypted.
- **high-entropy (`enc?`)** — entropy near 8 bit/byte: the expected shape of a
  self-encrypted or compressed chunk (cannot be *proven* encrypted).
- **other (`bin`)** — structured binary matching none of the above.

DataMap and media matches are precise; "high-entropy" is a heuristic, since
self-encrypted output is by design indistinguishable from random data.

For speed on large stores, chunks at least `--assume-encrypted-above` bytes
(default 3.5 MiB) are taken to be self-encrypted without scanning their
payload — a full-size chunk is virtually always self-encrypted data, and this
avoids faulting in gigabytes. Magic-byte detection still runs first (so a large
unencrypted media file is recognized); set the threshold to `0` to scan every
chunk.

Exit codes: `0` ok · `1` open/read error · `2` verification failures — so the
tool doubles as an integrity check in scripts and CI:

```console
$ ant-db-inspector /var/antnode --verify --no-chunks || echo "corruption!"
$ ant-db-inspector /var/antnode --json | jq '.environments[0].statistics'
```

## testdb-gen

Generates a test database set in the exact ant-node format (same `heed`
version, same env options, address = BLAKE3 of the content — checked against
the test vector from ant-node's own test suite). Deterministic and
reproducible via `--seed`; sizes are a realistic mix including one 4 MiB
edge-case chunk. The paid list contains all stored chunk addresses plus a few
paid-but-not-yet-uploaded keys.

To exercise `--classify`, the store also contains a few **plaintext** chunks and
real **public DataMap** chunks. The DataMaps use the same `rmp-serde`
(MessagePack) wire format the autonomi client produces; the inspector's parser
is verified against ground-truth bytes emitted by the real `self_encryption`
crate (see the `detects_real_datamap_*` tests).

```console
$ testdb-gen --out testdata --count 100 --plaintext 4 --datamaps 2 --extra-paid 5 --seed 42
```

## Sample output

```text
$ ant-db-inspector testdata/chunks.mdb --verify --limit 5

Database: chunks.mdb — chunk store
════════════════════════════════════════════════════════════════════════

Environment
  env path      : testdata/chunks.mdb
  data file     : testdata/chunks.mdb/data.mdb  10.12 MiB (10,608,640 B)
  lock file     : present
  page size     : 4096 B
  map size      : 10.12 MiB (10,608,640 B)
  last txn id   : 1
  last page     : 2589
  readers       : 1 / 126

LMDB meta pages (raw, both generations)
  format        : magic ok, version 1, page size 4096 B, env flags 0x0008
  meta 0        : txn id 0  last page 1  map size on disk 1.00 GiB
  meta 1        : txn id 1  last page 2589  map size on disk 1.00 GiB  [active]
  freelist DB : root page -  depth 0  branch/leaf/overflow 0/0/0  entries 0
  main DB     : root page 1369  depth 2  branch/leaf/overflow 1/9/2578  entries 106

Space accounting
  file size     : 10.12 MiB (10,608,640 B)
  touched span  : 10.12 MiB (10,608,640 B)
  live pages    : 10.12 MiB (10,608,640 B)  (100.0% of span)
  reclaimable   : 0 B (0 B)
  payload       : 9.94 MiB (10,418,677 B)
  struct. overhead: 185.51 KiB (189,963 B)

Tables (LMDB databases)
  NAME          ENTRIES  DEPTH   BRANCH    LEAF  OVERFLOW           USED
  (main)            106      2        1       9      2578      10.11 MiB

Schema (main)
  key           : 32-byte XOR address (BLAKE3 hash of chunk content)
  value         : raw chunk bytes (no wrapper, no metadata)
  key lengths   : 106 × 32 B
  format check  : OK — matches the ant-node chunk store format

Records: 106

Content verification (BLAKE3(value) == key)
  checked: 106   ok: 106   failed: 0   skipped: 0 empty-value, 0 non-XorName-key

Records (XOR address · size)
  00ac779cc21688baf8f956467b22d603aaf8bf718f2375715824935ec701fdcc     135,452 B
  0146a5ba1b5d23442504f513f89c1ab9925164c3be72984cd075bc1ab81e1610     101,754 B
  01bd17483321b39fbf4b044f8edd3d2ab333fa4af63bdb0554e3816711c7dc2b      88,140 B
  0307b275fe3d21f0313d9229be1c05b4704e9437efdcecd23a76857893337b4f       5,687 B
  03f539842a2ea96dd0ec481dc8034da2d71948a3f3d344463119fe5d12de76ab       1,077 B
  … list truncated at 5 of 106 records (--limit)

Statistics (value sizes)
  total payload : 9.94 MiB (10,418,677 B)
  min / max     : 125 B (125 B) / 4.00 MiB (4,194,304 B)
  mean / median : 95.99 KiB (98,289 B) / 14.11 KiB (14,446 B)
  p90 / p99     : 242.92 KiB (248,745 B) / 482.84 KiB (494,424 B)

  Size histogram
         < 1 KiB │████████████████████                     8
         1–2 KiB │████████████████████████████             11
         2–4 KiB │█████████████████████████████████        13
         4–8 KiB │███████████████████████                  9
        8–16 KiB │████████████████████████████████████████ 16
       16–32 KiB │███████████████████████                  9
       32–64 KiB │████████████████████████████             11
      64–128 KiB │█████████████████████████████████        13
     128–256 KiB │███████████████                          6
     256–512 KiB │███████████████████████                  9
   512 KiB–1 MiB │                                         0
         1–2 MiB │                                         0
         2–3 MiB │                                         0
         3–4 MiB │███                                      1
         > 4 MiB │                                         0
```

Extracting the raw bytes of one chunk (self-encrypted for a normal upload):

```console
$ ant-db-inspector testdata/chunks.mdb --extract 00ac77…01fdcc -o chunk.bin
wrote 135452 bytes to chunk.bin

$ ant-db-inspector testdata --dump-all ./out/
dumped 106 chunks (9.94 MiB) to ./out/
```

## Notes

- Databases are opened with `READ_ONLY`; LMDB may create a missing lock file
  or register a reader slot — that is normal and safe even on a running node.
- For very large databases use `--no-chunks` or `--limit`; statistics are
  always computed over **all** records.
- `--verify` exits with code 2 on any mismatch, so a byte flip anywhere in a
  stored chunk is detected reliably.
- `--classify` reads every value (entropy is sampled from the first 64 KiB per
  chunk to stay fast); it is off by default so plain metadata scans stay cheap.
- `--extract`/`--dump-all` emit the stored bytes unchanged. For self-encrypted
  uploads that is not the file plaintext — decryption needs the DataMap and the
  file's other chunks, which a single node does not hold.

## License

MIT

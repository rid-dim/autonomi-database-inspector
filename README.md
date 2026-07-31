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
- `--verify`: recomputes BLAKE3 over every chunk and compares it to the key
- `--preview N`: hex preview of the first N value bytes per record

| Option | Effect |
|---|---|
| `--json` | full report as JSON (for scripts and analysis pipelines) |
| `--verify` | integrity check: `BLAKE3(value) == key` for every chunk |
| `--no-chunks` | suppress the per-record address list |
| `--limit N` | cap the record list at N entries per database (0 = all) |
| `--sort addr\|size` | list order: address ascending / size descending |
| `--preview N` | show first N value bytes as hex per record |
| `--no-lock` | open without the LMDB lock file (snapshots on read-only media; never while a node is writing) |

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

```console
$ testdb-gen --out testdata --count 100 --extra-paid 5 --seed 42
```

## Sample output

```text
$ ant-db-inspector testdata --verify --limit 5
ant-node database inspector — testdata

Database: chunks.mdb — chunk store
════════════════════════════════════════════════════════════════════════

Environment
  env path      : testdata/chunks.mdb
  data file     : testdata/chunks.mdb/data.mdb  10.11 MiB (10,596,352 B)
  lock file     : present
  page size     : 4096 B
  map size      : 10.11 MiB (10,596,352 B)
  last txn id   : 1
  last page     : 2586
  readers       : 1 / 126

LMDB meta pages (raw, both generations)
  format        : magic ok, version 1, page size 4096 B, env flags 0x0008
  meta 0        : txn id 0  last page 1  map size on disk 1.00 GiB
  meta 1        : txn id 1  last page 2586  map size on disk 1.00 GiB  [active]
  freelist DB : root page -  depth 0  branch/leaf/overflow 0/0/0  entries 0
  main DB     : root page 1369  depth 2  branch/leaf/overflow 1/8/2576  entries 100

Space accounting
  file size     : 10.11 MiB (10,596,352 B)
  touched span  : 10.11 MiB (10,596,352 B)
  live pages    : 10.11 MiB (10,596,352 B)  (100.0% of span)
  reclaimable   : 0 B (0 B)
  payload       : 9.93 MiB (10,410,261 B)
  struct. overhead: 181.73 KiB (186,091 B)

Tables (LMDB databases)
  NAME          ENTRIES  DEPTH   BRANCH    LEAF  OVERFLOW           USED
  (main)            100      2        1       8      2576      10.10 MiB

Schema (main)
  key           : 32-byte XOR address (BLAKE3 hash of chunk content)
  value         : raw chunk bytes (no wrapper, no metadata)
  key lengths   : 100 × 32 B
  format check  : OK — matches the ant-node chunk store format

Records: 100

Content verification (BLAKE3(value) == key)
  checked: 100   ok: 100   failed: 0   skipped: 0 empty-value, 0 non-XorName-key

Records (XOR address · size)
  00ac779cc21688baf8f956467b22d603aaf8bf718f2375715824935ec701fdcc     135,452 B
  0146a5ba1b5d23442504f513f89c1ab9925164c3be72984cd075bc1ab81e1610     101,754 B
  01bd17483321b39fbf4b044f8edd3d2ab333fa4af63bdb0554e3816711c7dc2b      88,140 B
  0307b275fe3d21f0313d9229be1c05b4704e9437efdcecd23a76857893337b4f       5,687 B
  03f539842a2ea96dd0ec481dc8034da2d71948a3f3d344463119fe5d12de76ab       1,077 B
  … list truncated at 5 of 100 records (--limit)

Statistics (value sizes)
  total payload : 9.93 MiB (10,410,261 B)
  min / max     : 125 B (125 B) / 4.00 MiB (4,194,304 B)
  mean / median : 101.66 KiB (104,102 B) / 15.68 KiB (16,058 B)
  p90 / p99     : 242.92 KiB (248,745 B) / 482.84 KiB (494,424 B)

  Size histogram
         < 1 KiB │████████                                 5
         1–4 KiB │██████████████████████████████████       21
        4–16 KiB │████████████████████████████████████████ 25
       16–64 KiB │████████████████████████████████         20
      64–256 KiB │██████████████████████████████           19
   256 KiB–1 MiB │██████████████                           9
         1–4 MiB │                                         0
         ≥ 4 MiB │██                                       1

Database: paid_list.mdb — paid list
════════════════════════════════════════════════════════════════════════

Environment
  env path      : testdata/paid_list.mdb
  data file     : testdata/paid_list.mdb/data.mdb  20.00 KiB (20,480 B)
  ...

Schema (main)
  key           : 32-byte XOR address of a paid-authorized key
  value         : empty (set membership only)
  key lengths   : 105 × 32 B
  format check  : OK — matches the ant-node paid list format

Records: 105
```

## Notes

- Databases are opened with `READ_ONLY`; LMDB may create a missing lock file
  or register a reader slot — that is normal and safe even on a running node.
- For very large databases use `--no-chunks` or `--limit`; statistics are
  always computed over **all** records.
- `--verify` exits with code 2 on any mismatch, so a byte flip anywhere in a
  stored chunk is detected reliably.

## License

MIT

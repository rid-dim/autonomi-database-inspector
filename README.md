# ant-inspect

Read-only inspector for [ant-node](https://github.com/WithAutonomi/ant-node)
chunk stores and self-encryption **DataMaps**. Point it at an absolute path —
a node directory, the `chunks/` store, any directory full of chunks, or a
single file — and it tells you what is there: layout, counts, sizes,
statistics, what kind of content each chunk is (DataMap / self-encrypted /
plaintext), and for a DataMap the ordered list of chunk addresses with a check
of which of them the local store holds. Built for shell scripting: bare
address lists, tab-separated rows, JSON, meaningful exit codes.

It never writes to the node's data. (The optional `--decrypt` writes the
reconstructed file to the path *you* name.)

> This replaces the earlier LMDB database inspector. Since
> [ADR-0014](https://github.com/WithAutonomi/ant-node/blob/main/docs/adr/ADR-0014-file-based-chunk-store-and-lmdb-retirement.md)
> ant-node stores one file per chunk; `chunks.mdb` is being retired and the
> old tool is obsolete.

## Quickstart

```console
# build (needs a Rust toolchain)
cargo build --release
# → target/release/ant-inspect  and  target/release/teststore-gen

# a node
ant-inspect ~/.local/share/ant/nodes/<peer-id>                # Linux default node root
ant-inspect "~/Library/Application Support/ant/nodes/<peer-id>" # macOS
ant-inspect /path/to/node --classify --datamaps                # + content classes, DataMaps found

# a file: is it a DataMap? stats + chunk addresses in order
ant-inspect /path/to/node/chunks/fa/00ac7cbe…1afa
ant-inspect some.datamap --addresses                          # just the addresses, one per line
ant-inspect some.datamap --is-datamap && echo "valid DataMap"

# try it on the bundled live-network sample
ant-inspect samples/live-store --datamaps --classify
ant-inspect samples/live-store/chunks/fa/00ac7cbe1fe3e49fcd9e490eb313fabc2fe4407e67196292e961c3b34e9b1afa --resolve
```

## What ant-node stores (background)

Verified against the ant-node, ant-client and self_encryption sources on
2026-09-16.

**Chunk store** (`src/storage/file_store.rs`, ADR-0014) — one immutable file
per chunk, the filename *is* the address:

```text
{root}/chunks/                   store root
{root}/chunks/layout.json        {"schema":1,"scheme":"suffix-hex","shard_chars":2,"depth":1,"name_encoding":"lower-hex"}
{root}/chunks/.lock              advisory single-process lock
{root}/chunks/<xy>/<64-hex>      xy = the LAST two hex chars of the address (256 shards)
{root}/chunks/<xy>/.tmp.<pid>.…  an in-flight write (swept at next start)
{root}/chunks/<xy>/*.not-a-chunk an entry the node quarantined
```

Address = **BLAKE3** of the content (the node checks this on every PUT and
GET). Max chunk size 4 MiB. Sharding uses the address *suffix* because a node
holds chunks close to its own ID, so the leading bits are all alike.

Beside the store, a node root holds `paid_list.mdb/` (still LMDB),
`migration-state.json` (phase `bridging` → `committed` → `files_only`) and,
until retirement finishes, the legacy `chunks.mdb/` (or `chunks.mdb.retired/`
with a `RETIRED` marker inside).

**DataMaps** (`self_encryption` 0.36, used by `ant-client`) — the retrieval
metadata of a self-encrypted file: per chunk `index`, `dst_hash` (address of
the encrypted chunk), `src_hash` (hash of the plaintext chunk), `src_size`.
A **public** upload stores the DataMap as an ordinary chunk, serialized with
`rmp_serde` (MessagePack) as `[1, [chunk_infos…], child]`; the address you
share (`ant file download <ADDR>`) is that chunk's address. Files with more
than 3 chunks get a **shrunk** DataMap: the root DataMap is itself
self-encrypted, and the stored map carries `child = level` and points at
those wrapper chunks, not at file data. A **private** upload keeps the DataMap
in a `.datamap` file (same MessagePack bytes) and only the chunks go on the
network.

`ant-inspect` parses all forms that occur: current MessagePack, the legacy
`DataMapLevel` MessagePack wrapper of the old client, `bincode`
(`DataMap::to_bytes`, the form found *inside* shrunk levels) and the legacy
JSON `.datamap`. Every parse is validated (contiguous indices, sane sizes,
whole input consumed), so a positive is trustworthy.

## Usage

```text
ant-inspect <PATH> [OPTIONS]
```

`PATH` is auto-detected:

- **node root** (has `chunks/`) or **chunk store** (has `layout.json`):
  *store mode* — ant-node's rules apply, and anything the node would not
  index (wrong shard, uppercase name, temp/quarantined entries) is flagged.
- **any other directory**: *directory mode* — walked recursively, every
  regular file is a chunk candidate, whatever the structure (flat, sharded on
  the first or last N hex characters, nested deeper). Nothing is judged; the
  structure actually found is reported. Use this for your own chunk
  collections and for stores with a different layout.
- **a file**: chunk / DataMap / `.datamap`. For its chunks the tool looks in
  the store or directory the file lives in (it climbs out of hex-named shard
  directories to the top of the structure), or in `--store DIR`, and can pull
  missing ones from the network with `--fetch`.

| Option | Effect |
|---|---|
| `--json` | full report as JSON |
| `-l`, `--list` | one tab-separated line per chunk. Store: `address size [class]`. DataMap: `index address src_size [src_hash] [present\|missing]` |
| `-a`, `--addresses` | bare addresses, one per line. DataMap: its chunk addresses in order (exit 3 if not a DataMap). Store: all chunk addresses |
| `--sort addr\|size`, `--limit N` | order / cap for lists |
| `-q`, `--quiet` | no report, only the requested list |
| `--verify` | recompute BLAKE3 of every chunk file and compare with its name; exit 2 on mismatch. Reads everything: budget for the store's full size |
| `-j`, `--jobs N` | parallel readers for `--verify` / `--classify` / `--datamaps` (default: CPUs, max 8). Raise on NAS/network storage, lower on a single spinning disk |
| *(always)* | flags entries the node would not index: in-flight temp files, quarantined `*.not-a-chunk`, uppercase names, chunk files in the wrong shard directory, foreign files |
| `-c`, `--classify` | classify every chunk (datamap / encrypted / media / text / binary) and print the distribution |
| `-d`, `--datamaps` | find every public DataMap in the store; per map: level, chunk count, content size, how many of its chunks are local |
| `--assume-encrypted-above BYTES` | with `--classify`, skip scanning payloads at least this large (default 3.5 MiB; 0 = scan all) |
| `--chunk ADDR` | inspect one chunk of the store by address |
| `--locate ADDR` | print the file path for an address (exit 3 if absent) |
| `-s`, `--store DIR` | store or directory to look for a DataMap's chunks in (default: the one the file lives in) |
| `--fetch` | download chunks not found locally with the `ant` CLI (`ant chunk get`) into `--fetch-dir` (default `./fetched-chunks`) and use them; applies to every level with `--resolve`/`--decrypt`. Already-fetched chunks are reused |
| `--ant-bin PATH`, `--ant-args "…"` | the ant binary for `--fetch` and extra arguments placed before the subcommand, e.g. `--ant-args "-b 1.2.3.4:10000"` |
| `-r`, `--resolve` | shrunk DataMap: decrypt the parent level(s) from local chunks down to the root DataMap |
| `--decrypt FILE` | reconstruct the file from local chunks (all must be present) and write it to FILE; every chunk's plaintext is checked against `src_hash` |
| `--is-datamap` | exit 0 if the file is a DataMap, 3 otherwise; prints nothing |
| `--src` | also print `src_hash` in DataMap lists |

Exit codes: `0` ok · `1` error · `2` verification failures · `3` not a
DataMap / not found.

### Shell recipes

```console
# Is this record a valid DataMap? How many chunks, how big?
$ ant-inspect "$f" --is-datamap && ant-inspect "$f" --json | jq '.datamap.stats'

# Chunk addresses of a DataMap, in order, into a file
$ ant-inspect "$f" --addresses > chunks.txt

# Which of a DataMap's chunks does my node hold?
$ ant-inspect "$f" --store /path/to/node --list -q | awk -F'\t' '$4=="missing"'

# Every public DataMap on the node, with local coverage, as TSV
$ ant-inspect /path/to/node --datamaps --json \
    | jq -r '.datamaps[] | [.address, .child, .chunk_count, .content_bytes, .local_present] | @tsv'

# Biggest 20 chunks
$ ant-inspect /path/to/node --list -q --sort size --limit 20

# Content mix of the node
$ ant-inspect /path/to/node --classify --json | jq '.content_distribution'

# Integrity check in a cron job
$ ant-inspect /path/to/node --verify -q || echo "corrupt chunk files!"

# Where is chunk X? cat its bytes
$ cat "$(ant-inspect /path/to/node --locate "$addr")" | xxd | head

# Rebuild a public file from a DataMap: fetch whatever is missing via the ant CLI
$ ant chunk get "$addr" -o dm.chunk
$ ant-inspect dm.chunk --fetch --decrypt out.bin             # resolves shrunk levels, fetches, decrypts, verifies
$ ant-inspect dm.chunk --fetch --ant-args "-b 1.2.3.4:10000" --resolve --addresses   # explicit bootstrap peers

# A DataMap in a store with a different layout (e.g. sharded on the first 3 hex chars)
$ ant-inspect /big/store/abc/abc123…  --resolve              # the store is found automatically
$ ant-inspect some.datamap --store /big/store --list -q      # or name it
```

## Repairing a store

There is no index file to repair. The node rebuilds its key set from the
directory names under `chunks/` at every start (ADR-0014: "the filesystem is
the sole authority"), so a chunk is "known" exactly when it sits at
`chunks/<xy>/<address>` as a regular file with a 64-character lowercase hex
name whose last two characters equal the shard directory. Anything else on
disk is skipped by the node's scan. `ant-inspect <node>` lists those cases
under "other entries":

| Finding | What the node does | Fix |
|---|---|---|
| in-flight temp file `.tmp.*` | deletes it at next start | nothing |
| `*.not-a-chunk` | quarantined earlier (a case-folded twin of a real name) | delete, or rename to the correct lowercase name if the content is good |
| uppercase-named file | ignored (would be quarantined) | rename to lowercase |
| chunk file in the wrong shard directory | ignored ("Move it or delete it") | move to `chunks/<last two hex>/` |
| foreign / non-regular file, file directly in `chunks/` | ignored | remove or move |
| empty 0-byte file with a chunk name | indexed by name, fails on read, quarantined, re-fetched | delete the file (an interrupted write); replication restores it |
| content does not hash to the name (`--verify`) | detected on read, quarantined, re-fetched from peers | delete the file; replication restores it |

Files added while the node runs are not indexed until it restarts. Recipe:

```console
$ ant-inspect /path/to/node --verify            # lists every problem and exits 2 on bad content
$ addr=$(ant-inspect "$f" --json | jq -r .address)          # true address of a stray file
$ mv "$f" "/path/to/node/chunks/${addr: -2}/$addr"          # put it where the node looks
$ ant-inspect /path/to/node --locate "$addr"                # confirm
# then restart the node
```

The paid list (`paid_list.mdb`) is independent of all this: it gates which
replicas the node *accepts*, not which chunks it serves, and it rebuilds
itself by majority confirmation from the paid close group.

## Content classification

A node's chunk store holds opaque bytes; the only rule is
`BLAKE3(content) == address`. Self-encryption happens in the client, so a
node can hold three kinds of things, and `--classify` (or the single-file
report) tells them apart:

- **datamap** — a public DataMap. Detected *precisely* by deserializing and
  validating it.
- **encrypted** — entropy at the random-data ceiling: the shape of a
  self-encrypted (or compressed) chunk. A heuristic — encrypted output is by
  design indistinguishable from random bytes, so this cannot be *proven*. For
  tiny chunks the bar is scaled to what the sample length allows.
- **media** — a known file format by magic bytes (PNG, JPEG, PDF, ZIP, MP3, …):
  unencrypted content someone stored with `ant chunk put`. Precise.
- **text** — mostly printable, low entropy: probably plaintext. Heuristic.
- **binary** — structured bytes matching none of the above.

Full-size chunks (≥ 3.5 MiB by default) are assumed encrypted without reading
their payload; magic bytes are still checked first.

## Sample output

```text
$ ant-inspect samples/live-store --datamaps --classify

Target: samples/live-store  — node root directory
════════════════════════════════════════════════════════════════════════

Store
  chunks dir    : samples/live-store/chunks
  layout.json   : schema 1, scheme suffix-hex, 2 hex chars, depth 1, names lower-hex  [current]
  lock file     : absent
  shards        : 13 of 256 directories present, 12 non-empty; files per shard min 0 / max 1 / mean 0.05
  chunk files   : 12
  total size    : 141.78 KiB (145,180 B)
  on disk       : 168.00 KiB (172,032 B)  (allocated blocks)
  other entries : none
  address spread: 0 leading bits shared by all addresses; 12 distinct first bytes, 12 distinct last bytes (shards)

Node root
  entries       : chunks/
  migration     : no migration-state.json (fresh file-only node or pre-migration build)
  legacy LMDB   : chunks.mdb/ absent (retired)
  paid list     : paid_list.mdb/ absent

Statistics (chunk file sizes)
  total         : 141.78 KiB (145,180 B)
  min / max     : 130 B / 31.66 KiB (32,415 B)
  mean / median : 11.81 KiB (12,098 B) / 15.16 KiB (15,526 B)
  p90 / p99     : 31.65 KiB (32,410 B) / 31.66 KiB (32,415 B)

  Size histogram
          < 1 KiB │████████████████████████████████████████ 6
          …
         8–16 KiB │████████████████████                     3
        16–32 KiB │████████████████████                     3

Content classification
  datamap           3   25.0%         974 B   public DataMap (unencrypted retrieval metadata)
  encrypted         9   75.0%    140.83 KiB   high entropy — most likely self-encrypted (heuristic)

Public DataMaps in store: 3
  ADDRESS                                                           LEVEL    CHUNKS     CONTENT  LOCAL
  00ac7cbe1fe3e49fcd9e490eb313fabc2fe4407e67196292e961c3b34e9b1afa  child 1       3       330 B  3/3
  2c9b71c789f02fe377c72218d3314626e91ab6e3f4ac8327213423aeb307c843  child 1       3  114.85 KiB  3/3
  9f8ea63f705b75916548e2477c4a90022e9e9a31e01e85d99e987fc81b56130a  child 1       3   54.93 KiB  3/3
```

A public DataMap fetched from the live network (BegBlag.mp3 from the
Autonomi WebRTC demo), with the shrunk level resolved from the local chunks:

```text
$ ant-inspect samples/live-store/chunks/fa/00ac7cbe…1afa --resolve

File       : samples/live-store/chunks/fa/00ac7cbe1fe3e49fcd9e490eb313fabc2fe4407e67196292e961c3b34e9b1afa  (316 B)
Address    : 00ac7cbe1fe3e49fcd9e490eb313fabc2fe4407e67196292e961c3b34e9b1afa  (BLAKE3 of content)  — matches filename
Content    : public DataMap (unencrypted retrieval metadata)  [entropy 5.60 bit/B]

DataMap
  format         : msgpack (current network format, version 1)
  level          : child 1 (shrunk — entries describe the encrypted parent DataMap, not file data)
  chunks         : 3 (3 distinct addresses)
  content size   : 330 B  [sum of src_size = parent DataMap size]
  serialized     : 316 B
  network address: 00ac7cbe1fe3e49fcd9e490eb313fabc2fe4407e67196292e961c3b34e9b1afa  (BLAKE3 of the msgpack encoding = its address as a public chunk)
  chunk src size : min 110 / max 110 / mean 110
  local store    : 3 of 3 chunks present in …/samples/live-store/chunks (390 B on disk) — complete

  Chunks (index · address · src size · local)
      0  70a0b43add6a8584198334d9bf6856c098d0b143e4523f7f644ccc0b1176063b          110 B  present (130 B)
      1  4083d9a146cc529a7b816f8eff4e68594c0300033b08e706eb55bf5d86bd314d          110 B  present (130 B)
      2  ba7058a438406896e301fa65b1ac5de7c4e5201b36177251e2d2e6796201a9a3          110 B  present (130 B)

Root DataMap (resolved)
  format         : bincode (DataMap::to_bytes, version 1)
  level          : root (entries are the file's data chunks)
  chunks         : 4 (4 distinct addresses)
  content size   : 15.04 MiB (15,766,382 B)  [sum of src_size = file size]
  …
  Chunks (index · address · src size · local)
      0  e4d0508a9f0cf102a21871a931cb08be87375245a699c74f23fea00c3a0861ae    4,190,208 B  MISSING
      1  28e86a98f4582283e31d7b304f94509030974ffd0afaf802c25b333649fca6c9    4,190,208 B  MISSING
      2  8cfb508645969d54dd357c26460a0cc40db9dfde52eec33172cff343b79c67d2    4,190,208 B  MISSING
      3  45257aa53e48f80180c7e23d29f10214f5924a9f29f3f01e0818d162d9a331a2    3,195,758 B  MISSING
```

With those four data chunks fetched into the store, `--decrypt BegBlag.mp3`
reproduces the 15 MB MP3 (verified: `file` reports ID3v2.2 / MPEG layer III).

## Test data

`samples/live-store/` is a 172 KB node root filled from the **live network**:
three public DataMaps (Ubuntu ISO, a 5.8 GB MKV, BegBlag.mp3) plus the chunks
of their shrunk level. See [`samples/README.md`](samples/README.md) for the
addresses and how they were fetched. The tests (`cargo test`) run the binary
against it.

`teststore-gen` builds a bigger store in the exact ant-node layout using the
real `self_encryption` crate: several files are self-encrypted, their chunks
stored, their DataMaps stored as public chunks (one large enough to be shrunk),
one private `.datamap` file written beside the store, plus plaintext, media and
orphan chunks, `migration-state.json` and an empty `paid_list.mdb/`.
Deterministic via `--seed`.

```console
$ teststore-gen --out testdata --with-junk
$ ant-inspect testdata --classify --datamaps --verify
$ ant-inspect testdata/private/private-0.bin.datamap --store testdata --list
$ ant-inspect testdata --chunk <shrunk-datamap-address> --decrypt file4.bin   # blake3 matches the generator's printout
```

## Notes

- Scanning stats every chunk file (name + size), in parallel across
  subdirectories, keeping ~80 bytes per chunk in memory; millions of files
  are fine. `--verify`, `--classify` and `--datamaps` then read every file
  with `--jobs` parallel readers, which takes as long as reading the whole
  store takes (a 3 TB store over a 1 Gbit/s NAS link is many hours). Both
  phases show a progress line with throughput and ETA on stderr when it is a
  terminal; the report itself is printed at the end, so redirecting stdout
  to a file is fine.
- `--fetch` shells out to the `ant` CLI (WithAutonomi/ant-client). It needs
  bootstrap peers: put `bootstrap_peers.toml` from the release next to the
  binary or pass `--ant-args "-b ip:port,…"`. Downloads land in
  `--fetch-dir`, never in a node's store.
- Reading a store while the node runs is safe: the node treats the filesystem
  as the sole authority and only ever creates temp files, renames them into
  place and unlinks. A chunk that appears or vanishes mid-scan is simply
  counted or not.
- `.datamap` files and DataMap chunks contain no key material beyond the
  DataMap itself: with all chunks at hand, anyone holding a DataMap can
  reconstruct the file. That is what `--decrypt` does, offline.
- `paid_list.mdb/` and a not-yet-retired `chunks.mdb/` are reported by size
  only; this tool does not open LMDB.

## License

MIT

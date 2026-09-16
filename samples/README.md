# Sample data

## `live-store/` — real chunks from the Autonomi network

A minimal node root in the exact ant-node file layout (`chunks/layout.json`,
`chunks/<xy>/<address>`), filled with data fetched from the live network on
2026-09-16 with `ant chunk get`. Total 172 KB. Used by the tests
(`cargo test`) and handy for trying the tool:

| Public DataMap (chunk address) | Describes | Level |
|---|---|---|
| `9f8ea63f705b75916548e2477c4a90022e9e9a31e01e85d99e987fc81b56130a` | ubuntu-20.10-desktop-amd64.iso (2.8 GB) | child 1, 3 chunks |
| `2c9b71c789f02fe377c72218d3314626e91ab6e3f4ac8327213423aeb307c843` | Citizen-Vigilante.mkv (5.8 GB) | child 1, 3 chunks |
| `00ac7cbe1fe3e49fcd9e490eb313fabc2fe4407e67196292e961c3b34e9b1afa` | BegBlag.mp3 (15 MB, from the WebRTC demo catalogue) | child 1, 3 chunks |

For every DataMap the store also holds the three chunks of its shrunk level,
so `--resolve` can decrypt the parent (root) DataMap offline. The *data*
chunks of the files are **not** included (they are GBs for the first two).
BegBlag's four data chunks (15 MB) are small enough to fetch if you want to try
`--decrypt`:

```console
$ ant-inspect samples/live-store/chunks/fa/00ac7cbe… --resolve --addresses \
    | while read a; do ant chunk get "$a" -o "samples/live-store/chunks/${a: -2}/$a"; done
$ ant-inspect samples/live-store/chunks/fa/00ac7cbe… --decrypt BegBlag.mp3
```

More public DataMaps to play with (from the demo catalogue at
`https://webrtc-demo.autonomi.space/demo-catalogue.json`):
`dbf90f10b6e42f38525a9d85512e648a9a26468b704ee10fe2ff31d2322a08a6` (Hubble
deep field, JPEG), `4c68023df9c4a477324a63b653a2a56a43c15559b6b839b8a6d1b1737a8bf5ed`
(SVG figure), `56def42a30b3028411e3029911a2df7c98c32f9b61e9526392ee9e588ef4f2d5`
(Earthrise, JPEG — was not retrievable from the main network at the time).

### Fetching chunks yourself

The `ant` CLI (WithAutonomi/ant-client releases) needs bootstrap peers; the
release tarball ships `bootstrap_peers.toml`, or pass them explicitly:

```console
$ ant -b 207.148.94.42:10000,45.77.50.10:10000,66.135.23.83:10000 chunk get <ADDRESS> -o <FILE>
```

# cidr

`cidr` is a fast, immutable IPv4/IPv6 lookup library for Go: build a set of CIDR
prefixes once, then answer two questions with zero per-query allocation —

- **membership** — *is this address in the set?* (`Set.Contains` → yes/no)
- **value lookup** — *what is attached to the most-specific prefix covering this
  address?* (`Table[V].Lookup` → yes + data, e.g. the owning AS number and
  organisation)

It is built for static, build-once-query-many workloads: blocklists and
allowlists, IP-to-ASN and geo tables, parked/sinkhole ranges, firewall feeds.
For those, a sorted range array was both **faster and an order of magnitude
smaller** than a prefix trie in a design-time comparison (the trie is not part of
this repository and the comparison is not reproduced here; see
[Architecture](docs/architecture.md) for the trade-off).

No dependency beyond the Go standard library.

## Data flow

```
  SOURCES                     BUILD (once)                QUERY (many, concurrent)
  ───────                     ────────────                ────────────────────────
  spec text ─┐
  refs JSON ─┤  Load*/Parse*   Builder            ┌─ Set.Contains(addr)  → yes/no
  <cidr> …  ─┼──────────────►  TableBuilder[V] ───┤
  lo–hi     ─┘  Add / AddPrefix  │ .Freeze()      └─ Table[V].Lookup(addr) → value + ok
                / AddRange       ▼
                          immutable, sorted integer range arrays
                          (one binary search · 0 alloc · lock-free reads)
```

## Documentation

- **Start here** — [Introduction](docs/introduction.md) (what the name means and
  the one idea it rests on) and the
  [Executive summary](docs/executive-summary.md) (what this is and why it exists)
- **Deep dive** — [Architecture](docs/architecture.md): the range-array design,
  longest-prefix match, benchmarks, and the trie trade-off
- **Operations** — [User guide](docs/userguide.md): the API, the spec and refs
  formats, data sources, the CLI, and day-2 refresh
- **Examples** — [example/README](example/README.md): library, HTTP, Unix-socket,
  and MCP integrations

## Features

- **Two structures, one job each**: `Set` (membership) merges overlaps for the
  smallest form; `Table[V]` (value lookup) resolves nesting into
  **longest-prefix match** at build time.
- **Zero-allocation queries** — a single binary search over a contiguous,
  cache-friendly array. No pointer-chasing, no interface dispatch.
- **IPv4 and IPv6** through one `net/netip` code path.
- **Generic values** — `Table[V]` carries any `V`: a struct, an `Info`, or a
  compact `uint64` via `EncodeASN`/`DecodeASN`.
- **Immutable and concurrent-safe** once built (`Builder`/`TableBuilder` →
  `Freeze`), so many goroutines can query without a lock.
- **Loaders for any feed** — `LoadASN`/`LoadSet` read a `<cidr> <ASN> <org>`
  stream; `LoadFunc` takes any custom `<cidr> data...` format; `AddRange`
  ingests start/end address ranges (iptoasn, RIR delegated files) directly.

## Quick start

```go
package main

import (
	"fmt"
	"net/netip"

	"github.com/netstar-labs/cidr"
)

func main() {
	// Membership — yes/no.
	b := cidr.NewBuilder()
	b.AddPrefix("192.0.2.0/24")
	b.AddPrefix("2001:db8::/32")
	set := b.Freeze()
	fmt.Println(set.Contains(netip.MustParseAddr("192.0.2.10"))) // true

	// Value lookup — yes + data, most-specific prefix wins.
	tb := cidr.NewTableBuilder[string]()
	tb.AddPrefix("1.1.1.0/24", "AS13335 Cloudflare")
	tb.AddPrefix("1.1.1.128/25", "AS13335 customer sub-block") // nested, more specific
	table := tb.Freeze()

	who, ok := table.Lookup(netip.MustParseAddr("1.1.1.200"))
	fmt.Println(who, ok) // "AS13335 customer sub-block" true
}
```

## The spec format

`ParseSpec`, `LoadSet`, and `LoadASN` read a whitespace-delimited text stream,
one prefix per line — the shape of a typical IP-to-ASN table:

```
# comments and blank lines are ignored
10.0.0.0/8
1.1.1.0/24     13335 Cloudflare, Inc.
8.8.8.0/24     AS15169 Google LLC
# a bare address is a /32 host route
203.0.113.7    64500 Example Org
2001:db8::/32  64502 Documentation v6
```

The ASN (optionally `AS`-prefixed) and organisation name are optional; a plain
list of CIDRs is a valid degenerate case. Only whole lines beginning with `#`
are comments; a `#` inside a line is data, so annotations go on their own line.

```go
set, table, err := cidr.LoadASN(specReader) // membership Set + value Table[Info]
```

The same lines also come wrapped in the common refs JSON envelope
(`{"name","version","list":[...]}`, e.g. `refs.netstar.dev`) — `cidr.LoadRefsASN`
/ `LoadRefsSet` / `ParseRefs` read it, and the `cidr` CLI's `-spec` accepts
either form. An envelope with no `list` key, or trailing data after it, is an
error (`"list": []` and `null` are valid and empty).

For non-ASN feeds, `LoadFunc` builds a `Table[V]` of any value type from a
per-line parse callback, and `AddRange` ingests start/end ranges. Where to pull
real ASN/geo data (MaxMind, iptoasn, CAIDA, …) and how to convert it is in the
[user guide](docs/userguide.md#data-sources).

## Command-line tool

`cmd/cidr` is a standalone lookup tool over a spec file. Addresses come from the
arguments, or from stdin (one per line) when none are given.

```sh
go install github.com/netstar-labs/cidr/cmd/cidr@latest

cidr -spec asn.txt 1.1.1.200 8.8.8.8              # NDJSON, one object per address
printf '1.1.1.1\n9.9.9.9\n' | cidr -spec asn.txt -brief
cidr -spec block.txt -match < ips.txt             # filter: print only listed addresses
```

Flags: `-spec FILE` (required), `-brief` (terse aligned lines), `-match`
(grep-like filter), `-quiet` (no stderr tally), `-version`. A run tally lands on
stderr. Exit status follows grep: `0` ok (with `-match`, at least one address
matched), `1` no match (`-match` only), `2` any error — including an unreadable
spec or a failed write to stdout.

Cross-compile a version-stamped static binary with [`build/cidr`](build/cidr)
(`linux/amd64`, with an optional `scp` install to a host).

### More tools

[`cmd/`](cmd) ships seven more programs — see the [cmd README](cmd/README.md):

- **[`ipfold`](cmd/ipfold)** — fold an unorganized IP list into the minimal CIDR
  set (`10.0.0.12`, `.13`, `.14`, `.15` → `10.0.0.12/30`); built for 100M+
  addresses (`ipfold < ips.txt`).
- **[`ipunfold`](cmd/ipunfold)** — the inverse: expand CIDRs back into the
  individual addresses they cover (`ipunfold < cidrs.txt`), with `-count` to
  size the output first and `-max` to bound it.
- **[`iptoasn`](cmd/iptoasn)**, **[`mm-geolite2-asn`](cmd/mm-geolite2-asn)**,
  **[`mm-dbip`](cmd/mm-dbip)** — fetch a provider's IP-to-ASN/geo table and
  write the cidr spec, with an optional systemd generator (see
  [data sources](docs/userguide.md#data-sources)). Like `rir-country` and
  `provider-function`, they publish `-o FILE` atomically and exit 1 — leaving the
  previous file untouched — on a failed fetch or zero usable rows
  ([failure behaviour](cmd/README.md#failure-behaviour)).
- **[`rir-country`](cmd/rir-country)** — build a country spec from the five RIR
  delegated files: the primary record, with no account, key or vendor terms.
- **[`provider-function`](cmd/provider-function)** — build a
  `<cidr> <function> <provider>` spec from the address space operators publish
  about themselves (AWS, Google Cloud, Cloudflare, Fastly, Tor): also a primary
  record, and the seam for adding further sources.
- **[`mmdb-write`](cmd/mmdb-write)** — compile a cidr spec into a MaxMind DB
  (`.mmdb`) file, supporting both ASN (`GeoIP2-ASN`-compatible) and Country
  (`GeoLite2-Country`-compatible) output schemas, selected by `-db-type` (a
  country spec needs `-db-type GeoLite2-Country`). The most specific prefix wins
  whatever the input order, and it exits 1 without writing a file when nothing
  was inserted. Pipe any data generator directly: `iptoasn | mmdb-write -o asn.mmdb`.
  In a script prefer the staged form,
  `iptoasn -o spec && mmdb-write -in spec -o asn.mmdb`: a plain shell pipe
  without `pipefail` reports only the last command's status, so a failed download
  still yields a (truncated) database and exit 0.
- **[`mmdb-build-countries`](cmd/mmdb-build-countries)** — build the country
  nomenclature dataset (from Wikidata) that `mmdb-write` uses for Country DBs.

## Examples

Each is a self-contained `main.go` with no dependency beyond the standard
library and this package — see [example/](example/README.md).

| Example | What it shows | Run |
|---|---|---|
| [`library/`](example/library) | the package used directly: `Set`, `Table[Info]`, the encoded-`uint64` path, nesting, IPv6 | `go run ./example/library` |
| [`http/`](example/http) | an HTTP REST API — `/contains`, `/lookup`, and an NDJSON batch stream | `go run ./example/http -addr :8080` |
| [`unix/`](example/unix) | a Unix-domain-socket line service: address in, JSON line out | `go run ./example/unix -socket /tmp/cidr.sock` |
| [`mcp/`](example/mcp) | an MCP (Model Context Protocol) stdio server exposing the set as agent tools | `go run ./example/mcp` |

## Performance

Both queries are a single binary search over integer arrays, with no allocation.
Measured with `go test -run xxx -bench . -benchmem -count 6 .` on an Apple M2 Pro
(10 cores), Go 1.27.3 darwin/arm64, a lightly loaded machine; the six runs of
each benchmark agree to within 4%, and the table gives the median (min in
parentheses). Each benchmark builds a set of random `/24`s (IPv4) or `/48`s
(IPv6) and queries 4,096 random addresses in rotation — at these densities
almost all of them are misses:

| `BenchmarkSetContains…` / `BenchmarkTableLookup…` | set | `Set.Contains` | `Table.Lookup` | allocs |
|---|---|---:|---:|---:|
| *(no suffix)* | 4,000 IPv4 `/24`s | 40 ns (39.7) | 44 ns (43.6) | 0 |
| `V6` | 4,000 IPv6 `/48`s | 49 ns (48.6) | 54 ns (53.0) | 0 |
| `500k` | 500,000 IPv4 `/24`s | 81 ns (80.0) | 90 ns (89.3) | 0 |
| `V6500k` | 500,000 IPv6 `/48`s | 100 ns (98.9) | 108 ns (107.5) | 0 |

Going from 4,000 to 500,000 prefixes about doubles the time, and IPv6 costs
roughly 20–25% more than IPv4 at either size. Before the integer layout (frozen
arrays of `netip.Addr`) the 4,000-prefix IPv4 case measured 87–88 ns on the same
machine.

In a design-time comparison against a path-compressed prefix trie (not part of
this repository and not reproduced here), the range array was
roughly **2× faster on IPv4, allocation-free where the trie allocates per query,
and ~8–60× smaller in memory**; the gap widens with set size. The one thing the
array gives up — cheap incremental insert/remove of single prefixes under live
queries — is not what a static, wholesale-rebuilt set needs. The full analysis,
including when a trie *is* the right choice, is in
[docs/architecture.md](docs/architecture.md).

## Layout

The package is five root `.go` files (plus the `cmd/`, `example/`, and `build/`
trees):

| File | Purpose |
|---|---|
| [`cidr.go`](cidr.go) | Package doc; `ParsePrefix`, `LastAddr`; the `Set` membership type, its `Builder`, and the range-merge that fuses overlaps at `Freeze` |
| [`table.go`](table.go) | `Table[V]` longest-prefix-match value table and `TableBuilder[V]`; the build-time line sweep that resolves nesting; `EncodeASN`/`DecodeASN` |
| [`input.go`](input.go) | Text/JSON loaders — `ParseSpec`, `LoadSet`, `LoadASN`, `BuildASN`, `LoadFunc`, the `Refs` envelope (`ParseRefs`/`LoadRefs*`), and the `Info`/`SpecEntry` types |
| [`range.go`](range.go) | Range ingest — `AddRange`, `RangePrefixes`/`AppendRangePrefixes`, and the `u128` range-to-CIDR arithmetic behind them |
| [`mmdb.go`](mmdb.go) | Stdlib-only MaxMind DB (`.mmdb`) reader — `OpenMMDB`/`OpenMMDBBytes`, `(*MMDB).Lookup`/`Metadata`/`Close`; safe for concurrent lookups |

## Install

```sh
go get github.com/netstar-labs/cidr
```

Requires Go 1.25 or newer.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).

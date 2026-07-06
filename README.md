# cidr

`cidr` is a fast, immutable IPv4/IPv6 lookup library for Go: build a set of CIDR
prefixes once, then answer two questions with zero per-query allocation —

- **membership** — *is this address in the set?* (`Set.Contains` → yes/no)
- **value lookup** — *what is attached to the most-specific prefix covering this
  address?* (`Table[V].Lookup` → yes + data, e.g. the owning AS number and
  organisation)

It is built for static, build-once-query-many workloads: blocklists and
allowlists, IP-to-ASN and geo tables, parked/sinkhole ranges, firewall feeds.
For those, a sorted range array is both **faster and an order of magnitude
smaller** than a prefix trie (see [Architecture](docs/architecture.md)).

No dependency beyond the Go standard library.

## Documentation

- [Executive summary](docs/executive-summary.md) — what this is and why it exists
- [User guide](docs/userguide.md) — API, the spec format, and usage patterns
- [Architecture](docs/architecture.md) — the range-array design, longest-prefix
  match, benchmarks, and the trie trade-off
- [Examples](example/README.md) — library, HTTP, Unix-socket, and MCP integrations

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
203.0.113.7    64500 Example Org        # a bare address is a /32 host route
2001:db8::/32  64502 Documentation v6
```

The ASN (optionally `AS`-prefixed) and organisation name are optional; a plain
list of CIDRs is a valid degenerate case.

```go
set, table, err := cidr.LoadASN(specReader) // membership Set + value Table[Info]
```

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
(grep-like filter; exit 1 if nothing matched), `-quiet` (no stderr tally),
`-version`. A run tally lands on stderr.

Cross-compile a version-stamped static binary with [`build/cidr`](build/cidr)
(`linux/amd64`, with an optional `scp` install to a host).

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

Both queries are a single binary search with no allocation (Apple M2 Pro, Go
1.25):

| operation | time | allocations |
|---|---:|---:|
| `Set.Contains` | ~88 ns/op | 0 |
| `Table.Lookup` | ~88 ns/op | 0 |

Against a path-compressed prefix trie on the same data, the range array is
roughly **2× faster on IPv4, allocation-free where the trie allocates per query,
and ~8–60× smaller in memory**; the gap widens with set size. The one thing the
array gives up — cheap incremental insert/remove of single prefixes under live
queries — is not what a static, wholesale-rebuilt set needs. The full analysis,
including when a trie *is* the right choice, is in
[docs/architecture.md](docs/architecture.md).

## Install

```sh
go get github.com/netstar-labs/cidr
```

Requires Go 1.25 or newer.

## License

See [LICENSE](LICENSE).

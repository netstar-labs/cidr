# cidr — User Guide

How to build and query the two structures, load a spec, and run the set under
concurrency. For the design, see [architecture.md](architecture.md).

## Install

```sh
go get github.com/netstar-labs/cidr
```

Requires Go 1.25+. Import as `github.com/netstar-labs/cidr`.

## The model in one minute

- Everything is **build once, query many**. You accumulate prefixes into a
  builder, call `Freeze`, and get back an immutable, concurrent-safe value.
- Pick the structure by the question:
  - **`Set`** — *is this address listed?* (yes/no)
  - **`Table[V]`** — *what value owns this address?* (yes + data, most-specific
    prefix wins)
- Addresses are `net/netip.Addr`. Prefixes are `net/netip.Prefix`, or strings
  via the built-in parser.

## Membership: `Set`

```go
b := cidr.NewBuilder()
b.Add(netip.MustParsePrefix("10.0.0.0/8")) // a netip.Prefix
b.AddPrefix("192.0.2.0/24")                // or parse a string (CIDR or bare IP)
b.AddPrefix("203.0.113.7")                 // a bare address becomes a /32 host route
set := b.Freeze()

set.Contains(netip.MustParseAddr("10.1.2.3")) // true
set.Contains(netip.MustParseAddr("8.8.8.8"))  // false
set.Len()                                     // number of merged intervals
```

`AddPrefix` returns a parse error for invalid input; `Add` silently ignores an
invalid (zero) prefix. Overlapping and adjacent prefixes are merged at `Freeze`,
so `Len` reports intervals, not the number of prefixes you added.

## Value lookup: `Table[V]`

`Table[V]` is generic in the value. Add `(prefix, value)` pairs; `Lookup`
returns the value of the most-specific prefix covering the address.

```go
tb := cidr.NewTableBuilder[string]()
tb.AddPrefix("1.1.1.0/24", "AS13335 Cloudflare")
tb.AddPrefix("1.1.1.128/25", "AS13335 sub-block") // nested, more specific
table := tb.Freeze()

table.Lookup(netip.MustParseAddr("1.1.1.10"))  // "AS13335 Cloudflare", true
table.Lookup(netip.MustParseAddr("1.1.1.200")) // "AS13335 sub-block", true  (the /25 wins)
table.Lookup(netip.MustParseAddr("9.9.9.9"))   // "", false
table.Contains(netip.MustParseAddr("9.9.9.9")) // false  (membership, ignoring the value)
```

Adding the same prefix twice keeps the **last** value.

### Choosing the value type `V`

- **A struct** for rich data — e.g. the built-in [`Info`](#the-spec-loader)
  (`{Prefix, ASN, Org}`), returned as JSON by the service examples.
- **A `string`** for a simple label.
- **A `uint64`** for a compact, copyable code. `EncodeASN` packs an AS number
  (low 32 bits), an org id (24 bits), and flags (8 bits) into one word;
  `DecodeASN` unpacks it. Keep the org names in a side slice indexed by the id:

  ```go
  tb := cidr.NewTableBuilder[uint64]()
  orgs := []string{}
  for i, e := range entries {
      orgs = append(orgs, e.Org)
      tb.Add(e.Prefix, cidr.EncodeASN(e.ASN, uint32(i), 0))
  }
  table := tb.Freeze()

  if code, ok := table.Lookup(ip); ok {
      asn, orgID, flags := cidr.DecodeASN(code)
      name := orgs[orgID]
      _ = asn; _ = flags; _ = name
  }
  ```

## The spec loader

Most sets come from a text feed. `ParseSpec` reads a whitespace-delimited
`<cidr> [ASN] [org...]` stream — the shape of a public IP-to-ASN table:

```
# blank lines and #-comments are ignored
10.0.0.0/8
1.1.1.0/24     13335 Cloudflare, Inc.
8.8.8.0/24     AS15169 Google LLC        # a leading "AS" is accepted
203.0.113.7    64500 Example Org         # a bare address is a /32 host route
2001:db8::/32  64502 Documentation v6
```

The ASN and org are optional; a bare CIDR list is valid. Lines whose first field
is not a valid prefix are skipped (so an occasional junk line in a large feed
does not fail the load) — only an underlying I/O error is returned.

```go
entries, err := cidr.ParseSpec(r)              // []cidr.SpecEntry{Prefix, ASN, Org}

set, err := cidr.LoadSet(r)                     // membership only
set, table, err := cidr.LoadASN(r)              // Set + Table[cidr.Info] in one pass
```

`cidr.Info` is `{Prefix string, ASN uint32, Org string}` and marshals to JSON.
`LoadASN` builds both a membership `Set` and a value `Table[Info]` from the same
input, so you can answer both questions.

### Custom formats with `LoadFunc`

`ParseSpec`/`LoadASN` are ASN-shaped. For any other `<cidr> <data...>` feed,
`LoadFunc` builds a `Table[V]` and hands the format to you: a `parse` callback
maps a line's whitespace fields to a prefix and value, returning `false` to skip
the line (blank lines and `#`-comments are dropped for you).

For example, a feed that maps networks to **six-digit classification codes**
(an industry taxonomy, a threat category, a tenant id — anything), with an
optional label after the code:

```
# <cidr> <6-digit code> [label...]
1.1.1.0/24     518210 Data Processing & Hosting
1.1.1.128/25   541512 Computer Systems Design      # nested, more specific
10.0.0.0/8     999999 Private Use
2001:db8::/32  100002 Documentation
```

```go
type Class struct {
    Code  int    `json:"code"`
    Label string `json:"label"`
}

table, err := cidr.LoadFunc(r, func(f []string) (netip.Prefix, Class, bool) {
    if len(f) < 2 {
        return netip.Prefix{}, Class{}, false
    }
    p, err := cidr.ParsePrefix(f[0])
    if err != nil {
        return netip.Prefix{}, Class{}, false // skip a bad prefix
    }
    code, err := strconv.Atoi(f[1])
    if err != nil || code < 100000 || code > 999999 {
        return netip.Prefix{}, Class{}, false // enforce six digits
    }
    return p, Class{Code: code, Label: strings.Join(f[2:], " ")}, true
})

c, ok := table.Lookup(netip.MustParseAddr("1.1.1.200")) // {541512, "Computer Systems Design"}, true
```

The value is your own type, so the parse callback *is* the decoder — no
interface to implement. Longest-prefix match still applies: `1.1.1.200` matches
the nested `/25` (code `541512`) over the covering `/24`.

### Range-based feeds with `AddRange`

Some feeds give **start/end address ranges** rather than CIDRs (iptoasn.com, the
RIR delegated files). `AddRange` takes an inclusive `[lo, hi]` interval directly:

```go
b.AddRange(lo, hi)         // *Builder — one membership interval
tb.AddRange(lo, hi, v)     // *TableBuilder[V] — value v across the range
```

For a `Table`, the range is decomposed into its minimal set of CIDR prefixes
(each carrying `v`) so longest-prefix match stays well defined — a more-specific
range's pieces have longer masks and win. Reversed or mixed-family ranges are
ignored.

## Data sources

Where to get data to feed the loaders. The ranking is by how directly a source
provides *CIDR (or range) + value*:

| Source | Format | Native shape | Access | Notes |
|---|---|---|---|---|
| **MaxMind GeoLite2 ASN** | CSV: `network,asn,org` | CIDR | free account + key | maps 1:1 to the ASN spec; separate v4/v6 files; CC BY-SA (attribution) |
| **iptoasn.com** | TSV: `start end asn cc desc` | **range** | free, no account | easiest bulk; hourly; use `AddRange` |
| **CAIDA / RouteViews pfx2as** | `prefix<tab>len<tab>AS` | CIDR | free/open | from the live BGP table; no org names (join AS→org separately) |
| **IPinfo Lite / DB-IP Lite** | CSV / MMDB | CIDR / range | free w/ signup | ASN + org, CC BY |
| **RouteViews / RIPE RIS MRT** | MRT dumps | prefixes | free/open | the raw global table; needs an MRT parser |
| **Team Cymru IP-to-ASN** | bulk whois / DNS | range | free | best for enrichment, not bulk build |
| **MaxMind / DB-IP GeoLite** | CSV: `network,country,...` | CIDR | free (account/CC BY) | for geo `Table`s rather than ASN |

Convert MaxMind's CSV to the ASN spec (org may be quoted, so parse it as CSV):

```python
import csv, sys                      # GeoLite2-ASN-Blocks-IPv4.csv on stdin
for row in csv.reader(sys.stdin):
    if row and '/' in row[0]:
        print(row[0], row[1], row[2])  # -> "1.0.0.0/24 13335 Cloudflare, Inc."
```

A range feed like iptoasn (`start end asn ... desc`) is read straight into a
`Table` with `AddRange` and a `LoadFunc`-style parse, no CIDR conversion needed.

### Fetching iptoasn with `cmd/iptoasn`

The bundled [`cmd/iptoasn`](../cmd/iptoasn) tool does the fetch and conversion
for you: it downloads the iptoasn.com table, decomposes each start/end range to
CIDRs (via `RangePrefixes`), and writes the `<cidr> <ASN> <org>` spec that
`LoadASN` reads back.

```sh
iptoasn -family v4 -o ip2asn-v4.cidr     # fetch IPv4 -> spec file
iptoasn -in ip2asn-combined.tsv.gz       # convert a local (gzipped) TSV
iptoasn | cidr -spec /dev/stdin 8.8.8.8  # or pipe straight into the CLI
```

Flags: `-family` (`v4`/`v6`/`combined`), `-url`, `-in`, `-o`, `-unrouted`
(keep AS0 rows), `-country` (prepend the country code). AS0 "Not routed" rows
are dropped by default.

## Parsing prefixes and addresses

- `cidr.ParsePrefix(s)` accepts a CIDR (`"10.0.0.0/8"`, `"2001:db8::/32"`) or a
  bare address (`"1.2.3.4"`, `"::1"`, promoted to a `/32` or `/128`), returning a
  masked `netip.Prefix`.
- Query addresses are `netip.Addr` — use `netip.ParseAddr` for strings.

### Converting from `net.IP`

If your addresses arrive as `net.IP` (e.g. from DNS answers or the older `net`
API), convert once at the boundary:

```go
if a, ok := netip.AddrFromSlice(ip); ok {
    covered := set.Contains(a.Unmap()) // Unmap folds ::ffff:1.2.3.4 to 1.2.3.4
}
```

The library `Unmap`s internally too, so an IPv4-in-IPv6 address matches the IPv4
side either way.

## Concurrency and refresh

A frozen `Set`/`Table[V]` is immutable, so any number of goroutines may query it
without a lock. There is no in-place update; to refresh, build a new value and
swap the pointer atomically:

```go
var current atomic.Pointer[cidr.Set]
// startup / on each scheduled reload:
current.Store(rebuildFromFeed())
// hot path:
if current.Load().Contains(ip) { ... }
```

Builders are **not** concurrent-safe; do all `Add` calls from one goroutine
before `Freeze`.

## API reference

### Membership

| Symbol | Purpose |
|---|---|
| `NewBuilder() *Builder` | start a membership set |
| `(*Builder) Add(netip.Prefix)` | add a prefix |
| `(*Builder) AddPrefix(string) error` | parse and add a CIDR or bare address |
| `(*Builder) AddRange(lo, hi netip.Addr)` | add an inclusive address range |
| `(*Builder) Freeze() *Set` | compile to an immutable `Set` |
| `(*Set) Contains(netip.Addr) bool` | membership test |
| `(*Set) Len() int` | number of merged intervals |

### Value lookup

| Symbol | Purpose |
|---|---|
| `NewTableBuilder[V]() *TableBuilder[V]` | start a value table |
| `(*TableBuilder[V]) Add(netip.Prefix, V)` | add a prefix with a value |
| `(*TableBuilder[V]) AddPrefix(string, V) error` | parse and add |
| `(*TableBuilder[V]) AddRange(lo, hi netip.Addr, V)` | add a value across an address range |
| `(*TableBuilder[V]) Freeze() *Table[V]` | compile to an immutable `Table[V]` |
| `(*Table[V]) Lookup(netip.Addr) (V, bool)` | most-specific value + found flag |
| `(*Table[V]) Contains(netip.Addr) bool` | membership, ignoring the value |

### Spec + helpers

| Symbol | Purpose |
|---|---|
| `ParsePrefix(string) (netip.Prefix, error)` | parse a CIDR or bare address |
| `RangePrefixes(lo, hi netip.Addr) []netip.Prefix` | decompose a range into its minimal CIDR set |
| `ParseSpec(io.Reader) ([]SpecEntry, error)` | parse a `<cidr> ASN org` stream |
| `LoadSet(io.Reader) (*Set, error)` | spec → membership `Set` |
| `LoadASN(io.Reader) (*Set, *Table[Info], error)` | spec → `Set` + `Table[Info]` |
| `LoadFunc[V](io.Reader, parse) (*Table[V], error)` | any custom `<cidr> data...` feed → `Table[V]` |
| `EncodeASN(asn, orgID uint32, flags uint8) uint64` | pack a compact value |
| `DecodeASN(uint64) (asn, orgID uint32, flags uint8)` | unpack it |
| `Info`, `SpecEntry` | value and parsed-entry types |

## Command-line tool

`cmd/cidr` is a standalone lookup tool. It loads a spec and looks up addresses
from the arguments, or from stdin (one per line) when none are given.

```sh
go install github.com/netstar-labs/cidr/cmd/cidr@latest

cidr -spec asn.txt 1.1.1.200 8.8.8.8        # NDJSON: {"ip","member","info"?}
cidr -spec asn.txt -brief 1.1.1.200         # "<ip> member ASNNN <org>" lines
printf '1.1.1.1\n9.9.9.9\n' | cidr -spec asn.txt
cidr -spec block.txt -match < ips.txt       # print only listed addresses (exit 1 if none)
```

| Flag | Effect |
|---|---|
| `-spec FILE` | the spec to load (required) |
| `-brief` | terse aligned lines instead of NDJSON |
| `-match` | filter mode: print only addresses in the set; exit 1 if none matched |
| `-quiet` | suppress the run tally on stderr |
| `-version` | print the stamped version and exit |

A tally (`spec=… prefixes=… intervals=… queried=… member=…`) is written to
stderr unless `-quiet`. Build a version-stamped `linux/amd64` static binary with
`build/cidr [user@host]`.

## Worked examples

Runnable integrations live in [example/](../example/README.md): a library tour,
an HTTP REST API, a Unix-socket line service, and an MCP server. Each loads a
built-in demo spec (or a `-spec` file) and answers both membership and value
queries.

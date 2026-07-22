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

### Refs JSON envelope

The common refs resource format wraps the spec lines in a named, versioned JSON
envelope (as published at `refs.netstar.dev` — `parked.ip.json`, blocklists, …):

```json
{ "name": "parked", "version": 20260705, "list": ["1.2.3.0/24", "8.8.8.0/24 15169 Google LLC"] }
```

Each `list` entry uses the same `<cidr> [ASN] [org]` grammar, so both a bare
CIDR list and an IP-to-ASN list are valid bodies. Load it with the JSON analogues
of `LoadSet`/`LoadASN`, or decode the envelope for its metadata:

```go
set, table, err := cidr.LoadRefsASN(r)   // Set + Table[Info], like LoadASN
set, err := cidr.LoadRefsSet(r)          // membership only

rf, err := cidr.ParseRefs(r)             // rf.Name, rf.Version, rf.List
entries := rf.Entries()                  // []SpecEntry, then build however
```

The `cidr` CLI's `-spec` accepts either form — it sniffs the first byte, so a
`.json` refs file and a text spec both work with no flag.

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
| **MaxMind GeoLite2 ASN** | CSV: `network,asn,org` | CIDR | free account + key | 1:1 with the ASN spec; separate v4/v6; CC BY-SA — `cmd/mm-geolite2-asn` |
| **iptoasn.com** | TSV: `start end asn cc desc` | **range** | free, no account | easiest bulk; hourly — `cmd/iptoasn` |
| **CAIDA / RouteViews pfx2as** | `prefix<tab>len<tab>AS` | CIDR | free/open | from the live BGP table; no org names (join AS→org separately) |
| **DB-IP Lite** | CSV: `start,end,...` | **range** | free, CC BY | country or ASN datasets — `cmd/mm-dbip` |
| **RouteViews / RIPE RIS MRT** | MRT dumps | prefixes | free/open | the raw global table; needs an MRT parser |
| **Team Cymru IP-to-ASN** | bulk whois / DNS | range | free | best for enrichment, not bulk build |
| **MaxMind / DB-IP GeoLite** | CSV: `network,country,...` | CIDR | free (account/CC BY) | for geo `Table`s rather than ASN |

### Fetch/convert tools

Three tools under [`cmd/`](../cmd) fetch a provider's table and write the cidr
spec directly: range-based sources are decomposed to CIDRs (via
`RangePrefixes`), CIDR-native sources pass through. Each also reads a local file
with `-in` (gzip auto-detected) and writes to stdout or `-o FILE`, with a tally
on stderr.

**[`cmd/iptoasn`](../cmd/iptoasn)** — iptoasn.com IP-to-ASN (free, no account);
range-based. Three output modes:

- `-output asn` (default): `<cidr> <ASN> <org>` — pipe to `mmdb-write` or `LoadASN`.
- `-output country`: `<cidr> <country>` — pipe to `mmdb-write -db-type GeoLite2-Country`.
- `-country`: prepend the country to the org in ASN mode: `<cidr> <ASN> <country> <org>`.

```sh
iptoasn -family v4 -o ip2asn-v4.cidr             # v4 | v6 | combined
iptoasn -output country -o iptoasn-country.cidr   # country format
iptoasn -in ip2asn-combined.tsv.gz               # convert a local (gzipped) TSV
```

Flags: `-output` (`asn`/`country`), `-family`, `-url`, `-in`, `-o`, `-unrouted`
(keep AS0 rows), `-country` (prepend country to org in asn mode). AS0 "Not
routed" rows are dropped by default. In country mode, rows with country `None` are also skipped.

**[`cmd/mm-geolite2-asn`](../cmd/mm-geolite2-asn)** — MaxMind GeoLite2 ASN (needs a
free license key); CIDR-native → `<cidr> <ASN> <org>` (`LoadASN`):

```sh
mm-geolite2-asn -license YOUR_KEY -o geolite2-asn.cidr   # download the CSV zip
mm-geolite2-asn -in GeoLite2-ASN-CSV.zip                 # or a local zip/.csv/.csv.gz
```

Flags: `-license`, `-family` (`v4`/`v6`/`both`), `-url`, `-in`, `-o`. The
download is the GeoLite2-ASN-CSV zip; the blocks CSVs are already CIDR-native.

**[`cmd/mm-dbip`](../cmd/mm-dbip)** — DB-IP Lite (free, CC BY); range-based. `-db
country` → `<cidr> <country>` (load with `LoadFunc`); `-db asn` → `<cidr> <ASN>
<org>` (`LoadASN`):

```sh
mm-dbip -db country -o dbip-country.cidr    # current month's country lite
mm-dbip -db asn    -o dbip-asn.cidr
mm-dbip -in dbip-country-lite-2026-07.csv.gz
```

Flags: `-db` (`country`/`asn`), `-month` (default: current UTC month), `-url`,
`-in`, `-o`. Without `-in`/`-url` the current month's file is fetched.

**[`cmd/mmdb-write`](../cmd/mmdb-write)** — compiles any cidr spec into a MaxMind
DB (`.mmdb`) file. The output schema is selected by `-db-type`:
`GeoLite2-ASN` (default) or `GeoLite2-Country`.

For **ASN** (`-db-type GeoLite2-ASN`, default): each record holds
`autonomous_system_number` (uint32) and `autonomous_system_organization` (string).
Input is `<cidr> <ASN> <org>` format from any data generator.

For **Country** (`-db-type GeoLite2-Country`): each record holds
`continent`, `country`, and `registered_country` in the standard GeoLite2
schema — with country data extracted from Wikidata. Since the source spec provides only
one country per prefix, `country` and `registered_country` are set to the same
value (the operator's country).

Input is `<cidr> <country_code>` — obtainable from `iptoasn -output country`,
`mm-dbip -db country`, or any spec with 2-letter ISO codes in the second field.

```sh
# ASN MMDB — pipe any ASN generator
iptoasn -family combined | mmdb-write -o iptoasn-asn.mmdb
mm-geolite2-asn -license YOUR_KEY | mmdb-write -o geolite2-asn.mmdb
mm-dbip -db asn | mmdb-write -o dbip-asn.mmdb

# Country MMDB — pipe any country generator
iptoasn -output country | mmdb-write -db-type GeoLite2-Country -o iptoasn-country.mmdb
mm-dbip -db country | mmdb-write -db-type GeoLite2-Country -o dbip-country.mmdb

# From an existing spec file
mmdb-write -in my-asn.cidr -o asn.mmdb
mmdb-write -in my-country.cidr -db-type GeoLite2-Country -o country.mmdb
```

Flags: `-in`, `-o`, `-db-type` (default `GeoLite2-ASN`), `-description`
(default `IPtoASN`), `-build-epoch`, `-ip-version` (4 or 6, default 6).

Scheduled MMDB regeneration: `build/mmdb-iptoasn-write --generator` installs a
daily oneshot service + timer that fetches iptoasn.com and compiles
`/var/lib/cidr/iptoasn-asn.mmdb` and `/var/lib/cidr/iptoasn-country.mmdb`.

The embedded country metadata lives at `cmd/mmdb-write/data/countries.json`.
Refresh it from Wikidata like so:

```sh
# Recommended: download Wikidata country info
go run ./cmd/mmdb-build-countries
```

### Scheduled generation (systemd)

Each generator has a build script under [`build/`](../build) that cross-compiles
a version-stamped `linux/amd64` binary and, in `--generator` mode, installs a
oneshot systemd service plus a timer that regenerates the spec (or MMDB) into
`/var/lib/cidr/` on a schedule (iptoasn daily, DB-IP monthly, MaxMind weekly,
MMDB compile after MaxMind):

```sh
build/iptoasn --generator user@host                       # daily    -> ip2asn.cidr
build/mm-dbip --generator user@host                       # monthly  -> dbip-country.cidr
build/mm-geolite2-asn --generator --key YOUR_KEY user@host # weekly   -> geolite2-asn.cidr
build/mmdb-iptoasn-write --generator user@host            # daily -> iptoasn-asn.mmdb + iptoasn-country.mmdb
```

`--cli` (the default) builds just the binary — nothing is scheduled. With no
host the install package is left under `build/install/` to copy and run
(`sudo ./<tool>.sh`) yourself.

For `mm-geolite2-asn`, `--generator` **requires `--key`** (MaxMind downloads are
authenticated) and refuses to build without one. The key is written to a
mode-600 `EnvironmentFile` (`/etc/cidr/mm-geolite2-asn.env`) that the service
reads as `$MAXMIND_LICENSE_KEY`; it never appears in the unit file or the process
arguments.

### Folding an address list (`cmd/ipfold`)

[`cmd/ipfold`](../cmd/ipfold) is a utility that turns an unorganized list of IP
addresses (mixed IPv4/IPv6, one per line) into the minimal CIDR set: it sorts,
de-duplicates, and folds runs of consecutive addresses — `10.0.0.12`, `.13`,
`.14`, `.15` collapse to `10.0.0.12/30`.

```sh
ipfold < ips.txt                 # fold stdin -> stdout (v4 block, then v6)
ipfold -in ips.txt -o cidrs.txt
ipfold -4 < ips.txt              # IPv4 output only
```

It is built for scale: the IPv4 side parses addresses straight from bytes and
aggregates through a 2³²-bit bitmap (bounded ~512 MiB, O(n), robust to duplicate
input) — ~120M addresses fold to CIDRs in roughly 20 s at ~0.5 GiB. Build a
stamped binary with `build/ipfold [user@host]`. The output is a valid spec for
`LoadSet`.

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

### Spec + helpers

| Symbol | Purpose |
|---|---|
| `ParsePrefix(string) (netip.Prefix, error)` | parse a CIDR or bare address |
| `RangePrefixes(lo, hi netip.Addr) []netip.Prefix` | decompose a range into its minimal CIDR set |
| `AppendRangePrefixes(dst, lo, hi) []netip.Prefix` | RangePrefixes into a reused buffer (hot loops) |
| `ParseSpec(io.Reader) ([]SpecEntry, error)` | parse a `<cidr> ASN org` stream |
| `LoadSet(io.Reader) (*Set, error)` | spec → membership `Set` |
| `LoadASN(io.Reader) (*Set, *Table[Info], error)` | spec → `Set` + `Table[Info]` |
| `LoadFunc[V](io.Reader, parse) (*Table[V], error)` | any custom `<cidr> data...` feed → `Table[V]` |
| `ParseRefs(io.Reader) (*Refs, error)` | decode a `{name,version,list}` refs JSON envelope |
| `(*Refs) Entries() []SpecEntry` | parse the refs list into spec entries |
| `LoadRefsSet(io.Reader) (*Set, error)` | refs JSON → membership `Set` |
| `LoadRefsASN(io.Reader) (*Set, *Table[Info], error)` | refs JSON → `Set` + `Table[Info]` |
| `EncodeASN(asn, orgID uint32, flags uint8) uint64` | pack a compact value |
| `DecodeASN(uint64) (asn, orgID uint32, flags uint8)` | unpack it |
| `Info`, `SpecEntry`, `Refs` | value, parsed-entry, and refs-envelope types |

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

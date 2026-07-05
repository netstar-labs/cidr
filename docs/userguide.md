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
| `(*Builder) Freeze() *Set` | compile to an immutable `Set` |
| `(*Set) Contains(netip.Addr) bool` | membership test |
| `(*Set) Len() int` | number of merged intervals |

### Value lookup

| Symbol | Purpose |
|---|---|
| `NewTableBuilder[V]() *TableBuilder[V]` | start a value table |
| `(*TableBuilder[V]) Add(netip.Prefix, V)` | add a prefix with a value |
| `(*TableBuilder[V]) AddPrefix(string, V) error` | parse and add |
| `(*TableBuilder[V]) Freeze() *Table[V]` | compile to an immutable `Table[V]` |
| `(*Table[V]) Lookup(netip.Addr) (V, bool)` | most-specific value + found flag |
| `(*Table[V]) Contains(netip.Addr) bool` | membership, ignoring the value |

### Spec + helpers

| Symbol | Purpose |
|---|---|
| `ParsePrefix(string) (netip.Prefix, error)` | parse a CIDR or bare address |
| `ParseSpec(io.Reader) ([]SpecEntry, error)` | parse a `<cidr> ASN org` stream |
| `LoadSet(io.Reader) (*Set, error)` | spec → membership `Set` |
| `LoadASN(io.Reader) (*Set, *Table[Info], error)` | spec → `Set` + `Table[Info]` |
| `EncodeASN(asn, orgID uint32, flags uint8) uint64` | pack a compact value |
| `DecodeASN(uint64) (asn, orgID uint32, flags uint8)` | unpack it |
| `Info`, `SpecEntry` | value and parsed-entry types |

## Worked examples

Runnable integrations live in [example/](../example/README.md): a library tour,
an HTTP REST API, a Unix-socket line service, and an MCP server. Each loads a
built-in demo spec (or a `-spec` file) and answers both membership and value
queries.

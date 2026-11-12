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
table.Lookup(netip.MustParseAddr("9.9.9.9"))   // "", false  (ok reports membership; Table has no Contains)
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
# blank lines and whole-line #-comments are ignored
10.0.0.0/8
1.1.1.0/24     13335 Cloudflare, Inc.
# a leading "AS" is accepted
8.8.8.0/24     AS15169 Google LLC
# a bare address is a /32 host route
203.0.113.7    64500 Example Org
2001:db8::/32  64502 Documentation v6
```

The ASN and org are optional; a bare CIDR list is valid. If the second field is
not a valid ASN it starts the org instead (and the ASN is 0), so the grammar is
`<cidr> [ASN] [org...]`.

**Only whole lines that begin with `#` are comments.** A `#` anywhere else in a
line is data: `203.0.113.7 64500 Example Org # note` yields the org
`Example Org # note`. Put each annotation on its own `#` line.

Fields are split on whitespace only, so a comma-separated line
(`10.0.0.0/8,64500,Example`) has an invalid first field and is skipped like any
other junk (`ipfold` and `ipunfold`, by contrast, split their first field on
whitespace *or* commas). Lines whose first field is not a valid prefix are
skipped (so an occasional junk line in a large feed does not fail the load — but
see [Concurrency and refresh](#concurrency-and-refresh): a feed that is *all*
junk loads as an empty set, with no error). The only error is a failed read,
which includes `bufio.ErrTooLong` for a line of 1 MiB or more (a trailing `\r` counts). On error:
`ParseSpec` returns the entries parsed before the failure plus the error;
`LoadSet` and `LoadASN` return nil plus the error; `LoadFunc` returns a non-nil
`Table` of the lines read before the failure plus the error (discard it unless a
partial table is acceptable).

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
CIDR list and an IP-to-ASN list are valid bodies. The envelope is read strictly:
a missing or renamed `list` key is an error, and so is anything but whitespace
after the JSON value (trailing garbage, a second envelope), so a mangled feed
cannot pass for an empty set. `"list": []` and `"list": null` are valid and
empty (a Go producer marshals an empty nil slice as `null`). Load it with the JSON
analogues of `LoadSet`/`LoadASN`, or decode the envelope for its metadata:

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
the line (blank lines and whole-line `#`-comments are dropped for you; a `#`
inside a line stays in its field).

For example, a feed that maps networks to **six-digit classification codes**
(an industry taxonomy, a threat category, a tenant id — anything), with an
optional label after the code:

```
# <cidr> <6-digit code> [label...]
1.1.1.0/24     518210 Data Processing & Hosting
# nested, more specific
1.1.1.128/25   541512 Computer Systems Design
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
ignored, and a zone on either bound is dropped (queries ignore zones too, so a
zoned bound would otherwise sort after the plain address and the range's first
address would never match).

One caveat: when a nested range and its covering range decompose to an
*identical* piece, longest-prefix match cannot separate them and `Add`'s rule
decides — the value added last wins. For example `10.0.0.0–10.0.0.127` inside
`10.0.0.0–10.0.0.191` both produce `10.0.0.0/25`, so after

```go
tb.AddRange(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.191"), "outer")
tb.AddRange(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.127"), "inner")
```

`10.0.0.5` is `"inner"` and `10.0.0.150` is `"outer"`; add them in the opposite
order and `10.0.0.5` becomes `"outer"`. Add covering ranges **before** the
ranges nested in them.

## Data sources

Where to get data to feed the loaders. The ranking is by how directly a source
provides *CIDR (or range) + value*:

| Source | Format | Native shape | Access | Notes |
|---|---|---|---|---|
| **RIR delegated-extended** | `reg\|cc\|type\|start\|value\|date\|status` | **range** (v4 count) | free, no account | the **primary** country record; the five RIRs publish it and vendor country sets derive from it — `cmd/rir-country` |
| **Operator-published ranges** | JSON (AWS, Google Cloud, Fastly) or one-per-line text (Cloudflare, Tor) | CIDR-native (Tor: bare addresses) | free, public endpoints | also a **primary** record — the operator publishes its own space; `<cidr> <function> <provider> [anycast]` for `LoadFunc`, not `LoadASN` — `cmd/provider-function` |
| **MaxMind GeoLite2 ASN** | CSV: `network,asn,org` | CIDR | free account + key | 1:1 with the ASN spec; separate v4/v6; CC BY-SA — `cmd/mm-geolite2-asn` |
| **iptoasn.com** | TSV: `start end asn cc desc` | **range** | free, no account | easiest bulk; hourly — `cmd/iptoasn` |
| **CAIDA / RouteViews pfx2as** | `prefix<tab>len<tab>AS` | CIDR | free/open | from the live BGP table; no org names (join AS→org separately) |
| **DB-IP Lite** | CSV: `start,end,...` | **range** | free, CC BY | country or ASN datasets — `cmd/mm-dbip` |
| **RouteViews / RIPE RIS MRT** | MRT dumps | prefixes | free/open | the raw global table; needs an MRT parser |
| **Team Cymru IP-to-ASN** | bulk whois / DNS | range | free | best for enrichment, not bulk build |
| **MaxMind / DB-IP GeoLite** | CSV: `network,country,...` | CIDR | free (account/CC BY) | for geo `Table`s rather than ASN |

### Fetch/convert tools

Five tools under [`cmd/`](../cmd) fetch a source's table and write the cidr
spec directly: range-based sources are decomposed to CIDRs (via
`RangePrefixes`), CIDR-native sources pass through. Each also reads a local file
with `-in` (gzip auto-detected, except `provider-function`, below) and writes to
stdout or `-o FILE`, with a tally on stderr. `-o FILE` is published atomically
and a run that cannot publish a complete file exits 1 — see
[Generator failure behaviour](#generator-failure-behaviour).

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
(keep AS0 rows), `-country` (prepend country to org in asn mode), `-timeout`. AS0 "Not
routed" rows are dropped by default. In country mode, rows with country `None` are also skipped.

**`-country` is not a fixed-column format.** A row whose source country is `None`
gets no country field — `<cidr> <ASN> <org>` rather than `<cidr> <ASN> <CC>
<org>` — so a consumer must not read the third field positionally as a country
code; it may be the first word of the organisation.

**[`cmd/mm-geolite2-asn`](../cmd/mm-geolite2-asn)** — MaxMind GeoLite2 ASN (needs a
free license key); CIDR-native → `<cidr> <ASN> <org>` (`LoadASN`):

```sh
mm-geolite2-asn -license YOUR_KEY -o geolite2-asn.cidr   # download the CSV zip
mm-geolite2-asn -in GeoLite2-ASN-CSV.zip                 # or a local zip/.csv/.csv.gz
```

Flags: `-license`, `-family` (`v4`/`v6`/`both`), `-url`, `-in`, `-o`, `-timeout`. The
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
`-in`, `-o`, `-timeout`. Without `-in`/`-url` the current month's file is fetched.

**[`cmd/rir-country`](../cmd/rir-country)** — the five RIR delegated-extended
files → `<cidr> <country>` (`LoadFunc`). No account, no licence key, no vendor:
this is the record the registries publish themselves, and the vendor country
datasets derive from it.

```sh
rir-country -o rir-country.cidr             # all five registries
rir-country -registry lacnic -o lacnic.cidr # one registry
rir-country -in arin.txt,ripencc.txt        # local files, comma-separated
```

Flags: `-registry` (`all`/`afrinic`/`apnic`/`arin`/`lacnic`/`ripencc`),
`-conflict` (`date`/`specific`), `-conflict-log FILE`, `-in`, `-o`, `-timeout`.

The ipv4 `value` field is an address **count**, not a prefix length, and it is
often not a power of two (763 such records as published on 2026-09-17), so a
single record can decompose into several prefixes via `RangePrefixes`. Only `allocated`/`assigned` ipv4/ipv6 rows
carrying a two-letter country are kept; asn rows, summary lines, the version
header, and `reserved`/`available` blocks are skipped. A reserved block is not
delegated to a country, so addresses inside one correctly **miss**.

Two registries occasionally claim the same prefix with different countries — a
handful at any time (two, as published on 2026-09-17). `-conflict` picks the
rule:

| Rule | Resolves by |
|---|---|
| `date` *(default)* | the later delegation date wins |
| `specific` | the narrower source allocation wins |

Prefixes of *different* lengths never conflict here: both are written and
longest-prefix match resolves them at load, which is already "most specific
wins". Where the chosen rule cannot separate two records — equal dates, or
equally specific sources — the lower country code wins, so the output does not
depend on the order the files were read. Every conflict is printed on stderr
(capped at ten, with the remainder counted); `-conflict-log FILE` writes them
all as TSV. Output is sorted, so repeated runs over the same input are
byte-identical and can be checksummed.

**[`cmd/provider-function`](../cmd/provider-function)** — the address space
operators publish about themselves → `<cidr> <function> <provider> [anycast]`
(`LoadFunc`, **not** `LoadASN`). Another primary record: AWS publishes AWS's
ranges, the Tor Project publishes Tor's exits, so nothing infers anything.

```sh
provider-function -o provider-function.cidr   # all five providers
provider-function -provider aws -o aws.cidr   # one
provider-function -in aws=ip-ranges.json      # local files, provider=path
```

Flags: `-provider` (`all`/`aws`/`cloudflare`/`fastly`/`google-cloud`/`tor`),
`-in`, `-o`, `-conflict-log FILE`, `-timeout`. `-in` takes `provider=path` pairs
rather than a bare path — the five feeds have four shapes, so the format cannot
be inferred from a filename — and, unlike the other generators, does not
auto-detect gzip. With both `-in` and `-provider`, `-in` wins and says so.

Function is a closed set of three: `cloud`, `cdn`, `tor-exit`. Sources that
publish their own space cannot honestly support `residential`, `mobile`,
`transit` or `scanner` — nobody publishes a "these are consumer broadband" file
— so those labels need other sources and arrive with them. The optional
`anycast` marker is applied **only** where the operator's own documentation uses
the word (AWS Global Accelerator, Cloudflare, Fastly); CloudFront and Route 53
are deliberately unmarked, because the only claim this table can defend is "the
operator said so". It is not an anycast detector.

AWS lists a prefix once per service it belongs to, with `AMAZON` as a catch-all
superset — 2,298 of 7,795 distinct IPv4 prefixes as published on 2026-09-21 — so
within one operator's feed a service with an explicit mapping outranks the
catch-all. **That specificity rule stops at the provider boundary**: it says
nothing about two different operators, so a disagreement between them is counted
and reported on stderr, never resolved silently. `-conflict-log FILE` writes
every one as TSV. Output is sorted and byte-identical across runs.

Nothing fails quietly: unusable rows are counted per provider as
`malformed[...]`, an attempted provider appears in `records[...]` even at zero,
and a feed (one URL or `-in` entry) that produced **no** usable rows is a hard error with no file
written — none of these feeds is legitimately empty, so zero rows means the
fetch or the parse broke, and writing anyway would truncate the published spec
on a "successful" timer run.

To add a source, see
[Adding another source](../cmd/README.md#adding-another-source) — the first
question is whether the source describes its *own* address space, because an
inferential source belongs in its own generator, not mixed in with these.

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

**The schema follows `-db-type`**: a type containing `Country` writes the country
schema, anything else the ASN schema. A country (or `provider-function`) spec
given to the ASN schema is not an error — every record comes out with ASN 0 and
the second field as its organisation — so `mmdb-write` warns on stderr when
**every** inserted record has ASN 0; give such a spec `-db-type GeoLite2-Country`.

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

**In a script, stage the steps instead of piping them.** A plain shell pipe
without `pipefail` reports only the *last* command's status, and a generator's
stdout is not atomic: if the download fails part-way, `mmdb-write` compiles the
rows that already arrived and the pipeline exits 0 with a truncated database.
(`set -o pipefail` makes the status honest, but the truncated file is still
written.) Run the generator to a file first, and compile only if it succeeded:

```sh
iptoasn -o spec && mmdb-write -in spec -o iptoasn-asn.mmdb
iptoasn -output country -o spec && mmdb-write -in spec -db-type GeoLite2-Country -o iptoasn-country.mmdb
```

**The most specific prefix wins, whatever the input order.** `mmdb-write` inserts
entries shortest prefix first (a stable sort, so of two identical prefixes the
last in the spec wins), so the database answers as `cidr` would from the same
spec — `10.1.0.0/16` before or after `10.0.0.0/8` makes no difference. The
residual divergences are `mmdbwriter`'s: IPv6 prefixes inside or covering `::/96`
(which holds the IPv4 subtree), and the networks that alias it (`2001::/32`,
`2002::/16`, `::ffff:0:0/96`), are skipped or write through into the IPv4 side.

stderr carries a tally,
`inserted=N skipped: unparseable=… pseudo-code=… unknown-country=… unknown-continent=… aliased=…`.
If nothing was inserted — an empty spec, or every entry skipped (an ASN spec given
`-db-type GeoLite2-Country` skips all of them as unknown countries) — it exits 1
and writes no file. `-o FILE` is published atomically (temp file beside the
target, fsync, rename; a symlinked target is followed, an existing mode kept, new
files 0644), so a failure leaves the previous database untouched.

Flags: `-in`, `-o`, `-db-type` (default `GeoLite2-ASN`), `-description`
(default: `IPtoASN` for `GeoLite2-ASN`, otherwise the db-type), `-build-epoch`,
`-ip-version` (4 or 6, default 6), `-record-size` (24/28/32, default 24).

Scheduled MMDB regeneration: `build/mmdb-iptoasn-write --generator` installs a
daily oneshot service + timer that fetches iptoasn.com and compiles
`/var/lib/cidr/iptoasn-asn.mmdb` and `/var/lib/cidr/iptoasn-country.mmdb`.

The embedded country metadata lives at `cmd/mmdb-write/data/countries.json`.
Refresh it from Wikidata like so:

```sh
# Recommended: download Wikidata country info
go run ./cmd/mmdb-build-countries
```

### Generator failure behaviour

Applies to `iptoasn`, `mm-dbip`, `mm-geolite2-asn`, `rir-country` and
`provider-function`; each succeeds only when it has published a complete file,
not merely when it exited. **A monitor must use the exit code**: a failure exits
non-zero — `1` for a failed run, `2` for most flag-parsing errors (a few validated
settings, such as `iptoasn -family`, also exit `1`) — and no longer prints a
`rows=0` tally with exit 0.

- **Atomic output.** `-o FILE` is written to a hidden `.<name>.tmp-*` in the
  target's directory, fsynced, and renamed over the target only once every check
  has passed: a reader sees the previous complete file or the new one, never a
  prefix. A symlinked target is followed (the link survives), a special file such
  as `/dev/null` is written through, an existing mode is kept (new files 0644). On
  any failure the previous file is untouched. Because it is a rename, a hard link
  to the output stops seeing updates and a custom owner is not preserved; a run
  killed mid-download leaves a hidden temp file that a `*.cidr` glob ignores.
  Stdout is a stream — rows already flushed are gone — so atomicity is a property
  of `-o FILE`.
- **Zero usable rows exits 1 and publishes nothing** (an HTML error page or empty
  body used to produce a 0-byte file and exit 0), as does a truncated stream, a
  dropped connection or corrupt gzip.
- **`-timeout` is also the idle (stall) deadline.** Beyond bounding the dial, TLS
  handshake and response headers, a download that sends no byte for `-timeout`
  fails; a large, slow download that keeps sending completes. `-timeout 0` means
  no limit. (The systemd units add a wall-clock `TimeoutStartSec`, below.)
- **`rir-country`** prints a stderr line per registry
  (`<registry> rows=N malformed=N header=bool`) before its summary and exits 1 if
  a registry that was read contributed no records.
- **`provider-function`** counts rows per feed (one URL, or one `-in` entry) and
  fails if *any* feed yielded none; a missing or `null` top-level array in a JSON
  feed (AWS `prefixes`/`ipv6_prefixes`, Fastly `addresses`/`ipv6_addresses`,
  Google `prefixes`) is a hard shape error naming the key; a line of 1 MiB or more
  in a line-list feed is an error.
- **`-conflict-log FILE`** is written atomically, but after the spec is
  published: if it fails, the run exits 1 with the new spec already in place.

Details per tool are in the [cmd README](../cmd/README.md#failure-behaviour).

### Scheduled generation (systemd)

Each generator has a build script under [`build/`](../build) that cross-compiles
a version-stamped `linux/amd64` binary and, in `--generator` mode, installs a
oneshot systemd service plus a timer that regenerates the spec (or MMDB) into
`/var/lib/cidr/` on a schedule (iptoasn daily, DB-IP monthly, MaxMind weekly;
the MMDB compile runs daily, from iptoasn):

```sh
build/iptoasn --generator user@host                       # daily    -> ip2asn.cidr
build/mm-dbip --generator user@host                       # monthly  -> dbip-country.cidr
build/rir-country --generator user@host                   # daily    -> rir-country.cidr
build/provider-function --generator user@host              # daily    -> provider-function.cidr
build/mm-geolite2-asn --generator --key YOUR_KEY user@host # weekly   -> geolite2-asn.cidr
build/mmdb-iptoasn-write --generator user@host            # daily -> iptoasn-asn.mmdb + iptoasn-country.mmdb
```

Every generator unit sets `TimeoutStartSec` (a `Type=oneshot` unit has no start
timeout by default, so a hung run would block the timer forever): 30 minutes for
`iptoasn`, `rir-country` and `provider-function`, 1 hour for `mm-dbip`,
`mm-geolite2-asn` and the MMDB compile (for the staged MMDB unit, whether the
bound is per step or for the whole sequence has not been verified on Linux). A
failed run (non-zero exit, or the timeout) never leaves a half-written published
file; each file is replaced only by its own final rename. The `mmdb-iptoasn-write` unit is
**staged, not piped**: one `ExecStart=` per step (fetch the spec, compile to
`….new`, `mv` over the live file), which systemd runs in order and stops at the
first failure, so a failed download never reaches `mmdb-write` and the live
database is only ever replaced by its final atomic `mv` — the ASN database is
moved before the country half runs, so a failure there can leave a new ASN
database beside the previous country one; `ExecStopPost=` removes the temp files
on every path. The live `.mmdb` is a fresh file on each run
(owner and mode as a new file, not preserved from the previous one).

`--cli` (the default) builds just the binary — nothing is scheduled. With no
host the install package is left under `build/install/` to copy and run
(`sudo ./<tool>.sh`) yourself.

`build/iptoasn` reads `OUTFILE`, `GENARGS`, and `TIMER` from the environment,
so one installer can emit a different dataset shape without editing the script.
`OUTFILE` is the file written into `/var/lib/cidr/`, `GENARGS` the switches
handed to the generator, and `TIMER` the `OnCalendar` expression; unset, each
keeps the default above. To schedule the combined ASN + country spec
(`<cidr> <ASN> <CC> <org>`) that a `Table[V]` carrying both fields expects:

```sh
OUTFILE=iptoasn-asn-cc.cidr GENARGS="-family combined -country" \
    build/iptoasn --generator user@host
```

Note the default `GENARGS` produces `<cidr> <ASN> <org>` with **no** country
column, so a loader that reads field 3 as a country code must be pointed at a
spec built with `-country` — the two differ only in a column, not a filename. Even
then the column is optional: a row whose source country is `None` has no country
field, so read field 3 only after checking that it is one.

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

### Expanding CIDRs to addresses (`cmd/ipunfold`)

[`cmd/ipunfold`](../cmd/ipunfold) is the inverse: it reads CIDR prefixes and
writes every address each one covers, one per line — `10.0.0.12/30` unfolds back
to `10.0.0.12`, `.13`, `.14`, `.15`. A bare address is accepted as its own `/32`
or `/128`, host bits in a prefix are masked rather than rejected, and only the
first field of a line is read, so an `ipfold` output round-trips and a
`<cidr> <ASN> <org>` spec expands too.

```sh
ipunfold < cidrs.txt              # expand stdin -> stdout, in input order
ipunfold -in cidrs.txt -o ips.txt
ipunfold -4 < cidrs.txt           # IPv4 prefixes only
ipunfold -count < cidrs.txt       # size the output before writing it
```

Expansion streams in input order and nothing is buffered, sorted, or
de-duplicated, so overlapping input prefixes emit overlapping addresses — pipe
through `ipfold` to normalize. Unlike folding, the output size is set by the
input's *coverage*, not its line count: a single `/8` is 16.7M addresses
(~0.2 s) and an IPv6 `/64` is 1.8×10¹⁹. Use `-count` to check first, and `-max N`
in scripts, which aborts with a non-zero exit before the prefix that would push
output past `N` (keeping whatever was already written). Build a stamped binary
with `build/ipunfold [user@host]`.

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
side either way. Mapped prefixes (`::ffff:a.b.c.d/n`, n ≥ 96) are stored as the
IPv4 prefix `/n−96`; shorter prefixes stay IPv6.

## Concurrency and refresh

A frozen `Set`/`Table[V]` is immutable, so any number of goroutines may query it
without a lock. There is no in-place update; to refresh, build a new value and
swap the pointer atomically:

```go
var current atomic.Pointer[cidr.Set]

// reload builds a Set from the feed and swaps it in only if it looks sane.
func reload(r io.Reader) error {
	set, err := cidr.LoadSet(r)
	if err != nil {
		return err // keep serving the previous Set
	}
	if set.Len() == 0 { // or a floor suited to the feed, e.g. under half the old Len
		return errors.New("feed loaded empty; keeping the previous set")
	}
	current.Store(set)
	return nil
}

// startup: a failure is fatal, since current is nil until a Set is stored.
if err := reload(feed); err != nil { log.Fatal(err) }
// each scheduled reload: log the error and keep serving the old Set.
if err := reload(feed); err != nil { log.Print(err) }
// hot path:
if current.Load().Contains(ip) { ... }
```

**Guard the swap.** The loaders skip lines they cannot parse without reporting
them, so a feed that is really an HTML error page, an empty body or the wrong
format *loads as an empty set with a nil error* — and swapping that in turns every
lookup into a miss. Check `Len()` (or a minimum that suits the feed, or a
fraction of the previous `Len`) before `Store`. `Table` has no `Len`: after
`LoadASN`/`LoadRefsASN` check the returned `Set`, and with `LoadFunc` count the
lines your callback accepts. (The generators in [`cmd/`](../cmd) apply the same
rule to their own output: zero usable rows is an error and publishes nothing.)

Builders are **not** concurrent-safe; do all `Add` calls from one goroutine
before `Freeze`.

## API reference

### Membership

| Symbol | Purpose |
|---|---|
| `NewBuilder() *Builder` | start a membership set |
| `(*Builder) Add(netip.Prefix)` | add a prefix |
| `(*Builder) AddPrefix(string) error` | parse and add a CIDR or bare address |
| `(*Builder) AddRange(lo, hi netip.Addr)` | add an inclusive address range (zones on the bounds are ignored) |
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
| `LastAddr(netip.Prefix) netip.Addr` | last (all-host-bits-set) address of a prefix's masked range; host bits in the input are ignored, no IPv4-mapped folding |
| `RangePrefixes(lo, hi netip.Addr) []netip.Prefix` | decompose a range into its minimal CIDR set |
| `AppendRangePrefixes(dst, lo, hi) []netip.Prefix` | RangePrefixes into a reused buffer (hot loops) |
| `ParseSpec(io.Reader) ([]SpecEntry, error)` | parse a `<cidr> [ASN] [org...]` stream |
| `LoadSet(io.Reader) (*Set, error)` | spec → membership `Set` |
| `LoadASN(io.Reader) (*Set, *Table[Info], error)` | spec → `Set` + `Table[Info]` |
| `BuildASN([]SpecEntry) (*Set, *Table[Info])` | already-parsed entries → `Set` + `Table[Info]` (the step `LoadASN` wraps) |
| `LoadFunc[V](io.Reader, parse) (*Table[V], error)` | any custom `<cidr> data...` feed → `Table[V]` |
| `ParseRefs(io.Reader) (*Refs, error)` | decode a `{name,version,list}` refs JSON envelope; a missing/renamed `list` or trailing data is an error (`[]` and `null` are empty) |
| `(*Refs) Entries() []SpecEntry` | parse the refs list into spec entries |
| `LoadRefsSet(io.Reader) (*Set, error)` | refs JSON → membership `Set` |
| `LoadRefsASN(io.Reader) (*Set, *Table[Info], error)` | refs JSON → `Set` + `Table[Info]` |
| `EncodeASN(asn, orgID uint32, flags uint8) uint64` | pack a compact value |
| `DecodeASN(uint64) (asn, orgID uint32, flags uint8)` | unpack it |
| `Info`, `SpecEntry`, `Refs` | value, parsed-entry, and refs-envelope types |

### MaxMind DB reader

A stdlib-only reader for `.mmdb` files (for example those `mmdb-write`
produces). Each lookup decodes a `map[string]any` for the record, so it is
**not** allocation-free like `Set.Contains` and `Table.Lookup`.

| Symbol | Purpose |
|---|---|
| `OpenMMDB(path string) (*MMDB, error)` | read and parse the database at `path` |
| `OpenMMDBBytes(data []byte) (*MMDB, error)` | parse an in-memory database (the slice is retained, not copied; do not mutate it) |
| `(*MMDB) Lookup(net.IP) (record map[string]any, ok bool, err error)` | the record for an address; `ok` is false when there is none |
| `(*MMDB) Metadata() map[string]any` | the decoded metadata (`node_count`, `record_size`, `ip_version`, `database_type`, …) |
| `(*MMDB) Close() error` | a no-op kept for API symmetry; safe to call concurrently with lookups |

An `*MMDB` is safe for concurrent lookups. The file is treated as untrusted
input:

- **Format checks at open.** `binary_format_major_version` must be 2 and
  `ip_version` 4 or 6 (a missing value is as invalid as a wrong one); anything
  else is an error rather than being read as IPv6.
- **Value widths are enforced.** A `uint16` is at most 2 bytes, `uint32` 4,
  `uint64` 8, `int32` 4 and `uint128` 16; a `double` is exactly 8 and a `float`
  exactly 4; a `bool` has size 0 or 1.
- **Each `Lookup` has a decode budget** (and so does the metadata decode at open):
  the section's length times 4 work units, held between 1 MiB and 32 MiB of units
  (`minDecodeCost`/`maxDecodeCost` in `mmdb.go`). A container is charged for its
  full declared size before anything is allocated, so a hostile record fails with
  `decode budget exceeded` instead of amplifying. One unit buys at most about
  1.3 bytes of heap, so a single `Lookup` allocates at most ~42 MB at the ceiling
  (the derivation is in the comment above `minDecodeCost` in `mmdb.go`); that is
  per call, so concurrent lookups multiply it by the number in flight. Real
  records cost a tiny fraction of it.
- **`Metadata()` returns the database's own map**, not a copy: it is shared by
  every caller and by concurrent lookups, so treat it (and the maps and slices
  inside it) as read-only; copy it before changing anything.

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
| `-match` | filter mode: print only addresses in the set; exit 1 if none matched (see below) |
| `-quiet` | suppress the run tally on stderr |
| `-version` | print the stamped version and exit |

Exit status follows grep: **0** success (with `-match`, at least one address
matched), **1** no match (`-match` only), **2** any error — bad usage, an
unreadable spec or input, or a failed write to stdout. An invalid address in the
input is skipped (with a note on stderr, except under `-match`), not an error.

A tally (`spec=… prefixes=… intervals=… queried=… member=…`) is written to
stderr unless `-quiet`. Build a version-stamped `linux/amd64` static binary with
`build/cidr [user@host]`.

## Worked examples

Runnable integrations live in [example/](../example/README.md): a library tour,
an HTTP REST API, a Unix-socket line service, and an MCP server. Each loads a
built-in demo spec (or a `-spec` file) and answers both membership and value
queries.

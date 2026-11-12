# Command-line tools

Ten programs built on the [`cidr`](..) package. Install any one with
`go install github.com/netstar-labs/cidr/cmd/<name>@latest`, or cross-compile a
version-stamped static `linux/amd64` binary with the matching
[`build/<name>`](../build) script (`build/<name> [user@host]` optionally installs
it over ssh). Each prints its build with `-version`.

| Tool | Purpose |
|---|---|
| [`cidr`](cidr) | look up addresses against a CIDR/ASN spec — membership + longest-prefix value |
| [`ipfold`](ipfold) | fold an unorganized IP list into the minimal CIDR set |
| [`ipunfold`](ipunfold) | expand CIDRs back into the individual addresses they cover |
| [`iptoasn`](iptoasn) | fetch iptoasn.com → `<cidr> <ASN> <org>` or `<cidr> <country>` spec |
| [`mm-geolite2-asn`](mm-geolite2-asn) | fetch MaxMind GeoLite2 ASN → ASN spec |
| [`mm-dbip`](mm-dbip) | fetch DB-IP Lite (country or ASN) → cidr spec |
| [`rir-country`](rir-country) | fetch the five RIR delegated files → country spec, from the primary record |
| [`provider-function`](provider-function) | fetch AWS/Google/Cloudflare/Fastly/Tor published ranges → `<cidr> <function> <provider>` spec |
| [`mmdb-write`](mmdb-write) | compile a cidr spec into a MaxMind DB (`.mmdb`) file |
| [`mmdb-build-countries`](mmdb-build-countries) | update Wikidata country nomenclature for `.mmdb` |

## Query & utilities

### `cidr` — spec lookup

Loads a `<cidr> [ASN] [org]` spec and looks up addresses from the arguments or
stdin. NDJSON by default; `-brief` for terse lines; `-match` as a grep-like
filter. Exit status follows grep: `0` ok (with `-match`, at least one address
matched), `1` no match (`-match` only), `2` any error — usage, an unreadable
spec or input, or a failed write to stdout. A malformed address on the command
line or stdin is skipped (with a note on stderr, except under `-match`), not an error.

```sh
cidr -spec asn.txt 1.1.1.200 8.8.8.8
printf '1.1.1.1\n9.9.9.9\n' | cidr -spec asn.txt -brief
cidr -spec block.txt -match < ips.txt        # print only listed addresses
```

### `ipfold` — aggregate an IP list to CIDRs

Reads an unorganized, mixed IPv4/IPv6 list (one per line), sorts and
de-duplicates it, and folds runs of consecutive addresses into the minimal CIDR
set — `10.0.0.12`, `.13`, `.14`, `.15` collapse to `10.0.0.12/30`.

```sh
ipfold < ips.txt                 # v4 block, then v6
ipfold -in ips.txt -o cidrs.txt
ipfold -4 < ips.txt              # IPv4 output only
```

Built for scale: IPv4 aggregates through a 2³²-bit bitmap (bounded ~512 MiB,
O(n), duplicate-robust) and parses straight from bytes — ~120M addresses fold in
roughly 20 s at ~0.5 GiB. The output is a valid spec for `cidr -spec`. Only the
first field of a line is read, split on whitespace **or commas**, so `10.0.0.12 note`
and `10.0.0.12,note` both fold. (The spec parser behind `cidr -spec` and `mmdb-write`
splits on whitespace only: a `<cidr>,<ASN>,<org>` line is not a spec line and is
skipped.)

### `ipunfold` — expand CIDRs to an address list

The inverse of `ipfold`: reads CIDR prefixes and writes every address each one
covers, one per line. A bare address is accepted as its own `/32` or `/128` (so
an `ipfold` output round-trips), host bits in a prefix are masked rather than
rejected, and only the first field of a line is read (fields split on whitespace
or commas) — so a `<cidr> <ASN> <org>` spec expands too.

```sh
ipunfold < cidrs.txt              # expand stdin -> stdout
ipunfold -in cidrs.txt -o ips.txt
ipunfold -4 < cidrs.txt           # IPv4 prefixes only
ipunfold -count < cidrs.txt       # how many addresses would this be?
```

Expansion streams in input order — nothing is buffered, sorted, or
de-duplicated, so overlapping input prefixes emit overlapping addresses (pipe
through `ipfold` to normalize). Output is unbounded by nature: one `/8` is 16.7M
addresses (~0.2 s) and an IPv6 `/64` is 1.8×10¹⁹. Check the size with `-count`
first; in scripts, `-max N` aborts with a non-zero exit before the prefix that
would push output past `N`, keeping whatever was already written.

Flags: `-in`, `-o`, `-4`, `-6`, `-count`, `-max` (default 0: no limit), `-version`.

### `mmdb-write` — compile cidr spec to MaxMind DB

Compiles any cidr spec into a MaxMind DB (`.mmdb`) file. The output schema is
selected by `-db-type`:

- `GeoLite2-ASN` (default): `autonomous_system_number` / `autonomous_system_organization`
- `GeoLite2-Country`: `continent` / `country` / `registered_country` in the
  standard GeoLite2 schema, using an embedded country dataset built from Wikidata.
  Since the source spec provides only one country per prefix, `country` and
  `registered_country` are set to the same value (the operator's country from
  the source). GeoLite2 distinguishes them — physical location vs registrant
  country.

The `iptoasn` tool can feed both formats: `iptoasn` for ASN, `iptoasn -output country` for country.

```sh
iptoasn | mmdb-write -o iptoasn-asn.mmdb
iptoasn -output country | mmdb-write -db-type GeoLite2-Country -o iptoasn-country.mmdb
mm-geolite2-asn -in GeoLite2-ASN-CSV.zip | mmdb-write -o geolite2.mmdb
mm-dbip -db asn | mmdb-write -o dbip-asn.mmdb
mm-dbip -db country | mmdb-write -db-type GeoLite2-Country -o dbip-country.mmdb
mmdb-write -in my-spec.cidr -o my-asn.mmdb                    # from a file
```

In a script, stage it instead (`iptoasn -o spec && mmdb-write -in spec -o db`) —
a plain shell pipe reports only the last command's status; see
[Pipelines](#pipelines).

Flags: `-in`, `-o`, `-db-type` (default `GeoLite2-ASN`), `-description`
(default: `IPtoASN` for `GeoLite2-ASN`, otherwise the db-type), `-build-epoch`,
`-ip-version` (4 or 6, default 6), `-record-size` (24/28/32, default 24).

**The schema follows `-db-type`.** A db-type containing `Country` writes the
country schema and reads the second field as a two-letter country code; any other
type writes the ASN schema (`<cidr> <ASN> <org>`). A country (or
`provider-function`) spec given to the ASN schema is not an error — every record
comes out with ASN 0 and the second field as the organisation — so `mmdb-write`
warns on stderr when **every** inserted record has ASN 0. Give a country spec the
matching `-db-type`.

**Most specific prefix wins, whatever the input order.** Entries are inserted
shortest prefix first (a stable sort, so of two identical prefixes the last in
the spec wins), so `10.1.0.0/16` before or after `10.0.0.0/8` gives the same
database — the one `cidr` would answer from the same spec. Residual divergences,
by `mmdbwriter`'s design: IPv6 prefixes inside or covering `::/96` (which holds
the IPv4 subtree), and the networks that alias it (`2001::/32`, `2002::/16`,
`::ffff:0:0/96`) are skipped or write through into the IPv4 side.

**Tally and exit status.** stderr carries
`inserted=N skipped: unparseable=… pseudo-code=… unknown-country=… unknown-continent=… aliased=…`.
If nothing was inserted — an empty spec, or every entry skipped (an ASN spec given
`-db-type GeoLite2-Country` skips them all as unknown countries) — it exits 1 and
writes no file. With `-o FILE` the database is published atomically (temp file in
the target's directory, fsync, rename; a symlinked target is followed, an existing
file's mode kept, new files 0644; a failure leaves the previous file untouched).

Country metadata is stored in `cmd/mmdb-write/data/countries.json` and embedded
at build time. Refresh it from [Wikidata](https://www.wikidata.org) like so:

```sh
go run ./cmd/mmdb-build-countries
```

#### Pipelines

The real magic is in the pipelines: any generator can be piped directly
into `mmdb-write` to produce a MaxMind DB without intermediate files.

```sh
# ASN MMDB
iptoasn -family combined | mmdb-write -o iptoasn-asn.mmdb
mm-geolite2-asn -license YOUR_KEY | mmdb-write -o geolite2-asn.mmdb
mm-dbip -db asn | mmdb-write -o dbip-asn.mmdb

# Country MMDB
iptoasn -output country | mmdb-write -db-type GeoLite2-Country -o iptoasn-country.mmdb
mm-dbip -db country | mmdb-write -db-type GeoLite2-Country -o dbip-country.mmdb
```

**Caution: in a script, do not rely on the pipe.** A plain shell pipe without
`pipefail` reports the *last* command's status, so a generator that fails part-way
through a download (stdout is not atomic: rows already flushed are already sent)
leaves `mmdb-write` compiling a truncated spec, and the pipeline exits 0. (With
`set -o pipefail` the status is honest, but the truncated database is still
written.) Stage it, so the database is never built from a failed fetch:

```sh
iptoasn -o spec && mmdb-write -in spec -o iptoasn-asn.mmdb
iptoasn -output country -o spec && mmdb-write -in spec -db-type GeoLite2-Country -o iptoasn-country.mmdb
```

Scheduled regeneration via `build/mmdb-iptoasn-write --generator` — installs a
daily oneshot service + timer that fetches iptoasn.com and compiles
`/var/lib/cidr/iptoasn-asn.mmdb` and `/var/lib/cidr/iptoasn-country.mmdb`
automatically. The unit is staged, not piped: one `ExecStart=` per step (fetch the
spec, compile to `….new`, `mv` over the live file), so systemd stops at the first
failing step and a live database is only ever replaced whole, by its own `mv`.
The ASN database is moved into place before the country half runs, so a failure
in the country half can leave a new ASN database beside the previous country one.
`TimeoutStartSec=1h` bounds start-up (whether systemd applies it per `ExecStart=`
step or to the whole sequence has not been verified on a Linux host).

## Data generators (fetch + convert)

Each downloads a provider's table and writes a cidr spec; range-based sources
are decomposed to CIDRs. All write stdout or `-o FILE` with a tally on stderr,
and each has a `build/<name> --generator` mode that installs a oneshot systemd
service + timer to regenerate the spec into `/var/lib/cidr/` on a schedule — see
the [user guide](../docs/userguide.md#scheduled-generation-systemd). A generator
succeeds only if it published a complete file: see
[Failure behaviour](#failure-behaviour).

Two things differ per generator, so check the tool's own section rather than
assuming:

- **Which loader reads the output back.** The ASN/geo generators emit
  `<cidr> <ASN> <org>` or `<cidr> <country>` for `cidr.LoadASN` / `cmd/cidr`.
  `provider-function` does not: its value is not an ASN, so it needs
  `cidr.LoadFunc`. **`LoadASN` will not reject it** — `parseSpecLine` accepts a
  non-numeric second field and folds the rest into `Org`, so `cidr -spec` on a
  function table silently reports `"org":"cloud aws"`. Use the right loader.
- **The `-in` form.** Most take `-in FILE` (local, gzip auto-detected).
  `provider-function` takes `-in provider=path` pairs and does not auto-detect
  gzip, because its five feeds have four different shapes and the format cannot
  be inferred from a filename.

### Failure behaviour

Shared by `iptoasn`, `mm-dbip`, `mm-geolite2-asn`, `rir-country` and
`provider-function`. **A monitor must look at the exit code**: a failure exits
non-zero — `1` for a failed run, `2` for most flag-parsing errors (a few
validated settings, such as `iptoasn -family`, also exit `1`) — and no longer
prints a `rows=0` tally with exit 0.

- **Atomic output.** With `-o FILE` the spec is written to a hidden
  `.<name>.tmp-*` in the target's directory, fsynced, and renamed over the target
  only after every check has passed, so a reader sees the previous complete file
  or the new one, never a prefix. A symlinked target is followed (the link
  survives); a special file such as `/dev/null` is written through, not replaced;
  an existing file's mode is kept (new files get 0644). On any failure — fetch,
  stall, corrupt or truncated input, no usable rows — the previous file is left
  untouched. Two consequences of rename: a hard link to the output no longer sees
  updates, and a custom owner is not preserved. A run killed mid-download leaves a
  hidden `.<name>.tmp-*` behind, which a `*.cidr` glob ignores. Stdout (no `-o`,
  or `-o -`) is a stream, not a file: rows already flushed are already gone, so
  atomicity is a property of `-o FILE`.
- **Zero usable rows is an error.** An HTML error page or empty body used to
  publish a 0-byte file and exit 0; it now exits 1 with `no usable rows …;
  nothing published, previous output left untouched`. A truncated stream or
  dropped connection is an error too, never a short file.
- **`-timeout` (default 30s) is also the idle deadline.** It bounds the dial, TLS
  handshake and response headers, *and* the gap between bytes of the body: a
  server that stops sending fails the run after `-timeout`, while a large, slow
  download that keeps sending completes (there is no overall deadline). `-timeout 0`
  means no limit at all. The build units add a wall-clock cap, `TimeoutStartSec`.
- **`rir-country`** prints one stderr line per registry —
  `rir-country: <registry> rows=N malformed=N header=bool` — before its summary,
  and exits 1, naming the registry, when a registry that was read contributed no
  records. A file without its version header counts one malformed line.
- **`provider-function`** guards per **feed** (one URL, or one `-in` entry), not
  per provider; see [`provider-function`](#provider-function).
- **`mm-geolite2-asn`** checks the CSV header of every file and counts non-prefix
  rows as skipped; **`mm-dbip`** skips a row with an empty or invalid ASN (counted
  as malformed).
- **`-conflict-log FILE`** (`rir-country`, `provider-function`) is itself written
  atomically, but after the spec is published: if writing it fails the run exits 1
  with the new spec already in place.

### `iptoasn`

iptoasn.com IP-to-ASN (free, no account); range-based.

- `-output asn` (default): `<cidr> <ASN> <org>` — pipe to `mmdb-write` for ASN MMDB.
- `-output country`: `<cidr> <country>` — pipe to `mmdb-write -db-type GeoLite2-Country`.

```sh
iptoasn -family v4 -o ip2asn-v4.cidr           # v4 | v6 | combined, asn format
iptoasn -output country -o country.cidr         # country format
iptoasn -in ip2asn-combined.tsv.gz
```

Flags: `-output` (`asn`/`country`), `-family`, `-url`, `-in`, `-o`, `-unrouted`
(keep AS0 rows), `-country` (prepend country to org in asn mode), `-timeout`.

With `-country`, a row whose source country is `None` gets **no** country field:
`<cidr> <ASN> <org>` instead of `<cidr> <ASN> <CC> <org>`. The file is therefore
not a fixed-column format — a consumer must not read the third field positionally
as a country code (it may be the first word of the org). Country mode
(`-output country`) skips `None` rows entirely.

### `mm-geolite2-asn`

MaxMind GeoLite2 ASN (free license key); CIDR-native → `<cidr> <ASN> <org>`.

```sh
mm-geolite2-asn -license YOUR_KEY -o geolite2-asn.cidr   # download the CSV zip
mm-geolite2-asn -in GeoLite2-ASN-CSV.zip                 # or a local zip/.csv/.csv.gz
```

Flags: `-license` (or `$MAXMIND_LICENSE_KEY`), `-family` (`v4`/`v6`/`both`),
`-url`, `-in`, `-o`, `-timeout`. Its `build --generator` mode **requires `--key`** and
refuses without one, storing it in a mode-600 EnvironmentFile.

### `mm-dbip`

DB-IP Lite (free, CC BY); range-based. `-db country` → `<cidr> <country>`;
`-db asn` → `<cidr> <ASN> <org>`.

```sh
mm-dbip -db country -o dbip-country.cidr    # current month's country lite
mm-dbip -db asn -o dbip-asn.cidr
mm-dbip -in dbip-country-lite-2026-07.csv.gz
```

Flags: `-db` (`country`/`asn`), `-month` (default: current UTC month), `-url`,
`-in`, `-o`, `-timeout`. Without `-in`/`-url` the current month's file is fetched.

### `rir-country`

The five RIR delegated-extended files → `<cidr> <country>`. This is the
**primary record** — the registries publish it themselves and the vendor country
datasets derive from it — so there is no account, licence key or vendor terms.

```sh
rir-country -o rir-country.cidr                  # all five registries
rir-country -registry arin -o arin.cidr          # just one
rir-country -in arin.txt,ripencc.txt             # local files, comma-separated
rir-country -conflict specific -o rir.cidr       # other tie-break rule
```

Flags: `-registry` (`all` or `afrinic`/`apnic`/`arin`/`lacnic`/`ripencc`),
`-conflict` (`date`/`specific`), `-conflict-log FILE`, `-in`, `-o`, `-timeout`.

For ipv4 the published `value` is an address **count** and is not always a power
of two (763 such records as published on 2026-09-17), so one record can become
several prefixes. Only `allocated`/`assigned`
ipv4/ipv6 rows with a two-letter country are kept; asn rows, summaries, the
version header and `reserved`/`available` blocks are skipped.

Each registry's yield is reported on stderr (see [Failure
behaviour](#failure-behaviour)), and the run fails, publishing nothing, if a
registry that was read contributed nothing.

**Conflicts.** Two registries can claim the same prefix with different
countries. `-conflict date` (default) takes the later delegation date;
`-conflict specific` takes the narrower source allocation. Prefixes of
*different* lengths never collide — the spec keeps both and longest-prefix match
resolves them at load, which is already "most specific wins". Where the rule
cannot separate two records the lower country code wins so output does not
depend on input order, and **every** conflict is reported on stderr
(`-conflict-log FILE` writes them all as TSV). Output is sorted, so two runs
over the same input are byte-identical.

### `provider-function`

The address space operators publish about themselves →
`<cidr> <function> <provider> [anycast]`. Like `rir-country`, this is the
**primary record** — the operator publishes the list, so there is no account,
licence key, vendor terms, or heuristic between the source and the answer.

```sh
provider-function                                # all five providers
provider-function -provider aws -o aws.cidr      # one
provider-function -in aws=ip-ranges.json         # local files, provider=path
```

Flags: `-provider` (`all` or `aws`/`cloudflare`/`fastly`/`google-cloud`/`tor`),
`-in`, `-o`, `-conflict-log FILE`, `-timeout`. Giving both `-in` and `-provider`
lets `-in` win, with a warning on stderr.

**Nothing fails quietly.** Unusable rows are counted per provider and reported as
`malformed[...]`; an attempted provider always appears in `records[...]`, at zero
if it yielded nothing, and stderr carries one
`feed <provider> <name> rows=N malformed=N` line per feed. A **feed** — one URL,
or one `-in` entry — that produced no usable rows is a hard error and no output
file is written, and the error names every dead feed. The unit is the feed, not
the provider: Cloudflare's `ips-v6` being empty fails the run even though `ips-v4`
is healthy. None of these feeds is ever legitimately empty, so zero rows means the
fetch or the parse broke, and writing the file anyway would truncate the published
spec on a "successful" `--generator` timer run.

Shape changes are hard errors for the same reason. A JSON feed whose expected
top-level array is **missing or `null`** (AWS `prefixes` / `ipv6_prefixes`, Fastly
`addresses` / `ipv6_addresses`, Google `prefixes`) has changed shape and fails
naming the key, instead of dropping a whole address family; a present-but-empty
array is accepted (the feed-level guard decides). A Google entry with neither
`ipv4Prefix` nor `ipv6Prefix` counts as malformed, and a line-list feed with a
line of 1 MiB or more fails rather than losing every row after it. `-o -` writes
to stdout.

Sources: AWS `ip-ranges.json`, Google Cloud `cloud.json`, Cloudflare `ips-v4` +
`ips-v6`, Fastly `public-ip-list`, Tor `torbulkexitlist`. Read back with
`cidr.LoadFunc` — the value is not an ASN, so `LoadASN` is the wrong loader.

**Function is three labels, on purpose.** `cloud`, `cdn` and `tor-exit` are what
self-published address space can honestly support; nobody publishes a "these are
consumer broadband" file, so `residential`, `mobile`, `transit` and `scanner`
need other sources and arrive with them. A taxonomy wider than the evidence
would make the table look complete while the missing labels are merely absent.

**`tor-exit` is perishable in a way the others are not.** Cloud and CDN ranges
change slowly; Tor exit relays churn constantly, so the bulk list is a snapshot
of who was exiting when it was fetched. A daily build both carries relays that
have since stopped and misses ones that have since started — it is accurate
about the past, not the present, and "not in the table" is not "not a Tor exit".
Rebuild on the cadence the decision needs. The other four are fine daily.

**The `anycast` marker is conservative.** It appears only where the operator's
own documentation uses the word: AWS Global Accelerator ("static anycast IP
addresses"), Cloudflare and Fastly. CloudFront and Route 53 are deliberately not
marked even though a commercial dataset would mark both — the only claim this
table can defend is "the operator said so", and one inferred row mixed in with
published ones leaves a consumer unable to tell which kind any row is. This is
not an anycast detector: it covers addresses whose operator publishes a list,
which is most of the traffic-carrying anycast space and almost none of the tail.

A full run on 2026-09-21 produced 13,796 **prefixes**: 11,273 AWS, 1,377 Tor
exits, 1,103 Google Cloud, 22 Cloudflare, 21 Fastly, with no cross-provider
conflicts. Note the tool's own stderr tally reports `records[...]` per provider
— published records, which exceed prefixes because AWS lists a prefix once per
service (17,526 AWS records collapse to 11,273 prefixes). The single `prefixes=`
figure on that line is the one to compare against the numbers above.

**Overlapping prefixes.** AWS lists a prefix once per service it belongs to, and
`AMAZON` is a catch-all superset of the specific ones — as published on
2026-09-21, 2,298 of 7,795 distinct IPv4 prefixes carried more than one label.
A service with an explicit mapping (`CLOUDFRONT` → cdn, `GLOBALACCELERATOR` →
cloud + anycast) outranks the catch-all, so a CDN edge cannot be silently
downgraded to generic cloud by JSON order. A prefix left claimed by two
different functions is counted and reported on stderr, never resolved silently;
`-conflict-log` writes every one as TSV. Output is sorted, so two runs over the
same input are byte-identical.

#### Adding another source

Three questions decide *where* a new source goes, in order. Getting the first
one wrong is the expensive mistake, because it is the one that quietly devalues
the existing table.

**1. Does the source describe its own address space?** Everything in
`provider-function` is a *primary record* — AWS publishes AWS's ranges, the Tor
Project publishes Tor's exits. That is the whole reason a consumer can trust a
row without knowing anything else about how it was produced.

A source that *infers* something about somebody else's addresses — a
reverse-DNS naming classifier, an ASN-organisation-name heuristic, a commercial
usage-type feed — does **not** belong in this command, however good it is. Mixing
inferred rows in with published ones leaves a consumer unable to tell which kind
any given row is, and the provenance boundary should be a file and binary
boundary, not a column that a downstream reader can forget to check. Give it its
own generator writing its own spec, and let the consumer merge the two knowing
which is which. Adding a *confidence* column is the right move there, and the
wrong move here — every row in this file is equally, maximally attested.

**2. Is the shape range-like and slow-moving?** `cidr` builds a static table and
answers longest-prefix lookups against it. A time-bounded behavioural
observation ("this address was scanning last Tuesday") is a log with a TTL, not
a prefix table, and forcing it into a spec file loses the one property that
makes it meaningful.

**3. If yes to both — add a provider.** It is a map entry and a parser:

```go
// 1. a label, if the source supports one the closed set does not already carry
const funcExample = "example"

// 2. the provider's own published feed(s) and the parser for their shape
"example": {
    urls:  []string{"https://example.net/ranges.json"},
    parse: parseExample,
},

// 3. the name, in providerOrder — this fixes fetch order AND the tie-break
//    when two operators disagree, so its position is a deliberate statement
//    about which source wins, not an alphabetical accident
var providerOrder = []string{"aws", "cloudflare", "example", "fastly", …}
```

A parser hands **raw prefix strings** up to the collector rather than parsing
them itself:

```go
func parseExample(r io.Reader, emit func(string, entry)) error {
    // decode, then for each range:
    emit(rawPrefixString, entry{function: funcExample})
    return nil
}
```

That is deliberate: parsing in one place is what gives the malformed counter a
single home. A parser that calls `cidr.ParsePrefix` itself and drops failures
silently is how this command originally shipped a feed-shape change as a
zero-byte file and a clean exit.

For a plain one-prefix-per-line feed there is no parser to write at all — reuse
`parseLineList(entry{...})`, as Cloudflare and Tor do.

**What you get for free**, and therefore must not re-implement per provider:
malformed counting, the zero-rows-is-an-error guard, deterministic sorted output,
conflict detection and reporting, and the `-in provider=path` test seam. **What
you must supply**: a fixture test in `main_test.go` covering the feed's real
shape, a seed in `FuzzParsers`, and — if the source's ranges can overlap another
provider's — a view on where its name belongs in `providerOrder`.

### `mmdb-build-countries`

Builds the country nomenclature dataset used by `mmdb-write -db-type GeoLite2-Country`.

Fetches country metadata via two [Wikidata](https://www.wikidata.org) SPARQL queries (countries + continents):
ISO codes (`P297`), translated names in 8 locales (`de`, `en`, `es`, `fr`, `ja`,
`pt-BR`, `ru`, `zh-CN`), continent mapping (`P30`), EU membership (`P463` with
end-date filtering), and GeoNames IDs (`P1566`). GeoNames IDs are used in MaxMind databases.

No external attribution required — Wikidata is CC0 / public domain.

```sh
mmdb-build-countries                                       # two Wikidata queries
mmdb-build-countries -o data/countries.json                # custom output path
```

Flags: `-o` (default `cmd/mmdb-write/data/countries.json`), `-wikidata-url`
(default `https://query.wikidata.org/sparql`), `-allow-missing`. If any country
lacks a GeoNames id, a continent, or an English name, it prints them and exits 1
without writing the file; `-allow-missing` writes it anyway (the id is then
omitted, and `mmdb-write` writes such a country without a `geoname_id`).

---

For embedding the library directly (no CLI), see [`example/`](../example) and the
[user guide](../docs/userguide.md).

# Command-line tools

Five programs built on the [`cidr`](..) package. Install any one with
`go install github.com/netstar-labs/cidr/cmd/<name>@latest`, or cross-compile a
version-stamped static `linux/amd64` binary with the matching
[`build/<name>`](../build) script (`build/<name> [user@host]` optionally installs
it over ssh). Each prints its build with `-version`.

| Tool | Purpose |
|---|---|
| [`cidr`](cidr) | look up addresses against a CIDR/ASN spec — membership + longest-prefix value |
| [`ipfold`](ipfold) | fold an unorganized IP list into the minimal CIDR set |
| [`iptoasn`](iptoasn) | fetch iptoasn.com → `<cidr> <ASN> <org>` spec |
| [`mm-geolite2-asn`](mm-geolite2-asn) | fetch MaxMind GeoLite2 ASN → ASN spec |
| [`mm-dbip`](mm-dbip) | fetch DB-IP Lite (country or ASN) → cidr spec |

## Query & utilities

### `cidr` — spec lookup

Loads a `<cidr> [ASN] [org]` spec and looks up addresses from the arguments or
stdin. NDJSON by default; `-brief` for terse lines; `-match` as a grep-like
filter (exit 1 if nothing matched).

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
O(n), duplicate-robust) and parses straight from bytes — 100M+ addresses fold in
seconds. The output is a valid spec for `cidr -spec`.

## Data generators (fetch + convert)

Each downloads a provider's IP-to-ASN/geo table and writes the cidr spec that
`cidr.LoadASN` / `cmd/cidr` read back; range-based sources are decomposed to
CIDRs. All take `-in FILE` (local, gzip auto-detected) instead of fetching, and
write stdout or `-o FILE` with a tally on stderr. Each also has a
`build/<name> --generator` mode that installs a oneshot systemd service + timer
to regenerate the spec into `/var/lib/cidr/` on a schedule — see the
[user guide](../docs/userguide.md#scheduled-generation-systemd).

### `iptoasn`

iptoasn.com IP-to-ASN (free, no account); range-based → `<cidr> <ASN> <org>`.

```sh
iptoasn -family v4 -o ip2asn-v4.cidr     # v4 | v6 | combined
iptoasn -in ip2asn-combined.tsv.gz
```

Flags: `-family`, `-url`, `-in`, `-o`, `-unrouted` (keep AS0 rows), `-country`.

### `mm-geolite2-asn`

MaxMind GeoLite2 ASN (free license key); CIDR-native → `<cidr> <ASN> <org>`.

```sh
mm-geolite2-asn -license YOUR_KEY -o geolite2-asn.cidr   # download the CSV zip
mm-geolite2-asn -in GeoLite2-ASN-CSV.zip                 # or a local zip/.csv/.csv.gz
```

Flags: `-license` (or `$MAXMIND_LICENSE_KEY`), `-family` (`v4`/`v6`/`both`),
`-url`, `-in`, `-o`. Its `build --generator` mode **requires `--key`** and
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
`-in`, `-o`.

---

For embedding the library directly (no CLI), see [`example/`](../example) and the
[user guide](../docs/userguide.md).

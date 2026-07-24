# Command-line tools

Seven programs built on the [`cidr`](..) package. Install any one with
`go install github.com/netstar-labs/cidr/cmd/<name>@latest`, or cross-compile a
version-stamped static `linux/amd64` binary with the matching
[`build/<name>`](../build) script (`build/<name> [user@host]` optionally installs
it over ssh). Each prints its build with `-version`.

| Tool | Purpose |
|---|---|---|
| [`cidr`](cidr) | look up addresses against a CIDR/ASN spec — membership + longest-prefix value |
| [`ipfold`](ipfold) | fold an unorganized IP list into the minimal CIDR set |
| [`iptoasn`](iptoasn) | fetch iptoasn.com → `<cidr> <ASN> <org>` or `<cidr> <country>` spec |
| [`mm-geolite2-asn`](mm-geolite2-asn) | fetch MaxMind GeoLite2 ASN → ASN spec |
| [`mm-dbip`](mm-dbip) | fetch DB-IP Lite (country or ASN) → cidr spec |
| [`mmdb-write`](mmdb-write) | compile a cidr spec into a MaxMind DB (`.mmdb`) file |
| [`mmdb-build-countries`](mmdb-build-countries) | update Wikidata country nomenclature for `.mmdb` |

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
O(n), duplicate-robust) and parses straight from bytes — ~120M addresses fold in
roughly 20 s at ~0.5 GiB. The output is a valid spec for `cidr -spec`.

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

Flags: `-in`, `-o`, `-db-type` (default `GeoLite2-ASN`), `-description`
(default: `IPtoASN` for `GeoLite2-ASN`, otherwise the db-type), `-build-epoch`,
`-ip-version` (4 or 6, default 6), `-record-size` (24/28/32, default 24).

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

Scheduled regeneration via `build/mmdb-iptoasn-write --generator` — installs a
daily oneshot service + timer that fetches iptoasn.com and compiles
`/var/lib/cidr/iptoasn-asn.mmdb` and `/var/lib/cidr/iptoasn-country.mmdb` automatically.

## Data generators (fetch + convert)

Each downloads a provider's IP-to-ASN/geo table and writes the cidr spec that
`cidr.LoadASN` / `cmd/cidr` read back; range-based sources are decomposed to
CIDRs. All take `-in FILE` (local, gzip auto-detected) instead of fetching, and
write stdout or `-o FILE` with a tally on stderr. Each also has a
`build/<name> --generator` mode that installs a oneshot systemd service + timer
to regenerate the spec into `/var/lib/cidr/` on a schedule — see the
[user guide](../docs/userguide.md#scheduled-generation-systemd).

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
(default `https://query.wikidata.org/sparql`).

---

For embedding the library directly (no CLI), see [`example/`](../example) and the
[user guide](../docs/userguide.md).

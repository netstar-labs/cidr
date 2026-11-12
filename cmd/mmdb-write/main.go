// Command mmdb-write compiles a cidr spec into a MaxMind DB (.mmdb) file.
// The output schema matches GeoLite2-ASN or GeoLite2-Country depending on
// -db-type.
//
// Pipeline usage (pipe any cidr data source directly to mmdb-write):
//
//	iptoasn | mmdb-write -o asn.mmdb
//	mm-geolite2-asn -in GeoLite2-ASN-CSV.zip | mmdb-write -o geolite2.mmdb
//	mm-dbip -db asn | mmdb-write -o dbip-asn.mmdb
//	mm-dbip -db country | mmdb-write -db-type GeoLite2-Country -o dbip-country.mmdb
//	mmdb-write -in my-spec.cidr -o my-asn.mmdb                    # from a file
//	cat my-spec.cidr | mmdb-write -db-type MyCustomDB -o out.mmdb # custom type
package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/netstar-labs/cidr"
)

// Version and Revision are stamped at build time via -ldflags -X (see build/mmdb-write).
var (
	Version  = "dev"
	Revision = "unknown"
)

// versionString is the -version line, as a function so tests can assert its shape.
func versionString() string { return fmt.Sprintf("mmdb-write %s (%s)", Version, Revision) }

//go:embed data/countries.json
var countriesJSON []byte

type continentInfo struct {
	GeonameID uint32            `json:"geoname_id"`
	Names     map[string]string `json:"names"`
}

type countryInfo struct {
	GeonameID         uint32            `json:"geoname_id"`
	Names             map[string]string `json:"names"`
	ContinentCode     string            `json:"continent_code"`
	IsInEuropeanUnion bool              `json:"is_in_european_union,omitempty"`
}

type countryDB struct {
	Continents map[string]continentInfo `json:"continents"`
	Countries  map[string]countryInfo   `json:"countries"`
}

var countryData countryDB

func init() {
	if err := json.Unmarshal(countriesJSON, &countryData); err != nil {
		panic("mmdb-write: embedded data/countries.json: " + err.Error())
	}
}

func main() {
	version := flag.Bool("version", false, "print version and exit")
	in := flag.String("in", "", "read spec from this file instead of stdin")
	out := flag.String("o", "", "write MMDB to this file instead of stdout")
	dbType := flag.String("db-type", "GeoLite2-ASN", `MMDB database_type (e.g. "GeoLite2-ASN", "GeoLite2-Country")`)
	description := flag.String("description", "", "database description (default: db type)")
	buildEpoch := flag.Int64("build-epoch", 0, "build epoch (Unix timestamp, default: now)")
	ipVersion := flag.Int("ip-version", 6, "IP version (4 or 6, default 6 for dual-stack)")
	recordSize := flag.Int("record-size", 24, "record size in bits (24, 28, or 32; default 24)")
	flag.Parse()

	if *version {
		fmt.Println(versionString())
		return
	}

	if err := run(*in, *out, *dbType, *description, *buildEpoch, *ipVersion, *recordSize); err != nil {
		fmt.Fprintln(os.Stderr, "mmdb-write:", err)
		os.Exit(1)
	}
}

func run(in, out, dbType, description string, buildEpoch int64, ipVersion, recordSize int) error {
	if description == "" {
		if dbType == "GeoLite2-ASN" {
			description = "IPtoASN"
		} else {
			description = dbType
		}
	}

	var r io.Reader = os.Stdin
	if in != "" {
		f, err := os.Open(in)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}

	entries, err := cidr.ParseSpec(r)
	if err != nil {
		return fmt.Errorf("reading spec: %w", err)
	}
	if len(entries) == 0 {
		return errors.New("empty spec (no valid entries)")
	}

	isCountry := strings.Contains(dbType, "Country")
	var (
		n  int64
		tl tally
	)
	build := func(w io.Writer) error {
		bw := bufio.NewWriter(w)
		var err error
		n, tl, err = writeMMDB(bw, entries, dbType, description, buildEpoch, ipVersion, recordSize, isCountry)
		if err != nil {
			return err
		}
		return bw.Flush()
	}

	dst := "stdout"
	var werr error
	if out == "" {
		werr = build(os.Stdout)
	} else {
		dst = out
		werr = writeFileAtomic(out, build)
	}
	if werr != nil {
		return werr
	}

	if w := tl.asnWarning(isCountry); w != "" {
		fmt.Fprintf(os.Stderr, "mmdb-write: warning: %s\n", w)
	}
	fmt.Fprintf(os.Stderr, "mmdb-write: %s bytes=%d -> %s\n", tl, n, dst)
	return nil
}

// writeFileAtomic writes the output of write to path so that a failure at any
// point leaves a previous file at path untouched: it writes a temporary file in
// the same directory (the same filesystem, so the rename is atomic), fsyncs it,
// and renames it over path only on success. A pre-existing file's permission bits
// are kept; a new file gets 0644.
func writeFileAtomic(path string, write func(w io.Writer) error) (err error) {
	mode := os.FileMode(0o644)
	if st, serr := os.Stat(path); serr == nil {
		mode = st.Mode().Perm()
	}
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err = write(f); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// tally counts what writeMMDB did with each spec entry: how many it inserted and
// how many it skipped, by reason.
type tally struct {
	inserted         int
	nonZeroASN       int // inserted records with ASN != 0 (ASN mode)
	unparseable      int // prefix does not round-trip through net.ParseCIDR
	pseudoCode       int // country mode: EU, AP, ZZ, Unknown or empty
	unknownCountry   int // country mode: code absent from the dataset
	unknownContinent int // country mode: the country's continent is absent from the dataset
	aliased          int // mmdbwriter refuses it (2001::/32, 2002::/16, ::ffff:0:0/96 alias IPv4)
}

func (t tally) String() string {
	return fmt.Sprintf("inserted=%d skipped: unparseable=%d pseudo-code=%d unknown-country=%d unknown-continent=%d aliased=%d",
		t.inserted, t.unparseable, t.pseudoCode, t.unknownCountry, t.unknownContinent, t.aliased)
}

// asnWarning returns a warning when an ASN-mode database holds only ASN 0
// records, which means the input was a country/function spec, not an ASN one.
func (t tally) asnWarning(isCountry bool) string {
	if isCountry || t.inserted == 0 || t.nonZeroASN > 0 {
		return ""
	}
	return fmt.Sprintf("all %d inserted records have ASN 0; input looks like a country/function spec; use -db-type GeoLite2-Country (or another type containing \"Country\")", t.inserted)
}

// maxWarnings caps the per-entry warnings printed for one run; the tally counts the rest.
const maxWarnings = 10

// treeDepth is the depth in the search tree at which Insert places p in an IPv6
// tree: an IPv4 prefix lives under ::/96, so it sits 96 levels deeper than its
// length. Comparing raw Bits() would put "::/48" (an IPv6 prefix that covers the
// whole IPv4 subtree) after "10.0.0.0/8".
func treeDepth(p netip.Prefix) int {
	if p.Addr().Is4() {
		return p.Bits() + 96
	}
	return p.Bits()
}

// writeMMDB compiles a cidr spec into a MaxMind DB and writes it to w.
// When isCountry is true, each spec entry's Org field is treated as an ISO
// country code and looked up in the embedded country dataset to build a
// GeoLite2-Country-style record (continent + country + registered_country).
// registered_country mirrors country (IPtoASN carries a single country per
// range), and non-country pseudo-codes (EU, AP, ZZ, Unknown, empty) are skipped.
//
// mmdbwriter inserts with replace semantics: a prefix inserted after a covering
// one carves its range out of it, but a covering prefix inserted after a nested
// one erases it. The library answers longest-prefix-first, so entries are
// inserted shortest-first (by treeDepth; stable, so of equal prefixes the last in
// the spec wins, as in the library). Three families remain divergent by
// mmdbwriter's design: prefixes of ::/96 or shorter (they cover the IPv4
// subtree), and the networks that alias it (2001::/32, 2002::/16,
// ::ffff:0:0/96), which are skipped or write through into the IPv4 subtree.
//
// It returns the bytes written and what it did with each entry. When nothing was
// inserted it writes nothing and returns an error.
func writeMMDB(w io.Writer, entries []cidr.SpecEntry, dbType, description string, buildEpoch int64, ipVersion, recordSize int, isCountry bool) (int64, tally, error) {
	var tl tally
	if buildEpoch == 0 {
		buildEpoch = time.Now().Unix()
	}

	tree, err := mmdbwriter.New(
		mmdbwriter.Options{
			DatabaseType: dbType,
			Description: map[string]string{
				"en": description,
			},
			BuildEpoch:              buildEpoch,
			IPVersion:               ipVersion,
			RecordSize:              recordSize,
			Languages:               []string{"en"},
			IncludeReservedNetworks: true,
		},
	)
	if err != nil {
		return 0, tl, fmt.Errorf("creating writer: %w", err)
	}

	entries = slices.Clone(entries) // sort a copy; the caller's slice is not ours
	sort.SliceStable(entries, func(i, j int) bool {
		return treeDepth(entries[i].Prefix) < treeDepth(entries[j].Prefix)
	})

	warned := 0
	warn := func(format string, args ...any) {
		if warned++; warned <= maxWarnings {
			fmt.Fprintf(os.Stderr, "mmdb-write: warning: "+format+"\n", args...)
		}
	}

	for _, e := range entries {
		_, network, err := net.ParseCIDR(e.Prefix.String())
		if err != nil {
			tl.unparseable++
			continue
		}

		var record mmdbtype.DataType
		if isCountry {
			isoCode := e.Org
			if isoCode == "" || isoCode == "Unknown" || isoCode == "EU" || isoCode == "AP" || isoCode == "ZZ" {
				tl.pseudoCode++
				continue
			}
			ci, ok := countryData.Countries[isoCode]
			if !ok {
				tl.unknownCountry++
				warn("unknown country code %q, skipping %s", isoCode, e.Prefix)
				continue
			}
			cont, ok := countryData.Continents[ci.ContinentCode]
			if !ok {
				tl.unknownContinent++
				warn("unknown continent code %q for %s, skipping %s", ci.ContinentCode, isoCode, e.Prefix)
				continue
			}

			countryRec := map[string]any{
				"geoname_id": ci.GeonameID,
				"iso_code":   isoCode,
				"names":      ci.Names,
			}
			rcRec := maps.Clone(countryRec)
			if ci.IsInEuropeanUnion {
				countryRec["is_in_european_union"] = true
				rcRec["is_in_european_union"] = true
			}

			record = mmdbtype.Map{
				"continent": toMMDBType(map[string]any{
					"code":       ci.ContinentCode,
					"geoname_id": cont.GeonameID,
					"names":      cont.Names,
				}),
				"country":            toMMDBType(countryRec),
				"registered_country": toMMDBType(rcRec),
			}
		} else {
			record = mmdbtype.Map{
				"autonomous_system_number":       mmdbtype.Uint32(e.ASN),
				"autonomous_system_organization": mmdbtype.String(e.Org),
			}
		}

		if err := tree.Insert(network, record); err != nil {
			var aliased *mmdbwriter.AliasedNetworkError
			if errors.As(err, &aliased) {
				tl.aliased++
				warn("skipping %s (aliased network)", e.Prefix)
				continue
			}
			return 0, tl, fmt.Errorf("insert %s: %w", e.Prefix, err)
		}
		tl.inserted++
		if e.ASN != 0 {
			tl.nonZeroASN++
		}
	}

	if tl.inserted == 0 {
		return 0, tl, fmt.Errorf("nothing to write: no entry was inserted (%s)", tl)
	}
	n, err := tree.WriteTo(w)
	return n, tl, err
}

// toMMDBType recursively converts a Go value to an mmdbtype value.
func toMMDBType(v any) mmdbtype.DataType {
	switch x := v.(type) {
	case map[string]any:
		m := make(mmdbtype.Map, len(x))
		for k, val := range x {
			m[mmdbtype.String(k)] = toMMDBType(val)
		}
		return m
	case map[string]string: // e.g. a names map straight from the country schema
		m := make(mmdbtype.Map, len(x))
		for k, val := range x {
			m[mmdbtype.String(k)] = mmdbtype.String(val)
		}
		return m
	case string:
		return mmdbtype.String(x)
	case uint32:
		return mmdbtype.Uint32(x)
	case float64:
		return mmdbtype.Uint32(uint32(x))
	case bool:
		return mmdbtype.Bool(x)
	case nil:
		return mmdbtype.String("")
	case []any:
		s := make(mmdbtype.Slice, len(x))
		for i, val := range x {
			s[i] = toMMDBType(val)
		}
		return s
	default:
		return mmdbtype.String(fmt.Sprint(x))
	}
}

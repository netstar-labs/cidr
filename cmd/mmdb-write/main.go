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
	"net"
	"os"
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
		fmt.Printf("mmdb-write %s (%s)\n", Version, Revision)
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

	var w io.Writer = os.Stdout
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriter(w)

	isCountry := strings.Contains(dbType, "Country")
	n, err := writeMMDB(bw, entries, dbType, description, buildEpoch, ipVersion, recordSize, isCountry)
	if err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	dst := "stdout"
	if out != "" {
		dst = out
	}
	fmt.Fprintf(os.Stderr, "mmdb-write: entries=%d bytes=%d -> %s\n", len(entries), n, dst)
	return nil
}

// writeMMDB compiles a cidr spec into a MaxMind DB and writes it to w.
// When isCountry is true, each spec entry's Org field is treated as an ISO
// country code and looked up in the embedded country dataset to build a
// GeoLite2-Country-style record (continent + country + registered_country).
func writeMMDB(w io.Writer, entries []cidr.SpecEntry, dbType, description string, buildEpoch int64, ipVersion, recordSize int, isCountry bool) (int64, error) {
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
		return 0, fmt.Errorf("creating writer: %w", err)
	}

	for _, e := range entries {
		_, network, err := net.ParseCIDR(e.Prefix.String())
		if err != nil {
			continue
		}

		var record mmdbtype.DataType
		if isCountry {
			isoCode := e.Org
			if isoCode == "" || isoCode == "Unknown" || isoCode == "EU" || isoCode == "AP" {
				continue
			}
			ci, ok := countryData.Countries[isoCode]
			if !ok {
				fmt.Fprintf(os.Stderr, "mmdb-write: warning: unknown country code %q, skipping %s\n", isoCode, e.Prefix)
				continue
			}
			cont, ok := countryData.Continents[ci.ContinentCode]
			if !ok {
				fmt.Fprintf(os.Stderr, "mmdb-write: warning: unknown continent code %q for %s, skipping %s\n", ci.ContinentCode, isoCode, e.Prefix)
				continue
			}

			contNames := toNamesAny(cont.Names)
			countryNames := toNamesAny(ci.Names)

			countryRec := map[string]any{
				"geoname_id": ci.GeonameID,
				"iso_code":   isoCode,
				"names":      countryNames,
			}
			rcRec := map[string]any{
				"geoname_id": ci.GeonameID,
				"iso_code":   isoCode,
				"names":      countryNames,
			}
			if ci.IsInEuropeanUnion {
				countryRec["is_in_european_union"] = true
				rcRec["is_in_european_union"] = true
			}

			record = mmdbtype.Map{
				"continent": toMMDBType(map[string]any{
					"code":       ci.ContinentCode,
					"geoname_id": cont.GeonameID,
					"names":      contNames,
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
			return 0, fmt.Errorf("insert %s: %w", e.Prefix, err)
		}
	}

	return tree.WriteTo(w)
}

// toNamesAny converts a map[string]string (from our structs) to map[string]any
// so that toMMDBType recurses into it properly.
func toNamesAny(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
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

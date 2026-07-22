package main

import (
	"bytes"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
	"github.com/oschwald/maxminddb-golang/v2"
)

var sampleSpec = strings.Join([]string{
	"1.0.0.0/24 13335 Cloudflare, Inc.",
	"8.8.8.0/24 15169 Google LLC",
	"203.0.113.0/24 64500 Example Org",
	"2001:db8::/32 64501 DOC",
	"# comment line",
	"",
	"10.0.0.0/8 0 RFC 1918",
}, "\n") + "\n"

func toUint32(v any) uint32 {
	switch x := v.(type) {
	case uint64:
		return uint32(x)
	case uint32:
		return x
	case float64:
		return uint32(x)
	default:
		return 0
	}
}

func TestWriteMMDB(t *testing.T) {
	entries, err := cidr.ParseSpec(strings.NewReader(sampleSpec))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}

	f, err := os.CreateTemp("", "mmdb-write-test-*.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	var buf bytes.Buffer
	n, err := writeMMDB(&buf, entries, "Test-DB", "test database", 0, 6, 24, false)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("wrote zero bytes")
	}
	if err := os.WriteFile(f.Name(), buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	reader, err := maxminddb.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if reader.Metadata.DatabaseType != "Test-DB" {
		t.Errorf("database_type = %q, want Test-DB", reader.Metadata.DatabaseType)
	}
	if reader.Metadata.IPVersion != 6 {
		t.Errorf("ip_version = %d, want 6", reader.Metadata.IPVersion)
	}
	if reader.Metadata.RecordSize != 24 {
		t.Errorf("record_size = %d, want 24", reader.Metadata.RecordSize)
	}
	if len(reader.Metadata.Languages) != 1 || reader.Metadata.Languages[0] != "en" {
		t.Errorf("languages = %v, want [en]", reader.Metadata.Languages)
	}
	if reader.Metadata.Description["en"] != "test database" {
		t.Errorf("description[en] = %q, want %q", reader.Metadata.Description["en"], "test database")
	}

	cases := []struct {
		ip      string
		network string
		asn     uint32
		org     string
	}{
		{"1.0.0.1", "1.0.0.0/24", 13335, "Cloudflare, Inc."},
		{"8.8.8.8", "8.8.8.0/24", 15169, "Google LLC"},
		{"203.0.113.50", "203.0.113.0/24", 64500, "Example Org"},
		{"2001:db8::1", "2001:db8::/32", 64501, "DOC"},
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		var result map[string]any
		r := reader.Lookup(ip)
		if !r.Found() {
			t.Errorf("lookup %s: not found", c.ip)
			continue
		}
		if err := r.Decode(&result); err != nil {
			t.Errorf("lookup %s: decode: %v", c.ip, err)
			continue
		}
		asn := toUint32(result["autonomous_system_number"])
		org, _ := result["autonomous_system_organization"].(string)
		if asn != c.asn {
			t.Errorf("lookup %s: ASN = %d, want %d", c.ip, asn, c.asn)
		}
		if org != c.org {
			t.Errorf("lookup %s: org = %q, want %q", c.ip, org, c.org)
		}
	}

	// Test not found
	notFound := netip.MustParseAddr("9.9.9.9")
	r := reader.Lookup(notFound)
	if r.Found() {
		t.Error("9.9.9.9 should not be found")
	}
}

func TestSpecRoundTrip(t *testing.T) {
	entries, _ := cidr.ParseSpec(strings.NewReader(sampleSpec))
	f, err := os.CreateTemp("", "mmdb-write-roundtrip-*.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	var buf bytes.Buffer
	if _, err := writeMMDB(&buf, entries, "GeoLite2-ASN", "test", 0, 6, 24, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.Name(), buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	reader, err := maxminddb.Open(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	networks := 0
	for range reader.Networks() {
		networks++
	}
	if networks != 5 {
		t.Errorf("expected 5 networks, got %d", networks)
	}
}

var countrySpec = strings.Join([]string{
	"1.0.0.0/24 AU",
	"8.8.8.0/24 US",
	"203.0.113.0/24 DE",
	"2001:db8::/32 JP",
}, "\n") + "\n"

func TestCountryMMDB(t *testing.T) {
	entries, err := cidr.ParseSpec(strings.NewReader(countrySpec))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected 4 entries, got %d", len(entries))
	}

	var buf bytes.Buffer
	n, err := writeMMDB(&buf, entries, "GeoLite2-Country", "test country db", 0, 6, 24, true)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("wrote zero bytes")
	}

	reader, err := maxminddb.OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	if reader.Metadata.DatabaseType != "GeoLite2-Country" {
		t.Errorf("database_type = %q, want GeoLite2-Country", reader.Metadata.DatabaseType)
	}

	cases := []struct {
		ip      string
		isoCode string
	}{
		{"1.0.0.1", "AU"},
		{"8.8.8.8", "US"},
		{"203.0.113.50", "DE"},
		{"2001:db8::1", "JP"},
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		var result map[string]any
		r := reader.Lookup(ip)
		if !r.Found() {
			t.Errorf("lookup %s: not found", c.ip)
			continue
		}
		if err := r.Decode(&result); err != nil {
			t.Errorf("lookup %s: decode: %v", c.ip, err)
			continue
		}

		// Check continent
		continent, _ := result["continent"].(map[string]any)
		if continent == nil {
			t.Errorf("lookup %s: missing continent", c.ip)
			continue
		}
		if _, ok := continent["code"].(string); !ok {
			t.Errorf("lookup %s: continent.code missing", c.ip)
		}
		if gid := toUint32(continent["geoname_id"]); gid == 0 {
			t.Errorf("lookup %s: continent.geoname_id missing or zero", c.ip)
		}
		names, _ := continent["names"].(map[string]any)
		if names == nil || names["en"] == nil {
			t.Errorf("lookup %s: continent.names missing", c.ip)
		}

		// Check country
		country, _ := result["country"].(map[string]any)
		if country == nil {
			t.Errorf("lookup %s: missing country", c.ip)
			continue
		}
		if got, _ := country["iso_code"].(string); got != c.isoCode {
			t.Errorf("lookup %s: iso_code = %q, want %q", c.ip, got, c.isoCode)
		}

		// Check registered_country mirrors country
		rc, _ := result["registered_country"].(map[string]any)
		if rc == nil {
			t.Errorf("lookup %s: missing registered_country", c.ip)
			continue
		}
		if got, _ := rc["iso_code"].(string); got != c.isoCode {
			t.Errorf("lookup %s: registered_country.iso_code = %q, want %q", c.ip, got, c.isoCode)
		}
		if toUint32(rc["geoname_id"]) != toUint32(country["geoname_id"]) {
			t.Errorf("lookup %s: registered_country.geoname_id != country.geoname_id", c.ip)
		}
	}

	// Unknown country code should be skipped
	unknownSpec := "10.0.0.0/8 XX\n"
	uEntries, _ := cidr.ParseSpec(strings.NewReader(unknownSpec))
	var ubuf bytes.Buffer
	un, err := writeMMDB(&ubuf, uEntries, "GeoLite2-Country", "test", 0, 6, 24, true)
	if err != nil {
		t.Fatal(err)
	}
	if un == 0 {
		// If we wrote zero bytes, that's OK (no valid entries)
		// Just check no crash happened
	}
}

func TestVersionString(t *testing.T) {
	Version, Revision = "v1.2.3", "abcdef012345"
	if got, want := versionString(), "mmdb-write v1.2.3 (abcdef012345)"; got != want {
		t.Errorf("versionString() = %q, want %q", got, want)
	}
}

// TestCountryPseudoCodesSkipped: non-country pseudo-codes (and codes absent from
// the dataset) are dropped, so no bogus record is emitted — only the real
// country survives.
func TestCountryPseudoCodesSkipped(t *testing.T) {
	spec := strings.Join([]string{
		"1.0.0.0/24 US",
		"2.0.0.0/24 EU",
		"3.0.0.0/24 AP",
		"4.0.0.0/24 ZZ",
		"5.0.0.0/24 Unknown",
		"6.0.0.0/24 XX", // not a pseudo-code, but absent from the dataset -> skipped
	}, "\n") + "\n"
	entries, err := cidr.ParseSpec(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := writeMMDB(&buf, entries, "GeoLite2-Country", "test", 0, 6, 24, true); err != nil {
		t.Fatal(err)
	}
	reader, err := maxminddb.OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	n := 0
	for range reader.Networks() {
		n++
	}
	if n != 1 {
		t.Errorf("networks = %d, want 1 (only US)", n)
	}
	if r := reader.Lookup(netip.MustParseAddr("1.0.0.1")); !r.Found() {
		t.Error("US network missing")
	}
	if r := reader.Lookup(netip.MustParseAddr("2.0.0.1")); r.Found() {
		t.Error(`pseudo-code "EU" should have been skipped`)
	}
}

// TestCountryAmericanSamoa: ISO code "AS" — which collides with the "AS" ASN
// prefix in the spec parser — round-trips to an American Samoa (Oceania) record.
func TestCountryAmericanSamoa(t *testing.T) {
	entries, err := cidr.ParseSpec(strings.NewReader("1.2.3.0/24 AS\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Org != "AS" {
		t.Fatalf("parsed = %+v, want one entry with Org=AS", entries)
	}
	var buf bytes.Buffer
	if _, err := writeMMDB(&buf, entries, "GeoLite2-Country", "test", 0, 6, 24, true); err != nil {
		t.Fatal(err)
	}
	reader, err := maxminddb.OpenBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	var result map[string]any
	r := reader.Lookup(netip.MustParseAddr("1.2.3.4"))
	if !r.Found() {
		t.Fatal("1.2.3.4 not found")
	}
	if err := r.Decode(&result); err != nil {
		t.Fatal(err)
	}
	country, _ := result["country"].(map[string]any)
	if got, _ := country["iso_code"].(string); got != "AS" {
		t.Errorf("country.iso_code = %q, want AS", got)
	}
	cont, _ := result["continent"].(map[string]any)
	if got, _ := cont["code"].(string); got != "OC" {
		t.Errorf("continent.code = %q, want OC (Oceania)", got)
	}
}

package cidr

import (
	"net"
	"testing"
)

// testdata/test-asn.mmdb is a GeoLite2-ASN-schema database built by the
// mmdb-write command from a fixed spec (see mmdb_test.go's companion in the
// commit message): 1.0.0.0/24 → AS13335, 8.8.8.0/24 → AS15169,
// 9.9.9.0/24 → AS19281, 2606:4700:4700::/48 → AS13335. Dual-stack (ip_version 6),
// 24-bit records.
func TestMMDBLookupASN(t *testing.T) {
	cases := []struct {
		ip   string
		asn  uint64
		org  string
		want bool
	}{
		{"1.0.0.1", 13335, "CLOUDFLARENET", true}, // IPv4-in-IPv6 (::/96) path
		{"8.8.8.8", 15169, "GOOGLE", true},
		{"9.9.9.9", 19281, "QUAD9", true},
		{"2606:4700:4700::1111", 13335, "CLOUDFLARENET", true}, // native IPv6
		{"203.0.113.1", 0, "", false},                          // not in any listed range
		{"2001:db8::1", 0, "", false},
	}
	// Every record size, because 24/28/32-bit node records use distinct encodings
	// (28-bit splits the middle byte's nibbles) — the fixtures are the same spec.
	for _, f := range []string{"test-asn.mmdb", "test-asn28.mmdb", "test-asn32.mmdb"} {
		t.Run(f, func(t *testing.T) {
			db, err := OpenMMDB("testdata/" + f)
			if err != nil {
				t.Fatalf("OpenMMDB: %v", err)
			}
			defer db.Close()
			if got := db.Metadata()["database_type"]; got != "GeoLite2-ASN" {
				t.Errorf("database_type = %v, want GeoLite2-ASN", got)
			}
			for _, c := range cases {
				rec, ok, err := db.Lookup(net.ParseIP(c.ip))
				if err != nil {
					t.Fatalf("Lookup(%s): %v", c.ip, err)
				}
				if ok != c.want {
					t.Errorf("Lookup(%s) found=%v, want %v", c.ip, ok, c.want)
					continue
				}
				if !ok {
					continue
				}
				if got := rec["autonomous_system_number"]; got != c.asn {
					t.Errorf("Lookup(%s) ASN = %v (%T), want %d", c.ip, got, got, c.asn)
				}
				if got := rec["autonomous_system_organization"]; got != c.org {
					t.Errorf("Lookup(%s) org = %v, want %q", c.ip, got, c.org)
				}
			}
		})
	}
}

// testdata/test-country.mmdb is a GeoLite2-Country-schema database with nested
// maps (continent / country / registered_country). Two ranges share the "US"
// record, so the writer deduplicates it and the second lookup resolves through a
// data-section POINTER — exercising the pointer-follow path.
func TestMMDBLookupCountryNested(t *testing.T) {
	db, err := OpenMMDB("testdata/test-country.mmdb")
	if err != nil {
		t.Fatalf("OpenMMDB: %v", err)
	}
	defer db.Close()

	cases := []struct{ ip, iso, continent string }{
		{"1.0.0.1", "US", "NA"},
		{"8.8.8.8", "US", "NA"}, // deduped → pointer-resolved record
		{"81.2.69.1", "GB", "EU"},
		{"2001:67c:2e8::1", "DE", "EU"},
	}
	for _, c := range cases {
		rec, ok, err := db.Lookup(net.ParseIP(c.ip))
		if err != nil || !ok {
			t.Fatalf("Lookup(%s) ok=%v err=%v", c.ip, ok, err)
		}
		country, _ := rec["country"].(map[string]any)
		if got, _ := country["iso_code"].(string); got != c.iso {
			t.Errorf("Lookup(%s) country.iso_code = %q, want %q", c.ip, got, c.iso)
		}
		continent, _ := rec["continent"].(map[string]any)
		if got, _ := continent["code"].(string); got != c.continent {
			t.Errorf("Lookup(%s) continent.code = %q, want %q", c.ip, got, c.continent)
		}
		// names is a nested map[lang]string — confirms recursive map decode.
		if names, _ := country["names"].(map[string]any); len(names) == 0 {
			t.Errorf("Lookup(%s) country.names empty — nested map not decoded", c.ip)
		}
	}
}

func TestMMDBOpenErrors(t *testing.T) {
	if _, err := OpenMMDBBytes([]byte("not an mmdb file at all")); err == nil {
		t.Error("expected an error for a file without the metadata marker")
	}
	if _, err := OpenMMDB("testdata/does-not-exist.mmdb"); err == nil {
		t.Error("expected an error opening a missing file")
	}
}

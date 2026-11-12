package main

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

func TestZeroGeonameIDOmitted(t *testing.T) {
	countryData.Countries["XZ"] = countryInfo{Names: map[string]string{"en": "Xland"}, ContinentCode: "EU"}
	t.Cleanup(func() { delete(countryData.Countries, "XZ") })
	entries, _ := cidr.ParseSpec(strings.NewReader("1.0.0.0/24 XZ\n2.0.0.0/24 DE\n"))
	var buf bytes.Buffer
	if _, _, err := writeMMDB(&buf, entries, "GeoLite2-Country", "t", 1, 6, 24, true); err != nil {
		t.Fatal(err)
	}
	db, err := cidr.OpenMMDBBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for ip, wantID := range map[string]bool{"1.0.0.1": false, "2.0.0.1": true} {
		rec, ok, err := db.Lookup(net.ParseIP(ip))
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", ip, ok, err)
		}
		for _, k := range []string{"country", "registered_country"} {
			m, _ := rec[k].(map[string]any)
			if _, has := m["geoname_id"]; has != wantID {
				t.Errorf("%s %s: geoname_id present = %v, want %v", ip, k, has, wantID)
			}
			if m["iso_code"] == nil {
				t.Errorf("%s %s: iso_code missing", ip, k)
			}
		}
	}
}

// TestShippedCountriesComplete: every country in the embedded dataset has a
// GeoNames id, a continent that exists, and an English name, unless it is listed
// here with the reason. (AC, CQ and TA are not GeoNames countries, but have ids
// for their territories and a fixed continent.)
func TestShippedCountriesComplete(t *testing.T) {
	exempt := map[string]string{} // code -> reason
	if len(countryData.Countries) < 200 {
		t.Fatalf("only %d countries embedded", len(countryData.Countries))
	}
	for code, c := range countryData.Countries {
		if _, ok := exempt[code]; ok {
			continue
		}
		if c.GeonameID == 0 {
			t.Errorf("%s: no geoname_id", code)
		}
		if _, ok := countryData.Continents[c.ContinentCode]; !ok {
			t.Errorf("%s: continent %q is empty or unknown", code, c.ContinentCode)
		}
		if c.Names["en"] == "" {
			t.Errorf("%s: no en name", code)
		}
	}
}

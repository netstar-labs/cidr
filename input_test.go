package cidr

import (
	"strings"
	"testing"
)

const sampleSpec = `
# an IP-to-ASN spec with comments and blank lines

10.0.0.0/8            # bare CIDR, no ASN
1.1.1.0/24 13335 Cloudflare, Inc.
8.8.8.0/24 AS15169 Google LLC
1.1.1.128/25 64500 More Specific Sub
203.0.113.7 64501 Host Route Org
2001:db8::/32 64502 v6 Org
garbage line that is not a prefix
`

func TestParseSpec(t *testing.T) {
	entries, err := ParseSpec(strings.NewReader(sampleSpec))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 6 { // the garbage line and comments are skipped
		t.Fatalf("got %d entries, want 6", len(entries))
	}
	// spot-check the AS-prefixed and multi-word org parsing
	var google, cf SpecEntry
	for _, e := range entries {
		switch e.Prefix.String() {
		case "8.8.8.0/24":
			google = e
		case "1.1.1.0/24":
			cf = e
		}
	}
	if google.ASN != 15169 || google.Org != "Google LLC" {
		t.Errorf("google = %+v", google)
	}
	if cf.ASN != 13335 || cf.Org != "Cloudflare, Inc." {
		t.Errorf("cloudflare = %+v", cf)
	}
}

func TestLoadASN(t *testing.T) {
	set, table, err := LoadASN(strings.NewReader(sampleSpec))
	if err != nil {
		t.Fatal(err)
	}

	// membership
	if !set.Contains(mustAddr("10.1.2.3")) {
		t.Error("10.1.2.3 should be a member")
	}
	if set.Contains(mustAddr("11.0.0.0")) {
		t.Error("11.0.0.0 should not be a member")
	}

	// value lookup, including the nested more-specific (1.1.1.128/25 wins)
	if info, ok := table.Lookup(mustAddr("1.1.1.200")); !ok || info.ASN != 64500 {
		t.Errorf("1.1.1.200 = %+v (ok=%v), want ASN 64500", info, ok)
	}
	if info, ok := table.Lookup(mustAddr("1.1.1.10")); !ok || info.ASN != 13335 {
		t.Errorf("1.1.1.10 = %+v (ok=%v), want ASN 13335", info, ok)
	}
	if info, ok := table.Lookup(mustAddr("203.0.113.7")); !ok || info.Org != "Host Route Org" {
		t.Errorf("host route = %+v (ok=%v)", info, ok)
	}
	if info, ok := table.Lookup(mustAddr("2001:db8::1")); !ok || info.ASN != 64502 {
		t.Errorf("v6 = %+v (ok=%v)", info, ok)
	}
	if _, ok := table.Lookup(mustAddr("192.0.2.1")); ok {
		t.Error("192.0.2.1 should miss")
	}
}

func TestLoadSet(t *testing.T) {
	set, err := LoadSet(strings.NewReader("1.0.0.0/24\n1.0.1.0/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(mustAddr("1.0.1.55")) {
		t.Error("expected membership")
	}
}

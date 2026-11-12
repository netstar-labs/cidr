package main

import (
	"bytes"
	"strings"
	"testing"
)

// goldenCSV is the GeoLite2-ASN-Blocks shape: a header, then network,asn,org.
// It covers a quoted org with a comma, padded fields, host bits in the network
// (masked on output), a v6 block, an empty ASN, and a header-like junk row.
const goldenCSV = `network,autonomous_system_number,autonomous_system_organization
1.0.0.0/24,13335,"Cloudflare, Inc."
1.0.4.0/22, 38803 , Wirefreebroadband Pty Ltd 
10.1.2.3/8,64500,masked
2001:200::/32,2500,WIDE Project
1.0.8.0/24,,No ASN
not,a,prefix
`

func goldens(t *testing.T) []struct{ name, got string } {
	t.Helper()
	var buf bytes.Buffer
	if _, err := convertCSV(strings.NewReader(goldenCSV), &buf); err != nil {
		t.Fatal(err)
	}
	return []struct{ name, got string }{
		{"blocks", buf.String()},
	}
}

// recorded holds the generator's output for fixed input, produced by
// TestPrintGoldens and pasted here deliberately — a golden the test computes
// from the code under test is not a golden, it is a tautology.
var recorded = map[string]string{
	"blocks": "1.0.0.0/24 13335 Cloudflare, Inc.\n1.0.4.0/22 38803 Wirefreebroadband Pty Ltd\n10.0.0.0/8 64500 masked\n2001:200::/32 2500 WIDE Project\n",
}

// TestPrintGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recorded.
//
//	go test -run TestPrintGoldens -v ./cmd/mm-geolite2-asn/
func TestPrintGoldens(t *testing.T) {
	for _, g := range goldens(t) {
		t.Logf("\t%q: %q,", g.name, g.got)
	}
}

// TestSpecOutputGolden pins the bytes this generator writes for fixed input.
func TestSpecOutputGolden(t *testing.T) {
	gs := goldens(t)
	if len(gs) != len(recorded) {
		t.Fatalf("%d golden cases but %d recorded: a case was added or removed without recording it", len(gs), len(recorded))
	}
	for _, g := range gs {
		want, ok := recorded[g.name]
		if !ok {
			t.Errorf("%s: no recorded golden", g.name)
			continue
		}
		if g.got != want {
			t.Errorf("%s:\n got  %q\n want %q\n\n"+
				"mm-geolite2-asn SPEC OUTPUT CHANGED. This is a format break. The spec carries no version "+
				"or kind marker, and the services that read it upgrade independently of this "+
				"generator: a reader built for the old output parses the new lines as a different "+
				"ASN, org, country or function — silently, because a field it does not expect is "+
				"folded into the org or the line is skipped, never rejected. Line ORDER is format too: "+
				"mmdb-write inserts in file order and a later covering prefix overwrites the nested "+
				"ones before it. If the output must change it needs a NEW, explicitly marked format "+
				"(a '#' header line naming it is ignored by every existing reader), not a new shape "+
				"for this one. Do not re-record this golden to make the test pass.",
				g.name, g.got, want)
		}
	}
}

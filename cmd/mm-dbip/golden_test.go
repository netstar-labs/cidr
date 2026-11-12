package main

import (
	"bytes"
	"strings"
	"testing"
)

// The DB-IP lite CSV shapes: country is start,end,cc; asn is start,end,asn,org.
// Each covers a single-CIDR range, a non-power-of-two range (several prefixes, in
// order) with a padded value, a v6 range, a quoted field with a comma, an empty
// value, and a short row.
const (
	goldenCountryCSV = "1.0.0.0,1.0.0.255,AU\n" +
		"1.0.4.0,1.0.4.6, CN \n" +
		"2001:db8::,2001:db8::ffff,ZZ\n" +
		"1.0.8.0,1.0.8.255,\n" +
		"1.0.9.0,1.0.9.255\n"
	goldenASNCSV = "1.1.1.0,1.1.1.255,13335,\"Cloudflare, Inc.\"\n" +
		"1.0.4.0,1.0.4.6,38803, Wirefreebroadband Pty Ltd \n" +
		"2001:db8::,2001:db8::ffff,64502,DOC\n" +
		"1.0.8.0,1.0.8.255,,No ASN Org\n" +
		"1.0.9.0,1.0.9.255,4134\n"
)

func goldens(t *testing.T) []struct{ name, got string } {
	t.Helper()
	run := func(csv, db string) string {
		var buf bytes.Buffer
		if _, err := convert(strings.NewReader(csv), &buf, db); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	return []struct{ name, got string }{
		{"country", run(goldenCountryCSV, "country")},
		{"asn", run(goldenASNCSV, "asn")},
	}
}

// recorded holds the generator's output for fixed input, produced by
// TestPrintGoldens and pasted here deliberately — a golden the test computes
// from the code under test is not a golden, it is a tautology.
var recorded = map[string]string{
	"country": "1.0.0.0/24 AU\n1.0.4.0/30 CN\n1.0.4.4/31 CN\n1.0.4.6/32 CN\n2001:db8::/112 ZZ\n1.0.8.0/24 \n",
	"asn":     "1.1.1.0/24 13335 Cloudflare, Inc.\n1.0.4.0/30 38803 Wirefreebroadband Pty Ltd\n1.0.4.4/31 38803 Wirefreebroadband Pty Ltd\n1.0.4.6/32 38803 Wirefreebroadband Pty Ltd\n2001:db8::/112 64502 DOC\n1.0.8.0/24  No ASN Org\n",
}

// TestPrintGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recorded.
//
//	go test -run TestPrintGoldens -v ./cmd/mm-dbip/
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
				"mm-dbip SPEC OUTPUT CHANGED. This is a format break. The spec carries no version "+
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

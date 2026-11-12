package main

import (
	"bytes"
	"strings"
	"testing"
)

// goldenTSV covers each row shape convert treats differently: a routed v4 range
// that is one CIDR, an AS0 "Not routed" range, a range that is not a power of two
// (several prefixes, in order), a "None" country, a v6 range, an org with inner
// runs of spaces, and a malformed row.
var goldenTSV = strings.Join([]string{
	"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed",
	"1.0.4.0\t1.0.4.6\t38803\tAU\tWPL-AS-AP  Wirefreebroadband Pty Ltd",
	"8.8.8.0\t8.8.8.255\t15169\tNone\tGOOGLE",
	"2001:db8::\t2001:db8::ffff\t64502\tZZ\tDOC",
	"bad line",
}, "\n") + "\n"

func goldens(t *testing.T) []struct{ name, got string } {
	t.Helper()
	run := func(o options) string {
		var buf bytes.Buffer
		if _, err := convert(strings.NewReader(goldenTSV), &buf, o); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	return []struct{ name, got string }{
		{"asn", run(options{outputMode: "asn"})},
		{"asn-unrouted", run(options{outputMode: "asn", unrouted: true})},
		{"asn-country", run(options{outputMode: "asn", country: true})},
		{"country", run(options{outputMode: "country"})},
	}
}

// recorded holds the generator's output for fixed input, produced by
// TestPrintGoldens and pasted here deliberately — a golden the test computes
// from the code under test is not a golden, it is a tautology.
var recorded = map[string]string{
	"asn":          "1.0.0.0/24 13335 CLOUDFLARENET\n1.0.4.0/30 38803 WPL-AS-AP  Wirefreebroadband Pty Ltd\n1.0.4.4/31 38803 WPL-AS-AP  Wirefreebroadband Pty Ltd\n1.0.4.6/32 38803 WPL-AS-AP  Wirefreebroadband Pty Ltd\n8.8.8.0/24 15169 GOOGLE\n2001:db8::/112 64502 DOC\n",
	"asn-unrouted": "1.0.0.0/24 13335 CLOUDFLARENET\n1.0.1.0/24 0 Not routed\n1.0.2.0/23 0 Not routed\n1.0.4.0/30 38803 WPL-AS-AP  Wirefreebroadband Pty Ltd\n1.0.4.4/31 38803 WPL-AS-AP  Wirefreebroadband Pty Ltd\n1.0.4.6/32 38803 WPL-AS-AP  Wirefreebroadband Pty Ltd\n8.8.8.0/24 15169 GOOGLE\n2001:db8::/112 64502 DOC\n",
	"asn-country":  "1.0.0.0/24 13335 US CLOUDFLARENET\n1.0.4.0/30 38803 AU WPL-AS-AP  Wirefreebroadband Pty Ltd\n1.0.4.4/31 38803 AU WPL-AS-AP  Wirefreebroadband Pty Ltd\n1.0.4.6/32 38803 AU WPL-AS-AP  Wirefreebroadband Pty Ltd\n8.8.8.0/24 15169 GOOGLE\n2001:db8::/112 64502 ZZ DOC\n",
	"country":      "1.0.0.0/24 US\n1.0.4.0/30 AU\n1.0.4.4/31 AU\n1.0.4.6/32 AU\n2001:db8::/112 ZZ\n",
}

// TestPrintGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recorded.
//
//	go test -run TestPrintGoldens -v ./cmd/iptoasn/
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
				"iptoasn SPEC OUTPUT CHANGED. This is a format break. The spec carries no version "+
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

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// goldenSources is one published file per provider, chosen so that every rule
// deciding the output bytes is exercised: the AWS catch-all against a specific
// service on the same prefix (in both JSON orders), GLOBALACCELERATOR's anycast
// marker, a cross-provider disagreement (broken by provider order and logged),
// two providers agreeing, a Tor host route nested in a cloud range (shorter
// prefix first), the same address at two lengths, and v4 before v6.
var goldenSources = []src{
	{"aws", awsDoc(
		aws4("3.0.0.0/15", "AMAZON")+","+
			aws4("13.32.0.0/15", "AMAZON")+","+aws4("13.32.0.0/15", "CLOUDFRONT")+","+
			aws4("13.35.0.0/16", "CLOUDFRONT")+","+aws4("13.35.0.0/16", "AMAZON")+","+
			aws4("15.197.0.0/24", "GLOBALACCELERATOR")+","+aws4("15.197.0.0/24", "AMAZON")+","+
			aws4("104.16.0.0/13", "AMAZON")+","+
			aws4("52.94.0.0/22", "AMAZON")+","+aws4("52.94.0.0/24", "EC2"),
		`{"ipv6_prefix":"2600:1f00::/24","service":"AMAZON"}`)},
	{"cloudflare", "173.245.48.0/20\n104.16.0.0/13\n2400:cb00::/32\n"},
	{"fastly", `{"addresses":["23.235.32.0/20","173.245.48.0/20"],"ipv6_addresses":["2a04:4e40::/32"]}`},
	{"google-cloud", `{"prefixes":[{"ipv4Prefix":"34.1.208.0/20"},{"ipv6Prefix":"2600:1900:4000::/44"}]}`},
	{"tor", "# exit list\n185.220.101.1\n3.0.0.7\n2001:db8::7\n"},
}

func goldens(t *testing.T) []struct{ name, got string } {
	t.Helper()
	spec, _, conflicts := convert(t, goldenSources...)
	path := filepath.Join(t.TempDir(), "conflicts.tsv")
	if err := writeConflictLog(path, conflicts); err != nil {
		t.Fatal(err)
	}
	log, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return []struct{ name, got string }{
		{"spec", spec},
		{"conflict-log", string(log)},
	}
}

// recorded holds the generator's output for fixed input, produced by
// TestPrintGoldens and pasted here deliberately — a golden the test computes
// from the code under test is not a golden, it is a tautology.
var recorded = map[string]string{
	"spec":         "3.0.0.0/15 cloud aws\n3.0.0.7/32 tor-exit tor\n13.32.0.0/15 cdn aws\n13.35.0.0/16 cdn aws\n15.197.0.0/24 cloud aws anycast\n23.235.32.0/20 cdn fastly anycast\n34.1.208.0/20 cloud google-cloud\n52.94.0.0/22 cloud aws\n52.94.0.0/24 cloud aws\n104.16.0.0/13 cloud aws\n173.245.48.0/20 cdn cloudflare anycast\n185.220.101.1/32 tor-exit tor\n2001:db8::7/128 tor-exit tor\n2400:cb00::/32 cdn cloudflare anycast\n2600:1900:4000::/44 cloud google-cloud\n2600:1f00::/24 cloud aws\n2a04:4e40::/32 cdn fastly anycast\n",
	"conflict-log": "prefix\ta_provider\ta_function\tb_provider\tb_function\twinner_provider\twinner_function\n104.16.0.0/13\taws\tcloud\tcloudflare\tcdn\taws\tcloud\n",
}

// TestPrintGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recorded.
//
//	go test -run TestPrintGoldens -v ./cmd/provider-function/
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
				"provider-function SPEC OUTPUT CHANGED. This is a format break. The spec carries no version "+
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

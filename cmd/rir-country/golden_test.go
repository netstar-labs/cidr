package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two registries' delegated files, chosen so that every rule deciding the output
// bytes is exercised: a non-power-of-two ipv4 count (several prefixes), the same
// address at two lengths (both kept; shorter first), v4 before v6, a conflict the
// date rule separates, a conflict the specificity rule separates the other way,
// and a full tie that falls back to the lower country code.
const (
	goldenARIN = `2.3|arin|1789563621568|6|19700101|20260916|-0400
arin|*|ipv4|*|4|summary
arin|US|asn|1|1|20010920|assigned|a
arin|US|ipv4|8.8.8.0|256|20010920|allocated|a
arin|US|ipv4|10.0.0.0|768|20000101|allocated|b
arin|CA|ipv4|192.0.2.0|256|20100101|assigned|c
arin|us|ipv6|2001:db8::|32|20200101|allocated|d
arin|ZZ|ipv4|198.51.100.0|256|20200101|available|e
`
	goldenRIPE = `2.3|ripencc|1789563621568|5|19700101|20260916|+0100
ripencc|DE|ipv4|192.0.2.0|256|20150101|allocated|f
ripencc|NL|ipv4|10.0.2.0|256|19990101|allocated|g
ripencc|GB|ipv4|8.8.8.0|256|20010920|assigned|h
ripencc|FR|ipv6|2001:db8::|48|20210101|allocated|i
ripencc|NL|ipv4|10.0.0.0|256|20210101|allocated|j
`
)

func goldens(t *testing.T) []struct{ name, got string } {
	t.Helper()
	run := func(mode string) (spec, log string) {
		table := map[netip.Prefix]rec{}
		var st stats
		var conflicts []conflict
		for _, f := range []struct{ name, body string }{{"arin", goldenARIN}, {"ripencc", goldenRIPE}} {
			if err := collect(strings.NewReader(f.body), f.name, table, mode, &st, &conflicts); err != nil {
				t.Fatal(err)
			}
		}
		var buf bytes.Buffer
		if err := emit(table, &buf, &st); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "conflicts.tsv")
		if err := writeConflictLog(path, conflicts); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return buf.String(), string(b)
	}
	dateSpec, dateLog := run(byDate)
	specSpec, specLog := run(bySpecific)
	return []struct{ name, got string }{
		{"spec/date", dateSpec},
		{"spec/specific", specSpec},
		{"conflict-log/date", dateLog},
		{"conflict-log/specific", specLog},
	}
}

// recorded holds the generator's output for fixed input, produced by
// TestPrintGoldens and pasted here deliberately — a golden the test computes
// from the code under test is not a golden, it is a tautology.
var recorded = map[string]string{
	"spec/date":             "8.8.8.0/24 GB\n10.0.0.0/23 US\n10.0.0.0/24 NL\n10.0.2.0/24 US\n192.0.2.0/24 DE\n2001:db8::/32 US\n2001:db8::/48 FR\n",
	"spec/specific":         "8.8.8.0/24 GB\n10.0.0.0/23 US\n10.0.0.0/24 NL\n10.0.2.0/24 NL\n192.0.2.0/24 CA\n2001:db8::/32 US\n2001:db8::/48 FR\n",
	"conflict-log/date":     "prefix\tcc_a\treg_a\tdate_a\tcc_b\treg_b\tdate_b\twinner\trule\tresolved\n192.0.2.0/24\tCA\tarin\t20100101\tDE\tripencc\t20150101\tDE\tdate\ttrue\n10.0.2.0/24\tUS\tarin\t20000101\tNL\tripencc\t19990101\tUS\tdate\ttrue\n8.8.8.0/24\tUS\tarin\t20010920\tGB\tripencc\t20010920\tGB\tdate\tfalse\n",
	"conflict-log/specific": "prefix\tcc_a\treg_a\tdate_a\tcc_b\treg_b\tdate_b\twinner\trule\tresolved\n192.0.2.0/24\tCA\tarin\t20100101\tDE\tripencc\t20150101\tCA\tspecific\tfalse\n10.0.2.0/24\tUS\tarin\t20000101\tNL\tripencc\t19990101\tNL\tspecific\ttrue\n8.8.8.0/24\tUS\tarin\t20010920\tGB\tripencc\t20010920\tGB\tspecific\tfalse\n",
}

// TestPrintGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recorded.
//
//	go test -run TestPrintGoldens -v ./cmd/rir-country/
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
				"rir-country SPEC OUTPUT CHANGED. This is a format break. The spec carries no version "+
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

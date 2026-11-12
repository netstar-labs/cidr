package cidr

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// The spec text and the refs envelope are written by generators (cmd/*, and
// feeds such as refs.netstar.dev) and read by services built against whatever
// version of this module they pinned, so a generator and a reader at different
// versions is the normal state. These goldens pin what the READER makes of fixed
// input: the line grammar, the refs envelope, the Info JSON shape, and the
// value-resolution rules (longest prefix wins; an exact duplicate keeps the last).

// renderEntries prints parsed entries one per line as prefix|asn|org, quoting the
// org so that whitespace changes are visible.
func renderEntries(es []SpecEntry) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%s|%d|%q\n", e.Prefix, e.ASN, e.Org)
	}
	return b.String()
}

// specGoldens renders each case. An error renders as just "error": its text comes
// from encoding/json or bufio and may change with the Go release, which is not a
// format change; that the input is rejected rather than accepted is.
func specGoldens() []struct{ name, got string } {
	spec := func(s string) string {
		es, err := ParseSpec(strings.NewReader(s))
		if err != nil {
			return "error"
		}
		return renderEntries(es)
	}
	refs := func(s string) string {
		rf, err := ParseRefs(strings.NewReader(s))
		if err != nil {
			return "error"
		}
		return fmt.Sprintf("name=%q version=%d\n", rf.Name, rf.Version) + renderEntries(rf.Entries())
	}
	info := func(i Info) string {
		b, err := json.Marshal(i)
		if err != nil {
			return "error"
		}
		return string(b)
	}
	// fields shows how LoadFunc tokenises a line before the caller's parse sees it.
	fields := func(s string) string {
		var b strings.Builder
		_, err := LoadFunc(strings.NewReader(s), func(f []string) (netip.Prefix, int, bool) {
			fmt.Fprintf(&b, "%q\n", f)
			return netip.Prefix{}, 0, false
		})
		if err != nil {
			return "error"
		}
		return b.String()
	}
	// lookup builds the LoadASN table and resolves fixed addresses through it.
	lookup := func(s string, addrs ...string) string {
		_, tab, err := LoadASN(strings.NewReader(s))
		if err != nil {
			return "error"
		}
		var b strings.Builder
		for _, a := range addrs {
			v, ok := tab.Lookup(netip.MustParseAddr(a))
			fmt.Fprintf(&b, "%s ok=%v %s|%d|%q\n", a, ok, v.Prefix, v.ASN, v.Org)
		}
		return b.String()
	}
	return []struct{ name, got string }{
		// --- the spec line grammar: "<cidr> [ASN] [org...]" ---
		{"Spec/bare-cidr", spec("10.0.0.0/8\n")},
		{"Spec/asn-org", spec("1.1.1.0/24 13335 Cloudflare, Inc.\n")},
		{"Spec/AS-prefix", spec("8.8.8.0/24 AS15169 Google LLC\n8.8.4.0/24 as15169 Google LLC\n")},
		{"Spec/asn-max-and-overflow", spec("10.0.0.0/8 4294967295 max\n11.0.0.0/8 4294967296 over\n")},
		{"Spec/country", spec("1.0.0.0/24 AU\n1.0.1.0/24 AS\n")},
		{"Spec/host-routes", spec("203.0.113.7 64500 Example Org\n::1\n")},
		{"Spec/host-bits-masked", spec("10.1.2.3/8 1 x\n2001:db8::1/32 2 y\n")},
		{"Spec/ipv4-mapped", spec("::ffff:10.0.0.0/104 1 mapped\n::ffff:0.0.0.0/96 3 boundary\n::ffff:0:0/95 2 short\n")},
		{"Spec/comments", spec("# whole line\n\n   # indented\n10.0.0.0/8 64500 Example # note\n")},
		{"Spec/whitespace", spec("  10.0.0.0/8\t64500   Multi   Space\tOrg  \r\n")},
		{"Spec/junk-skipped", spec("not-a-prefix 1 x\n10.0.0.0/33 2 y\n1.1.1.0/24,13335,Cloudflare\n10.0.0.0/8 3 ok\n")},
		{"Spec/provider-function-line", spec("3.0.0.0/15 cloud aws anycast\n")},
		{"Spec/iptoasn-country-variant", spec("1.0.0.0/24 13335 AU CLOUDFLARENET\n")},
		// --- the refs envelope ---
		{"Refs/envelope", refs(`{"name":"parked","version":20260705,"list":["1.2.3.0/24","8.8.8.0/24 AS15169 Google LLC","# c",""]}`)},
		{"Refs/unknown-field-ignored", refs(`{"name":"x","version":1,"list":["10.0.0.0/8"],"extra":{"a":1}}`)},
		{"Refs/version-as-string", refs(`{"name":"x","version":"20260705","list":["10.0.0.0/8"]}`)},
		// --- the Info JSON a service returns ---
		{"Info/full", info(Info{Prefix: "1.1.1.0/24", ASN: 13335, Org: "Cloudflare, Inc."})},
		{"Info/asn-zero", info(Info{Prefix: "10.0.0.0/8", Org: "RFC 1918"})},
		{"Info/prefix-only", info(Info{Prefix: "10.0.0.0/8"})},
		// --- how LoadFunc hands a line to the caller ---
		{"LoadFunc/fields", fields("# c\n\n 3.0.0.0/15  cloud\taws anycast \n10.0.0.0/8 x # y\n")},
		// --- value resolution: longest prefix wins, exact duplicate keeps the last ---
		{"LoadASN/resolution", lookup(
			"10.0.0.0/8 1 A\n10.1.0.0/16 2 B\n10.0.0.0/8 3 C\n2001:db8::/32 4 D\n2001:db8::/48 5 E\n",
			"10.1.2.3", "10.2.0.0", "11.0.0.0", "2001:db8::1", "2001:db8:1::1", "::ffff:10.1.0.1")},
	}
}

// recordedSpec holds the reader's output for fixed spec/refs input, produced by
// TestPrintSpecGoldens and pasted here deliberately — a golden the test computes
// from the code under test is not a golden, it is a tautology.
var recordedSpec = map[string]string{
	"Spec/bare-cidr":               "10.0.0.0/8|0|\"\"\n",
	"Spec/asn-org":                 "1.1.1.0/24|13335|\"Cloudflare, Inc.\"\n",
	"Spec/AS-prefix":               "8.8.8.0/24|15169|\"Google LLC\"\n8.8.4.0/24|15169|\"Google LLC\"\n",
	"Spec/asn-max-and-overflow":    "10.0.0.0/8|4294967295|\"max\"\n11.0.0.0/8|0|\"4294967296 over\"\n",
	"Spec/country":                 "1.0.0.0/24|0|\"AU\"\n1.0.1.0/24|0|\"AS\"\n",
	"Spec/host-routes":             "203.0.113.7/32|64500|\"Example Org\"\n::1/128|0|\"\"\n",
	"Spec/host-bits-masked":        "10.0.0.0/8|1|\"x\"\n2001:db8::/32|2|\"y\"\n",
	"Spec/ipv4-mapped":             "10.0.0.0/8|1|\"mapped\"\n0.0.0.0/0|3|\"boundary\"\n::fffe:0:0/95|2|\"short\"\n",
	"Spec/comments":                "10.0.0.0/8|64500|\"Example # note\"\n",
	"Spec/whitespace":              "10.0.0.0/8|64500|\"Multi Space Org\"\n",
	"Spec/junk-skipped":            "10.0.0.0/8|3|\"ok\"\n",
	"Spec/provider-function-line":  "3.0.0.0/15|0|\"cloud aws anycast\"\n",
	"Spec/iptoasn-country-variant": "1.0.0.0/24|13335|\"AU CLOUDFLARENET\"\n",
	"Refs/envelope":                "name=\"parked\" version=20260705\n1.2.3.0/24|0|\"\"\n8.8.8.0/24|15169|\"Google LLC\"\n",
	"Refs/unknown-field-ignored":   "name=\"x\" version=1\n10.0.0.0/8|0|\"\"\n",
	"Refs/version-as-string":       "error",
	"Info/full":                    "{\"prefix\":\"1.1.1.0/24\",\"asn\":13335,\"org\":\"Cloudflare, Inc.\"}",
	"Info/asn-zero":                "{\"prefix\":\"10.0.0.0/8\",\"org\":\"RFC 1918\"}",
	"Info/prefix-only":             "{\"prefix\":\"10.0.0.0/8\"}",
	"LoadFunc/fields":              "[\"3.0.0.0/15\" \"cloud\" \"aws\" \"anycast\"]\n[\"10.0.0.0/8\" \"x\" \"#\" \"y\"]\n",
	"LoadASN/resolution":           "10.1.2.3 ok=true 10.1.0.0/16|2|\"B\"\n10.2.0.0 ok=true 10.0.0.0/8|3|\"C\"\n11.0.0.0 ok=false |0|\"\"\n2001:db8::1 ok=true 2001:db8::/48|5|\"E\"\n2001:db8:1::1 ok=true 2001:db8::/32|4|\"D\"\n::ffff:10.1.0.1 ok=true 10.1.0.0/16|2|\"B\"\n",
}

// TestPrintSpecGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recordedSpec.
//
//	go test -run TestPrintSpecGoldens -v .
func TestPrintSpecGoldens(t *testing.T) {
	for _, g := range specGoldens() {
		t.Logf("\t%q: %q,", g.name, g.got)
	}
}

// TestSpecFormatGolden pins how ParseSpec, ParseRefs/Entries, LoadFunc, LoadASN
// and Info's JSON read and render fixed input.
func TestSpecFormatGolden(t *testing.T) {
	gs := specGoldens()
	if len(gs) != len(recordedSpec) {
		t.Fatalf("%d golden cases but %d recorded: a case was added or removed without recording it", len(gs), len(recordedSpec))
	}
	for _, g := range gs {
		want, ok := recordedSpec[g.name]
		if !ok {
			t.Errorf("%s: no recorded golden", g.name)
			continue
		}
		if g.got != want {
			t.Errorf("%s:\n got  %q\n want %q\n\n"+
				"SPEC / REFS / Info READING CHANGED. This is a format break. Spec text and refs "+
				"envelopes carry no format version, and the generators that write them and the "+
				"services that read them upgrade independently: a file written for the old grammar is "+
				"read under the new one as a different ASN, org, prefix or winning value — silently, "+
				"because a line that does not fit is skipped or folded into the org rather than "+
				"rejected. If the grammar must change, add a NEW, explicitly marked format (a '#' "+
				"header line is ignored by every existing reader) and keep this one reading as it does. "+
				"Do not re-record this golden to make the test pass.",
				g.name, g.got, want)
		}
	}
}

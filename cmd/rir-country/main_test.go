package main

import (
	"bytes"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

// convertString runs one delegated file through collect+emit, as run() does.
func convertString(t *testing.T, body, name, mode string) (string, stats, []conflict) {
	t.Helper()
	table := map[netip.Prefix]rec{}
	var st stats
	var conflicts []conflict
	if err := collect(strings.NewReader(body), name, table, mode, &st, &conflicts); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := emit(table, &buf, &st); err != nil {
		t.Fatal(err)
	}
	return buf.String(), st, conflicts
}

// TestConvertBasic covers the shapes that actually appear in a delegated file:
// the version header, a summary row, an asn row, reserved/available blocks, and
// real ipv4/ipv6 allocations.
func TestConvertBasic(t *testing.T) {
	const body = `2.3|arin|1789563621568|202683|19700101|20260916|-0400
arin|*|ipv4|*|80783|summary
arin|US|asn|1|1|20010920|assigned|e5e3b9c1
arin|US|ipv4|8.8.8.0|256|20010920|allocated|abc
arin|FR|ipv4|192.0.2.0|128|20200101|assigned|def
arin||ipv4|203.0.113.0|256|20200101|reserved|ghi
arin|GB|ipv6|2001:db8::|32|20200101|allocated|jkl
arin|ZZ|ipv4|198.51.100.0|256|20200101|available|mno
`
	got, st, conflicts := convertString(t, body, "arin", byDate)
	want := "8.8.8.0/24 US\n192.0.2.0/25 FR\n2001:db8::/32 GB\n"
	if got != want {
		t.Errorf("output:\n%q\nwant:\n%q", got, want)
	}
	if st.rows != 3 {
		t.Errorf("rows = %d, want 3", st.rows)
	}
	if st.prefixes != 3 {
		t.Errorf("prefixes = %d, want 3", st.prefixes)
	}
	if st.malformed != 0 {
		t.Errorf("malformed = %d, want 0", st.malformed)
	}
	if len(conflicts) != 0 {
		t.Errorf("conflicts = %v, want none", conflicts)
	}
}

// TestNonPowerOfTwoCount is the case that makes RangePrefixes mandatory: 763
// published ipv4 records carry a count that is not a power of two, so one
// record becomes several prefixes. 164.146.0.0 + 393216 is a real afrinic row.
func TestNonPowerOfTwoCount(t *testing.T) {
	const body = "afrinic|ZA|ipv4|164.146.0.0|393216|19930312|allocated|F363E51A\n"
	got, st, _ := convertString(t, body, "afrinic", byDate)
	// 393216 = 6 x 65536, so the range is 164.146.0.0 - 164.151.255.255.
	// 164.146.0.0 is /15-aligned but NOT /14-aligned (146 is not a multiple of
	// 4), so the minimal cover is a /15 followed by a /14, not the reverse.
	want := "164.146.0.0/15 ZA\n164.148.0.0/14 ZA\n"
	if got != want {
		t.Errorf("output:\n%q\nwant:\n%q", got, want)
	}
	if st.rows != 1 || st.prefixes != 2 {
		t.Errorf("stats = %+v, want 1 row / 2 prefixes", st)
	}
	// The whole published range must be covered, and nothing past it.
	set, err := cidr.LoadSet(strings.NewReader(got))
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"164.146.0.0", "164.151.255.255"} {
		if !set.Contains(netip.MustParseAddr(in)) {
			t.Errorf("%s should be covered", in)
		}
	}
	if set.Contains(netip.MustParseAddr("164.152.0.0")) {
		t.Error("164.152.0.0 is past the range and should not be covered")
	}
}

// TestConflictByDate uses the real 204.28.220.0/23 disagreement: arin says US
// (19940608), ripencc says SA (19940806). The later date wins.
func TestConflictByDate(t *testing.T) {
	const arin = "arin|US|ipv4|204.28.220.0|512|19940608|assigned|a\n"
	const ripe = "ripencc|SA|ipv4|204.28.220.0|512|19940806|assigned|b\n"

	table := map[netip.Prefix]rec{}
	var st stats
	var conflicts []conflict
	for _, src := range []struct{ body, name string }{{arin, "arin"}, {ripe, "ripencc"}} {
		if err := collect(strings.NewReader(src.body), src.name, table, byDate, &st, &conflicts); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := emit(table, &buf, &st); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "204.28.220.0/23 SA\n" {
		t.Errorf("output = %q, want the later-dated SA", got)
	}
	if st.conflicts != 1 {
		t.Errorf("conflicts = %d, want 1", st.conflicts)
	}
	if st.unresolved != 0 {
		t.Errorf("unresolved = %d, want 0 — the dates differ", st.unresolved)
	}
	if len(conflicts) != 1 || !conflicts[0].resolved {
		t.Fatalf("conflict not recorded as resolved: %+v", conflicts)
	}
}

// TestConflictOrderIndependent is the real 9.247.0.0/16 disagreement: arin says
// US, ripencc says AE, and the dates are IDENTICAL, so neither rule separates
// them. The result must still not depend on which file was read first.
func TestConflictOrderIndependent(t *testing.T) {
	const arin = "arin|US|ipv4|9.247.0.0|65536|19881216|assigned|a\n"
	const ripe = "ripencc|AE|ipv4|9.247.0.0|65536|19881216|assigned|b\n"

	for _, mode := range []string{byDate, bySpecific} {
		var outputs []string
		for _, order := range [][]struct{ body, name string }{
			{{arin, "arin"}, {ripe, "ripencc"}},
			{{ripe, "ripencc"}, {arin, "arin"}},
		} {
			table := map[netip.Prefix]rec{}
			var st stats
			var conflicts []conflict
			for _, src := range order {
				if err := collect(strings.NewReader(src.body), src.name, table, mode, &st, &conflicts); err != nil {
					t.Fatal(err)
				}
			}
			var buf bytes.Buffer
			if err := emit(table, &buf, &st); err != nil {
				t.Fatal(err)
			}
			outputs = append(outputs, buf.String())
			if st.unresolved != 1 {
				t.Errorf("%s: unresolved = %d, want 1 — nothing separates these", mode, st.unresolved)
			}
		}
		if outputs[0] != outputs[1] {
			t.Errorf("%s: output depends on read order: %q vs %q", mode, outputs[0], outputs[1])
		}
		if outputs[0] != "9.247.0.0/16 AE\n" {
			t.Errorf("%s: output = %q, want the lower country code AE", mode, outputs[0])
		}
	}
}

// TestConflictBySpecific proves the two rules genuinely differ: the narrower
// source allocation wins under -conflict specific even though it is older.
func TestConflictBySpecific(t *testing.T) {
	// Both records must emit the SAME prefix, or there is no conflict to
	// resolve — differing prefix lengths are left to the loader's LPM.
	//
	//	broad  10.1.1.0 + 768 -> 10.1.1.0/24 + 10.1.2.0/23, source cover /22
	//	narrow 10.1.1.0 + 256 -> 10.1.1.0/24,               source cover /24
	//
	// They collide on 10.1.1.0/24, and the two rules disagree there: broad has
	// the later date, narrow has the more specific source.
	const broad = "arin|US|ipv4|10.1.1.0|768|20200101|allocated|a\n"
	const narrow = "ripencc|DE|ipv4|10.1.1.0|256|19990101|allocated|b\n"

	run := func(mode string) (string, stats) {
		table := map[netip.Prefix]rec{}
		var st stats
		var conflicts []conflict
		for _, src := range []struct{ body, name string }{{broad, "arin"}, {narrow, "ripencc"}} {
			if err := collect(strings.NewReader(src.body), src.name, table, mode, &st, &conflicts); err != nil {
				t.Fatal(err)
			}
		}
		var buf bytes.Buffer
		if err := emit(table, &buf, &st); err != nil {
			t.Fatal(err)
		}
		return buf.String(), st
	}

	gotDate, stDate := run(byDate)
	if !strings.Contains(gotDate, "10.1.1.0/24 US") {
		t.Errorf("date mode: got %q, want the later-dated US for 10.1.1.0/24", gotDate)
	}
	if stDate.conflicts != 1 || stDate.unresolved != 0 {
		t.Errorf("date mode: stats = %+v, want 1 conflict / 0 unresolved", stDate)
	}

	gotSpec, stSpec := run(bySpecific)
	if !strings.Contains(gotSpec, "10.1.1.0/24 DE") {
		t.Errorf("specific mode: got %q, want the narrower-source DE for 10.1.1.0/24", gotSpec)
	}
	if stSpec.conflicts != 1 || stSpec.unresolved != 0 {
		t.Errorf("specific mode: stats = %+v, want 1 conflict / 0 unresolved", stSpec)
	}
	if gotDate == gotSpec {
		t.Error("the two rules produced identical output; this fixture is meant to separate them")
	}
	// The part of the broad record nobody disputes keeps its country in both modes.
	for _, got := range []string{gotDate, gotSpec} {
		if !strings.Contains(got, "10.1.2.0/23 US") {
			t.Errorf("undisputed remainder missing from %q", got)
		}
	}
}

// TestDeterministicOutput pins the sort: two runs over the same records must be
// byte-identical regardless of map iteration order, or the generated artifact
// cannot be diffed or checksummed between runs.
func TestDeterministicOutput(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 200; i++ {
		body.WriteString("arin|US|ipv4|10." + strconv.Itoa(i) + ".0.0|256|20200101|allocated|x\n")
	}
	body.WriteString("arin|GB|ipv6|2001:db8::|32|20200101|allocated|y\n")
	first, _, _ := convertString(t, body.String(), "arin", byDate)
	for i := 0; i < 5; i++ {
		again, _, _ := convertString(t, body.String(), "arin", byDate)
		if again != first {
			t.Fatal("output is not deterministic across runs")
		}
	}
	// v4 sorts before v6, and v4 sorts numerically rather than lexically.
	lines := strings.Split(strings.TrimSpace(first), "\n")
	if !strings.HasPrefix(lines[0], "10.0.0.0/24") {
		t.Errorf("first line = %q, want 10.0.0.0/24", lines[0])
	}
	if !strings.HasPrefix(lines[1], "10.1.0.0/24") {
		t.Errorf("second line = %q, want 10.1.0.0/24 (numeric, not lexical, order)", lines[1])
	}
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "2001:db8::/32") {
		t.Errorf("last line = %q, want the v6 prefix", last)
	}
}

// TestMalformedVsSkipped keeps the two tallies honest: a deliberately ignored
// line is not a parse failure, and a parse failure is not silently ignored.
func TestMalformedVsSkipped(t *testing.T) {
	const body = `arin|US|ipv4|not-an-ip|256|20200101|allocated|a
arin|US|ipv4|10.0.0.0|notanumber|20200101|allocated|b
arin|US|ipv4|10.0.0.0|0|20200101|allocated|c
arin|US|ipv6|2001:db8::|129|20200101|allocated|d
arin|US|ipv4|255.255.255.0|512|20200101|allocated|e
arin|US|asn|1|1|20200101|assigned|f
short|line
`
	got, st, _ := convertString(t, body, "arin", byDate)
	if got != "" {
		t.Errorf("output = %q, want nothing usable", got)
	}
	if st.malformed != 5 {
		t.Errorf("malformed = %d, want 5 (bad ip, bad count, zero count, /129, v4 overflow)", st.malformed)
	}
	if st.skipped != 2 {
		t.Errorf("skipped = %d, want 2 (asn row, short line)", st.skipped)
	}
	if st.rows != 0 {
		t.Errorf("rows = %d, want 0", st.rows)
	}
}

// TestRoundTripLoadFunc confirms the output is what LoadFunc actually consumes.
func TestRoundTripLoadFunc(t *testing.T) {
	const body = "arin|US|ipv4|8.8.8.0|256|20200101|allocated|a\n" +
		"ripencc|DE|ipv6|2a00::|12|20200101|allocated|b\n"
	got, _, _ := convertString(t, body, "arin", byDate)

	table, err := cidr.LoadFunc(strings.NewReader(got), func(f []string) (netip.Prefix, string, bool) {
		if len(f) < 2 {
			return netip.Prefix{}, "", false
		}
		p, err := cidr.ParsePrefix(f[0])
		if err != nil {
			return netip.Prefix{}, "", false
		}
		return p, f[1], true
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ addr, want string }{
		{"8.8.8.8", "US"},
		{"2a00::1", "DE"},
	} {
		v, ok := table.Lookup(netip.MustParseAddr(tc.addr))
		if !ok || v != tc.want {
			t.Errorf("Lookup(%s) = %q,%v; want %q", tc.addr, v, ok, tc.want)
		}
	}
	if _, ok := table.Lookup(netip.MustParseAddr("9.9.9.9")); ok {
		t.Error("9.9.9.9 is not in the spec and should miss")
	}
}

// TestCeilLog2 pins the source-specificity arithmetic the specific rule rests on.
func TestCeilLog2(t *testing.T) {
	for _, tc := range []struct {
		n    uint64
		want int
	}{
		{1, 0}, {2, 1}, {3, 2}, {4, 2}, {5, 3}, {256, 8}, {257, 9},
		{65536, 16}, {393216, 19}, // the real afrinic non-power-of-two row
	} {
		if got := ceilLog2(tc.n); got != tc.want {
			t.Errorf("ceilLog2(%d) = %d, want %d", tc.n, got, tc.want)
		}
	}
}

// TestReportConflictsAnnouncesCap proves the stderr cap states what it withheld
// rather than reading as completeness.
func TestReportConflictsAnnouncesCap(t *testing.T) {
	var many []conflict
	for i := 0; i < stderrConflicts+7; i++ {
		many = append(many, conflict{
			prefix: netip.MustParsePrefix("10.0.0.0/24"),
			a:      rec{cc: "US"}, b: rec{cc: "DE"}, winner: "DE", mode: byDate, resolved: true,
		})
	}
	var buf bytes.Buffer
	reportConflicts(&buf, many, "")
	if !strings.Contains(buf.String(), "7 more conflict(s) not shown") {
		t.Errorf("cap not announced in:\n%s", buf.String())
	}
}

// FuzzParseLine hammers the record parser, which sits on a trust boundary: it
// reads bytes fetched over the network. It must never panic, and a line it
// accepts must produce a valid, non-reversed, same-family range — otherwise
// RangePrefixes would silently return nothing and the record would vanish.
func FuzzParseLine(f *testing.F) {
	for _, seed := range []string{
		"arin|US|ipv4|8.8.8.0|256|20010920|allocated|abc",
		"afrinic|ZA|ipv4|164.146.0.0|393216|19930312|allocated|F363E51A",
		"arin|GB|ipv6|2001:db8::|32|20200101|allocated|jkl",
		"2.3|arin|1789563621568|202683|19700101|20260916|-0400",
		"arin|*|ipv4|*|80783|summary",
		"arin|US|ipv4|255.255.255.255|4294967295|20200101|allocated|x",
		"arin|US|ipv6|2001:db8::|129|20200101|allocated|x",
		"|||||||",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		lo, hi, e, ok, malformed := parseLine(line, "fuzz")
		if !ok {
			return
		}
		if malformed {
			t.Fatalf("parseLine returned ok and malformed together: %q", line)
		}
		if !lo.IsValid() || !hi.IsValid() {
			t.Fatalf("accepted %q with an invalid bound", line)
		}
		if lo.Is4() != hi.Is4() {
			t.Fatalf("accepted %q with mixed families", line)
		}
		if hi.Less(lo) {
			t.Fatalf("accepted %q with hi < lo", line)
		}
		if len(e.cc) != 2 {
			t.Fatalf("accepted %q with country %q", line, e.cc)
		}
		if e.srcBits < 0 || (lo.Is4() && e.srcBits > 32) || (!lo.Is4() && e.srcBits > 128) {
			t.Fatalf("accepted %q with srcBits %d", line, e.srcBits)
		}
		// An accepted record must decompose; otherwise it would be dropped.
		if len(cidr.RangePrefixes(lo, hi)) == 0 {
			t.Fatalf("accepted %q but it decomposes to nothing", line)
		}
	})
}

// TestUnalignedV6IsMalformed pins C1 from the audit: an ipv6 record whose start
// is not aligned to its prefix length must be rejected, not silently masked
// into a block the registry never published.
func TestUnalignedV6IsMalformed(t *testing.T) {
	const body = "ripencc|DE|ipv6|2001:db8::1|32|20200101|allocated|a\n" +
		"ripencc|DE|ipv6|2001:db8::|32|20200101|allocated|b\n"
	got, st, _ := convertString(t, body, "ripencc", byDate)
	if got != "2001:db8::/32 DE\n" {
		t.Errorf("output = %q, want only the aligned record", got)
	}
	if st.malformed != 1 {
		t.Errorf("malformed = %d, want 1 (the unaligned record)", st.malformed)
	}
	if st.rows != 1 {
		t.Errorf("rows = %d, want 1", st.rows)
	}
}

// TestThreeWayConflictOrderIndependent pins C3: with three registries claiming
// one prefix, resolution is applied pairwise as records arrive, so the rules
// must be commutative. Every permutation must land on the same country.
func TestThreeWayConflictOrderIndependent(t *testing.T) {
	type src struct{ body, name string }
	a := src{"arin|US|ipv4|10.9.0.0|256|20200101|allocated|a\n", "arin"}
	b := src{"ripencc|AE|ipv4|10.9.0.0|256|20200101|allocated|b\n", "ripencc"} // ties a on date
	c := src{"apnic|JP|ipv4|10.9.0.0|256|19990101|allocated|c\n", "apnic"}     // older

	perms := [][]src{
		{a, b, c}, {a, c, b}, {b, a, c}, {b, c, a}, {c, a, b}, {c, b, a},
	}
	for _, mode := range []string{byDate, bySpecific} {
		var seen []string
		for _, perm := range perms {
			table := map[netip.Prefix]rec{}
			var st stats
			var conflicts []conflict
			for _, s := range perm {
				if err := collect(strings.NewReader(s.body), s.name, table, mode, &st, &conflicts); err != nil {
					t.Fatal(err)
				}
			}
			var buf bytes.Buffer
			if err := emit(table, &buf, &st); err != nil {
				t.Fatal(err)
			}
			seen = append(seen, buf.String())
		}
		for i, got := range seen {
			if got != seen[0] {
				t.Fatalf("%s: permutation %d gave %q, permutation 0 gave %q", mode, i, got, seen[0])
			}
		}
	}
}

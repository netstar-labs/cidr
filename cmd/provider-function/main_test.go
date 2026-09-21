package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

// src is one provider's published file, as the test supplies it.
type src struct{ provider, body string }

// convert runs sources through parse+merge+emit exactly as run() does, minus
// the fetching and the file handling.
func convert(t *testing.T, sources ...src) (string, stats, []conflict) {
	t.Helper()
	table := map[netip.Prefix]entry{}
	st := stats{perSource: map[string]int{}}
	var conflicts []conflict

	for _, s := range sources {
		p, ok := providers[s.provider]
		if !ok {
			t.Fatalf("unknown provider %q", s.provider)
		}
		err := p.parse(strings.NewReader(s.body), func(pfx netip.Prefix, e entry) {
			e.provider = s.provider
			st.perSource[s.provider]++
			merge(table, pfx, e, &st, &conflicts)
		})
		if err != nil {
			t.Fatalf("%s: %v", s.provider, err)
		}
	}

	var b strings.Builder
	if err := emit(table, &b, &st); err != nil {
		t.Fatal(err)
	}
	return b.String(), st, conflicts
}

// specParser reads the emitted spec back — the "<cidr> <function> <provider>
// [anycast]" contract the package doc promises LoadFunc consumers.
func specParser(f []string) (netip.Prefix, entry, bool) {
	if len(f) < 3 {
		return netip.Prefix{}, entry{}, false
	}
	p, err := cidr.ParsePrefix(f[0])
	if err != nil {
		return netip.Prefix{}, entry{}, false
	}
	return p, entry{function: f[1], provider: f[2], anycast: len(f) > 3 && f[3] == "anycast"}, true
}

// awsDoc wraps prefix records in the real ip-ranges.json envelope.
func awsDoc(v4, v6 string) string {
	return `{"syncToken":"1","createDate":"2026-09-21","prefixes":[` + v4 +
		`],"ipv6_prefixes":[` + v6 + `]}`
}

func aws4(prefix, service string) string {
	return `{"ip_prefix":"` + prefix + `","region":"us-east-1","service":"` + service +
		`","network_border_group":"us-east-1"}`
}

// TestSpecificServiceBeatsCatchAll is the load-bearing case. AWS lists a prefix
// once per service it belongs to and "AMAZON" is a catch-all superset of the
// specific ones: as published on 2026-09-21, 2,298 of 7,795 distinct IPv4
// prefixes carried more than one label. 23.228.249.0/24 is a real CLOUDFRONT
// range that is also listed as AMAZON. Without precedence the answer would
// depend on map/JSON order, so both orders are asserted here — a CDN edge
// silently downgraded to generic cloud is exactly the misclassification this
// table exists to avoid.
func TestSpecificServiceBeatsCatchAll(t *testing.T) {
	for _, tc := range []struct{ name, doc string }{
		{"specific first", awsDoc(aws4("23.228.249.0/24", "CLOUDFRONT")+","+
			aws4("23.228.249.0/24", "AMAZON"), "")},
		{"catch-all first", awsDoc(aws4("23.228.249.0/24", "AMAZON")+","+
			aws4("23.228.249.0/24", "CLOUDFRONT"), "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, st, conflicts := convert(t, src{"aws", tc.doc})
			if want := "23.228.249.0/24 cdn aws\n"; got != want {
				t.Errorf("got %q, want %q", got, want)
			}
			if st.conflicts != 0 || len(conflicts) != 0 {
				t.Errorf("specificity separated these; want 0 conflicts, got %d", st.conflicts)
			}
		})
	}
}

// TestCatchAllDoesNotEraseTheAnycastMarker pins the other half of precedence:
// Global Accelerator is the one AWS service whose own documentation says
// "static anycast IP addresses", and every one of its ranges is also published
// under AMAZON. If the catch-all won, the marker would vanish from all 176 of
// them.
func TestCatchAllDoesNotEraseTheAnycastMarker(t *testing.T) {
	doc := awsDoc(aws4("15.230.0.0/24", "AMAZON")+","+
		aws4("15.230.0.0/24", "GLOBALACCELERATOR"), "")
	got, _, _ := convert(t, src{"aws", doc})
	if want := "15.230.0.0/24 cloud aws anycast\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestRepeatedPlainServicesAreNotConflicts keeps the tally honest: EC2, S3 and
// AMAZON on one prefix all mean "cloud", so the table must record agreement,
// not three-way disagreement. 195 real prefixes carry exactly that triple.
func TestRepeatedPlainServicesAreNotConflicts(t *testing.T) {
	doc := awsDoc(aws4("3.5.140.0/22", "EC2")+","+aws4("3.5.140.0/22", "AMAZON")+","+
		aws4("3.5.140.0/22", "S3"), "")
	got, st, _ := convert(t, src{"aws", doc})
	if want := "3.5.140.0/22 cloud aws\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if st.conflicts != 0 {
		t.Errorf("same answer three times is agreement; got %d conflicts", st.conflicts)
	}
}

// TestEveryProviderShape parses each of the five published formats as they
// actually returned on 2026-09-21 — three JSON envelopes plus two plain-text
// lists — and pins which of them carry the anycast marker.
func TestEveryProviderShape(t *testing.T) {
	got, st, _ := convert(t,
		src{"aws", awsDoc(aws4("3.5.140.0/22", "EC2"), `{"ipv6_prefix":"2600:1f00::/40","region":"us-east-1","service":"AMAZON"}`)},
		src{"cloudflare", "# comment\n\n104.16.0.0/13\n2400:cb00::/32\n"},
		src{"fastly", `{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}`},
		src{"google-cloud", `{"prefixes":[{"ipv4Prefix":"34.35.0.0/16","service":"Google Cloud","scope":"x"},{"ipv6Prefix":"2600:1900::/28","service":"Google Cloud","scope":"x"}]}`},
		src{"tor", "171.25.193.25\n80.67.167.81\n"},
	)
	want := strings.Join([]string{
		"3.5.140.0/22 cloud aws",
		"34.35.0.0/16 cloud google-cloud",
		"80.67.167.81/32 tor-exit tor",
		"104.16.0.0/13 cdn cloudflare anycast",
		"151.101.0.0/16 cdn fastly anycast",
		"171.25.193.25/32 tor-exit tor",
		"2400:cb00::/32 cdn cloudflare anycast",
		"2600:1900::/28 cloud google-cloud",
		"2600:1f00::/40 cloud aws",
		"2a04:4e40::/32 cdn fastly anycast",
		"",
	}, "\n")
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if st.prefixes != 10 {
		t.Errorf("prefixes = %d, want 10", st.prefixes)
	}
}

// TestTorBareAddressesBecomeHostRoutes pins the one shape difference between
// the Tor list and every other source: it publishes bare addresses, not
// prefixes. They must land as /32 host routes — not be skipped as unparseable,
// which would empty the label without failing anything.
func TestTorBareAddressesBecomeHostRoutes(t *testing.T) {
	got, st, _ := convert(t, src{"tor", "171.25.193.25\n\n198.98.51.189\n"})
	want := "171.25.193.25/32 tor-exit tor\n198.98.51.189/32 tor-exit tor\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if st.prefixes != 2 {
		t.Errorf("prefixes = %d, want 2", st.prefixes)
	}
}

// TestTorExitInsideACloudRangeStaysDistinct pins what happens when a /32 exit
// relay falls inside a provider's /16: longest-prefix match must return the
// exit, not the surrounding cloud range, or the label is silently unreachable
// for exactly the addresses a filter cares about.
//
// Checked against the live data rather than assumed: **0 of 1,377** exits were
// nested inside a published cloud/CDN range on 2026-09-21 — the big cloud
// providers' terms effectively keep exits out of the space this table covers,
// so the overlap is not a fact about today. It is tested because it costs
// nothing to pin, the consequence of getting it wrong is silent, and the
// provider list is expected to grow toward the hosting networks where exits
// actually do live.
func TestTorExitInsideACloudRangeStaysDistinct(t *testing.T) {
	spec, st, conflicts := convert(t,
		src{"aws", awsDoc(aws4("3.5.0.0/16", "EC2"), "")},
		src{"tor", "3.5.140.9\n"},
	)
	if st.conflicts != 0 || len(conflicts) != 0 {
		t.Errorf("nested prefixes of different lengths are not a conflict; got %d", st.conflicts)
	}

	table, err := cidr.LoadFunc(strings.NewReader(spec), specParser)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("3.5.140.9")); got.function != funcTorExit {
		t.Errorf("the exit relay resolved to %q, want %q", got.function, funcTorExit)
	}
	if got, _ := table.Lookup(netip.MustParseAddr("3.5.140.10")); got.function != funcCloud {
		t.Errorf("its neighbour resolved to %q, want %q", got.function, funcCloud)
	}
}

// TestDeterministicOutput pins the sort: v4 before v6, then by address, then by
// prefix length. Map iteration order is not stable, and a generated artifact
// whose output churns between runs cannot be diffed or checksummed — which is
// how a real change would be noticed at all.
func TestDeterministicOutput(t *testing.T) {
	doc := awsDoc(aws4("10.0.0.0/8", "AMAZON")+","+aws4("1.2.3.0/24", "AMAZON")+","+
		aws4("10.0.0.0/16", "AMAZON"), `{"ipv6_prefix":"2001:db8::/32","service":"AMAZON"}`)
	first, _, _ := convert(t, src{"aws", doc})
	want := "1.2.3.0/24 cloud aws\n10.0.0.0/8 cloud aws\n10.0.0.0/16 cloud aws\n2001:db8::/32 cloud aws\n"
	if first != want {
		t.Errorf("got:\n%s\nwant:\n%s", first, want)
	}
	for i := 0; i < 8; i++ {
		if again, _, _ := convert(t, src{"aws", doc}); again != first {
			t.Fatalf("run %d differs:\n%s\nvs\n%s", i, again, first)
		}
	}
}

// TestCrossProviderConflictIsReportedNotSilent covers the case precedence
// cannot resolve: two operators publishing the same prefix with different
// functions. It does not happen today (the live run reconciles to 0 conflicts),
// which is exactly why it needs a test — the machinery would otherwise be
// unexercised until the day it matters. The winner must not depend on read
// order, and the conflict must be counted rather than quietly collapsed.
func TestCrossProviderConflictIsReportedNotSilent(t *testing.T) {
	awsSide := src{"aws", awsDoc(aws4("104.16.0.0/13", "AMAZON"), "")}
	cfSide := src{"cloudflare", "104.16.0.0/13\n"}

	a, stA, conflictsA := convert(t, awsSide, cfSide)
	b, stB, conflictsB := convert(t, cfSide, awsSide)

	if a != b {
		t.Errorf("winner depends on read order:\n%s\nvs\n%s", a, b)
	}
	if want := "104.16.0.0/13 cloud aws\n"; a != want {
		t.Errorf("got %q, want %q (aws sorts before cloudflare)", a, want)
	}
	if stA.conflicts != 1 || stB.conflicts != 1 {
		t.Errorf("conflicts = %d/%d, want 1 each", stA.conflicts, stB.conflicts)
	}
	if len(conflictsA) != 1 || len(conflictsB) != 1 {
		t.Fatalf("conflict records = %d/%d, want 1 each", len(conflictsA), len(conflictsB))
	}
	// The record must name both sides, or -conflict-log is useless for deciding
	// which feed to trust.
	c := conflictsA[0]
	if c.a.provider == c.b.provider {
		t.Errorf("conflict record collapsed both sides to %q", c.a.provider)
	}
}

// TestRoundTripLoadFunc confirms the emitted spec is what cidr.LoadFunc
// actually consumes — the format claim the package doc makes — and that
// longest-prefix lookup returns the classification, marker included.
func TestRoundTripLoadFunc(t *testing.T) {
	spec, _, _ := convert(t,
		src{"aws", awsDoc(aws4("3.5.140.0/22", "EC2")+","+aws4("23.228.249.0/24", "CLOUDFRONT"), "")},
		src{"cloudflare", "104.16.0.0/13\n"},
	)

	table, err := cidr.LoadFunc(strings.NewReader(spec), specParser)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		addr     string
		function string
		provider string
		anycast  bool
	}{
		{"3.5.140.9", funcCloud, "aws", false},
		{"23.228.249.7", funcCDN, "aws", false},
		{"104.16.0.1", funcCDN, "cloudflare", true},
	} {
		got, ok := table.Lookup(netip.MustParseAddr(tc.addr))
		if !ok {
			t.Errorf("%s: not found", tc.addr)
			continue
		}
		if got.function != tc.function || got.provider != tc.provider || got.anycast != tc.anycast {
			t.Errorf("%s: got %+v, want %s/%s anycast=%v", tc.addr, got, tc.function, tc.provider, tc.anycast)
		}
	}
	if _, ok := table.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("8.8.8.8 is in no published range; want no match")
	}
}

// TestInRequiresProviderEqualsPath keeps the -in error honest: with four
// formats behind four providers, a bare path cannot be parsed by guessing, and
// the message has to say what the caller should have written.
func TestInRequiresProviderEqualsPath(t *testing.T) {
	_, err := openSources("all", "/tmp/ip-ranges.json", 0)
	if err == nil {
		t.Fatal("bare path accepted; want an error naming the provider=path form")
	}
	if !strings.Contains(err.Error(), "provider=path") {
		t.Errorf("error %q does not say what to write instead", err)
	}

	if _, err := openSources("all", "azure=/tmp/x.json", 0); err == nil ||
		!strings.Contains(err.Error(), "azure") {
		t.Errorf("unknown provider: got %v, want an error naming azure", err)
	}
}

// TestReportConflictsAnnouncesCap proves the stderr cap states what it withheld
// rather than reading as completeness.
func TestReportConflictsAnnouncesCap(t *testing.T) {
	var conflicts []conflict
	for i := 0; i < stderrConflicts+3; i++ {
		conflicts = append(conflicts, conflict{
			prefix: netip.MustParsePrefix("10.0.0.0/8"),
			a:      entry{function: funcCloud, provider: "aws"},
			b:      entry{function: funcCDN, provider: "cloudflare"},
			winner: entry{function: funcCloud, provider: "aws"},
		})
	}
	var b strings.Builder
	reportConflicts(&b, conflicts, "")
	if !strings.Contains(b.String(), "and 3 more conflicts") {
		t.Errorf("cap did not state the remainder:\n%s", b.String())
	}
}

// TestMalformedPrefixesAreSkippedNotFatal pins the trust boundary: these files
// are fetched over the network, and one bad row must not abort a build that the
// other 12,000 rows would have completed.
func TestMalformedPrefixesAreSkippedNotFatal(t *testing.T) {
	got, _, _ := convert(t,
		src{"aws", awsDoc(aws4("not-an-address", "AMAZON")+","+aws4("3.5.140.0/22", "AMAZON"), "")},
		src{"cloudflare", "999.999.999.0/24\n104.16.0.0/13\n"},
	)
	want := "3.5.140.0/22 cloud aws\n104.16.0.0/13 cdn cloudflare anycast\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

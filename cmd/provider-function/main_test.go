package main

import (
	"net/netip"
	"os"
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
	st := stats{perSource: map[string]int{}, malformed: map[string]int{}}
	var conflicts []conflict

	for _, s := range sources {
		p, ok := providers[s.provider]
		if !ok {
			t.Fatalf("unknown provider %q", s.provider)
		}
		st.perSource[s.provider] += 0
		if err := p.parse(strings.NewReader(s.body), collect(s.provider, &st, table, &conflicts)); err != nil {
			t.Fatalf("%s: %v", s.provider, err)
		}
	}

	var b strings.Builder
	if err := emit(table, &b); err != nil {
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
			got, _, conflicts := convert(t, src{"aws", tc.doc})
			if want := "23.228.249.0/24 cdn aws\n"; got != want {
				t.Errorf("got %q, want %q", got, want)
			}
			if len(conflicts) != 0 {
				t.Errorf("specificity separated these; want 0 conflicts, got %d", len(conflicts))
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
	doc := awsDoc(aws4("13.248.100.0/24", "AMAZON")+","+
		aws4("13.248.100.0/24", "GLOBALACCELERATOR"), "")
	got, _, _ := convert(t, src{"aws", doc})
	if want := "13.248.100.0/24 cloud aws anycast\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestRepeatedPlainServicesAreNotConflicts keeps the tally honest: EC2, S3 and
// AMAZON on one prefix all mean "cloud", so the table must record agreement,
// not three-way disagreement. 195 real prefixes carry exactly that triple.
func TestRepeatedPlainServicesAreNotConflicts(t *testing.T) {
	doc := awsDoc(aws4("3.5.140.0/22", "EC2")+","+aws4("3.5.140.0/22", "AMAZON")+","+
		aws4("3.5.140.0/22", "S3"), "")
	got, _, conflicts := convert(t, src{"aws", doc})
	if want := "3.5.140.0/22 cloud aws\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if len(conflicts) != 0 {
		t.Errorf("same answer three times is agreement; got %d conflicts", len(conflicts))
	}
}

// TestEveryProviderShape parses each of the five published formats as they
// actually returned on 2026-09-21 — three JSON envelopes plus two plain-text
// lists — and pins which of them carry the anycast marker.
func TestEveryProviderShape(t *testing.T) {
	got, _, _ := convert(t,
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
	if n := strings.Count(got, "\n"); n != 10 {
		t.Errorf("prefixes = %d, want 10", n)
	}
}

// TestTorBareAddressesBecomeHostRoutes pins the one shape difference between
// the Tor list and every other source: it publishes bare addresses, not
// prefixes. They must land as /32 host routes — not be skipped as unparseable,
// which would empty the label without failing anything.
func TestTorBareAddressesBecomeHostRoutes(t *testing.T) {
	got, _, _ := convert(t, src{"tor", "171.25.193.25\n\n198.98.51.189\n"})
	want := "171.25.193.25/32 tor-exit tor\n198.98.51.189/32 tor-exit tor\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if n := strings.Count(got, "\n"); n != 2 {
		t.Errorf("prefixes = %d, want 2", n)
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
	spec, _, conflicts := convert(t,
		src{"aws", awsDoc(aws4("3.5.0.0/16", "EC2"), "")},
		src{"tor", "3.5.140.9\n"},
	)
	if len(conflicts) != 0 {
		t.Errorf("nested prefixes of different lengths are not a conflict; got %d", len(conflicts))
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

	a, _, conflictsA := convert(t, awsSide, cfSide)
	b, _, conflictsB := convert(t, cfSide, awsSide)

	if a != b {
		t.Errorf("winner depends on read order:\n%s\nvs\n%s", a, b)
	}
	if want := "104.16.0.0/13 cloud aws\n"; a != want {
		t.Errorf("got %q, want %q (aws sorts before cloudflare)", a, want)
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

// TestRankDoesNotCrossTheProviderBoundary is the regression test for the
// audit's most serious finding (C2/A1, 2026-09-21, reproduced in both read
// orders). `rank` is specificity WITHIN one operator's feed — AWS lists a prefix
// once per service, with AMAZON as a catch-all. Comparing it across providers
// let an AWS rank-1 row silently override another operator's published claim
// AND drop that operator's anycast marker, without ever reaching the conflict
// path — the exact outcome the package doc says the design exists to prevent.
//
// The original TestCrossProviderConflictIsReportedNotSilent passed over this
// hole because it used AMAZON, making both sides rank 0.
func TestRankDoesNotCrossTheProviderBoundary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service string
	}{
		{"cloudfront vs cloudflare", "CLOUDFRONT"},
		{"global accelerator vs cloudflare", "GLOBALACCELERATOR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			awsSide := src{"aws", awsDoc(aws4("104.16.0.0/13", tc.service), "")}
			cfSide := src{"cloudflare", "104.16.0.0/13\n"}

			a, _, conflictsA := convert(t, awsSide, cfSide)
			b, _, conflictsB := convert(t, cfSide, awsSide)

			if a != b {
				t.Errorf("winner depends on read order:\n%s\nvs\n%s", a, b)
			}
			if len(conflictsA) != 1 || len(conflictsB) != 1 {
				t.Fatalf("a rank-1 AWS row silently beat another operator: conflicts = %d/%d, want 1 each",
					len(conflictsA), len(conflictsB))
			}
			if c := conflictsA[0]; c.a.provider == c.b.provider {
				t.Errorf("conflict record collapsed both sides to %q", c.a.provider)
			}
		})
	}
}

// TestAgreementAcrossProvidersIsNotAConflict is the other half of the same fix
// (C6). Two operators publishing the same prefix with the same classification
// agree; recording "cdn vs cdn -> cdn" reads as a defect report and inflates the
// number an operator watches for feed drift. The winner must still be
// deterministic.
func TestAgreementAcrossProvidersIsNotAConflict(t *testing.T) {
	cf := src{"cloudflare", "104.16.0.0/13\n"}
	fastly := src{"fastly", `{"addresses":["104.16.0.0/13"],"ipv6_addresses":[]}`}

	a, _, conflictsA := convert(t, cf, fastly)
	b, _, conflictsB := convert(t, fastly, cf)

	if len(conflictsA) != 0 || len(conflictsB) != 0 {
		t.Errorf("identical classifications are agreement; got %d/%d conflicts",
			len(conflictsA), len(conflictsB))
	}
	if a != b {
		t.Errorf("winner depends on read order:\n%s\nvs\n%s", a, b)
	}
	if want := "104.16.0.0/13 cdn cloudflare anycast\n"; a != want {
		t.Errorf("got %q, want %q (cloudflare sorts before fastly)", a, want)
	}
}

// TestMalformedRowsAreCounted is the regression test for the audit's other
// reproduced defect (C1/B2): every parser dropped unusable rows with no counter,
// so a feed answering 200 with the wrong shape produced a short table and a
// clean exit.
func TestMalformedRowsAreCounted(t *testing.T) {
	_, st, _ := convert(t,
		src{"aws", awsDoc(aws4("not-an-address", "AMAZON")+","+aws4("3.5.140.0/22", "AMAZON"), "")},
		src{"cloudflare", "999.999.999.0/24\n104.16.0.0/13\n"},
	)
	if st.malformed["aws"] != 1 {
		t.Errorf("aws malformed = %d, want 1", st.malformed["aws"])
	}
	if st.malformed["cloudflare"] != 1 {
		t.Errorf("cloudflare malformed = %d, want 1", st.malformed["cloudflare"])
	}
	if st.perSource["aws"] != 1 || st.perSource["cloudflare"] != 1 {
		t.Errorf("good rows lost: aws=%d cloudflare=%d, want 1 each",
			st.perSource["aws"], st.perSource["cloudflare"])
	}
}

// TestAttemptedSourceProducingNothingIsAnError pins the guard that turns the
// worst reproduced failure into a loud one. Valid JSON with renamed fields (an
// HTTP 200 from a feed that changed shape) previously yielded exit 0 and a
// zero-byte file — which, under `build/provider-function --generator`, truncates
// the published spec on a "successful" timer run.
func TestAttemptedSourceProducingNothingIsAnError(t *testing.T) {
	st := stats{perSource: map[string]int{"aws": 0}, malformed: map[string]int{"aws": 3}}
	err := checkSourcesProduced([]source{{provider: "aws"}}, &st)
	if err == nil {
		t.Fatal("a source that produced nothing was accepted; want an error")
	}
	if !strings.Contains(err.Error(), "aws") {
		t.Errorf("error %q does not name the provider that failed", err)
	}

	st.perSource["aws"] = 1
	if err := checkSourcesProduced([]source{{provider: "aws"}}, &st); err != nil {
		t.Errorf("a source that produced rows was rejected: %v", err)
	}
}

// TestOversizedLineDoesNotAbortTheBuild pins the scanner buffer (C5). A single
// line longer than bufio.Scanner's 64KB default — a minified error page, or a
// feed served without newlines — previously aborted the whole run with
// "token too long", discarding every provider that had parsed correctly.
// rir-country/main.go:197 raises the same limit for the same reason.
func TestOversizedLineDoesNotAbortTheBuild(t *testing.T) {
	body := strings.Repeat("x", 70*1024) + "\n104.16.0.0/13\n"
	got, st, _ := convert(t, src{"cloudflare", body})
	if want := "104.16.0.0/13 cdn cloudflare anycast\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if st.malformed["cloudflare"] != 1 {
		t.Errorf("the oversized line should count as malformed; got %d",
			st.malformed["cloudflare"])
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

// FuzzParsers hammers all four parsers, which sit on a trust boundary: every
// byte they read arrives over the network from a third party. The house gate
// requires a re-fuzz of every parser on a trust boundary, and this command
// shipped four of them with none (audit D8 / CI gap, 2026-09-21).
//
// The contract asserted is deliberately narrow, because it is the contract that
// actually matters here: a parser must never panic, and anything it hands to
// the collector must either parse as a prefix or be counted as malformed —
// never silently vanish. Whether a given byte sequence is "valid" is the feed
// operator's business, not ours.
func FuzzParsers(f *testing.F) {
	f.Add("aws", `{"prefixes":[{"ip_prefix":"3.5.140.0/22","service":"EC2"}],"ipv6_prefixes":[]}`)
	f.Add("google-cloud", `{"prefixes":[{"ipv4Prefix":"34.35.0.0/16"},{"ipv6Prefix":"2600:1900::/28"}]}`)
	f.Add("fastly", `{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e40::/32"]}`)
	f.Add("cloudflare", "104.16.0.0/13\n2400:cb00::/32\n# comment\n\n")
	f.Add("tor", "171.25.193.25\n198.98.51.189\n")
	f.Add("aws", `{"prefixes":[{"ip_prefix":"","service":""}],"ipv6_prefixes":[{}]}`)
	f.Add("cloudflare", "\x00\xff\n/\n0.0.0.0/0\n::/0\n999.999.999.999\n")
	f.Add("tor", strings.Repeat("1.2.3.4\n", 64))

	f.Fuzz(func(t *testing.T, providerName, body string) {
		p, ok := providers[providerName]
		if !ok {
			t.Skip() // the provider set is closed and validated before parse is reached
		}
		table := map[netip.Prefix]entry{}
		st := stats{perSource: map[string]int{}, malformed: map[string]int{}}
		var conflicts []conflict

		// parse must not panic on any input; a decode error is a legitimate outcome.
		if err := p.parse(strings.NewReader(body), collect(providerName, &st, table, &conflicts)); err != nil {
			return
		}

		// Nothing may be lost without being counted: every row a parser emitted
		// is either in the table (possibly collapsed onto an existing prefix) or
		// in the malformed tally.
		if st.perSource[providerName] < len(table) {
			t.Fatalf("table holds %d prefixes from %d accepted records — rows appeared from nowhere",
				len(table), st.perSource[providerName])
		}

		// Whatever is in the table must round-trip through the spec format, or
		// the emitted file is not loadable by the loader the docs promise.
		var b strings.Builder
		if err := emit(table, &b); err != nil {
			t.Fatalf("emit failed on parsed input: %v", err)
		}
		if _, err := cidr.LoadFunc(strings.NewReader(b.String()), specParser); err != nil {
			t.Fatalf("emitted spec does not load back: %v\nspec:\n%s", err, b.String())
		}
	})
}

var benchN = 12000

// benchAWSDoc builds an ip-ranges.json of realistic shape and size: n distinct
// prefixes, each also published under the AMAZON catch-all, which is the 1.5×
// record-to-prefix ratio the real feed has (17,530 records over 11,273 prefixes
// on 2026-09-21).
func benchAWSDoc(n int) string {
	var b strings.Builder
	b.WriteString(`{"syncToken":"1","prefixes":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 0}), 24)
		svc := "EC2"
		if i%37 == 0 {
			svc = "CLOUDFRONT"
		}
		b.WriteString(aws4(p.String(), svc))
		b.WriteByte(',')
		b.WriteString(aws4(p.String(), "AMAZON"))
	}
	b.WriteString(`],"ipv6_prefixes":[]}`)
	return b.String()
}

// BenchmarkBuild is a regression tripwire, not an optimization target. The real
// run is dominated by five network fetches, so parse+merge+emit cost is three
// orders of magnitude below wall-clock — this exists to catch an accidental
// O(n²) in merge or emit, where the symptom would otherwise be "the daily timer
// got slow" long after the commit that caused it.
func BenchmarkBuild(b *testing.B) {
	doc := benchAWSDoc(benchN)
	b.SetBytes(int64(len(doc)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table := map[netip.Prefix]entry{}
		st := stats{perSource: map[string]int{}, malformed: map[string]int{}}
		var conflicts []conflict
		if err := parseAWS(strings.NewReader(doc), collect("aws", &st, table, &conflicts)); err != nil {
			b.Fatal(err)
		}
		var out strings.Builder
		if err := emit(table, &out); err != nil {
			b.Fatal(err)
		}
		if len(table) != benchN {
			b.Fatalf("table = %d prefixes, want %d", len(table), benchN)
		}
	}
}

// writeFixture drops a feed body in a temp dir and returns "provider=path".
func writeFixture(t *testing.T, dir, provider, body string) string {
	t.Helper()
	path := dir + "/" + provider + ".fixture"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return provider + "=" + path
}

// TestRunEndToEnd covers run() itself — flag handling aside, the whole
// orchestration: open, parse, merge, guard, emit, write. Everything above this
// exercises the pieces; the audit's two reproduced defects both lived in how the
// pieces were wired together, not in any one of them.
func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	in := strings.Join([]string{
		writeFixture(t, dir, "aws", awsDoc(aws4("23.228.249.0/24", "CLOUDFRONT")+","+
			aws4("23.228.249.0/24", "AMAZON")+","+aws4("3.5.140.0/22", "EC2"), "")),
		writeFixture(t, dir, "tor", "171.25.193.25\n"),
	}, ",")

	out := dir + "/out.cidr"
	if err := run("all", in, out, "", 0); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want := "3.5.140.0/22 cloud aws\n23.228.249.0/24 cdn aws\n171.25.193.25/32 tor-exit tor\n"
	if string(got) != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestRunWritesNoFileWhenASourceIsEmpty is the regression test for the worst
// reproduced failure, at the level it actually matters. A feed answering 200
// with the wrong shape previously produced exit 0 and a zero-byte file — under
// `build/provider-function --generator` that truncates the published spec on a
// "successful" timer run. The guard must fire BEFORE os.Create, so the previous
// day's file survives untouched.
func TestRunWritesNoFileWhenASourceIsEmpty(t *testing.T) {
	dir := t.TempDir()
	// Valid JSON, wrong field name — exactly what a feed shape change looks like.
	in := writeFixture(t, dir, "aws",
		`{"syncToken":"1","prefixes":[{"ipPrefix":"3.5.140.0/22","service":"EC2"}],"ipv6_prefixes":[]}`)

	out := dir + "/out.cidr"
	yesterday := "1.2.3.0/24 cloud aws\n"
	if err := os.WriteFile(out, []byte(yesterday), 0o600); err != nil {
		t.Fatal(err)
	}

	err := run("all", in, out, "", 0)
	if err == nil {
		t.Fatal("a feed that produced nothing was accepted; want an error")
	}
	if !strings.Contains(err.Error(), "aws") {
		t.Errorf("error %q does not name the provider that failed", err)
	}

	after, readErr := os.ReadFile(out)
	if readErr != nil {
		t.Fatalf("the previous file was destroyed: %v", readErr)
	}
	if string(after) != yesterday {
		t.Errorf("previous output was modified:\ngot:  %q\nwant: %q", after, yesterday)
	}
}

// TestWriteConflictLog pins the TSV a reviewer uses to decide which feed to
// trust — it has to name both sides and the winner, or it cannot settle
// anything.
func TestWriteConflictLog(t *testing.T) {
	path := t.TempDir() + "/conflicts.tsv"
	err := writeConflictLog(path, []conflict{{
		prefix: netip.MustParsePrefix("104.16.0.0/13"),
		a:      entry{function: funcCloud, provider: "aws"},
		b:      entry{function: funcCDN, provider: "cloudflare"},
		winner: entry{function: funcCloud, provider: "aws"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "prefix\ta_provider\ta_function\tb_provider\tb_function\twinner_provider\twinner_function\n" +
		"104.16.0.0/13\taws\tcloud\tcloudflare\tcdn\taws\tcloud\n"
	if string(got) != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

// TestPerSourceTallyShowsZero pins the reporting half of the silent-loss fix: a
// provider that contributed nothing must read as "=0", not be absent. Absent is
// how a dead feed looked like a feed that was never configured.
func TestPerSourceTallyShowsZero(t *testing.T) {
	got := perSourceTally(map[string]int{"aws": 0, "tor": 5})
	if !strings.Contains(got, "aws=0") {
		t.Errorf("tally %q hides the provider that produced nothing", got)
	}
	if !strings.Contains(got, "tor=5") {
		t.Errorf("tally %q lost a provider that produced rows", got)
	}
	// Order must follow providerOrder, not map iteration.
	if strings.Index(got, "aws=") > strings.Index(got, "tor=") {
		t.Errorf("tally %q is not in providerOrder", got)
	}
}

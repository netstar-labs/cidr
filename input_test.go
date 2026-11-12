package cidr

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

const sampleSpec = `
# an IP-to-ASN spec with comments and blank lines

# a bare CIDR, no ASN
10.0.0.0/8
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

// TestParseSpecCountryFallback: a second field that is not an ASN becomes the
// Org — the shape `iptoasn -output country` emits ("<cidr> <cc>"). The ISO code
// "AS" (American Samoa) must not be mistaken for the "AS" ASN prefix.
func TestParseSpecCountryFallback(t *testing.T) {
	cases := []struct {
		line    string
		wantASN uint32
		wantOrg string
	}{
		{"1.2.3.0/24 US", 0, "US"},
		{"1.2.3.0/24 AS", 0, "AS"},        // American Samoa, not an AS-prefixed ASN
		{"1.2.3.0/24 AS13335", 13335, ""}, // a real AS-prefixed ASN still parses
		{"1.2.3.0/24 13335 Cloudflare, Inc.", 13335, "Cloudflare, Inc."},
	}
	for _, c := range cases {
		e, ok := parseSpecLine(c.line)
		if !ok {
			t.Errorf("parseSpecLine(%q): not ok", c.line)
			continue
		}
		if e.ASN != c.wantASN || e.Org != c.wantOrg {
			t.Errorf("parseSpecLine(%q) = ASN %d Org %q, want ASN %d Org %q",
				c.line, e.ASN, e.Org, c.wantASN, c.wantOrg)
		}
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

func TestRefs(t *testing.T) {
	// an ASN-style refs body (list entries carry "<cidr> <ASN> <org>")
	const asnJSON = `{
	  "name": "asn",
	  "version": 20260705,
	  "list": [
	    "1.1.1.0/24 13335 Cloudflare, Inc.",
	    "1.1.1.128/25 99999 Sub-block",
	    "2001:db8::/32 64502 Docs",
	    "# a comment line",
	    "garbage"
	  ]
	}`

	rf, err := ParseRefs(strings.NewReader(asnJSON))
	if err != nil {
		t.Fatal(err)
	}
	if rf.Name != "asn" || rf.Version != 20260705 {
		t.Errorf("envelope = %+v", rf)
	}
	if got := len(rf.Entries()); got != 3 { // comment + garbage skipped
		t.Errorf("entries = %d, want 3", got)
	}

	set, table, err := LoadRefsASN(strings.NewReader(asnJSON))
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains(mustAddr("1.1.1.10")) || set.Contains(mustAddr("9.9.9.9")) {
		t.Error("membership wrong")
	}
	if info, ok := table.Lookup(mustAddr("1.1.1.200")); !ok || info.ASN != 99999 { // nested /25 wins
		t.Errorf("1.1.1.200 = %+v (ok=%v)", info, ok)
	}
	if info, ok := table.Lookup(mustAddr("2001:db8::1")); !ok || info.ASN != 64502 {
		t.Errorf("v6 = %+v (ok=%v)", info, ok)
	}

	// a parked-style body: bare CIDRs, membership only
	set2, err := LoadRefsSet(strings.NewReader(`{"name":"parked","version":1,"list":["10.0.0.0/8","192.0.2.0/24"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !set2.Contains(mustAddr("10.1.2.3")) {
		t.Error("parked membership wrong")
	}

	if _, err := ParseRefs(strings.NewReader("not json")); err == nil {
		t.Error("expected JSON parse error")
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

// TestLoadFuncClassification loads a "<cidr> <6-digit code> [label...]" feed
// through LoadFunc into a Table of a custom struct value. guideFeed is the exact
// text of the worked example in docs/userguide.md (annotations sit on their own
// '#' line, because a trailing '#' would become part of the label); the two
// malformed lines after it exercise the parse callback's rejections.
func TestLoadFuncClassification(t *testing.T) {
	type Class struct {
		Code  int
		Label string
	}
	const guideFeed = `# <cidr> <6-digit code> [label...]
1.1.1.0/24     518210 Data Processing & Hosting
# nested, more specific
1.1.1.128/25   541512 Computer Systems Design
10.0.0.0/8     999999 Private Use
2001:db8::/32  100002 Documentation
`
	const feed = guideFeed + `BOGUS          000001 not a prefix
1.2.3.0/24     42     too short
`
	table, err := LoadFunc(strings.NewReader(feed), func(f []string) (netip.Prefix, Class, bool) {
		if len(f) < 2 {
			return netip.Prefix{}, Class{}, false
		}
		p, err := ParsePrefix(f[0])
		if err != nil {
			return netip.Prefix{}, Class{}, false
		}
		code, err := strconv.Atoi(f[1])
		if err != nil || code < 100000 || code > 999999 { // enforce six digits
			return netip.Prefix{}, Class{}, false
		}
		return p, Class{Code: code, Label: strings.Join(f[2:], " ")}, true
	})
	if err != nil {
		t.Fatal(err)
	}

	if c, ok := table.Lookup(mustAddr("1.1.1.200")); !ok || c != (Class{541512, "Computer Systems Design"}) { // nested /25 wins
		t.Errorf("1.1.1.200 = %+v (ok=%v), want {541512 Computer Systems Design}", c, ok)
	}
	if c, ok := table.Lookup(mustAddr("2001:db8::1")); !ok || c != (Class{100002, "Documentation"}) {
		t.Errorf("2001:db8::1 = %+v (ok=%v)", c, ok)
	}
	if c, ok := table.Lookup(mustAddr("1.1.1.10")); !ok || c.Label != "Data Processing & Hosting" {
		t.Errorf("1.1.1.10 = %+v (ok=%v)", c, ok)
	}
	if _, ok := table.Lookup(mustAddr("8.8.8.8")); ok {
		t.Error("8.8.8.8 should miss")
	}
	// the malformed lines (bad prefix, short code) were skipped
	if _, ok := table.Lookup(mustAddr("1.2.3.4")); ok {
		t.Error("1.2.3.4 came from a rejected line and should miss")
	}
}

// TestSpecHashIsData pins the comment rule: only a whole line beginning with '#'
// is a comment; a '#' inside a line stays in its field.
func TestSpecHashIsData(t *testing.T) {
	const feed = "# whole-line comment\n  # indented whole-line comment\n203.0.113.7 64500 Example Org # note\n"
	entries, err := ParseSpec(strings.NewReader(feed))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ASN != 64500 || entries[0].Org != "Example Org # note" {
		t.Fatalf("entries = %+v, want one entry with Org %q", entries, "Example Org # note")
	}

	table, err := LoadFunc(strings.NewReader("10.0.0.0/8 x # y\n"), func(f []string) (netip.Prefix, string, bool) {
		p, err := ParsePrefix(f[0])
		return p, strings.Join(f[1:], " "), err == nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := table.Lookup(mustAddr("10.1.2.3")); v != "x # y" {
		t.Errorf("LoadFunc value = %q, want %q", v, "x # y")
	}
}

// TestLoadErrTooLong pins what each loader returns when a line is 1 MiB or
// longer (bufio.ErrTooLong): ParseSpec the entries read so far, LoadSet/LoadASN
// nil, LoadFunc a non-nil partial Table.
func TestLoadErrTooLong(t *testing.T) {
	feed := "1.1.1.0/24 13335 Cloudflare\n10.0.0.0/8 1 " + strings.Repeat("x", 2<<20) + "\n2.2.2.0/24 2 After\n"
	rd := func() io.Reader { return strings.NewReader(feed) }

	entries, err := ParseSpec(rd())
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("ParseSpec err = %v, want bufio.ErrTooLong", err)
	}
	if len(entries) != 1 || entries[0].Prefix.String() != "1.1.1.0/24" {
		t.Errorf("ParseSpec entries = %+v, want only the line before the long one", entries)
	}
	if set, err := LoadSet(rd()); set != nil || !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("LoadSet = %v, %v, want nil, ErrTooLong", set, err)
	}
	if set, table, err := LoadASN(rd()); set != nil || table != nil || !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("LoadASN = %v, %v, %v, want nil, nil, ErrTooLong", set, table, err)
	}
	tbl, err := LoadFunc(rd(), func(f []string) (netip.Prefix, string, bool) {
		p, perr := ParsePrefix(f[0])
		return p, "v", perr == nil
	})
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("LoadFunc err = %v, want bufio.ErrTooLong", err)
	}
	if tbl == nil {
		t.Fatal("LoadFunc returned a nil Table; want the partial one")
	}
	if _, ok := tbl.Lookup(mustAddr("1.1.1.1")); !ok {
		t.Error("partial Table lost the line read before the failure")
	}
	if _, ok := tbl.Lookup(mustAddr("2.2.2.2")); ok {
		t.Error("partial Table contains a line after the failure")
	}
}

// TestLoadLineLimitBoundary pins the exact scanner limit: a line of 1<<20 bytes
// (LF-terminated) fails with bufio.ErrTooLong and one byte shorter is accepted.
func TestLoadLineLimitBoundary(t *testing.T) {
	line := func(n int) string { // a valid spec line padded to exactly n bytes
		head := "10.0.0.0/8 1 "
		return head + strings.Repeat("x", n-len(head)) + "\n"
	}
	if _, err := ParseSpec(strings.NewReader(line(1<<20 - 1))); err != nil {
		t.Errorf("line of 1<<20-1 bytes: err = %v, want nil", err)
	}
	if _, err := ParseSpec(strings.NewReader(line(1 << 20))); !errors.Is(err, bufio.ErrTooLong) {
		t.Errorf("line of 1<<20 bytes: err = %v, want bufio.ErrTooLong", err)
	}
}

func TestParseRefsStrict(t *testing.T) {
	const ok = `{"name":"n","version":1,"list":["10.0.0.0/8"]}`
	for _, tc := range []struct {
		name, in string
		wantErr  bool
		wantLen  int
	}{
		{"normal", ok, false, 1},
		{"trailing whitespace", ok + " \n\t\r\n", false, 1},
		{"explicit empty list", `{"name":"n","version":1,"list":[]}`, false, 0},
		{"missing list", `{"name":"n","version":1}`, true, 0},
		{"renamed list", `{"name":"n","version":1,"lst":["10.0.0.0/8"]}`, true, 0},
		{"null list", `{"name":"n","version":1,"list":null}`, true, 0},
		{"empty object", `{}`, true, 0},
		{"trailing garbage", ok + ` garbage`, true, 0},
		{"trailing brace", ok + `}`, true, 0},
		{"two envelopes", ok + ok, true, 0},
		{"two envelopes newline", ok + "\n" + ok, true, 0},
		{"empty input", ``, true, 0},
	} {
		rf, err := ParseRefs(strings.NewReader(tc.in))
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
			continue
		}
		if err == nil && len(rf.List) != tc.wantLen {
			t.Errorf("%s: list len = %d, want %d", tc.name, len(rf.List), tc.wantLen)
		}
		if err != nil && rf != nil {
			t.Errorf("%s: got a non-nil Refs with an error", tc.name)
		}
	}

	// the Load* wrappers propagate the error rather than return an empty set
	if s, err := LoadRefsSet(strings.NewReader(`{"name":"n","version":1}`)); err == nil || s != nil {
		t.Errorf("LoadRefsSet missing list = %v, %v; want nil, error", s, err)
	}
	if s, tb, err := LoadRefsASN(strings.NewReader(ok + ok)); err == nil || s != nil || tb != nil {
		t.Errorf("LoadRefsASN two envelopes: want nil, nil, error")
	}
}

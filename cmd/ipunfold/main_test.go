package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

func unfold(t *testing.T, input string, o opts) (string, stats) {
	t.Helper()
	var buf bytes.Buffer
	st, err := run(strings.NewReader(input), &buf, o)
	if err != nil {
		t.Fatal(err)
	}
	return buf.String(), st
}

func TestUnfoldBasic(t *testing.T) {
	input := strings.Join([]string{
		"10.0.0.12/30",     // the ipfold README example, in reverse
		"192.168.1.1/32",   // lone host as a /32
		"172.16.0.9",       // bare address -> itself
		"2001:db8::2/127",  // v6 pair
		"8.8.8.0/30 15169", // spec line: trailing fields ignored
		"", "# comment", "not-an-ip", "10.0.0.0/33",
	}, "\n") + "\n"

	want := strings.Join([]string{
		"10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15",
		"192.168.1.1",
		"172.16.0.9",
		"2001:db8::2", "2001:db8::3",
		"8.8.8.0", "8.8.8.1", "8.8.8.2", "8.8.8.3",
	}, "\n") + "\n"

	got, st := unfold(t, input, opts{})
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if st.malformed != 2 { // "not-an-ip" and the out-of-range /33
		t.Errorf("malformed = %d, want 2", st.malformed)
	}
	if st.prefixes != 5 || st.v4pfx != 4 || st.v6pfx != 1 {
		t.Errorf("prefixes=%d v4=%d v6=%d, want 5/4/1", st.prefixes, st.v4pfx, st.v6pfx)
	}
	if st.total.String() != "12" {
		t.Errorf("total = %s, want 12", st.total)
	}
}

// TestUnfoldMaskedHostBits: a prefix carrying host bits is masked, not rejected.
func TestUnfoldMaskedHostBits(t *testing.T) {
	got, _ := unfold(t, "10.0.0.5/30\n", opts{})
	want := "10.0.0.4\n10.0.0.5\n10.0.0.6\n10.0.0.7\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestUnfoldUpperBound walks the last addresses of each family: the v4 counter
// must stop at 255.255.255.255 rather than wrap to 0, and the v6 walk must stop
// at the all-ones address rather than step to the invalid Addr.
func TestUnfoldUpperBound(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"255.255.255.254/31", "255.255.255.254\n255.255.255.255\n"},
		{
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127",
			"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe\nffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n",
		},
	} {
		if got, _ := unfold(t, tc.in+"\n", opts{}); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnfoldFamilyFilter(t *testing.T) {
	input := "10.0.0.0/31\n2001:db8::/127\n"
	if got, _ := unfold(t, input, opts{only4: true}); got != "10.0.0.0\n10.0.0.1\n" {
		t.Errorf("-4 got %q", got)
	}
	if got, _ := unfold(t, input, opts{only6: true}); got != "2001:db8::\n2001:db8::1\n" {
		t.Errorf("-6 got %q", got)
	}
}

// TestUnfoldCount checks the counting path, including an IPv6 prefix far past
// what a uint64 holds.
func TestUnfoldCount(t *testing.T) {
	// 10.0.0.0/24 (256) + ::/0 (2^128) + a /32 (1)
	got, st := unfold(t, "10.0.0.0/24\n::/0\n1.2.3.4\n", opts{count: true})
	const want = "340282366920938463463374607431768211713\n" // 2^128 + 257
	if got != want {
		t.Errorf("count = %q, want %q", got, want)
	}
	if st.total.String()+"\n" != want {
		t.Errorf("stats total = %s", st.total)
	}
}

func TestUnfoldMax(t *testing.T) {
	var buf bytes.Buffer
	// 4 addresses fit; the /24 that follows does not.
	st, err := run(strings.NewReader("10.0.0.0/30\n10.1.0.0/24\n10.2.0.0/32\n"), &buf, opts{max: 100})
	if err == nil {
		t.Fatal("expected a -max error")
	}
	if !strings.Contains(err.Error(), "10.1.0.0/24") {
		t.Errorf("error should name the offending prefix, got: %v", err)
	}
	// Everything up to the offending prefix is still written, and the tally
	// reports how far the run got.
	if buf.String() != "10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.3\n" {
		t.Errorf("partial output = %q", buf.String())
	}
	if st.total.String() != "4" {
		t.Errorf("total = %s, want 4", st.total)
	}
	// An IPv6 prefix wider than a uint64 must trip the guard, not overflow it.
	if _, err := run(strings.NewReader("2001:db8::/32\n"), &bytes.Buffer{}, opts{max: 1 << 62}); err == nil {
		t.Error("expected a -max error for a /32 v6 prefix")
	}
}

// TestRoundTrip confirms the expansion of a spec is exactly the set the spec
// describes: every emitted address is a member, and the emitted count matches
// the prefix arithmetic.
func TestRoundTrip(t *testing.T) {
	spec := "10.0.0.12/30\n192.168.1.1/32\n2001:db8::2/127\n0.0.0.0/29\n"
	set, err := cidr.LoadSet(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	out, st := unfold(t, spec, opts{})
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if st.total.String() != "15" || len(lines) != 15 { // 4 + 1 + 2 + 8
		t.Fatalf("emitted %d lines, total=%s, want 15", len(lines), st.total)
	}
	for _, l := range lines {
		a, err := netip.ParseAddr(l)
		if err != nil {
			t.Fatalf("unparsable output line %q: %v", l, err)
		}
		if !set.Contains(a) {
			t.Errorf("%s is not in the spec it was expanded from", l)
		}
	}
}

func TestLastV6(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2001:db8::/128", "2001:db8::"},
		{"2001:db8::/127", "2001:db8::1"},
		{"2001:db8::/120", "2001:db8::ff"},
		{"2001:db8::/119", "2001:db8::1ff"},
		{"2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		if got := lastV6(netip.MustParsePrefix(tc.in)); got.String() != tc.want {
			t.Errorf("lastV6(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestHostMask4(t *testing.T) {
	for bits, want := range map[int]uint32{0: 0xffffffff, 1: 0x7fffffff, 24: 0xff, 31: 1, 32: 0} {
		if got := hostMask4(bits); got != want {
			t.Errorf("hostMask4(%d) = %#x, want %#x", bits, got, want)
		}
	}
}

func TestAppendV4(t *testing.T) {
	// Formatting must match netip across the octet-width boundaries (1, 2 and
	// 3 digits) that the hand-rolled itoa branches on.
	for _, x := range []uint32{0, 1, 0x01020304, 0x0a00000b, 0x63646566, 0xc0a80101, 0xffffffff} {
		want := netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)}).String()
		if got := string(appendV4(nil, x)); got != want {
			t.Errorf("appendV4(%#x) = %s, want %s", x, got, want)
		}
	}
}

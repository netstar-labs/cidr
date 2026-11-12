package cidr

import (
	"math/rand"
	"net/netip"
	"slices"
	"testing"
)

// checkCover asserts the prefixes exactly tile [lo, hi]: contiguous, in order,
// no gaps, no overlap, first starts at lo and last ends at hi.
func checkCover(t *testing.T, lo, hi netip.Addr, ps []netip.Prefix) {
	t.Helper()
	if len(ps) == 0 {
		t.Fatalf("no prefixes for %v-%v", lo, hi)
	}
	cur := lo
	for i, p := range ps {
		if p.Masked() != p {
			t.Errorf("prefix %v not masked", p)
		}
		if p.Addr() != cur {
			t.Fatalf("piece %d starts at %v, want %v", i, p.Addr(), cur)
		}
		end := LastAddr(p)
		if i == len(ps)-1 {
			if end != hi {
				t.Fatalf("last piece ends at %v, want %v", end, hi)
			}
		} else {
			cur = end.Next()
		}
	}
}

func TestRangePrefixes(t *testing.T) {
	cases := []struct {
		lo, hi string
		n      int // expected piece count
	}{
		{"1.1.1.0", "1.1.1.255", 1},       // an aligned /24
		{"1.1.1.1", "1.1.1.2", 2},         // two host routes
		{"0.0.0.0", "255.255.255.255", 1}, // the whole v4 space -> /0
		{"10.0.0.0", "10.0.0.0", 1},       // a single address -> /32
		{"192.0.2.0", "192.0.2.130", 0},   // count checked below, not here
		{"2001:db8::", "2001:db8::ffff", 1},
		{"2001:db8::1", "2001:db8::2", 2},
	}
	for _, c := range cases {
		lo, hi := netip.MustParseAddr(c.lo), netip.MustParseAddr(c.hi)
		ps := RangePrefixes(lo, hi)
		checkCover(t, lo, hi, ps)
		if c.n > 0 && len(ps) != c.n {
			t.Errorf("%s-%s: got %d pieces, want %d (%v)", c.lo, c.hi, len(ps), c.n, ps)
		}
	}
}

func TestRangePrefixesRandom(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		a := r.Uint32()
		b := r.Uint32()
		if a > b {
			a, b = b, a
		}
		lo := netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
		hi := netip.AddrFrom4([4]byte{byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b)})
		checkCover(t, lo, hi, RangePrefixes(lo, hi))
	}
}

func TestSetAddRange(t *testing.T) {
	b := NewBuilder()
	b.AddRange(netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20"))
	b.AddRange(netip.MustParseAddr("2001:db8::"), netip.MustParseAddr("2001:db8::ff"))
	set := b.Freeze()

	for _, in := range []string{"192.0.2.10", "192.0.2.15", "192.0.2.20", "2001:db8::80"} {
		if !set.Contains(netip.MustParseAddr(in)) {
			t.Errorf("%s should be a member", in)
		}
	}
	for _, out := range []string{"192.0.2.9", "192.0.2.21", "2001:db8::100"} {
		if set.Contains(netip.MustParseAddr(out)) {
			t.Errorf("%s should not be a member", out)
		}
	}
}

func TestTableAddRange(t *testing.T) {
	tb := NewTableBuilder[int]()
	// a covering range, plus a more-specific sub-range with a different value
	tb.AddRange(netip.MustParseAddr("1.0.0.0"), netip.MustParseAddr("1.0.0.255"), 1)
	tb.AddRange(netip.MustParseAddr("1.0.0.64"), netip.MustParseAddr("1.0.0.127"), 2)
	table := tb.Freeze()

	cases := []struct {
		ip   string
		want int
		ok   bool
	}{
		{"1.0.0.10", 1, true},  // covering range only
		{"1.0.0.64", 2, true},  // sub-range (more specific) wins
		{"1.0.0.100", 2, true}, // sub-range
		{"1.0.0.128", 1, true}, // back to covering range
		{"1.0.1.0", 0, false},  // outside
	}
	for _, c := range cases {
		got, ok := table.Lookup(netip.MustParseAddr(c.ip))
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("Lookup(%s) = (%d,%v), want (%d,%v)", c.ip, got, ok, c.want, c.ok)
		}
	}
}

func TestAddRangeInvalid(t *testing.T) {
	// hi < lo, or mixed families: ignored, not panicking.
	b := NewBuilder()
	b.AddRange(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.1")) // reversed
	b.AddRange(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("::1"))      // mixed
	if set := b.Freeze(); set.Len() != 0 {
		t.Errorf("invalid ranges should add nothing, Len=%d", set.Len())
	}
}

func TestLastAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// IPv4: every host-bit count at the byte boundaries and a partial byte.
		{"0.0.0.0/0", "255.255.255.255"},
		{"10.0.0.0/8", "10.255.255.255"},
		{"192.168.0.0/16", "192.168.255.255"},
		{"192.0.2.0/24", "192.0.2.255"},
		{"192.0.2.0/25", "192.0.2.127"},
		{"192.0.2.128/25", "192.0.2.255"},
		{"203.0.113.0/31", "203.0.113.1"},
		{"203.0.113.7/32", "203.0.113.7"},
		{"255.255.255.255/32", "255.255.255.255"},
		{"0.0.0.0/32", "0.0.0.0"},
		// IPv6
		{"::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::/64", "2001:db8::ffff:ffff:ffff:ffff"},
		{"2001:db8::/119", "2001:db8::1ff"},
		{"2001:db8::/120", "2001:db8::ff"},
		{"2001:db8::/127", "2001:db8::1"},
		{"2001:db8::/128", "2001:db8::"},
		{"::/128", "::"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"8000::/1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"::/1", "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
		// Unmasked input: host bits in the address are ignored, not preserved.
		{"10.1.2.3/8", "10.255.255.255"},
		{"192.0.2.200/25", "192.0.2.255"},
		{"192.0.2.99/25", "192.0.2.127"},
		{"2001:db8:1:2:3:4:5:6/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"},
		{"2001:db8::dead:beef/120", "2001:db8::dead:beff"},
		// IPv4-mapped: LastAddr does not fold, so an IPv6 prefix stays IPv6.
		{"::ffff:10.0.0.0/104", "::ffff:10.255.255.255"},
		{"::ffff:10.0.0.0/120", "::ffff:10.0.0.255"},
		{"::ffff:10.0.0.1/128", "::ffff:10.0.0.1"},
		{"::ffff:10.1.2.3/112", "::ffff:10.1.255.255"},
		// Shorter than /96 the prefix is plain IPv6: its range is masked as such.
		{"::ffff:0.0.0.0/80", "::ffff:255.255.255.255"},
		{"::ffff:0.0.0.0/64", "::ffff:ffff:ffff:ffff"},
	} {
		p := netip.MustParsePrefix(tc.in)
		got := LastAddr(p)
		if got.String() != tc.want {
			t.Errorf("LastAddr(%s) = %s, want %s", tc.in, got, tc.want)
		}
		if got.Is4() != p.Addr().Is4() {
			t.Errorf("LastAddr(%s) = %s changed address family", tc.in, got)
		}
		// Invariants: inside the range, the range's last address, masked-equal.
		if !p.Contains(got) {
			t.Errorf("LastAddr(%s) = %s lies outside the prefix", tc.in, got)
		}
		if next := got.Next(); next.IsValid() && p.Contains(next) {
			t.Errorf("LastAddr(%s) = %s: %s is still inside the prefix", tc.in, got, next)
		}
	}

	// Invalid prefixes: no panic. The value is unspecified; only the absence of
	// a crash is part of the contract.
	for _, p := range []netip.Prefix{
		{},
		netip.PrefixFrom(netip.MustParseAddr("1.2.3.4"), -1),
		netip.PrefixFrom(netip.MustParseAddr("1.2.3.4"), 33),
		netip.PrefixFrom(netip.MustParseAddr("::1"), 129),
	} {
		_ = LastAddr(p)
	}
}

// TestAddRangeZoned: queries strip zones, so a zoned range must be stored
// unzoned. Otherwise lo (fe80::1%eth0) sorts after the plain fe80::1 and the
// first address of the range never matches in a Set.
func TestAddRangeZoned(t *testing.T) {
	lo := netip.MustParseAddr("fe80::1%eth0")
	hi := netip.MustParseAddr("fe80::5%eth0")

	b := NewBuilder()
	b.AddRange(lo, hi)
	s := b.Freeze()
	tb := NewTableBuilder[int]()
	tb.AddRange(lo, hi, 7)
	tab := tb.Freeze()

	for _, q := range []string{"fe80::1", "fe80::1%eth0", "fe80::3", "fe80::5", "fe80::5%wlan0"} {
		a := netip.MustParseAddr(q)
		if !s.Contains(a) {
			t.Errorf("Set.Contains(%s) = false, want true", q)
		}
		if v, ok := tab.Lookup(a); !ok || v != 7 {
			t.Errorf("Table.Lookup(%s) = %d,%v, want 7,true", q, v, ok)
		}
	}
	for _, q := range []string{"fe80::", "fe80::6"} {
		a := netip.MustParseAddr(q)
		if s.Contains(a) {
			t.Errorf("Set.Contains(%s) = true, want false", q)
		}
		if _, ok := tab.Lookup(a); ok {
			t.Errorf("Table.Lookup(%s) ok, want miss", q)
		}
	}
	// the stored interval is the plain, zone-free address range
	if s.lo6[0] != u128From16(netip.MustParseAddr("fe80::1")) || s.hi6[0] != u128From16(netip.MustParseAddr("fe80::5")) {
		t.Errorf("stored interval = %v-%v, want fe80::1-fe80::5", s.lo6[0], s.hi6[0])
	}
	// the prefix decomposition is zone-independent
	want := RangePrefixes(netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::5"))
	if got := RangePrefixes(lo, hi); !slices.Equal(got, want) {
		t.Errorf("RangePrefixes zoned = %v, want %v", got, want)
	}
	// differing zones on the same address are not "hi < lo"
	if got := RangePrefixes(netip.MustParseAddr("fe80::5%b"), netip.MustParseAddr("fe80::5%a")); len(got) != 1 {
		t.Errorf("RangePrefixes mixed zones = %v, want one /128", got)
	}
}

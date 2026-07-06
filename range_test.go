package cidr

import (
	"math/rand"
	"net/netip"
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
		end := lastAddr(p)
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

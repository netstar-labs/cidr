package cidr

import (
	"math/rand"
	"net/netip"
	"testing"
)

func TestTableLPMNesting(t *testing.T) {
	// A /16 owned by AS1, with a more-specific /24 sub-allocated to AS2.
	b := NewTableBuilder[uint32]()
	_ = b.AddPrefix("198.51.0.0/16", 1)
	_ = b.AddPrefix("198.51.100.0/24", 2)
	tab := b.Freeze()

	cases := []struct {
		ip      string
		wantASN uint32
		wantOK  bool
	}{
		{"198.51.100.10", 2, true}, // inside the more-specific -> AS2 wins
		{"198.51.100.255", 2, true},
		{"198.51.99.255", 1, true}, // inside /16 but outside /24 -> AS1
		{"198.51.101.0", 1, true},  // back to /16
		{"198.52.0.0", 0, false},   // outside everything
		{"198.50.255.255", 0, false},
	}
	for _, c := range cases {
		got, ok := tab.Lookup(mustAddr(c.ip))
		if ok != c.wantOK || got != c.wantASN {
			t.Errorf("Lookup(%s) = (%d,%v), want (%d,%v)", c.ip, got, ok, c.wantASN, c.wantOK)
		}
	}
}

func TestTableStringAndV6(t *testing.T) {
	b := NewTableBuilder[string]()
	_ = b.AddPrefix("2001:db8::/32", "AS1 outer")
	_ = b.AddPrefix("2001:db8:abcd::/48", "AS2 inner")
	_ = b.AddPrefix("10.0.0.0/8", "AS3 v4")
	tab := b.Freeze()

	if v, ok := tab.Lookup(mustAddr("2001:db8:abcd::1")); !ok || v != "AS2 inner" {
		t.Errorf("v6 nested = (%q,%v)", v, ok)
	}
	if v, ok := tab.Lookup(mustAddr("2001:db8:1234::1")); !ok || v != "AS1 outer" {
		t.Errorf("v6 outer = (%q,%v)", v, ok)
	}
	if v, ok := tab.Lookup(mustAddr("10.1.2.3")); !ok || v != "AS3 v4" {
		t.Errorf("v4 = (%q,%v)", v, ok)
	}
	if _, ok := tab.Lookup(mustAddr("2001:dead::1")); ok {
		t.Error("unrelated v6 should miss")
	}
}

func TestEncodeDecodeASN(t *testing.T) {
	for _, tc := range []struct {
		asn, org uint32
		flags    uint8
	}{
		{13335, 42, 0}, {0, 0, 0}, {4294967295, 0xffffff, 0xff}, {1, 16777215, 128},
	} {
		v := EncodeASN(tc.asn, tc.org, tc.flags)
		asn, org, flags := DecodeASN(v)
		if asn != tc.asn || org != tc.org || flags != tc.flags {
			t.Errorf("roundtrip %v -> (%d,%d,%d)", tc, asn, org, flags)
		}
	}
}

// oracle: value of the longest prefix covering a, by linear scan. Uses >= so
// that among equal-length duplicates the last-added (highest index) wins,
// matching Table's documented last-added-wins rule.
func lpmOracle(prefixes []netip.Prefix, vals []int, a netip.Addr) (int, bool) {
	best, bestLen := -1, -1
	for i, p := range prefixes {
		if p.Contains(a) && p.Bits() >= bestLen {
			best, bestLen = i, p.Bits()
		}
	}
	if best < 0 {
		return 0, false
	}
	return vals[best], true
}

func TestTableRandomParity(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	var prefixes []netip.Prefix
	var vals []int
	b := NewTableBuilder[int]()
	for i := 0; i < 3000; i++ {
		ones := 8 + r.Intn(20)
		a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), 0})
		p := netip.PrefixFrom(a, ones).Masked()
		prefixes = append(prefixes, p)
		vals = append(vals, i)
		b.Add(p, i)
	}
	tab := b.Freeze()
	for i := 0; i < 30000; i++ {
		a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
		gotV, gotOK := tab.Lookup(a)
		wantV, wantOK := lpmOracle(prefixes, vals, a)
		if gotOK != wantOK || (gotOK && gotV != wantV) {
			t.Fatalf("Lookup(%s) = (%d,%v), want (%d,%v)", a, gotV, gotOK, wantV, wantOK)
		}
	}
}

func BenchmarkTableLookup(b *testing.B) {
	r := rand.New(rand.NewSource(4))
	bl := NewTableBuilder[uint64]()
	for i := 0; i < 4000; i++ {
		a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), 0})
		bl.Add(netip.PrefixFrom(a, 24).Masked(), EncodeASN(uint32(i), uint32(i), 0))
	}
	tab := bl.Freeze()
	q := make([]netip.Addr, 4096)
	for i := range q {
		q[i] = netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
	}
	b.ReportAllocs()
	b.ResetTimer()
	var s uint64
	for i := 0; i < b.N; i++ {
		v, _ := tab.Lookup(q[i&4095])
		s ^= v
	}
	_ = s
}

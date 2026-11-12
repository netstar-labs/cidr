package cidr

import (
	"math/rand"
	"net/netip"
	"testing"
)

// This file checks the frozen Set/Table layout against a brute-force oracle
// that shares no code with the package: it normalises each added prefix with
// netip alone, then answers every query by scanning all of them.

// parityNorm folds an IPv4-mapped prefix (::ffff:a.b.c.d/n, n >= 96) to IPv4
// /n-96 and masks it, the documented Add behaviour, using netip only.
func parityNorm(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked()
}

// parityQuery is the address as the documented query rules see it: mapped
// addresses are matched as IPv4 and a zone is ignored.
func parityQuery(a netip.Addr) netip.Addr { return a.Unmap().WithZone("") }

// parityContains: is a covered by any added prefix?
func parityContains(added []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	q := parityQuery(a)
	for _, p := range added {
		if parityNorm(p).Contains(q) {
			return true
		}
	}
	return false
}

// parityLookup: the index of the longest covering prefix, the last added
// winning among identical ones; -1 when nothing covers a.
func parityLookup(added []netip.Prefix, a netip.Addr) int {
	if !a.IsValid() {
		return -1
	}
	q := parityQuery(a)
	best, bestBits := -1, -1
	for i, p := range added {
		n := parityNorm(p)
		if n.Contains(q) && n.Bits() >= bestBits {
			best, bestBits = i, n.Bits()
		}
	}
	return best
}

// parityEnds returns the first and last address of the normalised prefix,
// computed bytewise.
func parityEnds(p netip.Prefix) (first, last netip.Addr) {
	n := parityNorm(p)
	first = n.Addr()
	b := first.AsSlice()
	for i := n.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	last, _ = netip.AddrFromSlice(b)
	return first, last
}

var (
	parityV4Pool = []netip.Addr{
		netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.1.2.3"),
		netip.MustParseAddr("192.168.0.0"), netip.MustParseAddr("1.0.0.0"),
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"),
		netip.MustParseAddr("127.255.255.255"), netip.MustParseAddr("128.0.0.0"),
	}
	parityV6Pool = []netip.Addr{
		netip.MustParseAddr("2001:db8::"), netip.MustParseAddr("2001:db8:1:2:3:4:5:6"),
		netip.MustParseAddr("fe80::1"), netip.MustParseAddr("::"),
		netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		netip.MustParseAddr("7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		netip.MustParseAddr("8000::"), netip.MustParseAddr("::ffff:0:0"),
		netip.MustParseAddr("2001:db8:0:0:ffff:ffff:ffff:ffff"),
	}
)

// parityFlip flips a few random low-order bits of a, to make near neighbours.
func parityFlip(r *rand.Rand, a netip.Addr) netip.Addr {
	b := a.AsSlice()
	for range r.Intn(3) {
		bit := len(b)*8 - 1 - r.Intn(min(len(b)*8, 40))
		b[bit/8] ^= 0x80 >> (bit % 8)
	}
	out, _ := netip.AddrFromSlice(b)
	return out
}

// parityPrefixes draws n prefixes of the requested families, always including
// the family-edge cases and nested chains, duplicates and mapped forms.
func parityPrefixes(r *rand.Rand, n int, v4, v6 bool) []netip.Prefix {
	var ps []netip.Prefix
	pick := func() netip.Prefix {
		useV6 := v6 && (!v4 || r.Intn(2) == 0)
		if useV6 {
			a := parityFlip(r, parityV6Pool[r.Intn(len(parityV6Pool))])
			return netip.PrefixFrom(a, r.Intn(129)) // deliberately unmasked
		}
		a := parityFlip(r, parityV4Pool[r.Intn(len(parityV4Pool))])
		return netip.PrefixFrom(a, r.Intn(33))
	}
	for len(ps) < n {
		switch r.Intn(10) {
		case 0: // family edges
			switch r.Intn(4) {
			case 0:
				if v4 {
					ps = append(ps, netip.PrefixFrom(parityV4Pool[4], 32), netip.PrefixFrom(parityV4Pool[5], 32))
				}
			case 1:
				if v6 {
					ps = append(ps, netip.PrefixFrom(parityV6Pool[3], 128), netip.PrefixFrom(parityV6Pool[4], 128))
				}
			case 2:
				if v4 {
					ps = append(ps, netip.MustParsePrefix("0.0.0.0/0"))
				}
			default:
				if v6 {
					ps = append(ps, netip.MustParsePrefix("::/0"))
				}
			}
		case 1, 2: // nested chain: one address under several lengths, shuffled
			p := pick()
			var chain []netip.Prefix
			for l := p.Bits(); l >= 0 && len(chain) < 6; l -= 1 + r.Intn(9) {
				chain = append(chain, netip.PrefixFrom(p.Addr(), l))
			}
			r.Shuffle(len(chain), func(i, j int) { chain[i], chain[j] = chain[j], chain[i] })
			ps = append(ps, chain...)
		case 3: // duplicate of an earlier prefix (last added must win)
			if len(ps) > 0 {
				ps = append(ps, ps[r.Intn(len(ps))])
			}
		case 4: // IPv4-mapped prefix
			if v4 {
				a := parityFlip(r, parityV4Pool[r.Intn(len(parityV4Pool))])
				bits := 96 + r.Intn(33)
				ps = append(ps, netip.PrefixFrom(netip.AddrFrom16(a.As16()), bits))
			}
		default:
			ps = append(ps, pick())
		}
	}
	return ps
}

// parityQueries lists the queries for one added set: the first, last and +-1
// addresses of every prefix, random near neighbours, and mapped and zoned
// variants of all of them.
func parityQueries(r *rand.Rand, added []netip.Prefix) []netip.Addr {
	var base []netip.Addr
	for _, p := range added {
		first, last := parityEnds(p)
		base = append(base, first, last)
		if x := first.Prev(); x.IsValid() {
			base = append(base, x)
		}
		if x := last.Next(); x.IsValid() {
			base = append(base, x)
		}
		base = append(base, parityFlip(r, first), parityFlip(r, last))
	}
	for range 20 {
		base = append(base, parityFlip(r, parityV4Pool[r.Intn(len(parityV4Pool))]),
			parityFlip(r, parityV6Pool[r.Intn(len(parityV6Pool))]))
		var b [16]byte
		r.Read(b[:])
		base = append(base, netip.AddrFrom16(b), netip.AddrFrom4([4]byte(b[:4])))
	}
	base = append(base, parityV4Pool...)
	base = append(base, parityV6Pool...)
	qs := append([]netip.Addr(nil), base...)
	for _, a := range base {
		if a.Is4() {
			m := netip.AddrFrom16(a.As16())
			qs = append(qs, m, m.WithZone("eth0")) // mapped form, with and without a zone
		} else if !a.Is4In6() {
			qs = append(qs, a.WithZone("eth0")) // zoned form
		}
	}
	return append(qs, netip.Addr{})
}

// TestFrozenLayoutParity builds many random v4, v6 and mixed Sets and Tables
// and compares every query with the brute-force oracle above.
func TestFrozenLayoutParity(t *testing.T) {
	r := rand.New(rand.NewSource(40))
	var sets, tables, queries, hits int
	for iter := 0; iter < 600; iter++ {
		v4, v6 := true, true
		switch iter % 3 {
		case 0:
			v6 = false
		case 1:
			v4 = false
		}
		added := parityPrefixes(r, 1+r.Intn(40), v4, v6)
		sb := NewBuilder()
		tb := NewTableBuilder[int]()
		for i, p := range added {
			sb.Add(p)
			tb.Add(p, i)
		}
		set, tab := sb.Freeze(), tb.Freeze()
		sets++
		tables++
		for _, q := range parityQueries(r, added) {
			queries++
			gotC, wantC := set.Contains(q), parityContains(added, q)
			if gotC != wantC {
				t.Fatalf("iter %d: Set.Contains(%v) = %v, want %v; added %v", iter, q, gotC, wantC, added)
			}
			if wantC {
				hits++
			}
			v, ok := tab.Lookup(q)
			want := parityLookup(added, q)
			if ok != (want >= 0) || (ok && v != want) {
				t.Fatalf("iter %d: Table.Lookup(%v) = (%d,%v), want index %d; added %v", iter, q, v, ok, want, added)
			}
		}
	}
	if hits == 0 || hits == queries {
		t.Fatalf("degenerate query mix: %d hits of %d", hits, queries)
	}
	t.Logf("compared %d sets and %d tables on %d queries (%d hits, %d misses), each against Contains and Lookup",
		sets, tables, queries, hits, queries-hits)
}

// TestFrozenLayoutNoAlloc: queries allocate nothing, for IPv4, IPv6, IPv4-mapped
// and zoned addresses, in hits and misses alike.
func TestFrozenLayoutNoAlloc(t *testing.T) {
	sb := NewBuilder()
	tb := NewTableBuilder[int]()
	for i, p := range []string{"10.0.0.0/8", "10.1.0.0/16", "192.0.2.0/24", "2001:db8::/32", "2001:db8:1::/48", "fe80::/10"} {
		_ = sb.AddPrefix(p)
		_ = tb.AddPrefix(p, i)
	}
	set, tab := sb.Freeze(), tb.Freeze()
	for _, q := range []string{
		"10.1.2.3", "11.0.0.1", "192.0.2.9", "2001:db8:1::5", "2001:db9::1", "fe80::1%eth0",
		"::ffff:10.1.2.3", "::ffff:11.0.0.1", "::ffff:10.1.2.3%eth0", "::",
	} {
		a := netip.MustParseAddr(q)
		if n := testing.AllocsPerRun(100, func() { _ = set.Contains(a) }); n != 0 {
			t.Errorf("Set.Contains(%s) allocates %v times", q, n)
		}
		if n := testing.AllocsPerRun(100, func() { _, _ = tab.Lookup(a) }); n != 0 {
			t.Errorf("Table.Lookup(%s) allocates %v times", q, n)
		}
	}
}

// TestFrozenLayoutExactSize: Freeze sizes every array to its length, so a
// frozen value carries no append slack.
func TestFrozenLayoutExactSize(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	added := parityPrefixes(r, 200, true, true)
	sb := NewBuilder()
	tb := NewTableBuilder[int]()
	for i, p := range added {
		sb.Add(p)
		tb.Add(p, i)
	}
	s, tab := sb.Freeze(), tb.Freeze()
	if len(s.lo4) != len(s.hi4) || len(s.lo6) != len(s.hi6) || len(tab.st4) != len(tab.vi4) || len(tab.st6) != len(tab.vi6) {
		t.Fatal("parallel arrays differ in length")
	}
	for name, c := range map[string][2]int{
		"lo4": {len(s.lo4), cap(s.lo4)}, "hi4": {len(s.hi4), cap(s.hi4)},
		"lo6": {len(s.lo6), cap(s.lo6)}, "hi6": {len(s.hi6), cap(s.hi6)},
		"st4": {len(tab.st4), cap(tab.st4)}, "vi4": {len(tab.vi4), cap(tab.vi4)},
		"st6": {len(tab.st6), cap(tab.st6)}, "vi6": {len(tab.vi6), cap(tab.vi6)},
	} {
		if c[0] != c[1] {
			t.Errorf("%s: len %d cap %d, want equal", name, c[0], c[1])
		}
	}
	if s.Len() != len(s.lo4)+len(s.lo6) {
		t.Errorf("Len() = %d", s.Len())
	}
}

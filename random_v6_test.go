package cidr

import (
	"encoding/binary"
	"math/rand"
	"net/netip"
	"testing"
)

// Randomized IPv6 parity tests: the IPv6 counterparts of TestSetRandomParity,
// TestTableRandomParity and TestRangePrefixesRandom. They reuse the linear-scan
// oracles (containsOracle, lpmOracle) and checkCover, with a fixed seed so a
// failure reproduces.
//
// The generators stay out of the IPv4-mapped space ::ffff:0:0/96: a generated
// prefix never overlaps it (so ::/0 and other short prefixes that cover it are
// not drawn), no query address is inside it, and range endpoints are kept above
// it. How mapped addresses are handled is being changed separately; these tests
// are about the IPv6 interval logic, not that boundary.

var mappedV4 = netip.MustParsePrefix("::ffff:0:0/96")

func addrFrom128(hi, lo uint64) netip.Addr {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], hi)
	binary.BigEndian.PutUint64(b[8:], lo)
	return netip.AddrFrom16(b)
}

// randTail returns a with every bit at index >= keep (0 = most significant)
// replaced by a random bit; the first keep bits are preserved.
func randTail(r *rand.Rand, a netip.Addr, keep int) netip.Addr {
	b := a.As16()
	rnd := addrFrom128(r.Uint64(), r.Uint64()).As16()
	for i := 0; i < 128; i++ {
		if i >= keep {
			mask := byte(0x80) >> (i & 7)
			b[i>>3] = b[i>>3]&^mask | rnd[i>>3]&mask
		}
	}
	return netip.AddrFrom16(b)
}

// v6Bases returns n random /32 bases whose first group is non-zero, so they and
// everything under them lie above the mapped space.
func v6Bases(r *rand.Rand, n int) []netip.Addr {
	bases := make([]netip.Addr, n)
	for i := range bases {
		hi := r.Uint64()
		if hi>>48 == 0 {
			hi |= 1 << 63
		}
		bases[i] = addrFrom128(hi&0xffffffff00000000, 0)
	}
	return bases
}

// randV6Prefixes draws n prefixes of length 0-128 that nest and collide: half
// are fresh draws under one of a few /32 bases, the other half are children
// (or exact duplicates) of an earlier prefix. Prefixes overlapping the mapped
// space are rejected and redrawn.
func randV6Prefixes(r *rand.Rand, n int) []netip.Prefix {
	bases := v6Bases(r, 4)
	var out []netip.Prefix
	for len(out) < n {
		var p netip.Prefix
		switch k := r.Intn(8); {
		case k < 4 || len(out) == 0: // fresh draw under a base, any length
			a := randTail(r, bases[r.Intn(len(bases))], 32)
			p = netip.PrefixFrom(a, r.Intn(129)).Masked()
		case k == 4: // exact duplicate of an earlier prefix (last-added-wins)
			p = out[r.Intn(len(out))]
		default: // a descendant of an earlier prefix, up to 24 bits longer
			parent := out[r.Intn(len(out))]
			bits := min(128, parent.Bits()+r.Intn(25))
			p = netip.PrefixFrom(randTail(r, parent.Addr(), parent.Bits()), bits).Masked()
		}
		if p.Overlaps(mappedV4) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// randV6Queries returns queries biased to the prefix boundaries: each prefix's
// first and last address and their immediate neighbours, a random address
// inside it, plus a few fully random addresses. Addresses in the mapped space
// (and the invalid zero Addr from stepping off either end) are dropped.
func randV6Queries(r *rand.Rand, prefixes []netip.Prefix) []netip.Addr {
	var qs []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !mappedV4.Contains(a) {
			qs = append(qs, a)
		}
	}
	for _, p := range prefixes {
		first, last := p.Addr(), LastAddr(p)
		add(first)
		add(first.Prev())
		add(last)
		add(last.Next())
		add(randTail(r, first, p.Bits()))
	}
	for i := 0; i < len(prefixes); i++ {
		add(addrFrom128(r.Uint64(), r.Uint64()))
	}
	return qs
}

func TestSetRandomParityV6(t *testing.T) {
	r := rand.New(rand.NewSource(61))
	prefixes := randV6Prefixes(r, 600)
	b := NewBuilder()
	for _, p := range prefixes {
		b.Add(p)
	}
	set := b.Freeze()
	queries := randV6Queries(r, prefixes)
	var hits int
	for _, a := range queries {
		got, want := set.Contains(a), containsOracle(prefixes, a)
		if got != want {
			t.Fatalf("Contains(%s) = %v, want %v", a, got, want)
		}
		if want {
			hits++
		}
	}
	// guard against a degenerate generator that never (or always) hits
	if hits == 0 || hits == len(queries) {
		t.Fatalf("%d of %d queries hit; the generator should mix hits and misses", hits, len(queries))
	}
}

func TestTableRandomParityV6(t *testing.T) {
	r := rand.New(rand.NewSource(62))
	prefixes := randV6Prefixes(r, 600)
	vals := make([]int, len(prefixes))
	b := NewTableBuilder[int]()
	for i, p := range prefixes {
		vals[i] = i
		b.Add(p, i)
	}
	tab := b.Freeze()
	queries := randV6Queries(r, prefixes)
	var hits int
	for _, a := range queries {
		gotV, gotOK := tab.Lookup(a)
		wantV, wantOK := lpmOracle(prefixes, vals, a)
		if gotOK != wantOK || (gotOK && gotV != wantV) {
			t.Fatalf("Lookup(%s) = (%d,%v), want (%d,%v)", a, gotV, gotOK, wantV, wantOK)
		}
		if wantOK {
			hits++
		}
	}
	if hits == 0 || hits == len(queries) {
		t.Fatalf("%d of %d queries hit; the generator should mix hits and misses", hits, len(queries))
	}
}

// randV6Range returns a random inclusive range lo <= hi whose endpoints lie
// above the mapped space. Shapes: two arbitrary addresses; two addresses that
// share a long prefix (so the split is deep); a range ending at
// ffff:...:ffff; a single address; and a range from a prefix's first address to
// its last.
func randV6Range(r *rand.Rand, bases []netip.Addr) (lo, hi netip.Addr) {
	base := bases[r.Intn(len(bases))]
	switch r.Intn(5) {
	case 0:
		lo, hi = addrFrom128(r.Uint64()|1<<63, r.Uint64()), addrFrom128(r.Uint64()|1<<63, r.Uint64())
	case 1:
		keep := 32 + r.Intn(96)
		lo, hi = randTail(r, base, keep), randTail(r, base, keep)
	case 2:
		lo, hi = randTail(r, base, 32), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	case 3:
		lo = randTail(r, base, 32)
		hi = lo
	default:
		p := netip.PrefixFrom(randTail(r, base, 32), 32+r.Intn(97)).Masked()
		lo, hi = p.Addr(), LastAddr(p)
	}
	if hi.Less(lo) {
		lo, hi = hi, lo
	}
	return lo, hi
}

func TestRangePrefixesRandomV6(t *testing.T) {
	r := rand.New(rand.NewSource(63))
	bases := v6Bases(r, 4)
	for i := 0; i < 5000; i++ {
		lo, hi := randV6Range(r, bases)
		ps := RangePrefixes(lo, hi)
		checkCover(t, lo, hi, ps)
		for _, p := range ps {
			if p.Overlaps(mappedV4) {
				t.Fatalf("%v-%v: piece %v overlaps the mapped space", lo, hi, p)
			}
		}
	}
}

// TestSetAddRangeRandomV6 checks Set.AddRange on random v6 ranges against the
// interval itself: the endpoints and their neighbours, and random addresses
// inside and outside.
func TestSetAddRangeRandomV6(t *testing.T) {
	r := rand.New(rand.NewSource(64))
	bases := v6Bases(r, 4)
	for i := 0; i < 1000; i++ {
		lo, hi := randV6Range(r, bases)
		b := NewBuilder()
		b.AddRange(lo, hi)
		set := b.Freeze()
		in := func(a netip.Addr) bool { return lo.Compare(a) <= 0 && a.Compare(hi) <= 0 }
		qs := []netip.Addr{lo, hi, lo.Prev(), hi.Next(), randTail(r, lo, 100), randTail(r, hi, 100), addrFrom128(r.Uint64()|1<<63, r.Uint64())}
		for _, a := range qs {
			if !a.IsValid() || mappedV4.Contains(a) {
				continue
			}
			if got, want := set.Contains(a), in(a); got != want {
				t.Fatalf("range %v-%v: Contains(%s) = %v, want %v", lo, hi, a, got, want)
			}
		}
	}
}

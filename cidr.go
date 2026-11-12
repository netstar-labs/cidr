// Package cidr provides fast, immutable IPv4/IPv6 lookups over a set of CIDR
// prefixes, built once and queried concurrently with zero per-query allocation.
//
// Two structures cover the two questions callers ask:
//
//   - Set answers membership — "is this address in any added prefix?" (yes/no).
//     Overlapping prefixes are merged, so it is the smallest, fastest form.
//
//   - Table[V] answers value lookup — "what value is attached to the most
//     specific prefix covering this address?" (yes + data). It resolves nested
//     prefixes into disjoint segments at build time (longest-prefix match), so a
//     query is a single binary search that returns the value directly.
//
// Once frozen, both are backed by sorted, contiguous arrays of plain integers
// (uint32 for IPv4, a pair of uint64 words for IPv6): no pointer-chasing on the
// query path, no interface dispatch, and no pointers in the address arrays. The
// builders work in net/netip addresses; Freeze converts. For the static,
// build-once-query-many workloads this package targets — blocklists, allowlists,
// IP-to-ASN and geo tables — a
// sorted range array is designed to be faster and an order of magnitude smaller
// than a prefix trie. That comparison was made at design time against a
// path-compressed trie that is not part of this repository and is not
// reproduced here; see docs/architecture.md for the trade-off.
//
// The package also includes a stdlib-only MaxMind DB reader (OpenMMDB). MMDB
// lookups decode a map per query and are not allocation-free.
//
// The package has no dependency beyond the Go standard library.
//
// Build with a Builder / TableBuilder, then Freeze to an immutable value:
//
//	b := cidr.NewBuilder()
//	b.AddPrefix("192.0.2.0/24")
//	set := b.Freeze()
//	set.Contains(netip.MustParseAddr("192.0.2.10")) // true
package cidr

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
)

// iprange is a closed, inclusive address interval [lo, hi] within one family.
type iprange struct {
	lo, hi netip.Addr
}

// ParsePrefix parses "10.0.0.0/8" or "2001:db8::/32", or a bare address
// ("1.2.3.4", "::1") promoted to a host route (/32 or /128). The returned
// prefix is masked to its network address. An IPv4-mapped prefix
// (::ffff:a.b.c.d/n with n >= 96) is returned as the IPv4 prefix /n-96;
// shorter prefixes stay IPv6.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return unmapPrefix(p).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// unmapPrefix folds an IPv4-mapped prefix (::ffff:a.b.c.d/n, n >= 96) to the IPv4
// prefix /n-96, so it lands in the IPv4 array where Unmap()ed queries look; the
// rebase keeps longest-prefix match correct against native IPv4 prefixes.
// Prefixes shorter than /96 are genuinely IPv6 and are returned unchanged.
func unmapPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p
}

// LastAddr returns the last address of p's masked range: the network address with
// every host bit set (for IPv4 the broadcast address). The prefix is masked first,
// so host bits set in p.Addr() are ignored: LastAddr(10.1.2.3/8) is 10.255.255.255.
//
// An IPv4 prefix yields an IPv4 address and an IPv6 prefix an IPv6 address. LastAddr
// does no IPv4-mapped folding (Builder.Add does): the prefix ::ffff:10.0.0.0/104 is
// an IPv6 prefix and yields the IPv6 address ::ffff:10.255.255.255, not 10.255.255.255.
// For an invalid prefix (the zero Prefix, or Bits outside the family's width) the
// result is unspecified and does not panic; check p.IsValid first.
func LastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	a := p.Addr()
	if a.Is4() {
		return u128From4(a).or(lowMask(32 - p.Bits())).to4()
	}
	return u128From16(a).or(lowMask(128 - p.Bits())).to16()
}

// plusOneLess reports whether hi+1 < x, treating hi+1 as +infinity when hi is
// the maximum address of its family (so nothing sorts after it).
func plusOneLess(hi, x netip.Addr) bool {
	n := hi.Next()
	if !n.IsValid() {
		return false
	}
	return n.Less(x)
}

// mergeRanges sorts intervals by lo and coalesces overlapping or adjacent ones.
// It never modifies rs, and the result shares no memory with it: the sort and
// merge run in place on one private copy of rs. That copy is returned as is
// (capacity clipped to its length) when the merge kept at least three quarters
// of the intervals, since trimming would save little; otherwise it is copied to
// a slice sized to the merged length (up to allocator rounding) so the result
// does not pin the much larger input.
func mergeRanges(rs []iprange) []iprange {
	if len(rs) < 2 {
		return slices.Clone(rs)
	}
	work := slices.Clone(rs)
	slices.SortFunc(work, func(a, b iprange) int { return a.lo.Compare(b.lo) })
	n := 1 // work[:n] is the merged prefix; n <= index of the next element read
	for _, r := range work[1:] {
		last := &work[n-1]
		if plusOneLess(last.hi, r.lo) { // gap: r starts strictly past last.hi+1
			work[n] = r
			n++
			continue
		}
		if last.hi.Less(r.hi) {
			last.hi = r.hi
		}
	}
	if n >= len(work)*3/4 {
		return work[:n:n]
	}
	return slices.Clone(work[:n])
}

// Set is an immutable IPv4/IPv6 membership set. The zero Set is a valid empty
// set. Safe for concurrent use once built.
type Set struct {
	lo4, hi4 []uint32 // sorted, disjoint closed intervals [lo4[i], hi4[i]]
	lo6, hi6 []u128
}

// Builder accumulates prefixes for a Set. Not safe for concurrent use.
type Builder struct {
	v4, v6 []iprange
}

// NewBuilder returns an empty membership-set builder.
func NewBuilder() *Builder { return &Builder{} }

// Add inserts a prefix (masked to its network) into the set under construction.
// An IPv4-mapped prefix (::ffff:a.b.c.d/n with n >= 96) is stored as the IPv4
// prefix /n-96; shorter prefixes stay IPv6.
func (b *Builder) Add(p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	p = unmapPrefix(p).Masked()
	r := iprange{lo: p.Addr(), hi: LastAddr(p)}
	if p.Addr().Is4() {
		b.v4 = append(b.v4, r)
	} else {
		b.v6 = append(b.v6, r)
	}
}

// AddPrefix parses s (a CIDR or bare address, see ParsePrefix) and adds it,
// returning any parse error.
func (b *Builder) AddPrefix(s string) error {
	p, err := ParsePrefix(s)
	if err != nil {
		return err
	}
	b.Add(p)
	return nil
}

// Freeze compiles the accumulated prefixes into an immutable Set. The Set owns
// its storage: the Builder may be reused, and further Add and Freeze calls
// never affect a Set already returned.
func (b *Builder) Freeze() *Set {
	s := &Set{}
	m4 := mergeRanges(b.v4)
	s.lo4, s.hi4 = make([]uint32, len(m4)), make([]uint32, len(m4))
	for i, r := range m4 {
		s.lo4[i], s.hi4[i] = addr4(r.lo), addr4(r.hi)
	}
	m6 := mergeRanges(b.v6)
	s.lo6, s.hi6 = make([]u128, len(m6)), make([]u128, len(m6))
	for i, r := range m6 {
		s.lo6[i], s.hi6[i] = u128From16(r.lo), u128From16(r.hi)
	}
	return s
}

// Contains reports whether a is covered by any prefix in the set. An IPv4-mapped
// IPv6 address is matched as the IPv4 address it represents, and a zone on a is
// ignored.
func (s *Set) Contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		x := addr4(a)
		// First interval whose lo > x; the candidate is the one before it.
		i := search4(s.lo4, x)
		return i > 0 && x <= s.hi4[i-1] // x >= lo holds by construction
	}
	x := u128From16(a) // As16 ignores any zone
	i := search6(s.lo6, x)
	return i > 0 && !s.hi6[i-1].less(x)
}

// Len returns the number of disjoint intervals in the set (after merging), for
// both families. It is not the number of prefixes added.
func (s *Set) Len() int { return len(s.lo4) + len(s.lo6) }

// addr4 returns the IPv4 address a as an integer.
func addr4(a netip.Addr) uint32 {
	v := a.As4()
	return binary.BigEndian.Uint32(v[:])
}

// search4 returns the index of the first element of xs greater than x (len(xs)
// when none is): sort.Search without the closure call.
func search4(xs []uint32, x uint32) int {
	lo, hi := 0, len(xs)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if x < xs[m] {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return lo
}

// search6 is search4 for IPv6 addresses.
func search6(xs []u128, x u128) int {
	lo, hi := 0, len(xs)
	for lo < hi {
		m := int(uint(lo+hi) >> 1)
		if x.less(xs[m]) {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return lo
}

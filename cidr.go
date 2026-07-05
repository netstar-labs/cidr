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
// Both are backed by sorted, contiguous arrays of net/netip addresses: no
// pointer-chasing, no interface dispatch, and a flat memory layout that
// serialises trivially. For the static, build-once-query-many workloads this
// package targets — blocklists, allowlists, IP-to-ASN and geo tables — a sorted
// range array is both faster and an order of magnitude smaller than a prefix
// trie; see docs/architecture.md for the measurements and the trade-off.
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
	"net/netip"
	"sort"
	"strings"
)

// iprange is a closed, inclusive address interval [lo, hi] within one family.
type iprange struct {
	lo, hi netip.Addr
}

// ParsePrefix parses "10.0.0.0/8" or "2001:db8::/32", or a bare address
// ("1.2.3.4", "::1") promoted to a host route (/32 or /128). The returned
// prefix is masked to its network address.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// lastAddr returns the broadcast (all-host-bits-set) address of a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	p = p.Masked()
	a := p.Addr()
	if a.Is4() {
		v := a.As4()
		host := 32 - p.Bits()
		u := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
		if host < 32 {
			u |= (uint32(1) << host) - 1
		} else {
			u = ^uint32(0)
		}
		return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
	}
	v := a.As16()
	host := 128 - p.Bits()
	for i := 15; i >= 0 && host > 0; i-- {
		take := host
		if take > 8 {
			take = 8
		}
		v[i] |= byte((1 << take) - 1)
		host -= take
	}
	return netip.AddrFrom16(v)
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
func mergeRanges(rs []iprange) []iprange {
	if len(rs) < 2 {
		return rs
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo.Less(rs[j].lo) })
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if plusOneLess(last.hi, r.lo) { // gap: r starts strictly past last.hi+1
			out = append(out, r)
			continue
		}
		if last.hi.Less(r.hi) {
			last.hi = r.hi
		}
	}
	return out
}

// Set is an immutable IPv4/IPv6 membership set. The zero Set is a valid empty
// set. Safe for concurrent use once built.
type Set struct {
	v4 []iprange // sorted, disjoint
	v6 []iprange
}

// Builder accumulates prefixes for a Set. Not safe for concurrent use.
type Builder struct {
	v4, v6 []iprange
}

// NewBuilder returns an empty membership-set builder.
func NewBuilder() *Builder { return &Builder{} }

// Add inserts a prefix (masked to its network) into the set under construction.
func (b *Builder) Add(p netip.Prefix) {
	if !p.IsValid() {
		return
	}
	p = p.Masked()
	r := iprange{lo: p.Addr(), hi: lastAddr(p)}
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

// Freeze compiles the accumulated prefixes into an immutable Set.
func (b *Builder) Freeze() *Set {
	return &Set{v4: mergeRanges(b.v4), v6: mergeRanges(b.v6)}
}

// Contains reports whether a is covered by any prefix in the set.
func (s *Set) Contains(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	rs := s.v4
	if a.Is6() {
		rs = s.v6
	}
	// First interval whose lo > a; the candidate is the one before it.
	i := sort.Search(len(rs), func(i int) bool { return a.Less(rs[i].lo) })
	if i == 0 {
		return false
	}
	return !rs[i-1].hi.Less(a) // a <= hi (a >= lo holds by construction)
}

// Len returns the number of disjoint intervals in the set (after merging), for
// both families. It is not the number of prefixes added.
func (s *Set) Len() int { return len(s.v4) + len(s.v6) }

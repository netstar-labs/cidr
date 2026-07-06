package cidr

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// AddRange adds the inclusive address interval [lo, hi] to the membership set.
// Both ends must be the same family and lo <= hi; an invalid range is ignored.
// This is the natural entry point for range-based feeds (start/end columns)
// such as iptoasn.com or the RIR delegated files.
func (b *Builder) AddRange(lo, hi netip.Addr) {
	lo, hi = lo.Unmap(), hi.Unmap()
	if !validRange(lo, hi) {
		return
	}
	r := iprange{lo: lo, hi: hi}
	if lo.Is4() {
		b.v4 = append(b.v4, r)
	} else {
		b.v6 = append(b.v6, r)
	}
}

// AddRange attaches value v to the inclusive interval [lo, hi]. The range is
// decomposed into its minimal set of CIDR prefixes, each carrying v, so
// longest-prefix match stays well defined: a more-specific range's pieces have
// longer masks and win over a covering one. An invalid range is ignored.
func (b *TableBuilder[V]) AddRange(lo, hi netip.Addr, v V) {
	for _, p := range rangePrefixes(lo, hi) {
		b.Add(p, v)
	}
}

func validRange(lo, hi netip.Addr) bool {
	return lo.IsValid() && hi.IsValid() && lo.Is4() == hi.Is4() && !hi.Less(lo)
}

// rangePrefixes decomposes the inclusive interval [lo, hi] into the minimal,
// ordered set of CIDR prefixes that exactly cover it (the standard range-to-CIDR
// split). Returns nil for an invalid range.
func rangePrefixes(lo, hi netip.Addr) []netip.Prefix {
	lo, hi = lo.Unmap(), hi.Unmap()
	if !validRange(lo, hi) {
		return nil
	}
	v4 := lo.Is4()
	width := 128
	var a, b u128
	if v4 {
		width, a, b = 32, u128From4(lo), u128From4(hi)
	} else {
		a, b = u128From16(lo), u128From16(hi)
	}
	full := lowMask(width) // all-ones for the family

	var out []netip.Prefix
	for {
		// Largest block by alignment: a has this many trailing zero bits.
		alignK := a.trailingZeros()
		if alignK > width {
			alignK = width
		}
		// Largest block by remaining size: 2^fitK <= (b - a + 1).
		d := b.sub(a)
		fitK := width
		if d.cmp(full) != 0 { // not the whole space (avoids the +1 overflow)
			fitK = d.add(u128{0, 1}).highBit()
		}
		k := alignK
		if fitK < k {
			k = fitK
		}

		base := a.to4()
		if !v4 {
			base = a.to16()
		}
		out = append(out, netip.PrefixFrom(base, width-k))

		// blockLast = a + 2^k - 1, computed as a | (low-k-bits) to avoid overflow.
		blockLast := a.or(lowMask(k))
		if blockLast.cmp(b) >= 0 {
			break
		}
		a = blockLast.add(u128{0, 1})
	}
	return out
}

// u128 is a minimal unsigned 128-bit integer for range arithmetic. IPv4
// addresses occupy the low 32 bits (hi == 0).
type u128 struct{ hi, lo uint64 }

func u128From4(a netip.Addr) u128 {
	v := a.As4()
	return u128{0, uint64(binary.BigEndian.Uint32(v[:]))}
}

func u128From16(a netip.Addr) u128 {
	v := a.As16()
	return u128{binary.BigEndian.Uint64(v[:8]), binary.BigEndian.Uint64(v[8:])}
}

func (a u128) to4() netip.Addr {
	var v [4]byte
	binary.BigEndian.PutUint32(v[:], uint32(a.lo))
	return netip.AddrFrom4(v)
}

func (a u128) to16() netip.Addr {
	var v [16]byte
	binary.BigEndian.PutUint64(v[:8], a.hi)
	binary.BigEndian.PutUint64(v[8:], a.lo)
	return netip.AddrFrom16(v)
}

func (a u128) or(b u128) u128 { return u128{a.hi | b.hi, a.lo | b.lo} }

func (a u128) add(b u128) u128 {
	lo := a.lo + b.lo
	hi := a.hi + b.hi
	if lo < a.lo {
		hi++ // carry
	}
	return u128{hi, lo}
}

func (a u128) sub(b u128) u128 {
	lo := a.lo - b.lo
	hi := a.hi - b.hi
	if a.lo < b.lo {
		hi-- // borrow
	}
	return u128{hi, lo}
}

func (a u128) cmp(b u128) int {
	switch {
	case a.hi != b.hi:
		if a.hi < b.hi {
			return -1
		}
		return 1
	case a.lo != b.lo:
		if a.lo < b.lo {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// trailingZeros returns the number of low zero bits (128 for the zero value).
func (a u128) trailingZeros() int {
	if a.lo != 0 {
		return bits.TrailingZeros64(a.lo)
	}
	if a.hi != 0 {
		return 64 + bits.TrailingZeros64(a.hi)
	}
	return 128
}

// highBit returns the index of the most-significant set bit (-1 for zero), i.e.
// floor(log2(a)).
func (a u128) highBit() int {
	if a.hi != 0 {
		return 127 - bits.LeadingZeros64(a.hi)
	}
	if a.lo != 0 {
		return 63 - bits.LeadingZeros64(a.lo)
	}
	return -1
}

// lowMask returns a value with the low k bits set (0 <= k <= 128).
func lowMask(k int) u128 {
	switch {
	case k <= 0:
		return u128{}
	case k < 64:
		return u128{0, (1 << uint(k)) - 1}
	case k == 64:
		return u128{0, ^uint64(0)}
	case k < 128:
		return u128{(1 << uint(k-64)) - 1, ^uint64(0)}
	default:
		return u128{^uint64(0), ^uint64(0)}
	}
}

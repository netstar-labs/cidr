package cidr

import (
	"net/netip"
	"sort"
)

// Table is an immutable IPv4/IPv6 longest-prefix-match table returning a value V
// (e.g. an ASN, an org name, or an encoded uint64). Nesting is resolved at build
// time into disjoint segments, so Lookup is one binary search with no
// allocation. The zero Table is a valid empty table. Safe for concurrent use
// once built.
type Table[V any] struct {
	v4   []segment // sorted, disjoint; vi<0 marks a gap (no covering prefix)
	v6   []segment
	vals []V
}

// segment starts at `start` and carries the value index of the most-specific
// prefix covering [start, next segment). A negative vi is a gap.
type segment struct {
	start netip.Addr
	vi    int32
}

// pfx is an accumulated prefix with its mask length and value index.
type pfx struct {
	lo, hi netip.Addr
	length int
	vi     int32
}

// TableBuilder accumulates (prefix, value) pairs for a Table. Not safe for
// concurrent use.
type TableBuilder[V any] struct {
	v4, v6 []pfx
	vals   []V
}

// NewTableBuilder returns an empty value-table builder.
func NewTableBuilder[V any]() *TableBuilder[V] { return &TableBuilder[V]{} }

// Add attaches value v to prefix p (masked to its network). When prefixes nest,
// the longest (most specific) one wins at lookup time. Adding the same prefix
// more than once keeps the most recently added value.
func (b *TableBuilder[V]) Add(p netip.Prefix, v V) {
	if !p.IsValid() {
		return
	}
	p = p.Masked()
	vi := int32(len(b.vals))
	b.vals = append(b.vals, v)
	e := pfx{lo: p.Addr(), hi: lastAddr(p), length: p.Bits(), vi: vi}
	if p.Addr().Is4() {
		b.v4 = append(b.v4, e)
	} else {
		b.v6 = append(b.v6, e)
	}
}

// AddPrefix parses s (a CIDR or bare address, see ParsePrefix) and adds it with
// value v, returning any parse error.
func (b *TableBuilder[V]) AddPrefix(s string, v V) error {
	p, err := ParsePrefix(s)
	if err != nil {
		return err
	}
	b.Add(p, v)
	return nil
}

// Freeze compiles the accumulated prefixes into an immutable Table.
func (b *TableBuilder[V]) Freeze() *Table[V] {
	return &Table[V]{
		v4:   sweep(b.v4),
		v6:   sweep(b.v6),
		vals: b.vals,
	}
}

// dedup collapses exact-duplicate prefixes (same network and length), keeping
// the last-added value (highest vi). This makes the winner deterministic when
// the same prefix carries conflicting values; distinct prefixes are untouched.
func dedup(prefixes []pfx) []pfx {
	keep := make(map[[2]netip.Addr]pfx, len(prefixes))
	for _, p := range prefixes {
		k := [2]netip.Addr{p.lo, p.hi}
		if ex, ok := keep[k]; !ok || p.vi > ex.vi {
			keep[k] = p
		}
	}
	if len(keep) == len(prefixes) {
		return prefixes // no duplicates, avoid the copy
	}
	out := make([]pfx, 0, len(keep))
	for _, p := range keep {
		out = append(out, p)
	}
	return out
}

// sweep resolves nested/overlapping prefixes into disjoint segments, each
// labelled with the longest-prefix (most-specific) value. A line sweep opens
// each prefix at lo and closes it just past hi; at every boundary the winner is
// the longest active prefix. O((P+S)·log P) with a constant-length scan (≤129)
// per boundary.
func sweep(prefixes []pfx) []segment {
	if len(prefixes) == 0 {
		return nil
	}
	prefixes = dedup(prefixes)
	// open at lo, close just past hi (inf when hi is the family maximum).
	type event struct {
		at     netip.Addr
		inf    bool
		open   bool
		length int
		vi     int32
	}
	evs := make([]event, 0, len(prefixes)*2)
	for _, p := range prefixes {
		evs = append(evs, event{at: p.lo, open: true, length: p.length, vi: p.vi})
		if n := p.hi.Next(); n.IsValid() {
			evs = append(evs, event{at: n, length: p.length, vi: p.vi})
		} else {
			evs = append(evs, event{inf: true, length: p.length, vi: p.vi})
		}
	}
	sort.Slice(evs, func(i, j int) bool {
		if evs[i].inf != evs[j].inf {
			return !evs[i].inf // finite coordinates before +infinity
		}
		return evs[i].at.Less(evs[j].at)
	})

	var (
		count [129]int   // active prefixes per mask length (0..128)
		valBy [129]int32 // active value index per mask length
		out   []segment
	)
	for i := 0; i < len(evs); {
		at, inf := evs[i].at, evs[i].inf
		for i < len(evs) && evs[i].inf == inf && (inf || evs[i].at == at) {
			e := evs[i]
			if e.open {
				count[e.length]++
				valBy[e.length] = e.vi
			} else {
				count[e.length]--
			}
			i++
		}
		if inf { // past the address space; nothing left to emit
			break
		}
		winner := int32(-1)
		for l := 128; l >= 0; l-- {
			if count[l] > 0 {
				winner = valBy[l]
				break
			}
		}
		if len(out) > 0 && out[len(out)-1].vi == winner {
			continue // extend the previous segment
		}
		out = append(out, segment{start: at, vi: winner})
	}
	return out
}

// Lookup returns the value of the most-specific prefix covering a, or the zero V
// and false when no prefix covers it.
func (t *Table[V]) Lookup(a netip.Addr) (V, bool) {
	if !a.IsValid() {
		var zero V
		return zero, false
	}
	a = a.Unmap()
	segs := t.v4
	if a.Is6() {
		segs = t.v6
	}
	i := sort.Search(len(segs), func(i int) bool { return a.Less(segs[i].start) })
	if i == 0 {
		var zero V
		return zero, false
	}
	vi := segs[i-1].vi
	if vi < 0 {
		var zero V
		return zero, false
	}
	return t.vals[vi], true
}

// EncodeASN packs an autonomous-system answer into a uint64:
//
//	bits [31:0]  ASN            full 4-byte ASN space
//	bits [55:32] org id (24)    index into a caller-side []string (16.7M orgs)
//	bits [63:56] flags (8)      caller-defined (e.g. bogon / anycast / rir)
//
// It is the compact "encoded uint64" value for a Table[uint64]; DecodeASN
// recovers the fields, and the org id can index a side table for the full name.
func EncodeASN(asn uint32, orgID uint32, flags uint8) uint64 {
	return uint64(asn) | uint64(orgID&0xffffff)<<32 | uint64(flags)<<56
}

// DecodeASN unpacks a value produced by EncodeASN.
func DecodeASN(v uint64) (asn uint32, orgID uint32, flags uint8) {
	return uint32(v), uint32(v>>32) & 0xffffff, uint8(v >> 56)
}

package cidr

import (
	"math/rand"
	"net/netip"
	"testing"
)

// benchPrefixes returns n random prefixes of one family: /24 for IPv4, /48 for
// IPv6.
func benchPrefixes(r *rand.Rand, n int, v6 bool) []netip.Prefix {
	ps := make([]netip.Prefix, n)
	for i := range ps {
		if v6 {
			var a [16]byte
			r.Read(a[:6])
			a[0] = 0x20
			ps[i] = netip.PrefixFrom(netip.AddrFrom16(a), 48)
		} else {
			ps[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), 0}), 24)
		}
	}
	return ps
}

// benchQueries returns 4096 random addresses of one family.
func benchQueries(r *rand.Rand, v6 bool) []netip.Addr {
	q := make([]netip.Addr, 4096)
	for i := range q {
		if v6 {
			var a [16]byte
			r.Read(a[:])
			a[0] = 0x20
			q[i] = netip.AddrFrom16(a)
		} else {
			q[i] = netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
		}
	}
	return q
}

func benchSet(b *testing.B, n int, v6 bool) {
	r := rand.New(rand.NewSource(7))
	bl := NewBuilder()
	for _, p := range benchPrefixes(r, n, v6) {
		bl.Add(p.Masked())
	}
	set := bl.Freeze()
	q := benchQueries(r, v6)
	b.ReportAllocs()
	b.ResetTimer()
	var s bool
	for i := 0; i < b.N; i++ {
		s = s != set.Contains(q[i&4095])
	}
	_ = s
}

func benchTable(b *testing.B, n int, v6 bool) {
	r := rand.New(rand.NewSource(8))
	bl := NewTableBuilder[uint64]()
	for i, p := range benchPrefixes(r, n, v6) {
		bl.Add(p.Masked(), uint64(i))
	}
	tab := bl.Freeze()
	q := benchQueries(r, v6)
	b.ReportAllocs()
	b.ResetTimer()
	var s uint64
	for i := 0; i < b.N; i++ {
		v, _ := tab.Lookup(q[i&4095])
		s ^= v
	}
	_ = s
}

func BenchmarkSetContainsV6(b *testing.B)     { benchSet(b, 4000, true) }
func BenchmarkSetContains500k(b *testing.B)   { benchSet(b, 500000, false) }
func BenchmarkSetContainsV6500k(b *testing.B) { benchSet(b, 500000, true) }
func BenchmarkTableLookupV6(b *testing.B)     { benchTable(b, 4000, true) }
func BenchmarkTableLookup500k(b *testing.B)   { benchTable(b, 500000, false) }
func BenchmarkTableLookupV6500k(b *testing.B) { benchTable(b, 500000, true) }

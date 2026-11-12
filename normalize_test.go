package cidr

import (
	"net/netip"
	"strings"
	"testing"
)

// IPv4-mapped prefixes (#16): ::ffff:a.b.c.d/n with n >= 96 must be stored as the
// IPv4 prefix /n-96, because every query address is Unmap()ed to IPv4 first.

func TestParsePrefixMapped(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"::ffff:1.2.3.0/120", "1.2.3.0/24"},
		{"::ffff:1.2.3.4/128", "1.2.3.4/32"},
		{"::ffff:1.2.3.77/120", "1.2.3.0/24"}, // masked
		{"::ffff:0:0/96", "0.0.0.0/0"},
		{"::ffff:1.2.3.4", "1.2.3.4/32"}, // bare address, already unmapped
		{"1.2.3.0/24", "1.2.3.0/24"},
		{"::ffff:0:0/95", "::fffe:0:0/95"}, // shorter than /96 stays IPv6
		{"2001:db8::/32", "2001:db8::/32"},
	} {
		got, err := ParsePrefix(tc.in)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", tc.in, err)
		}
		if got != netip.MustParsePrefix(tc.want) {
			t.Errorf("ParsePrefix(%q) = %v, want %s", tc.in, got, tc.want)
		}
	}
}

// mappedAddrs are the two spellings of the same IPv4 query.
func mappedAddrs(s string) []netip.Addr {
	a := netip.MustParseAddr(s)
	return []netip.Addr{a, netip.AddrFrom16(a.As16())}
}

func TestMappedPrefixSet(t *testing.T) {
	for _, name := range []string{"Add", "AddPrefix", "LoadSet"} {
		t.Run(name, func(t *testing.T) {
			var s *Set
			switch name {
			case "Add":
				b := NewBuilder()
				b.Add(netip.MustParsePrefix("::ffff:1.2.3.0/120")) // bypasses ParsePrefix
				s = b.Freeze()
			case "AddPrefix":
				b := NewBuilder()
				if err := b.AddPrefix("::ffff:1.2.3.0/120"); err != nil {
					t.Fatal(err)
				}
				s = b.Freeze()
			case "LoadSet":
				var err error
				if s, err = LoadSet(strings.NewReader("::ffff:1.2.3.0/120\n")); err != nil {
					t.Fatal(err)
				}
			}
			if s.Len() != 1 || len(s.v4) != 1 || len(s.v6) != 0 {
				t.Fatalf("stored v4=%d v6=%d, want one v4 interval", len(s.v4), len(s.v6))
			}
			for _, in := range []string{"1.2.3.0", "1.2.3.4", "1.2.3.255"} {
				for _, a := range mappedAddrs(in) {
					if !s.Contains(a) {
						t.Errorf("Contains(%v) = false, want true", a)
					}
				}
			}
			for _, in := range []string{"1.2.2.255", "1.2.4.0"} {
				for _, a := range mappedAddrs(in) {
					if s.Contains(a) {
						t.Errorf("Contains(%v) = true, want false", a)
					}
				}
			}
		})
	}
}

func TestMappedPrefixTable(t *testing.T) {
	for _, name := range []string{"Add", "AddPrefix", "LoadASN"} {
		t.Run(name, func(t *testing.T) {
			var tb *Table[Info]
			switch name {
			case "Add":
				b := NewTableBuilder[Info]()
				b.Add(netip.MustParsePrefix("::ffff:1.2.3.0/120"), Info{ASN: 7})
				tb = b.Freeze()
			case "AddPrefix":
				b := NewTableBuilder[Info]()
				if err := b.AddPrefix("::ffff:1.2.3.0/120", Info{ASN: 7}); err != nil {
					t.Fatal(err)
				}
				tb = b.Freeze()
			case "LoadASN":
				var err error
				if _, tb, err = LoadASN(strings.NewReader("::ffff:1.2.3.0/120 AS7\n")); err != nil {
					t.Fatal(err)
				}
			}
			for _, a := range mappedAddrs("1.2.3.4") {
				v, ok := tb.Lookup(a)
				if !ok || v.ASN != 7 {
					t.Errorf("Lookup(%v) = %+v, %v; want ASN 7", a, v, ok)
				}
			}
			if name == "LoadASN" {
				v, _ := tb.Lookup(netip.MustParseAddr("1.2.3.4"))
				if v.Prefix != "1.2.3.0/24" {
					t.Errorf("Info.Prefix = %q, want 1.2.3.0/24", v.Prefix)
				}
			}
			if _, ok := tb.Lookup(netip.MustParseAddr("1.2.4.1")); ok {
				t.Error("1.2.4.1 matched, want miss")
			}
		})
	}
}

// The /n-96 rebase is what lets a mapped prefix take part in longest-prefix
// match against native IPv4 prefixes.
func TestMappedPrefixLPM(t *testing.T) {
	b := NewTableBuilder[int]()
	b.Add(netip.MustParsePrefix("::ffff:1.2.3.0/120"), 1)   // 1.2.3.0/24
	b.Add(netip.MustParsePrefix("1.2.3.0/25"), 2)           // native
	b.Add(netip.MustParsePrefix("::ffff:1.2.3.128/121"), 3) // 1.2.3.128/25
	tb := b.Freeze()
	for _, tc := range []struct {
		addr string
		want int // 0 = miss
	}{
		{"1.2.3.4", 2},
		{"1.2.3.127", 2},
		{"1.2.3.128", 3},
		{"1.2.3.130", 3},
		{"1.2.3.200", 3},
		{"1.2.3.255", 3},
		{"1.2.4.1", 0},
		{"1.2.2.255", 0},
	} {
		for _, a := range mappedAddrs(tc.addr) {
			v, ok := tb.Lookup(a)
			if tc.want == 0 {
				if ok {
					t.Errorf("Lookup(%v) = %d, want miss", a, v)
				}
			} else if !ok || v != tc.want {
				t.Errorf("Lookup(%v) = %d, %v; want %d", a, v, ok, tc.want)
			}
		}
	}
}

// Prefixes shorter than /96 are genuinely IPv6 and the families never cross: a
// default IPv6 route must not swallow IPv4 queries.
func TestShortMappedPrefixStaysV6(t *testing.T) {
	b := NewBuilder()
	for _, s := range []string{"::/0", "::fffe:0:0/95"} {
		if err := b.AddPrefix(s); err != nil {
			t.Fatal(err)
		}
	}
	s := b.Freeze()
	for _, a := range mappedAddrs("1.2.3.4") {
		if s.Contains(a) {
			t.Errorf("Contains(%v) = true, want false", a)
		}
	}
	if !s.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("::/0 should still match native IPv6")
	}
	if len(s.v4) != 0 {
		t.Errorf("v4 intervals = %d, want 0", len(s.v4))
	}

	tb := NewTableBuilder[int]()
	tb.Add(netip.MustParsePrefix("::/0"), 1)
	tt := tb.Freeze()
	if _, ok := tt.Lookup(netip.MustParseAddr("1.2.3.4")); ok {
		t.Error("Table ::/0 matched an IPv4 query")
	}
}

// Zoned query addresses (#17): netip sorts "fe80::1%eth0" just after "fe80::1", so
// without stripping the zone a Set failed exactly at the last address of a range
// (hi.Less(a)) while a Table, which compares only range starts, matched. A zone
// on the query address is ignored.

var zoneCases = []struct {
	prefix      string
	first, mid  string
	last, miss  string
	missAbove   string // just past the last address
	missBelowIs string // just before the first address
}{
	{"fe80::1/128", "fe80::1", "fe80::1", "fe80::1", "fe80::2", "fe80::2", "fe80::"},
	{"fe80::/64", "fe80::", "fe80::1234:5678", "fe80::ffff:ffff:ffff:ffff", "fe80:0:0:1::", "fe80:0:0:1::", "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	{"2001:db8::/32", "2001:db8::", "2001:db8:1234::1", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db9::", "2001:db9::", "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"},
}

func TestZonedQuerySet(t *testing.T) {
	// One set per prefix, so the last address of each range is a range end (a
	// combined set would merge fe80::1/128 into fe80::/64).
	for _, tc := range zoneCases {
		b := NewBuilder()
		if err := b.AddPrefix(tc.prefix); err != nil {
			t.Fatal(err)
		}
		s := b.Freeze()
		for _, in := range []string{tc.first, tc.mid, tc.last} {
			a := netip.MustParseAddr(in)
			for _, z := range []string{"", "eth0", "1"} {
				if !s.Contains(a.WithZone(z)) {
					t.Errorf("%s: Contains(%v%%%q) = false, want true", tc.prefix, a, z)
				}
			}
		}
		for _, in := range []string{tc.miss, tc.missAbove, tc.missBelowIs} {
			a := netip.MustParseAddr(in)
			if s.Contains(a.WithZone("eth0")) {
				t.Errorf("%s: Contains(%v%%eth0) = true, want miss", tc.prefix, a)
			}
		}
	}
}

func TestZonedQueryTable(t *testing.T) {
	for i, tc := range zoneCases {
		b := NewTableBuilder[int]()
		if err := b.AddPrefix(tc.prefix, i+1); err != nil {
			t.Fatal(err)
		}
		tb := b.Freeze()
		for _, in := range []string{tc.first, tc.mid, tc.last} {
			a := netip.MustParseAddr(in)
			for _, z := range []string{"", "eth0", "1"} {
				if v, ok := tb.Lookup(a.WithZone(z)); !ok || v != i+1 {
					t.Errorf("%s: Lookup(%v%%%q) = %d, %v; want %d", tc.prefix, a, z, v, ok, i+1)
				}
			}
		}
		for _, in := range []string{tc.miss, tc.missAbove, tc.missBelowIs} {
			a := netip.MustParseAddr(in)
			if v, ok := tb.Lookup(a.WithZone("eth0")); ok {
				t.Errorf("%s: Lookup(%v%%eth0) = %d, want miss", tc.prefix, a, v)
			}
		}
	}
}

// The combined case: the three prefixes together, nested fe80::1/128 inside fe80::/64.
func TestZonedQueryCombined(t *testing.T) {
	sb := NewBuilder()
	tb := NewTableBuilder[int]()
	for i, tc := range zoneCases {
		_ = sb.AddPrefix(tc.prefix)
		_ = tb.AddPrefix(tc.prefix, i+1)
	}
	s, tt := sb.Freeze(), tb.Freeze()
	for _, tc := range zoneCases {
		for _, in := range []string{tc.first, tc.mid, tc.last, tc.miss, tc.missAbove, tc.missBelowIs} {
			a := netip.MustParseAddr(in)
			z := a.WithZone("eth0")
			if got, want := s.Contains(z), s.Contains(a); got != want {
				t.Errorf("Set %v: zoned=%v unzoned=%v", a, got, want)
			}
			gv, gok := tt.Lookup(z)
			wv, wok := tt.Lookup(a)
			if gv != wv || gok != wok {
				t.Errorf("Table %v: zoned=(%d,%v) unzoned=(%d,%v)", a, gv, gok, wv, wok)
			}
		}
	}
}

func TestZonedQueryZeroAlloc(t *testing.T) {
	sb := NewBuilder()
	tb := NewTableBuilder[int]()
	for i, tc := range zoneCases {
		_ = sb.AddPrefix(tc.prefix)
		_ = tb.AddPrefix(tc.prefix, i+1)
	}
	s, tt := sb.Freeze(), tb.Freeze()
	plain := netip.MustParseAddr("fe80::ffff:ffff:ffff:ffff")
	zoned := plain.WithZone("eth0")
	var sink bool
	for _, a := range []netip.Addr{plain, zoned} {
		if n := testing.AllocsPerRun(100, func() { sink = s.Contains(a) }); n != 0 {
			t.Errorf("Set.Contains(%v): %v allocs, want 0", a, n)
		}
		if n := testing.AllocsPerRun(100, func() { _, sink = tt.Lookup(a) }); n != 0 {
			t.Errorf("Table.Lookup(%v): %v allocs, want 0", a, n)
		}
	}
	_ = sink
}

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

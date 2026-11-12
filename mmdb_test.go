package cidr

import (
	"errors"
	"math/rand/v2"
	"net"
	"path/filepath"
	"testing"
)

// testdata/test-asn.mmdb is a GeoLite2-ASN-schema database built by the
// mmdb-write command from a fixed spec (see mmdb_test.go's companion in the
// commit message): 1.0.0.0/24 → AS13335, 8.8.8.0/24 → AS15169,
// 9.9.9.0/24 → AS19281, 2606:4700:4700::/48 → AS13335. Dual-stack (ip_version 6),
// 24-bit records.
func TestMMDBLookupASN(t *testing.T) {
	cases := []struct {
		ip   string
		asn  uint64
		org  string
		want bool
	}{
		{"1.0.0.1", 13335, "CLOUDFLARENET", true}, // IPv4-in-IPv6 (::/96) path
		{"8.8.8.8", 15169, "GOOGLE", true},
		{"9.9.9.9", 19281, "QUAD9", true},
		{"2606:4700:4700::1111", 13335, "CLOUDFLARENET", true}, // native IPv6
		{"203.0.113.1", 0, "", false},                          // not in any listed range
		{"2001:db8::1", 0, "", false},
	}
	// Every record size, because 24/28/32-bit node records use distinct encodings
	// (28-bit splits the middle byte's nibbles) — the fixtures are the same spec.
	for _, f := range []string{"test-asn.mmdb", "test-asn28.mmdb", "test-asn32.mmdb"} {
		t.Run(f, func(t *testing.T) {
			db, err := OpenMMDB("testdata/" + f)
			if err != nil {
				t.Fatalf("OpenMMDB: %v", err)
			}
			defer db.Close()
			if got := db.Metadata()["database_type"]; got != "GeoLite2-ASN" {
				t.Errorf("database_type = %v, want GeoLite2-ASN", got)
			}
			for _, c := range cases {
				rec, ok, err := db.Lookup(net.ParseIP(c.ip))
				if err != nil {
					t.Fatalf("Lookup(%s): %v", c.ip, err)
				}
				if ok != c.want {
					t.Errorf("Lookup(%s) found=%v, want %v", c.ip, ok, c.want)
					continue
				}
				if !ok {
					continue
				}
				if got := rec["autonomous_system_number"]; got != c.asn {
					t.Errorf("Lookup(%s) ASN = %v (%T), want %d", c.ip, got, got, c.asn)
				}
				if got := rec["autonomous_system_organization"]; got != c.org {
					t.Errorf("Lookup(%s) org = %v, want %q", c.ip, got, c.org)
				}
			}
		})
	}
}

// testdata/test-country.mmdb is a GeoLite2-Country-schema database with nested
// maps (continent / country / registered_country). Two ranges share the "US"
// record, so the writer deduplicates it and the second lookup resolves through a
// data-section POINTER — exercising the pointer-follow path.
func TestMMDBLookupCountryNested(t *testing.T) {
	db, err := OpenMMDB("testdata/test-country.mmdb")
	if err != nil {
		t.Fatalf("OpenMMDB: %v", err)
	}
	defer db.Close()

	cases := []struct{ ip, iso, continent string }{
		{"1.0.0.1", "US", "NA"},
		{"8.8.8.8", "US", "NA"}, // deduped → pointer-resolved record
		{"81.2.69.1", "GB", "EU"},
		{"2001:67c:2e8::1", "DE", "EU"},
	}
	for _, c := range cases {
		rec, ok, err := db.Lookup(net.ParseIP(c.ip))
		if err != nil || !ok {
			t.Fatalf("Lookup(%s) ok=%v err=%v", c.ip, ok, err)
		}
		country, _ := rec["country"].(map[string]any)
		if got, _ := country["iso_code"].(string); got != c.iso {
			t.Errorf("Lookup(%s) country.iso_code = %q, want %q", c.ip, got, c.iso)
		}
		continent, _ := rec["continent"].(map[string]any)
		if got, _ := continent["code"].(string); got != c.continent {
			t.Errorf("Lookup(%s) continent.code = %q, want %q", c.ip, got, c.continent)
		}
		// names is a nested map[lang]string — confirms recursive map decode.
		if names, _ := country["names"].(map[string]any); len(names) == 0 {
			t.Errorf("Lookup(%s) country.names empty — nested map not decoded", c.ip)
		}
	}
}

func TestMMDBOpenErrors(t *testing.T) {
	if _, err := OpenMMDBBytes([]byte("not an mmdb file at all")); err == nil {
		t.Error("expected an error for a file without the metadata marker")
	}
	if _, err := OpenMMDB("testdata/does-not-exist.mmdb"); err == nil {
		t.Error("expected an error opening a missing file")
	}
}

// BenchmarkMMDBLookup measures the tree walk (the miss cases decode nothing) and the walk
// plus decode for hits, in an IPv6 database: an IPv4 address walks the ::/96 prefix first.
func BenchmarkMMDBLookup(b *testing.B) {
	db, err := OpenMMDB("testdata/test-asn.mmdb")
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range []struct{ name, ip string }{
		{"v4-miss", "203.0.113.1"},
		{"v4-hit", "8.8.8.8"},
		{"v6-miss", "2001:db8::1"},
		{"v6-hit", "2606:4700:4700::1111"},
	} {
		ip := net.ParseIP(c.ip)
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, _, err := db.Lookup(ip); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// refNode is the reference tree walk the lookup must agree with: the whole address, bit by
// bit from the root, with no shortcut. An IPv4 address in an IPv6 tree is 12 zero bytes +
// the address.
func refNode(m *MMDB, ip net.IP) (uint, error) {
	var addr []byte
	if v4 := ip.To4(); v4 != nil {
		if m.ipVersion == 6 {
			addr = append(make([]byte, 12), v4...)
		} else {
			addr = v4
		}
	} else if m.ipVersion == 6 {
		addr = ip.To16()
	} else {
		return 0, errors.New("v6 address in a v4 tree")
	}
	node := uint(0)
	for i := 0; i < len(addr)*8 && node < m.nodeCount; i++ {
		rec, err := m.record(node, (addr[i>>3]>>(7-uint(i&7)))&1 == 1)
		if err != nil {
			return 0, err
		}
		node = rec
	}
	return node, nil
}

// parityIPs returns a fixed mixed set of query addresses: random IPv4 (4-byte and
// IPv4-mapped 16-byte forms), random IPv6, IPv6 whose top 96 bits are zero (::a.b.c.d,
// which is NOT an IPv4 address), and addresses from the databases' known prefixes.
func parityIPs() []net.IP {
	rng := rand.New(rand.NewPCG(1, 2))
	var ips []net.IP
	for i := 0; i < 3000; i++ {
		a := make([]byte, 16)
		for j := range a {
			a[j] = byte(rng.Uint32())
		}
		switch i % 5 {
		case 0:
			ips = append(ips, net.IP(a[:4])) // IPv4, 4-byte form
		case 1:
			ips = append(ips, net.IPv4(a[0], a[1], a[2], a[3])) // IPv4, 16-byte mapped form
		case 2:
			ips = append(ips, net.IP(a)) // IPv6
		case 3:
			clear(a[:12])
			ips = append(ips, net.IP(a)) // ::a.b.c.d
		default:
			copy(a, []byte{0x26, 0x06, 0x47, 0x00, 0x47, 0x00}) // inside 2606:4700:4700::/48
			ips = append(ips, net.IP(a))
		}
	}
	for _, s := range []string{"1.0.0.1", "8.8.8.8", "9.9.9.9", "81.2.69.1", "203.0.113.1", "0.0.0.0", "255.255.255.255",
		"::", "::1", "::1.0.0.1", "::ffff:8.8.8.8", "2606:4700:4700::1111", "2001:67c:2e8::1", "2001:db8::1", "ffff::"} {
		ips = append(ips, net.ParseIP(s))
	}
	return ips
}

// The IPv4 start-node shortcut must give exactly the walk-everything result: the same final
// record for every query, on every testdata database (all record sizes) and on hand-built
// trees whose zero path ends early, loops, or is IPv4-only.
func TestMMDBLookupNodeParity(t *testing.T) {
	ips := parityIPs()
	check := func(t *testing.T, m *MMDB) {
		t.Helper()
		for _, ip := range ips {
			got, gerr := m.lookupNode(ip)
			want, werr := refNode(m, ip)
			if (gerr == nil) != (werr == nil) || (gerr == nil && got != want) {
				t.Fatalf("%v: lookupNode = (%d, %v), reference = (%d, %v)", ip, got, gerr, want, werr)
			}
		}
	}
	files, _ := filepath.Glob("testdata/*.mmdb")
	if len(files) < 4 {
		t.Fatalf("testdata: found %d databases, want at least 4", len(files))
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			m, err := OpenMMDB(f)
			if err != nil {
				t.Fatal(err)
			}
			if m.ipVersion == 6 && !m.v4StartOK {
				t.Error("IPv6 database: v4 start node not computed")
			}
			check(t, m)
		})
	}
	// hand-built: node_count 1, both records the same value (rec). ip_version selects 4 or 6.
	meta := func(ipv uint64) []byte {
		return encMapOf(
			encStr("binary_format_major_version"), encUint(5, 2),
			encStr("node_count"), encUint(6, 1),
			encStr("record_size"), encUint(5, 24),
			encStr("ip_version"), encUint(5, ipv))
	}
	for _, c := range []struct {
		name string
		rec  uint
		ipv  uint64
	}{
		{"v6 empty at the root (zero path ends at once)", 1, 6},
		{"v6 data at the root", 1 + 16, 6},
		{"v6 root loops to itself (all 128 bits walked)", 0, 6},
		{"v4 loops to itself", 0, 4},
		{"v4 data", 1 + 16, 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			m, err := OpenMMDBBytes(buildDB(c.rec, []byte{0xe0}, meta(c.ipv)))
			if err != nil {
				t.Fatal(err)
			}
			check(t, m)
		})
	}
}

// A v4 lookup in an IPv6 tree does not allocate: the 16-byte form lives on the stack and
// the 96 zero bits are not walked. (A miss decodes nothing, so it isolates the walk.)
func TestMMDBLookupV4MissNoAlloc(t *testing.T) {
	m, err := OpenMMDB("testdata/test-asn.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP("203.0.113.1")
	if n := testing.AllocsPerRun(100, func() { m.lookupNode(ip) }); n != 0 {
		t.Errorf("lookupNode(v4 in a v6 tree) allocates %v times, want 0", n)
	}
}

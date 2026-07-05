package cidr

import (
	"math/rand"
	"net/netip"
	"testing"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestSetContains(t *testing.T) {
	b := NewBuilder()
	for _, s := range []string{"10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32", "203.0.113.7"} {
		if err := b.AddPrefix(s); err != nil {
			t.Fatalf("add %s: %v", s, err)
		}
	}
	set := b.Freeze()

	cases := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},       // inside /8
		{"10.255.255.255", true}, // /8 broadcast
		{"11.0.0.0", false},      // just past /8
		{"9.255.255.255", false}, // just before /8
		{"192.0.2.0", true},      // network addr
		{"192.0.2.255", true},    // broadcast
		{"192.0.3.0", false},     // adjacent /24
		{"203.0.113.7", true},    // bare host /32
		{"203.0.113.8", false},   // neighbor of the /32
		{"2001:db8::1", true},    // inside v6 /32
		{"2001:db9::1", false},   // outside v6 /32
		{"::1", false},           // unrelated v6
	}
	for _, c := range cases {
		if got := set.Contains(mustAddr(c.ip)); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestSetMergeAndDefault(t *testing.T) {
	// adjacent + overlapping prefixes must coalesce; empty set matches nothing.
	empty := NewBuilder().Freeze()
	if empty.Contains(mustAddr("1.1.1.1")) {
		t.Error("empty set should contain nothing")
	}
	if empty.Len() != 0 {
		t.Errorf("empty Len = %d", empty.Len())
	}

	b := NewBuilder()
	_ = b.AddPrefix("1.0.0.0/24") // 1.0.0.0 - 1.0.0.255
	_ = b.AddPrefix("1.0.1.0/24") // adjacent -> should merge into one interval
	_ = b.AddPrefix("1.0.0.128/25")
	set := b.Freeze()
	if n := len(set.v4); n != 1 {
		t.Errorf("expected 1 merged interval, got %d", n)
	}
	for _, ip := range []string{"1.0.0.0", "1.0.0.255", "1.0.1.0", "1.0.1.255"} {
		if !set.Contains(mustAddr(ip)) {
			t.Errorf("merged set should contain %s", ip)
		}
	}
	if set.Contains(mustAddr("1.0.2.0")) {
		t.Error("merged set should not spill past the adjacent block")
	}
}

func TestSetDefaultRoute(t *testing.T) {
	b := NewBuilder()
	_ = b.AddPrefix("0.0.0.0/0")
	set := b.Freeze()
	for _, ip := range []string{"0.0.0.0", "128.0.0.1", "255.255.255.255"} {
		if !set.Contains(mustAddr(ip)) {
			t.Errorf("default route should contain %s", ip)
		}
	}
	if set.Contains(mustAddr("::1")) {
		t.Error("v4 default route must not match a v6 address")
	}
}

// naive linear-scan membership oracle.
func containsOracle(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func TestSetRandomParity(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var prefixes []netip.Prefix
	b := NewBuilder()
	for i := 0; i < 2000; i++ {
		ones := 8 + r.Intn(20)
		a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), 0})
		p := netip.PrefixFrom(a, ones).Masked()
		prefixes = append(prefixes, p)
		b.Add(p)
	}
	set := b.Freeze()
	for i := 0; i < 20000; i++ {
		a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
		if got, want := set.Contains(a), containsOracle(prefixes, a); got != want {
			t.Fatalf("Contains(%s) = %v, want %v", a, got, want)
		}
	}
}

func TestParsePrefix(t *testing.T) {
	for _, s := range []string{"10.0.0.0/8", "1.2.3.4", "2001:db8::/32", "::1"} {
		if _, err := ParsePrefix(s); err != nil {
			t.Errorf("ParsePrefix(%q) unexpected error: %v", s, err)
		}
	}
	for _, s := range []string{"", "not-an-ip", "10.0.0.0/40", "1.2.3.4/foo"} {
		if _, err := ParsePrefix(s); err == nil {
			t.Errorf("ParsePrefix(%q) expected error", s)
		}
	}
}

func BenchmarkSetContains(b *testing.B) {
	r := rand.New(rand.NewSource(2))
	bl := NewBuilder()
	for i := 0; i < 4000; i++ {
		a := netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), 0})
		bl.Add(netip.PrefixFrom(a, 24).Masked())
	}
	set := bl.Freeze()
	q := make([]netip.Addr, 4096)
	for i := range q {
		q[i] = netip.AddrFrom4([4]byte{byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256)), byte(r.Intn(256))})
	}
	b.ReportAllocs()
	b.ResetTimer()
	var s bool
	for i := 0; i < b.N; i++ {
		s = s != set.Contains(q[i&4095])
	}
	_ = s
}

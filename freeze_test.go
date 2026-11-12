package cidr

import (
	"net/netip"
	"slices"
	"sync"
	"testing"
)

func mustAdd(t testing.TB, b *Builder, prefixes ...string) {
	t.Helper()
	for _, s := range prefixes {
		if err := b.AddPrefix(s); err != nil {
			t.Fatalf("AddPrefix(%q): %v", s, err)
		}
	}
}

// TestFreezeBuilderReuse is the regression test for #13: Freeze used to sort
// the builder's backing array in place and hand it to the Set, so a later
// Add (fitting in spare capacity) plus Freeze rewrote the first Set.
func TestFreezeBuilderReuse(t *testing.T) {
	b := NewBuilder()
	mustAdd(t, b, "30.0.0.0/8", "10.0.0.0/8", "20.0.0.0/8", "10.1.0.0/16", "40.0.0.0/8")
	if cap(b.v4) <= len(b.v4) {
		t.Fatalf("precondition: want spare capacity in builder, got len=%d cap=%d", len(b.v4), cap(b.v4))
	}
	s1 := b.Freeze()

	mustAdd(t, b, "5.0.0.0/8", "25.0.0.0/8")
	s2 := b.Freeze()

	for _, c := range []struct {
		addr string
		want bool
	}{
		{"5.1.1.1", false}, {"10.1.1.1", true}, {"20.1.1.1", true},
		{"25.1.1.1", false}, {"30.1.1.1", true}, {"40.1.1.1", true},
	} {
		if got := s1.Contains(netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("s1.Contains(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
	if s1.Len() != 4 {
		t.Errorf("s1.Len() = %d, want 4", s1.Len())
	}
	for _, a := range []string{"5.1.1.1", "10.1.1.1", "20.1.1.1", "25.1.1.1", "30.1.1.1", "40.1.1.1"} {
		if !s2.Contains(netip.MustParseAddr(a)) {
			t.Errorf("s2.Contains(%s) = false, want true", a)
		}
	}
	if s2.Len() != 6 {
		t.Errorf("s2.Len() = %d, want 6", s2.Len())
	}
}

// TestFreezeConcurrentReuse queries a Set while the builder is reused; it is
// only meaningful under -race.
func TestFreezeConcurrentReuse(t *testing.T) {
	b := NewBuilder()
	mustAdd(t, b, "30.0.0.0/8", "10.0.0.0/8", "20.0.0.0/8", "10.1.0.0/16", "40.0.0.0/8",
		"2001:db8::/32", "2001:db7::/32", "2001:db9::/32")
	s1 := b.Freeze()

	in := netip.MustParseAddr("30.1.1.1")
	out := netip.MustParseAddr("5.1.1.1")
	in6 := netip.MustParseAddr("2001:db8::1")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if !s1.Contains(in) || s1.Contains(out) || !s1.Contains(in6) {
				t.Error("s1 answers changed while the builder was reused")
				return
			}
		}
	}()

	for i := range 8 {
		mustAdd(t, b, netip.PrefixFrom(netip.AddrFrom4([4]byte{5, byte(i), 0, 0}), 16).String(),
			netip.PrefixFrom(netip.AddrFrom4([4]byte{6, byte(i), 0, 0}), 16).String(),
			"2001:db6::/32")
		_ = b.Freeze()
	}
	close(stop)
	wg.Wait()
}

// TestFreezeRetention: a Set must not pin the builder's whole array.
func TestFreezeRetention(t *testing.T) {
	b := NewBuilder()
	base := netip.MustParseAddr("10.0.0.0").As4()
	for i := range 10000 {
		a := base
		a[2], a[3] = byte(i>>8), byte(i)
		b.Add(netip.PrefixFrom(netip.AddrFrom4(a), 32))
	}
	s := b.Freeze()
	if s.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", s.Len())
	}
	if c := cap(s.v4); c > 8 {
		t.Errorf("cap(s.v4) = %d, want <= 8 (Set retains builder storage)", c)
	}
}

// TestFreezeDoesNotMutateBuilder: Freeze must leave the builder's slices as
// they were, in order and content.
func TestFreezeDoesNotMutateBuilder(t *testing.T) {
	b := NewBuilder()
	mustAdd(t, b, "30.0.0.0/8", "10.0.0.0/8", "20.0.0.0/8", "10.1.0.0/16", "40.0.0.0/8",
		"2001:db9::/32", "2001:db7::/32", "2001:db8::/32")
	v4, v6 := slices.Clone(b.v4), slices.Clone(b.v6)
	_ = b.Freeze()
	if !slices.Equal(b.v4, v4) {
		t.Errorf("Freeze mutated b.v4:\n got %v\nwant %v", b.v4, v4)
	}
	if !slices.Equal(b.v6, v6) {
		t.Errorf("Freeze mutated b.v6:\n got %v\nwant %v", b.v6, v6)
	}
}

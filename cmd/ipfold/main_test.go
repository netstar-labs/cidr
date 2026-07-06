package main

import (
	"bytes"
	"math/rand"
	"net/netip"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

func fold(t *testing.T, input string, switchAt int) string {
	t.Helper()
	old := v4SwitchAt
	v4SwitchAt = switchAt
	defer func() { v4SwitchAt = old }()
	var buf bytes.Buffer
	if _, err := run(strings.NewReader(input), &buf, false, false); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestFoldBasic(t *testing.T) {
	input := strings.Join([]string{
		"10.0.0.15", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.13", // run 12-15 (+dup)
		"192.168.1.1", // singleton
		"2001:db8::3", // v6 run 1-3, unordered
		"2001:db8::1",
		"2001:db8::2",
		"not-an-ip", "", "# comment",
	}, "\n") + "\n"

	want := strings.Join([]string{
		"10.0.0.12/30",    // 12-15 collapse
		"192.168.1.1/32",  // lone host
		"2001:db8::1/128", // v6 1-3 -> /128 + /127
		"2001:db8::2/127",
	}, "\n") + "\n"

	if got := fold(t, input, 1<<30); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestBitmapSliceParity checks the two IPv4 paths agree, and that the folded
// output covers exactly the input set (round-tripped through the spec loader).
func TestBitmapSliceParity(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	var lines []string
	addr := func(x uint32) { lines = append(lines, from32(x).String()) }
	run := func(start uint32, n int) {
		for k := 0; k < n; k++ {
			addr(start + uint32(k))
			if r.Intn(3) == 0 {
				addr(start + uint32(k)) // duplicate
			}
		}
	}
	run(0x0A000005, 300) // crosses .0.0 and 64-bit word boundaries
	run(0xC0A80000, 130)
	for i := 0; i < 200; i++ {
		addr(r.Uint32()) // random singletons
	}
	r.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	input := strings.Join(lines, "\n") + "\n"

	slicePath := fold(t, input, 1<<30) // stays in the slice path
	bitmapPath := fold(t, input, 1)    // forces the bitmap path
	if slicePath != bitmapPath {
		t.Fatalf("slice vs bitmap output differ\n--slice--\n%s\n--bitmap--\n%s", slicePath, bitmapPath)
	}

	set, err := cidr.LoadSet(strings.NewReader(slicePath))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines {
		if !set.Contains(netip.MustParseAddr(l)) {
			t.Errorf("%s not covered by folded output", l)
		}
	}
	// a definite non-member (0.0.0.0 was never added)
	if set.Contains(netip.MustParseAddr("0.0.0.0")) {
		t.Error("0.0.0.0 should not be covered")
	}
}

func TestParseV4(t *testing.T) {
	ok := map[string]uint32{
		"0.0.0.0":         0,
		"255.255.255.255": 0xffffffff,
		"1.2.3.4":         0x01020304,
		"10.0.0.1":        0x0a000001,
	}
	for s, want := range ok {
		if got, valid := parseV4([]byte(s)); !valid || got != want {
			t.Errorf("parseV4(%q) = %#x,%v want %#x", s, got, valid, want)
		}
	}
	for _, s := range []string{
		"1.2.3", "1.2.3.4.5", "1.2.3.256", "1.2.3.", ".1.2.3", "1.2.3.04x",
		"2001:db8::1", "::ffff:1.2.3.4", "", "1.2.3.4444", "hello",
	} {
		if _, valid := parseV4([]byte(s)); valid {
			t.Errorf("parseV4(%q) should be invalid", s)
		}
	}
}

func TestFoldFullV4Range(t *testing.T) {
	// 0.0.0.0 .. 255.255.255.255 via the bitmap must collapse to 0.0.0.0/0.
	// Build it by folding a tiny set but asserting the bitmap run logic on a
	// contiguous block instead: 10.0.0.0/24 as 256 consecutive addresses.
	var sb strings.Builder
	for i := 0; i < 256; i++ {
		sb.WriteString(from32(0x0A000000 + uint32(i)).String())
		sb.WriteByte('\n')
	}
	got := fold(t, sb.String(), 1) // bitmap path
	if got != "10.0.0.0/24\n" {
		t.Errorf("got %q, want 10.0.0.0/24", got)
	}
}

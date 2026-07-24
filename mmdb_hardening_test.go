package cidr

import (
	"bytes"
	"net"
	"os"
	"testing"
)

// TestMMDBMalformedNoPanic feeds hostile data-section encodings straight to the decoder:
// each must return an error, never panic / OOM / hang / stack-overflow. A .mmdb is
// untrusted input, so these are the reader-hardening regressions.
func TestMMDBMalformedNoPanic(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"self-pointer", []byte{0x20, 0x00}},                      // pointer → itself (depth guard)
		{"amplified-array", []byte{0x1f, 0x04, 0xff, 0xff, 0xff}}, // array claims ~16M elements
		{"amplified-map", []byte{0xff, 0xff, 0xff, 0xff}},         // map claims ~16M entries
		{"deep-nesting", bytes.Repeat([]byte{0x01, 0x04}, 600)},   // 600 nested arrays (depth guard)
		{"truncated-string", []byte{0x4b}},                        // string len 11, no bytes follow
		{"empty", []byte{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := decodeMMDB(c.in, 0, 0, 0); err == nil {
				t.Fatalf("decodeMMDB(%s) = nil error; want an error (no panic/OOM/overflow)", c.name)
			}
		})
	}
}

// FuzzOpenMMDB asserts the reader never panics on arbitrary bytes: OpenMMDBBytes either
// errors or returns a database that answers a Lookup without crashing.
func FuzzOpenMMDB(f *testing.F) {
	for _, name := range []string{"test-asn.mmdb", "test-country.mmdb"} {
		if b, err := os.ReadFile("testdata/" + name); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("\xab\xcd\xefMaxMind.com\x20\x00")) // marker + a self-pointer metadata

	f.Fuzz(func(t *testing.T, data []byte) {
		db, err := OpenMMDBBytes(data)
		if err != nil {
			return
		}
		db.Lookup(net.ParseIP("1.1.1.1"))
		db.Lookup(net.ParseIP("2606:4700::1"))
		db.Close()
	})
}

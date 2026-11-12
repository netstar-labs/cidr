package cidr

import (
	"bytes"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
)

// Regression tests for the bounds on one decode of untrusted data: total work and output
// (a data DAG and a string fan-out), pointer-to-pointer, a tree record pointing into the
// data-section separator, and a wrapping extended type. Every hostile file is built by
// hand with the small encoder below and goes through the public API
// (OpenMMDBBytes / MMDB.Lookup); each must be rejected with an error, promptly.

// --- a minimal MaxMind DB encoder for building hostile inputs ---

// hdr encodes a control byte (+ extended type byte) and size bytes for typ and size.
func hdr(typ, size int) []byte {
	var out []byte
	ctrl := byte(0)
	if typ <= 7 {
		ctrl = byte(typ << 5)
	}
	var sz []byte
	switch {
	case size < 29:
		ctrl |= byte(size)
	case size < 285:
		ctrl |= 29
		sz = []byte{byte(size - 29)}
	case size < 65821:
		ctrl |= 30
		v := size - 285
		sz = []byte{byte(v >> 8), byte(v)}
	default:
		ctrl |= 31
		v := size - 65821
		sz = []byte{byte(v >> 16), byte(v >> 8), byte(v)}
	}
	out = append(out, ctrl)
	if typ > 7 {
		out = append(out, byte(typ-7))
	}
	return append(out, sz...)
}

func encStr(s string) []byte { return append(hdr(2, len(s)), s...) }

// encUint encodes v as type typ (5 uint16, 6 uint32, 9 uint64) in its minimal width.
func encUint(typ int, v uint64) []byte {
	var b []byte
	for ; v > 0; v >>= 8 {
		b = append([]byte{byte(v)}, b...)
	}
	return append(hdr(typ, len(b)), b...)
}

// encPtr encodes a pointer to p (relative to the section start) in its smallest form.
func encPtr(p int) []byte {
	switch {
	case p < 2048:
		return []byte{0x20 | byte(p>>8), byte(p)}
	case p < 2048+524288:
		v := p - 2048
		return []byte{0x28 | byte(v>>16), byte(v >> 8), byte(v)}
	default:
		v := p - 526336
		return []byte{0x30 | byte(v>>24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

// encMapOf encodes a map from pre-encoded key/value pairs (k0, v0, k1, v1, ...).
func encMapOf(kv ...[]byte) []byte {
	return append(hdr(7, len(kv)/2), bytes.Join(kv, nil)...)
}

// metaKV is the metadata every database needs: format version 2 and a 1-node IPv4 tree with
// 24-bit records.
func metaKV(extra ...[]byte) []byte {
	kv := [][]byte{
		encStr("binary_format_major_version"), encUint(5, 2),
		encStr("node_count"), encUint(6, 1),
		encStr("record_size"), encUint(5, 24),
		encStr("ip_version"), encUint(5, 4),
	}
	return encMapOf(append(kv, extra...)...)
}

// buildDB assembles tree (one node whose two records both hold rec), the 16-byte
// separator, data, the metadata marker and meta.
func buildDB(rec uint, data, meta []byte) []byte {
	var b []byte
	for i := 0; i < 2; i++ {
		b = append(b, byte(rec>>16), byte(rec>>8), byte(rec))
	}
	b = append(b, make([]byte, 16)...)
	b = append(b, data...)
	b = append(b, metaMarker...)
	return append(b, meta...)
}

// dag builds levels 0..n at section offset base: level 0 is a string, level i is an
// array of two pointers to level i-1. It returns the blob and the offset of level n.
// Decoding level n visits 2^n values although the blob is ~6 bytes per level.
func dag(base, n int) (blob []byte, top int) {
	top = base
	blob = encStr("x")
	for i := 1; i <= n; i++ {
		prev := top
		top = base + len(blob)
		blob = append(blob, hdr(11, 2)...)
		blob = append(blob, encPtr(prev)...)
		blob = append(blob, encPtr(prev)...)
	}
	return blob, top
}

// fanout builds, at section offset base, one str-byte string and then an array of n
// pointers to it. Decoding the array copies the string n times. Returns the blob and the
// offset of the array.
func fanout(base, n, str int) (blob []byte, top int) {
	blob = append(hdr(2, str), bytes.Repeat([]byte{'a'}, str)...)
	top = base + len(blob)
	blob = append(blob, hdr(11, n)...)
	for i := 0; i < n; i++ {
		blob = append(blob, encPtr(base)...)
	}
	return blob, top
}

// metaWith returns metadata whose extra key "x" holds the value encoded by build, which
// is placed after the map itself (offsets in the metadata are absolute).
func metaWith(build func(base int) (blob []byte, top int)) []byte {
	// The head's length depends on the width of the pointer to top, which depends on
	// the head's length: iterate to the fixed point (it settles in two rounds).
	top := 0
	for i := 0; i < 4; i++ {
		head := metaKV(encStr("x"), encPtr(top))
		blob, newTop := build(len(head))
		if newTop == top {
			return append(head, blob...)
		}
		top = newTop
	}
	panic("metaWith: offsets did not settle")
}

// dataRecord builds a database whose only record is the value build places in the data
// section, and returns it.
func dataRecord(build func(base int) (blob []byte, top int)) []byte {
	blob, top := build(0)
	return buildDB(uint(1+16+top), blob, metaKV())
}

func lookupAny(db *MMDB) error {
	_, _, err := db.Lookup(net.ParseIP("1.2.3.4"))
	return err
}

func wantBudgetErr(t *testing.T, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "decode budget exceeded") {
		t.Fatalf("err = %v, want a decode budget error", err)
	}
}

// dagLevels is the depth of the hostile DAGs: 2^40 values if it were decoded.
const dagLevels = 40

func TestMMDBDecodeBudgetDAGMetadata(t *testing.T) {
	data := buildDB(0, nil, metaWith(func(base int) ([]byte, int) { return dag(base, dagLevels) }))
	if len(data) > 1024 {
		t.Fatalf("hostile file is %d bytes; expected a tiny one", len(data))
	}
	_, err := OpenMMDBBytes(data)
	wantBudgetErr(t, err)
}

func TestMMDBDecodeBudgetDAGLookup(t *testing.T) {
	db, err := OpenMMDBBytes(dataRecord(func(base int) ([]byte, int) { return dag(base, dagLevels) }))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	wantBudgetErr(t, lookupAny(db))
}

// 10,000 pointers to one 60,000-byte string: ~30 KB of pointers, 600 MB of copies.
func TestMMDBDecodeBudgetStringFanOutMetadata(t *testing.T) {
	data := buildDB(0, nil, metaWith(func(base int) ([]byte, int) { return fanout(base, 10000, 60000) }))
	_, err := OpenMMDBBytes(data)
	wantBudgetErr(t, err)
}

func TestMMDBDecodeBudgetStringFanOutLookup(t *testing.T) {
	db, err := OpenMMDBBytes(dataRecord(func(base int) ([]byte, int) { return fanout(base, 10000, 60000) }))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	wantBudgetErr(t, lookupAny(db))
}

// The same fan-out through bytes (type 4) values: the copy is append([]byte(nil), ...).
func TestMMDBDecodeBudgetBytesFanOut(t *testing.T) {
	build := func(base int) ([]byte, int) {
		blob := append(hdr(4, 60000), bytes.Repeat([]byte{'b'}, 60000)...)
		top := base + len(blob)
		blob = append(blob, hdr(11, 10000)...)
		for i := 0; i < 10000; i++ {
			blob = append(blob, encPtr(base)...)
		}
		return blob, top
	}
	db, err := OpenMMDBBytes(dataRecord(build))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	wantBudgetErr(t, lookupAny(db))
}

// A pointer whose target is itself a pointer is invalid per the MaxMind DB spec.
func TestMMDBPointerToPointer(t *testing.T) {
	build := func(base int) ([]byte, int) {
		blob := encStr("x")                  // base+0
		p1 := base + len(blob)               // a pointer to the string ...
		blob = append(blob, encPtr(base)...) // base+2
		top := base + len(blob)
		blob = append(blob, hdr(11, 1)...)
		blob = append(blob, encPtr(p1)...) // ... and an array element pointing at that pointer
		return blob, top
	}
	db, err := OpenMMDBBytes(dataRecord(build))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	if err := lookupAny(db); err == nil || !strings.Contains(err.Error(), "pointer to a pointer") {
		t.Fatalf("Lookup err = %v, want a pointer-to-pointer error", err)
	}
	// and in the metadata
	if _, err := OpenMMDBBytes(buildDB(0, nil, metaWith(build))); err == nil {
		t.Fatal("OpenMMDBBytes with a pointer-to-pointer in the metadata: want an error")
	}
}

// A record value node with 0 < node-nodeCount < 16 points into the 16-byte zero
// separator, which is not data (a zero separator would otherwise decode as an empty
// map); 16 is the first data byte.
func TestMMDBRecordIntoSeparator(t *testing.T) {
	for _, d := range []uint{1, 5, 15} {
		db, err := OpenMMDBBytes(buildDB(1+d, []byte{0xe0}, metaKV()))
		if err != nil {
			t.Fatalf("OpenMMDBBytes: %v", err)
		}
		rec, ok, err := db.Lookup(net.ParseIP("1.2.3.4"))
		if err == nil {
			t.Errorf("record = nodeCount+%d: got (%v, %v, nil), want an error", d, rec, ok)
		}
	}
	// nodeCount+16 is data offset 0: here the empty map.
	db, err := OpenMMDBBytes(buildDB(1+16, []byte{0xe0}, metaKV()))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	rec, ok, err := db.Lookup(net.ParseIP("1.2.3.4"))
	if err != nil || !ok || rec == nil || len(rec) != 0 {
		t.Fatalf("record = nodeCount+16: got (%v, %v, %v), want an empty map, found", rec, ok, err)
	}
}

// The extended type is 7 + the next byte; computed in a byte it wrapped (0xFB -> 2,
// string; 0xFA -> 1, pointer). Only 8..15 are valid.
func TestMMDBExtendedTypeWrap(t *testing.T) {
	for _, ext := range []byte{0x00, 0x09, 0x80, 0xfa, 0xfb, 0xff} {
		// 0x00 is "extended, size 0"; a trailing byte keeps a wrapped pointer readable.
		val := []byte{0x00, ext, 0x00}
		_, err := OpenMMDBBytes(buildDB(0, nil, metaKV(encStr("x"), val)))
		if err == nil || !strings.Contains(err.Error(), "invalid extended type") {
			t.Errorf("extended type byte 0x%02x in metadata: err = %v, want an invalid-extended-type error", ext, err)
		}
	}
}

// --- the budget bounds memory: units are (at most about) bytes ---

// allocDelta reports the heap bytes allocated while f runs (TotalAlloc is cumulative, so
// no GC interference). Tests using it must not run in parallel.
func allocDelta(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A hostile record: an array declaring 2M elements, each a one-byte empty map (0xe0), in
// a 2 MB data section. Declared in full, it must be charged (2M*elemCost = 32M units
// against a 8M budget) before the slice is allocated, so the Lookup fails cheaply.
// Before the fix this pre-sized 4096, then grew by append, decoding ~2M maps.
func TestMMDBBudgetHostileArrayLookup(t *testing.T) {
	const n = 2_000_000
	blob := append(hdr(11, n), bytes.Repeat([]byte{0xe0}, n)...)
	db, err := OpenMMDBBytes(buildDB(1+16, blob, metaKV()))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	var lerr error
	got := allocDelta(func() { lerr = lookupAny(db) })
	wantBudgetErr(t, lerr)
	if got > 8<<20 {
		t.Errorf("hostile Lookup allocated %d bytes, want under 8 MiB", got)
	}
}

// The same with a map declaring 1M entries, each a one-byte key... (an empty string
// key, 0x40, then an empty map value): charged mapBaseCost + size*mapEntryCost up front.
func TestMMDBBudgetHostileMapLookup(t *testing.T) {
	const n = 1_000_000
	blob := append(hdr(7, n), bytes.Repeat([]byte{0x40, 0xe0}, n)...)
	db, err := OpenMMDBBytes(buildDB(1+16, blob, metaKV()))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	var lerr error
	got := allocDelta(func() { lerr = lookupAny(db) })
	wantBudgetErr(t, lerr)
	if got > 8<<20 {
		t.Errorf("hostile Lookup allocated %d bytes, want under 8 MiB", got)
	}
}

// Pointer fan-out to a tiny map: each 2-byte pointer builds a fresh (empty) map, which
// costs ~mapBaseCost, not just valueCost (the budget runs out after ~2,400 maps, not ~21,000). 100,000 pointers = a 200 KB file that would
// otherwise build 100,000 maps.
func TestMMDBBudgetMapFanOutLookup(t *testing.T) {
	const n = 100_000
	build := func(base int) ([]byte, int) {
		blob := []byte{0xe0} // base+0: an empty map
		top := base + len(blob)
		blob = append(blob, hdr(11, n)...)
		for i := 0; i < n; i++ {
			blob = append(blob, encPtr(base)...)
		}
		return blob, top
	}
	db, err := OpenMMDBBytes(dataRecord(build))
	if err != nil {
		t.Fatalf("OpenMMDBBytes: %v", err)
	}
	var lerr error
	got := allocDelta(func() { lerr = lookupAny(db) })
	wantBudgetErr(t, lerr)
	if got > 512<<10 {
		t.Errorf("hostile Lookup allocated %d bytes, want under 512 KiB", got)
	}
}

// Containers are charged for their declared count: the exact cost of a 100-slot array of
// empty strings, and of a one-entry map, is pinned, one unit short fails.
func TestDecodeMMDBBudgetContainers(t *testing.T) {
	arr := append(hdr(11, 100), bytes.Repeat([]byte{0x40}, 100)...)
	arrCost := valueCost + 100*elemCost + 100*valueCost
	mp := append(hdr(7, 1), append(encStr("k"), 0x40)...)
	mapCost := valueCost + mapBaseCost + mapEntryCost + (valueCost + 1) + valueCost
	for _, c := range []struct {
		name string
		buf  []byte
		cost int
	}{{"array", arr, arrCost}, {"map", mp, mapCost}} {
		if _, _, err := decodeMMDB(c.buf, 0, 0, 0, &budget{left: c.cost - 1}); err != errBudget {
			t.Errorf("%s one unit short: err = %v, want errBudget", c.name, err)
		}
		if _, _, err := decodeMMDB(c.buf, 0, 0, 0, &budget{left: c.cost}); err != nil {
			t.Errorf("%s exact budget: err = %v, want nil", c.name, err)
		}
	}
}

// TestMMDBBudgetBytesPerUnit measures the claim in the budget comment: on the worst
// shapes (many small allocations per unit of charge) a decode allocates no more than
// about a byte or two per unit it was charged.
func TestMMDBBudgetBytesPerUnit(t *testing.T) {
	const n = 20000
	arrayOfPtrs := func(target []byte) []byte { // target at 0, then an array of n pointers to it
		blob := append([]byte(nil), target...)
		top := len(blob)
		blob = append(blob, hdr(11, n)...)
		for i := 0; i < n; i++ {
			blob = append(blob, encPtr(0)...)
		}
		return blob[top:]
	}
	inlineElems := func(elem []byte) []byte {
		return append(hdr(11, n), bytes.Repeat(elem, n)...)
	}
	// keys "k000000"... distinct
	var mapKeys []byte
	for i := 0; i < n; i++ {
		mapKeys = append(mapKeys, encStr(fmt.Sprintf("k%06d", i))...)
		mapKeys = append(mapKeys, 0x40)
	}
	// each shape: a buffer, the offset of the value to decode (pointers need the target
	// before the array: build as target ++ array, decode at len(target)).
	type shape struct {
		name string
		buf  []byte
		off  int
	}
	withTarget := func(target []byte) shape {
		return shape{buf: append(append([]byte(nil), target...), arrayOfPtrs(target)...), off: len(target)}
	}
	shapes := []shape{
		func() shape { s := withTarget([]byte{0xe0}); s.name = "ptrs to empty map"; return s }(),
		func() shape { s := withTarget([]byte{0x00, 0x04}); s.name = "ptrs to empty array"; return s }(),
		func() shape { s := withTarget(encUint(9, 300)); s.name = "ptrs to uint64"; return s }(),
		func() shape { s := withTarget(encStr("a")); s.name = "ptrs to 1-byte string"; return s }(),
		func() shape { s := withTarget(append(hdr(4, 1), 'b')); s.name = "ptrs to 1-byte bytes"; return s }(),
		func() shape { s := withTarget(append(hdr(10, 1), 7)); s.name = "ptrs to uint128"; return s }(),
		func() shape {
			s := withTarget(append(hdr(7, 1), append(encStr("k"), 0x40)...))
			s.name = "ptrs to 1-entry map"
			return s
		}(),
		{"inline empty arrays", inlineElems([]byte{0x00, 0x04}), 0},
		{"inline 1-entry maps", inlineElems(append([]byte{0xe1}, append(encStr("k"), 0x40)...)), 0},
		{"map of empty strings", append(hdr(7, n), mapKeys...), 0},
	}
	for _, s := range shapes {
		bud := &budget{left: 1 << 40}
		start := bud.left
		var err error
		got := allocDelta(func() { _, _, err = decodeMMDB(s.buf, s.off, 0, 0, bud) })
		if err != nil {
			t.Errorf("%s: %v", s.name, err)
			continue
		}
		units := start - bud.left
		t.Logf("%-24s %9d units, %9d bytes allocated, %.2f B/unit", s.name, units, got, float64(got)/float64(units))
		if float64(got) > 2*float64(units) {
			t.Errorf("%s: %d bytes allocated for %d units: over 2 B/unit", s.name, got, units)
		}
	}
}

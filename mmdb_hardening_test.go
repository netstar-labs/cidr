package cidr

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
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
		{"self-pointer", []byte{0x20, 0x00}},                      // pointer → itself (rejected as a pointer to a pointer)
		{"amplified-array", []byte{0x1f, 0x04, 0xff, 0xff, 0xff}}, // array claims ~16M elements
		{"amplified-map", []byte{0xff, 0xff, 0xff, 0xff}},         // map claims ~16M entries
		{"deep-nesting", bytes.Repeat([]byte{0x01, 0x04}, 600)},   // 600 nested arrays (depth guard)
		{"truncated-string", []byte{0x4b}},                        // string len 11, no bytes follow
		{"empty", []byte{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := decodeTest(c.in, 0, 0, 0); err == nil {
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

// decodeTest runs decodeMMDB with a fresh budget sized from buf, as OpenMMDBBytes does
// for the metadata.
func decodeTest(buf []byte, off, ptrBase, depth int) (any, int, error) {
	return decodeMMDB(buf, off, ptrBase, depth, newBudget(len(buf)))
}

// walkRecords visits every distinct data-record offset reachable from the search tree.
func walkRecords(t *testing.T, m *MMDB, visit func(off int)) {
	t.Helper()
	seen := map[uint]bool{}
	var walk func(node uint)
	walk = func(node uint) {
		if node < m.nodeCount {
			for _, right := range []bool{false, true} {
				rec, err := m.record(node, right)
				if err != nil {
					t.Fatalf("record(%d): %v", node, err)
				}
				walk(rec)
			}
			return
		}
		if node == m.nodeCount || seen[node] {
			return
		}
		seen[node] = true
		visit(int(m.treeSize) + int(node-m.nodeCount))
	}
	walk(0)
}

// TestMMDBBudgetLegitimateData proves the decode budget does not reject real data: every
// distinct record of every testdata/*.mmdb (and of every file in $MMDB_BIG_DIR, for
// larger generated databases) decodes, and the largest budget any record consumed is
// reported against the budget it was given. Records must use under 1/16 of their budget.
func TestMMDBBudgetLegitimateData(t *testing.T) {
	files, _ := filepath.Glob("testdata/*.mmdb")
	if dir := os.Getenv("MMDB_BIG_DIR"); dir != "" {
		big, _ := filepath.Glob(filepath.Join(dir, "*.mmdb"))
		files = append(files, big...)
	}
	if len(files) == 0 {
		t.Fatal("no testdata/*.mmdb")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		db, err := OpenMMDBBytes(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		records, maxUsed, total := 0, 0, db.dataLen
		walkRecords(t, db, func(off int) {
			bud := newBudget(db.dataLen)
			start := bud.left
			if _, _, err := decodeMMDB(db.data, off, db.dataStart, 0, bud); err != nil {
				t.Fatalf("%s: record at data offset %d: %v", f, off-db.dataStart, err)
			}
			records++
			maxUsed = max(maxUsed, start-bud.left)
		})
		budget := newBudget(total).left
		t.Logf("%s: %d records, data section %d bytes; max budget used by one record %d of %d (%.4f%%, headroom %.0fx)",
			filepath.Base(f), records, db.dataLen, maxUsed, budget, 100*float64(maxUsed)/float64(budget), float64(budget)/float64(max(maxUsed, 1)))
		if maxUsed*16 > budget {
			t.Errorf("%s: a record used %d of a %d budget; headroom under 16x", f, maxUsed, budget)
		}
	}
}

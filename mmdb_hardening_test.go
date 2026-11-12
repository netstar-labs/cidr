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

// OpenMMDBBytes accepts only binary format major version 2 and ip_version 4 or 6; a
// missing key is invalid, not zero-and-ignored.
func TestMMDBOpenRejectsBadVersions(t *testing.T) {
	// meta builds metadata from the keys given (value 0 means: omit the key).
	meta := func(major, ipv uint64) []byte {
		kv := [][]byte{
			encStr("node_count"), encUint(6, 1),
			encStr("record_size"), encUint(5, 24),
		}
		if major != 0 {
			kv = append(kv, encStr("binary_format_major_version"), encUint(5, major))
		}
		if ipv != 0 {
			kv = append(kv, encStr("ip_version"), encUint(5, ipv))
		}
		return encMapOf(kv...)
	}
	cases := []struct {
		name         string
		major, ipVer uint64
		ok           bool
	}{
		{"v2 ip4", 2, 4, true},
		{"v2 ip6", 2, 6, true},
		{"major missing", 0, 4, false},
		{"major 1", 1, 4, false},
		{"major 3", 3, 4, false},
		{"major 258", 258, 4, false},
		{"ip_version missing", 2, 0, false},
		{"ip_version 5", 2, 5, false},
		{"ip_version 7", 2, 7, false},
		{"ip_version 260", 2, 260, false}, // 260 & 0xff == 4: must not be truncated into range
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := OpenMMDBBytes(buildDB(0, nil, meta(c.major, c.ipVer)))
			if c.ok && err != nil {
				t.Fatalf("OpenMMDBBytes: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("OpenMMDBBytes: want an error")
			}
		})
	}
	// a non-numeric version (a string) is invalid too
	bad := buildDB(0, nil, encMapOf(
		encStr("node_count"), encUint(6, 1), encStr("record_size"), encUint(5, 24),
		encStr("binary_format_major_version"), encStr("2"), encStr("ip_version"), encUint(5, 4)))
	if _, err := OpenMMDBBytes(bad); err == nil {
		t.Error("string binary_format_major_version: want an error")
	}
}

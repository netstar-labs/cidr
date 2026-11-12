package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

// buildASN compiles an ASN-mode spec and opens it with the library's MMDB reader.
func buildASN(t *testing.T, spec string) *cidr.MMDB {
	t.Helper()
	entries, err := cidr.ParseSpec(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, _, err := writeMMDB(&buf, entries, "GeoLite2-ASN", "test", 1700000000, 6, 24, false); err != nil {
		t.Fatal(err)
	}
	db, err := cidr.OpenMMDBBytes(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// asnOf returns the ASN the database holds for ip, or -1 when it has no record.
func asnOf(t *testing.T, db *cidr.MMDB, ip string) int {
	t.Helper()
	rec, ok, err := db.Lookup(net.ParseIP(ip))
	if err != nil {
		t.Fatalf("lookup %s: %v", ip, err)
	}
	if !ok {
		return -1
	}
	return int(toUint32(rec["autonomous_system_number"]))
}

// TestNestedPrefixOrder: the MMDB must give the longest-prefix answer whichever
// order the spec lists a nested and a covering prefix in. mmdbwriter replaces on
// insert, so file order used to decide the answer.
func TestNestedPrefixOrder(t *testing.T) {
	for _, spec := range []string{
		"10.0.0.0/8 1 A\n10.1.0.0/16 2 B\n",
		"10.1.0.0/16 2 B\n10.0.0.0/8 1 A\n",
	} {
		db := buildASN(t, spec)
		for ip, want := range map[string]int{"10.1.2.3": 2, "10.2.2.3": 1, "11.0.0.1": -1} {
			if got := asnOf(t, db, ip); got != want {
				t.Errorf("spec %q: %s -> AS%d, want AS%d", spec, ip, got, want)
			}
		}
	}
}

// TestDuplicatePrefixLastWins: the same prefix twice keeps the later value, as
// the library's Table does.
func TestDuplicatePrefixLastWins(t *testing.T) {
	db := buildASN(t, "10.0.0.0/8 1 A\n10.0.0.0/8 2 B\n10.1.0.0/16 3 C\n10.1.0.0/16 4 D\n")
	if got := asnOf(t, db, "10.9.9.9"); got != 2 {
		t.Errorf("10.9.9.9 -> AS%d, want AS2", got)
	}
	if got := asnOf(t, db, "10.1.9.9"); got != 4 {
		t.Errorf("10.1.9.9 -> AS%d, want AS4", got)
	}
}

// TestShortV6DoesNotEraseV4: IPv4 lives under ::/96 of the IPv6 tree, so "::/48"
// covers all of it. Ordered by raw Bits() "::/48" (48) would come after
// "10.0.0.0/8" (8) and erase it; ordered by tree depth (104 vs 48) it cannot.
func TestShortV6DoesNotEraseV4(t *testing.T) {
	for _, spec := range []string{
		"10.0.0.0/8 1 A\n::/48 2 B\n",
		"::/48 2 B\n10.0.0.0/8 1 A\n",
	} {
		db := buildASN(t, spec)
		if got := asnOf(t, db, "10.1.1.1"); got != 1 {
			t.Errorf("spec %q: 10.1.1.1 -> AS%d, want AS1", spec, got)
		}
	}
}

// TestInputNotReordered: writeMMDB sorts a copy, not the caller's slice.
func TestInputNotReordered(t *testing.T) {
	entries, _ := cidr.ParseSpec(strings.NewReader("10.1.0.0/16 2 B\n10.0.0.0/8 1 A\n"))
	var buf bytes.Buffer
	if _, _, err := writeMMDB(&buf, entries, "T", "t", 1, 6, 24, false); err != nil {
		t.Fatal(err)
	}
	if entries[0].ASN != 2 || entries[1].ASN != 1 {
		t.Errorf("entries were reordered: %+v", entries)
	}
}

// randAddrIn returns a random address inside p.
func randAddrIn(rng *rand.Rand, p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		if rng.IntN(2) == 1 {
			b[i>>3] |= 1 << (7 - uint(i&7))
		}
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// TestDifferentialAgainstLibrary: random nested specs (some with duplicate
// prefixes), listed in random order, must read back from the MMDB exactly as the
// library's own LoadASN Table answers them, for IPv4 and for native IPv6 under
// 2600::/16.
//
// The generator stays clear of what mmdbwriter handles differently by design and
// that therefore remains divergent from the library: IPv6 prefixes that cover
// ::/96 (anything of ::/96 or shorter, such as ::/48), and the networks that
// alias the IPv4 subtree (2001::/32, 2002::/16, ::ffff:0:0/96).
func TestDifferentialAgainstLibrary(t *testing.T) {
	rng := rand.New(rand.NewPCG(34, 35))
	for round := 0; round < 25; round++ {
		var lines []string
		n := 15 + rng.IntN(25)
		for i := 0; i < n; i++ {
			var p string
			if rng.IntN(2) == 0 {
				first := []int{10, 172}[rng.IntN(2)]
				p = fmt.Sprintf("%d.%d.%d.%d/%d", first, rng.IntN(2), rng.IntN(4), rng.IntN(256), 8+rng.IntN(23))
			} else {
				p = fmt.Sprintf("2600:%x:%x::/%d", rng.IntN(2), rng.IntN(4), 16+rng.IntN(49))
			}
			lines = append(lines, fmt.Sprintf("%s %d Org%d", p, i+1, i+1))
			if rng.IntN(6) == 0 { // the same prefix again with another value
				lines = append(lines, fmt.Sprintf("%s %d Dup%d", p, 1000+i, i))
			}
		}
		rng.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
		spec := strings.Join(lines, "\n") + "\n"

		_, table, err := cidr.LoadASN(strings.NewReader(spec))
		if err != nil {
			t.Fatal(err)
		}
		db := buildASN(t, spec)
		entries, _ := cidr.ParseSpec(strings.NewReader(spec))

		var probes []netip.Addr
		for _, e := range entries {
			probes = append(probes, e.Prefix.Masked().Addr(), randAddrIn(rng, e.Prefix), randAddrIn(rng, e.Prefix))
		}
		for i := 0; i < 20; i++ {
			probes = append(probes,
				randAddrIn(rng, netip.MustParsePrefix("10.0.0.0/8")),
				randAddrIn(rng, netip.MustParsePrefix("2600::/16")))
		}
		for _, a := range probes {
			info, want := table.Lookup(a)
			got := asnOf(t, db, a.String())
			switch {
			case !want && got != -1:
				t.Errorf("round %d %s: MMDB AS%d, library no match\n%s", round, a, got, spec)
			case want && got != int(info.ASN):
				t.Errorf("round %d %s: MMDB AS%d, library AS%d\n%s", round, a, got, info.ASN, spec)
			}
		}
		if t.Failed() {
			return
		}
	}
}

func TestTallyCountsByReason(t *testing.T) {
	spec := strings.Join([]string{
		"1.0.0.0/24 AU",
		"2.0.0.0/24 EU",    // pseudo-code
		"3.0.0.0/24 ZZ",    // pseudo-code
		"4.0.0.0/24 XX",    // unknown country
		"5.0.0.0/24",       // no org: pseudo-code
		"2001::/32 JP",     // aliased
		"2001:db8::/32 US", // inserted
	}, "\n") + "\n"
	entries, _ := cidr.ParseSpec(strings.NewReader(spec))
	var buf bytes.Buffer
	_, tl, err := writeMMDB(&buf, entries, "GeoLite2-Country", "t", 1, 6, 24, true)
	if err != nil {
		t.Fatal(err)
	}
	want := tally{inserted: 2, pseudoCode: 3, unknownCountry: 1, aliased: 1}
	if tl != want {
		t.Errorf("tally = %+v, want %+v", tl, want)
	}
	for _, s := range []string{"inserted=2", "pseudo-code=3", "unknown-country=1", "unknown-continent=0", "aliased=1", "unparseable=0"} {
		if !strings.Contains(tl.String(), s) {
			t.Errorf("tally string %q lacks %q", tl, s)
		}
	}
}

func TestUnknownContinentCounted(t *testing.T) {
	countryData.Countries["XC"] = countryInfo{GeonameID: 1, Names: map[string]string{"en": "X"}, ContinentCode: "QQ"}
	t.Cleanup(func() { delete(countryData.Countries, "XC") })
	entries, _ := cidr.ParseSpec(strings.NewReader("1.0.0.0/24 XC\n2.0.0.0/24 AU\n"))
	var buf bytes.Buffer
	_, tl, err := writeMMDB(&buf, entries, "GeoLite2-Country", "t", 1, 6, 24, true)
	if err != nil {
		t.Fatal(err)
	}
	if tl.unknownContinent != 1 || tl.inserted != 1 {
		t.Errorf("tally = %+v", tl)
	}
}

func TestNothingInsertedIsAnError(t *testing.T) {
	entries, _ := cidr.ParseSpec(strings.NewReader("1.0.0.0/24 EU\n2.0.0.0/24 ZZ\n"))
	var buf bytes.Buffer
	_, tl, err := writeMMDB(&buf, entries, "GeoLite2-Country", "t", 1, 6, 24, true)
	if err == nil || !strings.Contains(err.Error(), "pseudo-code=2") {
		t.Fatalf("err = %v, want a nothing-inserted error with the tally", err)
	}
	if buf.Len() != 0 || tl.inserted != 0 {
		t.Errorf("wrote %d bytes, tally %+v", buf.Len(), tl)
	}
}

func TestASNZeroWarning(t *testing.T) {
	// A country spec fed to ASN mode: every record is ASN 0.
	entries, _ := cidr.ParseSpec(strings.NewReader("1.0.0.0/24 AU\n2.0.0.0/24 FR\n"))
	var buf bytes.Buffer
	_, tl, err := writeMMDB(&buf, entries, "GeoLite2-ASN", "t", 1, 6, 24, false)
	if err != nil {
		t.Fatal(err)
	}
	w := tl.asnWarning(false)
	if !strings.Contains(w, "all 2 inserted records have ASN 0") || !strings.Contains(w, "-db-type") {
		t.Errorf("warning = %q", w)
	}
	if tl.asnWarning(true) != "" {
		t.Error("country mode must not warn")
	}
	entries, _ = cidr.ParseSpec(strings.NewReader("1.0.0.0/24 AU\n2.0.0.0/24 64500 X\n"))
	_, tl, _ = writeMMDB(&buf, entries, "GeoLite2-ASN", "t", 1, 6, 24, false)
	if w := tl.asnWarning(false); w != "" {
		t.Errorf("a database with a real ASN must not warn: %q", w)
	}
}

func readDir(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range des {
		names = append(names, d.Name())
	}
	return names
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.mmdb")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}

	// A failure part-way leaves the previous file untouched and no temp file behind.
	boom := errors.New("boom")
	err := writeFileAtomic(path, func(w io.Writer) error {
		w.Write([]byte("partial"))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "old" {
		t.Errorf("file = %q after a failed write, want old", b)
	}
	if names := readDir(t, dir); len(names) != 1 {
		t.Errorf("directory holds %v, want only out.mmdb", names)
	}

	// Success replaces it, keeping the permission bits.
	if err := writeFileAtomic(path, func(w io.Writer) error { _, err := w.Write([]byte("new")); return err }); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Errorf("file = %q, want new", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", st.Mode().Perm())
	}
	if names := readDir(t, dir); len(names) != 1 {
		t.Errorf("directory holds %v, want only out.mmdb", names)
	}
}

// TestRunEmptyResultLeavesOutput: a spec that inserts nothing is an error, and
// the previous output file is neither replaced nor left half-written.
func TestRunEmptyResultLeavesOutput(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.mmdb")
	in := filepath.Join(dir, "in.cidr")
	if err := os.WriteFile(in, []byte("1.0.0.0/24 EU\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(in, out, "GeoLite2-Country", "", 1, 6, 24); err == nil {
		t.Fatal("want an error when nothing is inserted")
	}
	if b, _ := os.ReadFile(out); string(b) != "previous" {
		t.Errorf("output = %q, want the previous file", b)
	}
	if names := readDir(t, dir); len(names) != 2 {
		t.Errorf("directory holds %v, want only out.mmdb and in.cidr", names)
	}

	// And with no previous file, none appears.
	os.Remove(out)
	if err := run(in, out, "GeoLite2-Country", "", 1, 6, 24); err == nil {
		t.Fatal("want an error when nothing is inserted")
	}
	if names := readDir(t, dir); len(names) != 1 {
		t.Errorf("directory holds %v, want only in.cidr", names)
	}
}

func TestRunWritesDatabase(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.mmdb")
	in := filepath.Join(dir, "in.cidr")
	if err := os.WriteFile(in, []byte("10.0.0.0/8 1 A\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(in, out, "GeoLite2-ASN", "", 1, 6, 24); err != nil {
		t.Fatal(err)
	}
	db, err := cidr.OpenMMDB(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := asnOf(t, db, "10.1.1.1"); got != 1 {
		t.Errorf("AS%d, want AS1", got)
	}
}

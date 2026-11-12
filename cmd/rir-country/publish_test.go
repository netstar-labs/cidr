package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression tests for #31: success means "published a complete file", not
// "exited 0".

const (
	previous = "9.9.9.0/24 US\n"

	arinOK     = "2.3|arin|1|2|19700101|20260101|-0400\narin|US|ipv4|8.8.8.0|256|20010920|allocated|a\n"
	ripeHeader = "2|ripencc|1|0|19700101|20260101|+0100\nripencc|*|ipv4|*|0|summary\n"
)

func seed(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "feed.cidr")
	if err := os.WriteFile(p, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// assertPreserved fails unless the feed is unchanged and no temp file is left.
func assertPreserved(t *testing.T, out string) {
	t.Helper()
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != previous {
		t.Errorf("previous feed was modified (%d bytes now)", len(b))
	}
	if es, _ := os.ReadDir(filepath.Dir(out)); len(es) != 1 {
		t.Errorf("files left beside the feed: %v", es)
	}
}

func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func manyRows(n int) string {
	var b strings.Builder
	b.WriteString("2.3|arin|1|1|19700101|20260101|-0400\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "arin|US|ipv4|10.%d.%d.0|256|20010920|allocated|x\n", i/256, i%256)
	}
	return b.String()
}

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	io.WriteString(zw, s)
	zw.Close()
	return buf.Bytes()
}

// within fails the test if f does not return in d.
func within(t *testing.T, d time.Duration, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("still running after %v", d)
		return nil
	}
}

func TestZeroRowsKeepsPreviousFile(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "", "arin.txt", []byte(ripeHeader))
	if err := run("all", byDate, in, out, "", time.Second); err == nil {
		t.Fatal("zero records reported success")
	}
	assertPreserved(t, out)
}

// One registry contributing nothing is a failure even though the other filled
// the table: that is exactly a registry that silently dropped out of the feed.
func TestPerRegistryZeroFails(t *testing.T) {
	out := seed(t)
	dir := t.TempDir()
	a := writeTemp(t, dir, "arin.txt", []byte(arinOK))
	b := writeTemp(t, dir, "ripencc.txt", []byte(ripeHeader))
	err := run("all", byDate, a+","+b, out, "", time.Second)
	if err == nil {
		t.Fatal("a registry with zero records reported success")
	}
	if !strings.Contains(err.Error(), "ripencc") {
		t.Errorf("error does not name the empty registry: %v", err)
	}
	assertPreserved(t, out)
}

func TestPerRegistryCountsAndHeader(t *testing.T) {
	srcs := []source{
		{name: "arin", r: strings.NewReader(arinOK), close: func() {}},
		// records but no version header line
		{name: "lacnic", r: strings.NewReader("lacnic|BR|ipv4|200.0.0.0|256|20010101|allocated|y\n"), close: func() {}},
		{name: "ripencc", r: strings.NewReader(ripeHeader), close: func() {}},
	}
	table := map[netip.Prefix]rec{}
	var st stats
	var conflicts []conflict
	regs, err := collectSources(srcs, byDate, table, &st, &conflicts)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]regStat{}
	for _, r := range regs {
		got[r.name] = r
	}
	if r := got["arin"]; r.rows != 1 || r.malformed != 0 || !r.header {
		t.Errorf("arin = %+v, want 1 row, no malformed, header", r)
	}
	if r := got["lacnic"]; r.rows != 1 || r.malformed != 1 || r.header {
		t.Errorf("lacnic = %+v, want 1 row, 1 malformed (no header)", r)
	}
	if r := got["ripencc"]; r.rows != 0 || !r.header {
		t.Errorf("ripencc = %+v, want 0 rows with header", r)
	}
	if st.malformed != 1 {
		t.Errorf("total malformed = %d, want 1", st.malformed)
	}
}

func TestMissingHeaderCountedMalformedViaRun(t *testing.T) {
	// A file with records but no header still publishes (it is only counted),
	// and a header of either version form is recognised.
	for _, hdr := range []string{"2|arin|1|1|19700101|20260101|-0400", "2.3|arin|1|1|19700101|20260101|-0400", "2.3a|arin|1|1|19700101|20260101|-0400"} {
		if !isVersionHeader(hdr) {
			t.Errorf("%q not recognised as a version header", hdr)
		}
	}
	for _, not := range []string{"arin|US|ipv4|8.8.8.0|256|20010920|allocated|a", "arin|*|ipv4|*|4|summary", "# comment", ""} {
		if isVersionHeader(not) {
			t.Errorf("%q wrongly recognised as a version header", not)
		}
	}
}

func TestMidStreamFailureKeepsPreviousFile(t *testing.T) {
	out := seed(t)
	full := gzipBytes(t, manyRows(3000))
	in := writeTemp(t, "", "arin.txt.gz", full[:len(full)-12])
	err := within(t, 10*time.Second, func() error { return run("all", byDate, in, out, "", time.Second) })
	if err == nil {
		t.Fatal("truncated gzip reported success")
	}
	assertPreserved(t, out)
}

func TestCorruptGzipIsError(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "", "arin.txt.gz", []byte{0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff})
	if err := run("all", byDate, in, out, "", time.Second); err == nil {
		t.Fatal("corrupt gzip reported success")
	}
	assertPreserved(t, out)
}

func TestStalledDownloadFailsPromptly(t *testing.T) {
	out := seed(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, arinOK[:20])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	saved := sources["arin"]
	sources["arin"] = srv.URL
	defer func() { sources["arin"] = saved }()

	start := time.Now()
	err := within(t, 10*time.Second, func() error { return run("arin", byDate, "", out, "", 300*time.Millisecond) })
	if err == nil {
		t.Fatal("stalled download reported success")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	assertPreserved(t, out)
}

func TestSuccessReplacesFiles(t *testing.T) {
	out := seed(t)
	logPath := filepath.Join(filepath.Dir(out), "conflicts.tsv")
	in := writeTemp(t, "", "arin.txt", []byte(arinOK))
	if err := run("all", byDate, in, out, logPath, time.Second); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "8.8.8.0/24 US\n" {
		t.Errorf("feed = %q", b)
	}
	if b, _ := os.ReadFile(logPath); !strings.HasPrefix(string(b), "prefix\tcc_a") {
		t.Errorf("conflict log = %q", b)
	}
	if es, _ := os.ReadDir(filepath.Dir(out)); len(es) != 2 {
		t.Errorf("files left (want feed + conflict log only): %v", es)
	}
}

package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression tests for #31: success means "published a complete file", not
// "exited 0".

const (
	previous = "9.9.9.0/24 64496 PREVIOUS\n"
	header   = "network,autonomous_system_number,autonomous_system_organization\n"
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

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func manyRows(n int) string {
	var b strings.Builder
	b.WriteString(header)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0/24,%d,ORG%d\n", i/256, i%256, 64512+i, i)
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

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, body)
	}
	zw.Close()
	return buf.Bytes()
}

// within fails the test if f does not return in d, so a regression back to
// spinning fails instead of hanging the suite.
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
	in := writeTemp(t, "blocks.csv", []byte(header))
	if err := run("", "both", "", in, out, time.Second); err == nil {
		t.Fatal("header-only input reported success")
	}
	assertPreserved(t, out)

	// A zip with no blocks files is the same failure.
	zin := writeTemp(t, "x.zip", zipOf(t, map[string]string{"README.txt": "hi"}))
	if err := run("", "both", "", zin, out, time.Second); err == nil {
		t.Fatal("zip without blocks files reported success")
	}
	assertPreserved(t, out)
}

func TestMidStreamFailureKeepsPreviousFile(t *testing.T) {
	out := seed(t)
	full := gzipBytes(t, manyRows(3000))
	in := writeTemp(t, "cut.csv.gz", full[:len(full)-12])
	err := within(t, 10*time.Second, func() error { return run("", "both", "", in, out, time.Second) })
	if err == nil {
		t.Fatal("truncated gzip reported success")
	}
	assertPreserved(t, out)
}

func TestTruncatedGzipDoesNotSpin(t *testing.T) {
	out := seed(t)
	full := gzipBytes(t, manyRows(500))
	in := writeTemp(t, "cut.csv.gz", full[:len(full)/2])
	err := within(t, 10*time.Second, func() error { return run("", "both", "", in, out, time.Second) })
	if err == nil {
		t.Fatal("truncated gzip reported success")
	}
	assertPreserved(t, out)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestConvertReadErrorIsReturned(t *testing.T) {
	r := io.MultiReader(strings.NewReader(header+"1.0.0.0/24,1,A\n"), errReader{})
	err := within(t, 10*time.Second, func() error {
		_, err := convertCSV(r, io.Discard)
		return err
	})
	if err == nil {
		t.Fatal("non-parse read error swallowed")
	}
}

// A malformed quote is a per-line CSV error: still counted and skipped.
func TestConvertParseErrorStillRecovers(t *testing.T) {
	in := header + "1.0.0.0/24,1,A\n2.0.0.0/24,2,\"bad\"quote\n3.0.0.0/24,3,C\n"
	var buf bytes.Buffer
	st, err := convertCSV(strings.NewReader(in), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != "1.0.0.0/24 1 A\n3.0.0.0/24 3 C\n" || st.malformed != 1 {
		t.Errorf("out=%q stats=%+v", buf.String(), st)
	}
}

func TestStalledDownloadFailsPromptly(t *testing.T) {
	out := seed(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "PK\x03\x04")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	err := within(t, 10*time.Second, func() error { return run("", "both", srv.URL, "", out, 300*time.Millisecond) })
	if err == nil {
		t.Fatal("stalled download reported success")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	assertPreserved(t, out)
}

// The output must not exist until there is something to publish: a failed
// fetch used to leave an empty file behind (os.Create ran first).
func TestFailedFetchCreatesNoOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "feed.cidr")
	if err := run("", "both", srv.URL, "", out, time.Second); err == nil {
		t.Fatal("HTTP 500 reported success")
	}
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Errorf("files created by a failed run: %v", es)
	}
}

func TestCorruptGzipIsError(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "bad.csv.gz", []byte{0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff})
	if err := run("", "both", "", in, out, time.Second); err == nil {
		t.Fatal("corrupt gzip reported success")
	}
	assertPreserved(t, out)
}

func TestHeaderValidated(t *testing.T) {
	for name, in := range map[string]string{
		"reordered": "autonomous_system_number,network,autonomous_system_organization\n13335,1.0.0.0/24,Cloudflare\n",
		"renamed":   "cidr,asn,org\n1.0.0.0/24,13335,Cloudflare\n",
		"no header": "1.0.0.0/24,13335,Cloudflare\n",
		"empty":     "",
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			_, err := convertCSV(strings.NewReader(in), &buf)
			if err == nil {
				t.Fatalf("accepted; output %q", buf.String())
			}
			if buf.Len() != 0 {
				t.Errorf("wrote %q before rejecting the header", buf.String())
			}
		})
	}
	// The header is validated per file: a zip whose second CSV is reordered fails.
	z := zipOf(t, map[string]string{
		"d/GeoLite2-ASN-Blocks-IPv4.csv": header + "1.0.0.0/24,13335,Cloudflare\n",
		"d/GeoLite2-ASN-Blocks-IPv6.csv": "autonomous_system_number,network,autonomous_system_organization\n2500,2001:200::/32,WIDE\n",
	})
	if _, err := processZip(z, "both", io.Discard); err == nil {
		t.Error("zip with a reordered second file accepted")
	}
	// Header names are accepted with a BOM and in any case.
	var buf bytes.Buffer
	if _, err := convertCSV(strings.NewReader("\ufeffNetwork,Autonomous_System_Number,Autonomous_System_Organization\n1.0.0.0/24,1,A\n"), &buf); err != nil {
		t.Errorf("BOM/case header rejected: %v", err)
	}
}

func TestNonPrefixRowsAreMalformed(t *testing.T) {
	in := header + "1.0.0.0/24,13335,Cloudflare\nnot,a,prefix\n1.0.1.0/24,,NoASN\n"
	var buf bytes.Buffer
	st, err := convertCSV(strings.NewReader(in), &buf)
	if err != nil {
		t.Fatal(err)
	}
	if st.rows != 1 || st.malformed != 2 {
		t.Errorf("stats = %+v, want rows=1 malformed=2 (non-prefix and empty ASN)", st)
	}
}

func TestSuccessReplacesFile(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "ok.csv", []byte(header+"1.0.0.0/24,13335,Cloudflare\n"))
	if err := run("", "both", "", in, out, time.Second); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "1.0.0.0/24 13335 Cloudflare\n" {
		t.Errorf("feed = %q", b)
	}
	if es, _ := os.ReadDir(filepath.Dir(out)); len(es) != 1 {
		t.Errorf("files left: %v", es)
	}
}

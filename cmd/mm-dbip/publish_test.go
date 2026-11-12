package main

import (
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

const previous = "9.9.9.0/24 US\n"

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
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "10.%d.%d.0,10.%d.%d.255,US\n", i/256, i%256, i/256, i%256)
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

// within runs f and fails the test if it does not return in d: a regression
// back to spinning must fail, not hang the suite.
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
	in := writeTemp(t, "empty.csv", []byte("junk\nmore,junk\n"))
	if err := run("country", "", "", in, out, time.Second); err == nil {
		t.Fatal("zero usable rows reported success")
	}
	assertPreserved(t, out)
}

func TestMidStreamFailureKeepsPreviousFile(t *testing.T) {
	out := seed(t)
	full := gzipBytes(t, manyRows(3000))
	in := writeTemp(t, "cut.csv.gz", full[:len(full)-12])
	err := within(t, 10*time.Second, func() error { return run("country", "", "", in, out, time.Second) })
	if err == nil {
		t.Fatal("truncated gzip reported success")
	}
	assertPreserved(t, out)
}

// A truncated .csv.gz makes the CSV reader return the gzip error on every call;
// treating that as a recoverable bad line spun forever.
func TestTruncatedGzipDoesNotSpin(t *testing.T) {
	out := seed(t)
	full := gzipBytes(t, manyRows(500))
	in := writeTemp(t, "cut.csv.gz", full[:len(full)/2])
	err := within(t, 10*time.Second, func() error { return run("country", "", "", in, out, time.Second) })
	if err == nil {
		t.Fatal("truncated gzip reported success")
	}
	assertPreserved(t, out)
}

func TestConvertReadErrorIsReturned(t *testing.T) {
	r := io.MultiReader(strings.NewReader("1.0.0.0,1.0.0.255,AU\n"), errReader{})
	err := within(t, 10*time.Second, func() error {
		_, err := convert(r, io.Discard, "country")
		return err
	})
	if err == nil {
		t.Fatal("non-parse read error swallowed")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// A malformed quote is a per-line CSV error: still counted and skipped.
func TestConvertParseErrorStillRecovers(t *testing.T) {
	const in = "1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.1.255,\"bad\"quote\n1.0.2.0,1.0.2.255,CN\n"
	var buf bytes.Buffer
	st, err := convert(strings.NewReader(in), &buf, "country")
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != "1.0.0.0/24 AU\n1.0.2.0/24 CN\n" || st.malformed != 1 {
		t.Errorf("out=%q stats=%+v", buf.String(), st)
	}
}

func TestStalledDownloadFailsPromptly(t *testing.T) {
	out := seed(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "1.0.0.0,1.0.0.255,AU\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	err := within(t, 10*time.Second, func() error { return run("country", "", srv.URL, "", out, 300*time.Millisecond) })
	if err == nil {
		t.Fatal("stalled download reported success")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	assertPreserved(t, out)
}

func TestCorruptGzipIsError(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "bad.csv.gz", []byte{0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff})
	if err := run("country", "", "", in, out, time.Second); err == nil {
		t.Fatal("corrupt gzip reported success")
	}
	assertPreserved(t, out)
}

func TestSuccessReplacesFile(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "ok.csv", []byte("1.0.0.0,1.0.0.255,AU\n"))
	if err := run("country", "", "", in, out, time.Second); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "1.0.0.0/24 AU\n" {
		t.Errorf("feed = %q", b)
	}
	if es, _ := os.ReadDir(filepath.Dir(out)); len(es) != 1 {
		t.Errorf("files left: %v", es)
	}
}

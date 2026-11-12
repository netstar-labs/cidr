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

const previous = "9.9.9.0/24 64496 PREVIOUS\n"

// seed writes a previously published feed and returns its path.
func seed(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "feed.cidr")
	if err := os.WriteFile(p, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// assertPreserved fails unless the feed is byte-identical to the seed and no temp
// file is left beside it.
func assertPreserved(t *testing.T, out string) {
	t.Helper()
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != previous {
		t.Errorf("previous feed was modified (%d bytes now)", len(b))
	}
	es, _ := os.ReadDir(filepath.Dir(out))
	if len(es) != 1 {
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
		fmt.Fprintf(&b, "10.%d.%d.0\t10.%d.%d.255\t%d\tUS\tORG%d\n", i/256, i%256, i/256, i%256, 64512+i, i)
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

func TestZeroRowsKeepsPreviousFile(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "empty.tsv", []byte("not\ta\trow\n\n"))
	err := run("combined", "", in, out, time.Second, options{outputMode: "asn"})
	if err == nil {
		t.Fatal("run produced zero usable rows and reported success")
	}
	assertPreserved(t, out)
}

func TestMidStreamFailureKeepsPreviousFile(t *testing.T) {
	out := seed(t)
	full := gzipBytes(t, manyRows(3000))
	in := writeTemp(t, "cut.tsv.gz", full[:len(full)-12]) // every row decodes; the trailer is gone
	err := run("combined", "", in, out, time.Second, options{outputMode: "asn"})
	if err == nil {
		t.Fatal("truncated gzip reported success")
	}
	assertPreserved(t, out)
}

func TestCorruptGzipIsError(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "bad.tsv.gz", []byte{0x1f, 0x8b, 0xff, 0xff, 0xff, 0xff})
	if err := run("combined", "", in, out, time.Second, options{outputMode: "asn"}); err == nil {
		t.Fatal("corrupt gzip reported success")
	}
	assertPreserved(t, out)
}

func TestStalledDownloadFailsPromptly(t *testing.T) {
	out := seed(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- run("combined", srv.URL, "", out, 300*time.Millisecond, options{outputMode: "asn"}) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled download reported success")
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("took %v", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run still blocked on a stalled server")
	}
	assertPreserved(t, out)
}

func TestSuccessReplacesFile(t *testing.T) {
	out := seed(t)
	in := writeTemp(t, "ok.tsv", []byte(sampleTSV))
	if err := run("combined", "", in, out, time.Second, options{outputMode: "asn"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(b), "1.0.0.0/24 13335 CLOUDFLARENET\n") || strings.Contains(string(b), "PREVIOUS") {
		t.Errorf("feed = %q", b)
	}
	if es, _ := os.ReadDir(filepath.Dir(out)); len(es) != 1 {
		t.Errorf("files left: %v", es)
	}
}

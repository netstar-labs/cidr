package feedio

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func TestOutputCommit(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "feed.cidr")
	if err := os.WriteFile(target, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	o, err := Create(target)
	if err != nil {
		t.Fatal(err)
	}
	if o.Name() != target {
		t.Errorf("Name = %q", o.Name())
	}
	io.WriteString(o, "new\n")

	// Before Commit: the target is untouched and the temp cannot match *.cidr.
	if got := readFile(t, target); got != "old\n" {
		t.Errorf("target changed before Commit: %q", got)
	}
	for _, n := range names(t, dir) {
		if n == "feed.cidr" {
			continue
		}
		if m, _ := filepath.Match("*.cidr", n); m {
			t.Errorf("temp %q matches *.cidr", n)
		}
		if !strings.HasPrefix(n, ".feed.cidr.tmp-") {
			t.Errorf("unexpected temp name %q", n)
		}
	}

	if err := o.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, target); got != "new\n" {
		t.Errorf("target = %q", got)
	}
	if ns := names(t, dir); len(ns) != 1 {
		t.Errorf("leftover files: %v", ns)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want the replaced file's 0640", fi.Mode().Perm())
	}
	o.Abort() // no-op after Commit
	if got := readFile(t, target); got != "new\n" {
		t.Errorf("Abort after Commit damaged the target: %q", got)
	}
}

func TestOutputNewFileMode(t *testing.T) {
	target := filepath.Join(t.TempDir(), "feed.cidr")
	o, err := Create(target)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(o, "x")
	if err := o.Commit(); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestOutputAbort(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "feed.cidr")
	os.WriteFile(target, []byte("old\n"), 0o644)
	o, err := Create(target)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(o, "partial")
	o.Abort()
	if got := readFile(t, target); got != "old\n" {
		t.Errorf("target = %q, want untouched", got)
	}
	if ns := names(t, dir); len(ns) != 1 {
		t.Errorf("temp not removed: %v", ns)
	}
	if err := o.Commit(); err == nil {
		t.Error("Commit after Abort should fail, not publish")
	}
}

func TestOutputNoTargetOnAbort(t *testing.T) {
	dir := t.TempDir()
	o, err := Create(filepath.Join(dir, "feed.cidr"))
	if err != nil {
		t.Fatal(err)
	}
	o.Abort()
	if ns := names(t, dir); len(ns) != 0 {
		t.Errorf("files left: %v", ns)
	}
}

func TestOutputMissingDir(t *testing.T) {
	if _, err := Create(filepath.Join(t.TempDir(), "nope", "feed.cidr")); err == nil {
		t.Error("expected error for a missing directory")
	}
}

func TestOutputStdout(t *testing.T) {
	for _, path := range []string{"", "-"} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := os.Stdout
		os.Stdout = w
		o, cerr := Create(path)
		os.Stdout = saved
		if cerr != nil {
			t.Fatal(cerr)
		}
		if o.Name() != "stdout" {
			t.Errorf("Name = %q", o.Name())
		}
		io.WriteString(o, "hello\n")
		if err := o.Commit(); err != nil {
			t.Fatal(err)
		}
		w.Close()
		b, _ := io.ReadAll(r)
		r.Close()
		if string(b) != "hello\n" {
			t.Errorf("path %q: stdout got %q", path, b)
		}
	}
}

// A server that sends headers and a few bytes, then stalls, must fail within
// about the idle period, not hang.
func TestFetchStallFails(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "some bytes\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	body, err := Fetch(srv.URL, "test", 5*time.Second, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	_, err = io.ReadAll(body)
	if err == nil {
		t.Fatal("stalled body read succeeded")
	}
	if !strings.Contains(err.Error(), "stalled") {
		t.Errorf("error does not say stalled: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v to fail a 200ms idle deadline", d)
	}
}

// A server that trickles bytes faster than the idle period must succeed even
// when the whole transfer takes much longer than the idle period.
func TestFetchTrickleSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 10; i++ {
			io.WriteString(w, "chunk\n")
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond)
		}
	}))
	defer srv.Close()

	start := time.Now()
	body, err := Fetch(srv.URL, "test", 5*time.Second, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("trickling body failed: %v", err)
	}
	if string(b) != strings.Repeat("chunk\n", 10) {
		t.Errorf("body = %q", b)
	}
	if time.Since(start) < 400*time.Millisecond {
		t.Error("transfer finished too fast to prove anything about the idle clock")
	}
}

// A slow consumer must not trip the idle deadline: the clock runs only while a
// Read waits on the network.
func TestFetchSlowConsumerSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 1<<20))
	}))
	defer srv.Close()
	body, err := Fetch(srv.URL, "test", 5*time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	buf := make([]byte, 1024)
	if _, err := body.Read(buf); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // consumer busy, not reading
	if _, err := io.Copy(io.Discard, body); err != nil {
		t.Fatalf("slow consumer was failed: %v", err)
	}
}

func TestFetchStatusAndUA(t *testing.T) {
	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.Header.Get("User-Agent")
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	if _, err := Fetch(srv.URL+"/missing", "test", time.Second, time.Second); err == nil {
		t.Error("404 should be an error")
	}
	body, err := Fetch(srv.URL, "my-agent", time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	body.Close()
	if ua != "my-agent" {
		t.Errorf("User-Agent = %q", ua)
	}
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(s))
	zw.Close()
	return buf.Bytes()
}

func TestMaybeGunzip(t *testing.T) {
	r, err := MaybeGunzip(strings.NewReader("plain text\n"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r); string(b) != "plain text\n" {
		t.Errorf("plain = %q", b)
	}

	r, err = MaybeGunzip(bytes.NewReader(gz(t, "zipped\n")))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r); string(b) != "zipped\n" {
		t.Errorf("gzip = %q", b)
	}

	// Empty and one-byte inputs are plain, not an error.
	for _, in := range []string{"", "x"} {
		r, err = MaybeGunzip(strings.NewReader(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if b, _ := io.ReadAll(r); string(b) != in {
			t.Errorf("%q round-trip = %q", in, b)
		}
	}
}

func TestMaybeGunzipCorrupt(t *testing.T) {
	// Magic bytes then garbage: a corrupt header is an error, not plain text.
	if _, err := MaybeGunzip(bytes.NewReader([]byte{0x1f, 0x8b, 0xff, 0xff, 0xff})); err == nil {
		t.Error("corrupt gzip header accepted")
	}
	// A truncated body surfaces from Read.
	full := gz(t, strings.Repeat("line\n", 1000))
	r, err := MaybeGunzip(bytes.NewReader(full[:len(full)/2]))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Error("truncated gzip body read without error")
	}
}

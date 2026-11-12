package feedio

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCreateFollowsSymlink: the link survives and the file it points at is
// replaced, keeping its mode.
func TestCreateFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.cidr")
	if err := os.WriteFile(real, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "current.cidr")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	o, err := Create(link)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(o, "new")
	if err := o.Commit(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link was replaced: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(real); string(b) != "new" {
		t.Fatalf("target = %q, want new", b)
	}
	if fi, _ := os.Stat(real); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600 kept", fi.Mode().Perm())
	}
}

// TestCreateWritesThroughSpecialFile: a device target is written to, never
// replaced by a rename.
func TestCreateWritesThroughSpecialFile(t *testing.T) {
	if _, err := os.Stat(os.DevNull); err != nil {
		t.Skip("no", os.DevNull)
	}
	o, err := Create(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(o, "x")
	if err := o.Commit(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(os.DevNull); err != nil || fi.Mode().IsRegular() {
		t.Fatalf("%s is no longer a device: %v %v", os.DevNull, fi, err)
	}
}

// TestFetchZeroIdleMeansNoIdleLimit: idle <= 0 disables the idle check, as a
// zero -timeout meant "no timeout" before; a body that arrives late still reads.
func TestFetchZeroIdleMeansNoIdleLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(200 * time.Millisecond)
		io.WriteString(w, "late body\n")
	}))
	defer srv.Close()
	for _, idle := range []time.Duration{0, -1} {
		rc, err := Fetch(srv.URL, "test", 0, idle)
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || string(b) != "late body\n" {
			t.Fatalf("idle=%v: %q, %v", idle, b, err)
		}
	}
}

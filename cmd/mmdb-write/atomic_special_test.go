package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileAtomicSpecialTargets pins that a symlinked -o target is followed
// (the link survives, the file it points at is replaced) and that a special file
// such as /dev/null is written through, never replaced by a rename.
func TestWriteFileAtomicSpecialTargets(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.mmdb")
	if err := os.WriteFile(real, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.mmdb")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := writeFileAtomic(link, func(w io.Writer) error { _, err := io.WriteString(w, "new"); return err }); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link was replaced: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(real); string(b) != "new" {
		t.Fatalf("target via link = %q, want new", b)
	}
	if fi, _ := os.Stat(real); fi.Mode().Perm() != 0o600 {
		t.Fatalf("target mode = %v, want 0600 kept", fi.Mode().Perm())
	}

	if _, err := os.Stat(os.DevNull); err != nil {
		t.Skip("no", os.DevNull)
	}
	if err := writeFileAtomic(os.DevNull, func(w io.Writer) error { _, err := io.WriteString(w, "x"); return err }); err != nil {
		t.Fatalf("write to %s: %v", os.DevNull, err)
	}
	if fi, err := os.Stat(os.DevNull); err != nil || fi.Mode().IsRegular() {
		t.Fatalf("%s is no longer a device: %v %v", os.DevNull, fi, err)
	}
}

package main

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

const spec = `
1.1.1.0/24     13335 Cloudflare, Inc.
1.1.1.128/25   99999 Customer Sub-block
8.8.8.0/24     15169 Google LLC
10.0.0.0/8
`

func TestResolveAndBrief(t *testing.T) {
	entries, err := cidr.ParseSpec(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	set, table := build(entries)

	cases := []struct {
		ip    string
		want  bool
		asn   uint32
		brief string
	}{
		{"1.1.1.10", true, 13335, "1.1.1.10                                member AS13335 Cloudflare, Inc."},
		{"1.1.1.200", true, 99999, "1.1.1.200                               member AS99999 Customer Sub-block"}, // nested /25 wins
		{"10.5.5.5", true, 0, "10.5.5.5                                member 10.0.0.0/8"},                      // member, no ASN
		{"9.9.9.9", false, 0, "9.9.9.9                                 -"},
	}
	for _, c := range cases {
		r := resolve(set, table, netip.MustParseAddr(c.ip))
		if r.Member != c.want {
			t.Errorf("%s member = %v, want %v", c.ip, r.Member, c.want)
		}
		if c.asn != 0 && (r.Info == nil || r.Info.ASN != c.asn) {
			t.Errorf("%s asn = %+v, want %d", c.ip, r.Info, c.asn)
		}
		if got := formatBrief(r); got != c.brief {
			t.Errorf("brief(%s)\n got %q\nwant %q", c.ip, got, c.brief)
		}
	}
}

// failAfter is a writer that accepts n bytes and then fails, like a full disk
// or a file-size limit.
type failAfter struct{ n int }

var errFull = errors.New("no space left on device")

func (w *failAfter) Write(p []byte) (int, error) {
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, errFull
	}
	w.n -= len(p)
	return len(p), nil
}

func writeSpec(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.txt")
	if err := os.WriteFile(path, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLI(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestExitCodes(t *testing.T) {
	sp := writeSpec(t)
	cases := []struct {
		name  string
		stdin string
		args  []string
		code  int
		out   string // substring of stdout, if non-empty
		err   string // substring of stderr, if non-empty
	}{
		{"lookup ok", "", []string{"-spec", sp, "-quiet", "1.1.1.1"}, 0, `"member":true`, ""},
		{"lookup miss is still ok", "", []string{"-spec", sp, "-quiet", "9.9.9.9"}, 0, `"member":false`, ""},
		{"match hit", "9.9.9.9\n8.8.8.8\n", []string{"-spec", sp, "-quiet", "-match"}, 0, "8.8.8.8", ""},
		{"match miss", "9.9.9.9\n", []string{"-spec", sp, "-quiet", "-match"}, 1, "", ""},
		{"match missing spec", "8.8.8.8\n", []string{"-spec", filepath.Join(t.TempDir(), "nope"), "-match"}, 2, "", "cidr:"},
		{"lookup missing spec", "", []string{"-spec", filepath.Join(t.TempDir(), "nope"), "1.1.1.1"}, 2, "", "cidr:"},
		{"no spec flag", "", []string{"1.1.1.1"}, 2, "", "-spec is required"},
		{"bad flag", "", []string{"-nosuchflag"}, 2, "", "nosuchflag"},
		{"version", "", []string{"-version"}, 0, "cidr ", ""},
	}
	for _, c := range cases {
		code, out, errOut := runCLI(t, c.stdin, c.args...)
		if code != c.code {
			t.Errorf("%s: exit %d, want %d (stderr %q)", c.name, code, c.code, errOut)
		}
		if c.out != "" && !strings.Contains(out, c.out) {
			t.Errorf("%s: stdout %q lacks %q", c.name, out, c.out)
		}
		if c.err != "" && !strings.Contains(errOut, c.err) {
			t.Errorf("%s: stderr %q lacks %q", c.name, errOut, c.err)
		}
	}
}

func TestWriteErrorExits2(t *testing.T) {
	sp := writeSpec(t)
	many := strings.Repeat("1.1.1.1\n", 2000) // well past bufio's 4 KiB buffer
	cases := []struct {
		name  string
		stdin string
		args  []string
		limit int
	}{
		{"flush fails (small output)", "", []string{"-spec", sp, "1.1.1.1"}, 0},
		{"mid-stream write fails (ndjson)", many, []string{"-spec", sp}, 100},
		{"mid-stream write fails (brief)", many, []string{"-spec", sp, "-brief"}, 100},
		{"mid-stream write fails (match)", many, []string{"-spec", sp, "-match"}, 100},
		{"flush fails (match, tiny)", "1.1.1.1\n", []string{"-spec", sp, "-match"}, 3},
	}
	for _, c := range cases {
		var e bytes.Buffer
		code := run(c.args, strings.NewReader(c.stdin), &failAfter{n: c.limit}, &e)
		if code != exitError {
			t.Errorf("%s: exit %d, want 2", c.name, code)
		}
		if !strings.Contains(e.String(), errFull.Error()) {
			t.Errorf("%s: stderr %q does not report the write error", c.name, e.String())
		}
		if strings.Contains(e.String(), "queried=") {
			t.Errorf("%s: stderr %q printed a tally for a failed run", c.name, e.String())
		}
	}
}

func TestVersionWriteError(t *testing.T) {
	var e bytes.Buffer
	if code := run([]string{"-version"}, strings.NewReader(""), &failAfter{}, &e); code != exitError {
		t.Errorf("exit %d, want 2", code)
	}
}

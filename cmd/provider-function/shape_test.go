package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for audit issue #33, items 2-4: a feed whose shape has
// changed, or which the line scanner cannot get through, must fail loudly
// instead of publishing a table with a whole address family (or the tail of the
// feed) silently missing.

// runKeeping runs run() over the -in specs against an existing output file and
// returns the error plus whether the previous content survived untouched.
func runKeeping(t *testing.T, dir string, specs ...string) (err error, kept bool) {
	t.Helper()
	out := filepath.Join(dir, "out.cidr")
	yesterday := "1.2.3.0/24 cloud aws\n"
	if werr := os.WriteFile(out, []byte(yesterday), 0o600); werr != nil {
		t.Fatal(werr)
	}
	err = run("all", strings.Join(specs, ","), out, "", 0)
	got, rerr := os.ReadFile(out)
	return err, rerr == nil && string(got) == yesterday
}

// TestAbsentExpectedArrayIsAHardError (#33 item 2): the AWS, Fastly and Google
// parsers decoded into plain slices, so a renamed or dropped top-level array was
// indistinguishable from an empty one. Each case keeps one healthy array so the
// feed still yields rows — which is exactly why the old guard did not fire.
func TestAbsentExpectedArrayIsAHardError(t *testing.T) {
	cases := []struct {
		name, provider, body, wantKey string
	}{
		{"aws no ipv6_prefixes", "aws",
			`{"prefixes":[` + aws4("3.5.140.0/22", "EC2") + `]}`, "ipv6_prefixes"},
		{"aws renamed prefixes", "aws",
			`{"ipPrefixes":[],"ipv6_prefixes":[{"ipv6_prefix":"2600:1f00::/24","service":"AMAZON"}]}`, "prefixes"},
		{"aws null ipv6_prefixes", "aws",
			`{"prefixes":[` + aws4("3.5.140.0/22", "EC2") + `],"ipv6_prefixes":null}`, "ipv6_prefixes"},
		{"fastly no ipv6_addresses", "fastly",
			`{"addresses":["23.235.32.0/20"]}`, "ipv6_addresses"},
		{"fastly renamed addresses", "fastly",
			`{"ipv4":["23.235.32.0/20"],"ipv6_addresses":["2a04:4e40::/32"]}`, "addresses"},
		{"google no prefixes", "google-cloud",
			`{"syncToken":"1","entries":[{"ipv4Prefix":"34.1.208.0/20"}]}`, "prefixes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			err, kept := runKeeping(t, dir, writeFixture(t, dir, c.provider, c.body))
			if err == nil {
				t.Fatal("feed with an absent expected array was accepted; want an error")
			}
			if !strings.Contains(err.Error(), c.wantKey) {
				t.Errorf("error %q does not name the missing array %q", err, c.wantKey)
			}
			if !kept {
				t.Error("previous output was modified")
			}
		})
	}
}

// TestPresentEmptyArrayIsAccepted pins the decision for item 2's other half: an
// array that is present but empty is a legitimate shape (the package doc
// leaves "is the feed usable" to the per-feed zero-row guard, and the existing
// end-to-end fixtures publish an empty ipv6_prefixes). Presence is what is
// checked, not length.
func TestPresentEmptyArrayIsAccepted(t *testing.T) {
	got, st, _ := convert(t,
		src{"aws", awsDoc(aws4("3.5.140.0/22", "EC2"), "")},
		src{"fastly", `{"addresses":[],"ipv6_addresses":["2a04:4e40::/32"]}`},
		src{"google-cloud", `{"prefixes":[{"ipv4Prefix":"34.1.208.0/20"}]}`},
	)
	want := "3.5.140.0/22 cloud aws\n34.1.208.0/20 cloud google-cloud\n2a04:4e40::/32 cdn fastly anycast\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if st.malformed["aws"]+st.malformed["fastly"]+st.malformed["google-cloud"] != 0 {
		t.Errorf("empty arrays counted as malformed: %v", st.malformed)
	}
}

// TestGoogleEntryWithNoPrefixIsMalformed (#33 item 3): an entry with neither
// ipv4Prefix nor ipv6Prefix was skipped without a trace. It is a row the parser
// cannot use, so it is counted; entries carrying either one still work.
func TestGoogleEntryWithNoPrefixIsMalformed(t *testing.T) {
	got, st, _ := convert(t, src{"google-cloud",
		`{"prefixes":[{"ipv4Prefix":"34.1.208.0/20"},{"service":"Google Cloud","scope":"x"},{"ipv6Prefix":"2600:1900:4000::/44"},{}]}`})
	want := "34.1.208.0/20 cloud google-cloud\n2600:1900:4000::/44 cloud google-cloud\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	if st.malformed["google-cloud"] != 2 {
		t.Errorf("malformed = %d, want 2 (the two entries with no prefix)", st.malformed["google-cloud"])
	}
	if st.perSource["google-cloud"] != 2 {
		t.Errorf("records = %d, want 2", st.perSource["google-cloud"])
	}
}

// TestGoogleFeedOfOnlyPrefixlessEntriesFails is item 3 at the level that
// matters: before, such a feed yielded rows=0 malformed=0 (so the guard's
// message could not even say why); now the entries are counted and the feed
// fails.
func TestGoogleFeedOfOnlyPrefixlessEntriesFails(t *testing.T) {
	dir := t.TempDir()
	err, kept := runKeeping(t, dir,
		writeFixture(t, dir, "google-cloud", `{"prefixes":[{"service":"a"},{"service":"b"}]}`))
	if err == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(err.Error(), "2 malformed") {
		t.Errorf("error %q does not report the two malformed entries", err)
	}
	if !kept {
		t.Error("previous output was modified")
	}
}

// TestLineOfOneMiBIsAHardError (#33 item 4): bufio.Scanner stops at a line
// longer than its buffer, so every row after it was lost, yet the code counted
// one malformed row and exited 0 with a truncated table.
func TestLineOfOneMiBIsAHardError(t *testing.T) {
	huge := strings.Repeat("x", 1024*1024+1)
	for _, p := range []string{"cloudflare", "tor"} {
		t.Run(p, func(t *testing.T) {
			dir := t.TempDir()
			body := "104.16.0.0/13\n" + huge + "\n104.24.0.0/14\n104.28.0.0/15\n"
			err, kept := runKeeping(t, dir, writeFixture(t, dir, p, body))
			if err == nil {
				t.Fatal("a feed with an unreadable 1 MiB line was accepted; its tail was silently dropped")
			}
			if !strings.Contains(err.Error(), "1 MiB") {
				t.Errorf("error %q does not say why", err)
			}
			if !kept {
				t.Error("previous output was modified")
			}
		})
	}
}

package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Regression tests for audit issue #33, items 1 and 5: the zero-row guard is per
// feed, and output and fetching go through internal/feedio.

// TestEmptySecondFeedOfAProviderFails (#33 item 1): Cloudflare publishes ips-v4
// and ips-v6 as two files. The guard counted per provider, so a dead ips-v6 was
// hidden by a healthy ips-v4 and the run exited 0 with no IPv6 Cloudflare rows.
func TestEmptySecondFeedOfAProviderFails(t *testing.T) {
	dir := t.TempDir()
	v4 := writeFixture(t, dir, "cloudflare", "173.245.48.0/20\n104.16.0.0/13\n")
	v6path := filepath.Join(dir, "ips-v6")
	if err := os.WriteFile(v6path, []byte("# nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err, kept := runKeeping(t, dir, v4, "cloudflare="+v6path)
	if err == nil {
		t.Fatal("an empty ips-v6 was accepted because ips-v4 had rows")
	}
	if !strings.Contains(err.Error(), v6path) {
		t.Errorf("error %q does not name the empty feed %s", err, v6path)
	}
	if strings.Contains(err.Error(), dir+"/cloudflare.fixture") {
		t.Errorf("error %q blames the healthy feed", err)
	}
	if !kept {
		t.Error("previous output was modified")
	}
}

// TestEveryEmptyFeedIsNamed: when several feeds are dead the error names all of
// them, so the operator fixes one problem per run, not one per retry.
func TestEveryEmptyFeedIsNamed(t *testing.T) {
	srcs := []source{
		{provider: "cloudflare", name: "v4", tally: tally{rows: 5}},
		{provider: "cloudflare", name: "v6", tally: tally{malformed: 2}},
		{provider: "tor", name: "tor-list"},
	}
	err := checkFeedsProduced(srcs)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"v6", "(2 malformed)", "tor-list"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "feed v4") {
		t.Errorf("error %q names the healthy feed", err)
	}
}

// TestReportFeedsOneLinePerFeed pins the stderr format added for item 1.
func TestReportFeedsOneLinePerFeed(t *testing.T) {
	var b strings.Builder
	reportFeeds(&b, []source{
		{provider: "cloudflare", name: "https://x/ips-v4", tally: tally{rows: 15}},
		{provider: "cloudflare", name: "https://x/ips-v6", tally: tally{rows: 0, malformed: 1}},
	})
	want := "provider-function: feed cloudflare https://x/ips-v4 rows=15 malformed=0\n" +
		"provider-function: feed cloudflare https://x/ips-v6 rows=0 malformed=1\n"
	if b.String() != want {
		t.Errorf("got:\n%q\nwant:\n%q", b.String(), want)
	}
}

// TestPerFeedTallyIsCounted runs real parsers through collect and checks the
// per-feed counters (not the per-provider ones) get the rows.
func TestPerFeedTallyIsCounted(t *testing.T) {
	var a, b tally
	table := map[netip.Prefix]entry{}
	st := stats{perSource: map[string]int{}, malformed: map[string]int{}}
	var conflicts []conflict
	if err := providers["cloudflare"].parse(strings.NewReader("104.16.0.0/13\nbogus\n"),
		collect("cloudflare", &a, &st, table, &conflicts)); err != nil {
		t.Fatal(err)
	}
	if err := providers["cloudflare"].parse(strings.NewReader(""),
		collect("cloudflare", &b, &st, table, &conflicts)); err != nil {
		t.Fatal(err)
	}
	if a != (tally{rows: 1, malformed: 1}) || b != (tally{}) {
		t.Errorf("feed tallies a=%+v b=%+v", a, b)
	}
	if st.perSource["cloudflare"] != 1 {
		t.Errorf("provider tally = %d, want 1", st.perSource["cloudflare"])
	}
}

// listDir returns the sorted names in dir, so a leftover temp file shows up.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// useProvider points one provider at test URLs for the duration of the test.
func useProvider(t *testing.T, name string, urls ...string) {
	t.Helper()
	old := providers[name]
	p := old
	p.urls = urls
	providers[name] = p
	t.Cleanup(func() { providers[name] = old })
}

// TestFetchedFeedIsPublishedAtomically covers the happy path through
// feedio.Fetch and feedio.Create, including the conflict log, and that no
// temporary file is left next to the output.
func TestFetchedFeedIsPublishedAtomically(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "provider-function-cidr") {
			http.Error(w, "no user agent", http.StatusForbidden)
			return
		}
		w.Write([]byte("171.25.193.25\n"))
	}))
	defer srv.Close()
	useProvider(t, "tor", srv.URL)

	dir := t.TempDir()
	out := filepath.Join(dir, "out.cidr")
	log := filepath.Join(dir, "conflicts.tsv")
	if err := run("tor", "", out, log, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != "171.25.193.25/32 tor-exit tor\n" {
		t.Fatalf("out = %q, %v", got, err)
	}
	if names := listDir(t, dir); strings.Join(names, ",") != "conflicts.tsv,out.cidr" {
		t.Errorf("directory holds %v; want only the two published files", names)
	}
}

// TestStalledFeedFailsPromptly (#33 item 5): the old fetch had no body
// deadline, so a server that sent headers and then went quiet hung the run (and
// the timer unit) forever. feedio.Fetch applies -timeout as an idle deadline.
func TestStalledFeedFailsPromptly(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	useProvider(t, "tor", srv.URL)

	dir := t.TempDir()
	out := filepath.Join(dir, "out.cidr")
	if err := os.WriteFile(out, []byte("yesterday\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- run("tor", "", out, "", 300*time.Millisecond) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "stalled") {
			t.Errorf("err = %v, want a stall error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run is still blocked on a stalled feed after 5s (timeout was 300ms)")
	}
	if got, _ := os.ReadFile(out); string(got) != "yesterday\n" {
		t.Errorf("previous output changed: %q", got)
	}
	if names := listDir(t, dir); len(names) != 1 {
		t.Errorf("directory holds %v; want only out.cidr", names)
	}
}

// TestPreviousOutputSurvivesEveryFailure (#33 item 5): whatever the reason a run
// fails, the file at -o is the previous complete file and no temp file remains.
func TestPreviousOutputSurvivesEveryFailure(t *testing.T) {
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>maintenance</html>`))
	}))
	defer garbage.Close()

	cases := []struct {
		name  string
		setup func(t *testing.T, dir string) (name, in string)
	}{
		{"http 404", func(t *testing.T, dir string) (string, string) {
			useProvider(t, "tor", notFound.URL)
			return "tor", ""
		}},
		{"zero usable rows", func(t *testing.T, dir string) (string, string) {
			useProvider(t, "cloudflare", garbage.URL, garbage.URL)
			return "cloudflare", ""
		}},
		{"invalid json", func(t *testing.T, dir string) (string, string) {
			return "all", writeFixture(t, dir, "aws", `{"prefixes":`)
		}},
		{"empty second feed", func(t *testing.T, dir string) (string, string) {
			e := filepath.Join(dir, "empty")
			if err := os.WriteFile(e, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return "all", writeFixture(t, dir, "cloudflare", "104.16.0.0/13\n") + ",cloudflare=" + e
		}},
		{"missing array", func(t *testing.T, dir string) (string, string) {
			return "all", writeFixture(t, dir, "fastly", `{"addresses":["23.235.32.0/20"]}`)
		}},
		{"too-long line", func(t *testing.T, dir string) (string, string) {
			return "all", writeFixture(t, dir, "tor", "1.2.3.4\n"+strings.Repeat("y", 2<<20)+"\n")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "out.cidr")
			if err := os.WriteFile(out, []byte("yesterday\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			name, in := c.setup(t, dir)
			before := listDir(t, dir)
			if err := run(name, in, out, filepath.Join(dir, "conflicts.tsv"), 5*time.Second); err == nil {
				t.Fatal("run succeeded; want a failure")
			}
			if got, _ := os.ReadFile(out); string(got) != "yesterday\n" {
				t.Errorf("previous output changed: %q", got)
			}
			if after := listDir(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
				t.Errorf("directory changed on failure: before %v after %v", before, after)
			}
		})
	}
}

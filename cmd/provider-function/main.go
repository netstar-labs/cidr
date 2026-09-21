// Command provider-function converts the IP-range files that cloud and CDN
// operators publish about themselves into the cidr spec format —
// "<cidr> <function> <provider> [anycast]" per line, which LoadFunc reads back.
//
// Like rir-country, and unlike mm-dbip or mm-geolite2-asn, this reads the
// *primary* record: the operator publishes the list, so there is no account,
// licence key, vendor terms, or heuristic between the source and the answer.
//
//	provider-function                                  # all five providers
//	provider-function -provider aws -o aws.cidr        # one
//	provider-function -in aws=ip-ranges.json           # local files, provider=path
//
// # Function is three values, on purpose
//
// An address's function — hosting, CDN, residential, mobile, transit, VPN exit,
// scanner — is the axis ipdb's design docs argue an IP record should assert.
// Sources that publish their own address space can honestly support three of
// those labels:
//
//	cloud     general compute and service ranges
//	cdn       content-delivery edge
//	tor-exit  Tor exit relays, from the Tor Project's own bulk list
//
// No operator publishes a "these are consumer broadband" file, so the remaining
// labels need other sources (CAIDA, commercial usage-type feeds, ASN-name
// heuristics) and arrive with them. A taxonomy wider than the evidence would
// make the table look complete while the missing labels are merely absent.
//
// # tor-exit is perishable in a way the others are not
//
// Cloud and CDN ranges change slowly — a table a day old is a table. Tor exit
// relays churn constantly: the bulk list is a snapshot of who was exiting when
// it was fetched, so a daily build both carries relays that have since stopped
// and misses ones that have since started. It is accurate about the past, not
// the present, and a consumer treating "not in the table" as "not a Tor exit"
// will be wrong regularly. Rebuild it on the cadence the decision needs.
//
// # The anycast marker is conservative
//
// The optional fourth field is present only where the operator's own
// documentation uses the word anycast — AWS Global Accelerator ("static anycast
// IP addresses"), Cloudflare and Fastly, which document their whole edge
// networks that way. CloudFront and Route 53 are deliberately *not* marked,
// although a commercial dataset would mark both: the only claim this table can
// defend is "the operator said so", and one inferred row mixed in with the
// published ones leaves a consumer unable to tell which kind any row is.
//
// This is not an anycast detector. It covers addresses whose operator publishes
// a list, which is most of the traffic-carrying anycast space and almost none of
// the long tail. Measured detection (RTT and path divergence from multiple
// vantage points) is a different tool with a different operational profile.
//
// # Overlapping prefixes
//
// AWS publishes a prefix once per service it belongs to, and the "AMAZON"
// service is a catch-all superset of the specific ones: as published on
// 2026-09-21, 2,298 of 7,795 distinct IPv4 prefixes carried more than one
// service label. Without a precedence rule, whether a CloudFront range came out
// "cdn" or "cloud" would depend on map iteration order.
//
// So: within one operator's feed, a service with an explicit mapping (there are
// exactly two — CLOUDFRONT and GLOBALACCELERATOR) outranks the catch-all. That
// specificity rule stops at the provider boundary: it says nothing about two
// different operators, so it never settles a disagreement between them. Any
// prefix left claimed by two different functions is counted and reported on
// stderr — never resolved silently. -conflict-log FILE writes every one as TSV.
// Output is sorted, so two runs over the same input are byte-identical.
//
// # Nothing fails quietly
//
// A row a parser cannot use is counted per provider and reported as
// malformed[...]; a provider that was attempted is always in the records[...]
// tally, including at zero. And a source that yielded no usable rows at all is
// a hard error, not an empty section of the table: none of these feeds is ever
// legitimately empty, so zero rows means the fetch or the parse broke. Without
// that guard a feed answering 200 with the wrong shape produced a clean exit
// and a zero-byte file — which, under build/provider-function --generator,
// truncates the published spec on a "successful" timer run.
//
// # -in and -provider
//
// -in takes provider=path pairs, not a bare path: the five feeds have four
// different shapes, so the format cannot be inferred from a filename. Unlike
// the other generators, -in does not auto-detect gzip. When both are given,
// -in wins and -provider is ignored with a warning on stderr.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
)

// The function labels published operator ranges can support. See the package
// doc for why the rest of ipdb's taxonomy is not here.
const (
	funcCloud   = "cloud"
	funcCDN     = "cdn"
	funcTorExit = "tor-exit"
)

// providerOrder fixes the fetch and tie-break order. Map iteration is random;
// the output must not be.
var providerOrder = []string{"aws", "cloudflare", "fastly", "google-cloud", "tor"}

// A provider's published feeds and the parser for their shape. One provider can
// publish more than one file (Cloudflare splits v4 and v6).
type provider struct {
	urls  []string
	parse func(r io.Reader, emit func(prefix string, e entry)) error
}

var providers = map[string]provider{
	"aws": {
		urls:  []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"},
		parse: parseAWS,
	},
	"cloudflare": {
		urls: []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"},
		// Cloudflare documents its whole edge network as anycast.
		parse: parseLineList(entry{function: funcCDN, anycast: true}),
	},
	"fastly": {
		urls:  []string{"https://api.fastly.com/public-ip-list"},
		parse: parseFastly,
	},
	"google-cloud": {
		urls:  []string{"https://www.gstatic.com/ipranges/cloud.json"},
		parse: parseGoogleCloud,
	},
	"tor": {
		urls:  []string{"https://check.torproject.org/torbulkexitlist"},
		parse: parseLineList(entry{function: funcTorExit}),
	},
}

// entry is one prefix's classification plus the precedence needed to resolve a
// prefix published twice.
type entry struct {
	function string
	provider string
	anycast  bool
	// rank is the specificity of the source label. A provider that publishes a
	// catch-all alongside specific services (AWS) emits rank 0 for the catch-all
	// and rank 1 for a service with an explicit mapping; higher wins.
	rank int
}

// awsServices maps the AWS service labels that mean something other than
// "general cloud range". Anything absent is funcCloud at rank 0 — including the
// "AMAZON" catch-all, which is why absence must be the low rank.
//
// CLOUDFRONT_ORIGIN_FACING is the origin-fetch side of the CDN, not the edge a
// client reaches, so it stays cloud. GLOBALACCELERATOR is an anycast front door
// for a customer's own application rather than a content-delivery network, so it
// is cloud with the marker, not cdn.
var awsServices = map[string]entry{
	"CLOUDFRONT":        {function: funcCDN, rank: 1},
	"GLOBALACCELERATOR": {function: funcCloud, anycast: true, rank: 1},
}

// Version and Revision are stamped at build time via -ldflags -X.
var (
	Version  = "dev"
	Revision = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	name := flag.String("provider", "all", `provider: "all" or one of `+strings.Join(providerOrder, ", "))
	in := flag.String("in", "", "comma-separated provider=path local files instead of fetching")
	out := flag.String("o", "", "write to this file instead of stdout")
	conflictLog := flag.String("conflict-log", "", "write every conflict to this file as TSV")
	timeout := flag.Duration("timeout", 30*time.Second, "dial/response-header timeout")
	flag.Parse()

	if *version {
		fmt.Printf("provider-function %s (%s)\n", Version, Revision)
		return
	}
	if *name != "all" {
		if _, ok := providers[*name]; !ok {
			fmt.Fprintf(os.Stderr, "provider-function: unknown provider %q (want all, %s)\n",
				*name, strings.Join(providerOrder, ", "))
			os.Exit(2)
		}
	}
	if *in != "" && *name != "all" {
		// -in wins. Say so rather than letting -provider look honoured.
		fmt.Fprintf(os.Stderr, "provider-function: -in is set, ignoring -provider %q\n", *name)
	}
	if err := run(*name, *in, *out, *conflictLog, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "provider-function:", err)
		os.Exit(1)
	}
}

// stats is only what cannot be derived at report time. Prefix and conflict
// counts are not here: they are len(table) and len(conflicts), and a counter
// that can disagree with the thing it counts is a bug waiting to be written.
type stats struct {
	// perSource counts published records accepted per provider — records, not
	// prefixes: AWS lists a prefix once per service it belongs to, and the
	// table collapses those. Every attempted provider gets an entry, including
	// a zero one, so a source that returned nothing usable is visible rather
	// than absent from the tally.
	perSource map[string]int
	// malformed counts rows a parser could not use, per provider. Without it a
	// feed that answers 200 with the wrong shape produces a short or empty
	// table and a clean exit — see the family's own counters in
	// rir-country/main.go.
	malformed map[string]int
}

type conflict struct {
	prefix netip.Prefix
	a, b   entry
	winner entry
}

func run(name, in, out, conflictLog string, timeout time.Duration) error {
	table := map[netip.Prefix]entry{}
	st := stats{perSource: map[string]int{}, malformed: map[string]int{}}
	var conflicts []conflict

	sources, err := openSources(name, in, timeout)
	if err != nil {
		return err
	}
	// Every source is opened before any is parsed, so a parse failure part-way
	// through leaves the rest open. Closing them all on the way out is the only
	// path that does not depend on where the loop stopped.
	defer closeAll(sources)

	for _, src := range sources {
		// An attempted provider is always in the tally, even at zero — the
		// alternative is a feed that failed being absent from the report rather
		// than visibly empty.
		st.perSource[src.provider] += 0
		err := providers[src.provider].parse(src.r, collect(src.provider, &st, table, &conflicts))
		if err != nil {
			return fmt.Errorf("%s: %w", src.name, err)
		}
	}
	if err := checkSourcesProduced(sources, &st); err != nil {
		return err
	}

	var w io.Writer = os.Stdout
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	bw := bufio.NewWriter(w)
	if err := emit(table, bw); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	if conflictLog != "" {
		if err := writeConflictLog(conflictLog, conflicts); err != nil {
			return err
		}
	}
	reportConflicts(os.Stderr, conflicts, conflictLog)

	dst := "stdout"
	if out != "" {
		dst = out
	}
	// Per-provider counts are published *records*, which exceed prefixes: AWS
	// lists a prefix once per service it belongs to, and the table collapses those.
	fmt.Fprintf(os.Stderr, "provider-function: records[%s] malformed[%s] prefixes=%d conflicts=%d -> %s\n",
		perSourceTally(st.perSource), perSourceTally(st.malformed), len(table), len(conflicts), dst)
	return nil
}

// collect returns the per-record callback a parser feeds: it turns the raw
// prefix text into a netip.Prefix, counts what it cannot parse, and merges the
// rest. Parsing in one place rather than in each of the four parsers is what
// gives the malformed counter a single home — without it, a feed answering 200
// with the wrong shape yields a short table and a clean exit.
func collect(provider string, st *stats, table map[netip.Prefix]entry, conflicts *[]conflict) func(string, entry) {
	return func(raw string, e entry) {
		p, err := cidr.ParsePrefix(raw)
		if err != nil {
			st.malformed[provider]++
			return
		}
		e.provider = provider
		st.perSource[provider]++
		merge(table, p, e, conflicts)
	}
}

// checkSourcesProduced refuses to write a table when a source that was actually
// attempted yielded nothing usable. None of these five feeds is ever legitimately
// empty, so zero rows means the fetch or the parse broke — and the failure is
// otherwise silent: build/provider-function --generator would truncate the
// published spec to empty on a "successful" timer run.
func checkSourcesProduced(sources []source, st *stats) error {
	seen := map[string]bool{}
	for _, src := range sources {
		if seen[src.provider] {
			continue
		}
		seen[src.provider] = true
		if st.perSource[src.provider] == 0 {
			return fmt.Errorf("provider %s produced no usable rows (%d malformed) — refusing to write a table that would look like an empty internet",
				src.provider, st.malformed[src.provider])
		}
	}
	return nil
}

// merge adds one classification, resolving a prefix already claimed. Rank
// decides first; a genuine disagreement between two equally specific sources is
// recorded and broken by provider order so the output does not depend on the
// order the files were read.
func merge(table map[netip.Prefix]entry, p netip.Prefix, e entry, conflicts *[]conflict) {
	prev, exists := table[p]
	if !exists {
		table[p] = e
		return
	}
	if prev.function == e.function && prev.anycast == e.anycast {
		// The same classification twice. Two providers agreeing is agreement,
		// not a disagreement to report — "cdn vs cdn -> cdn" in a conflict log
		// reads as a defect and inflates the number an operator watches for
		// feed drift. The winner still has to be deterministic, so fall through
		// to provider order without recording anything.
		if providerRank(e.provider) < providerRank(prev.provider) {
			table[p] = e
		}
		return
	}
	// rank is specificity WITHIN one provider's own feed — AWS lists a prefix
	// once per service and AMAZON is a catch-all superset of the specific ones.
	// It says nothing about two different operators, so comparing it across
	// providers would let an AWS service label silently override another
	// operator's published claim (and drop that operator's anycast marker)
	// without ever reaching the conflict path below.
	if prev.provider == e.provider && prev.rank != e.rank {
		if e.rank > prev.rank {
			table[p] = e
		}
		return // specificity separated them: not a disagreement
	}
	winner := prev
	if providerRank(e.provider) < providerRank(prev.provider) ||
		(e.provider == prev.provider && e.function < prev.function) {
		winner = e
	}
	*conflicts = append(*conflicts, conflict{prefix: p, a: prev, b: e, winner: winner})
	table[p] = winner
}

func providerRank(name string) int {
	for i, p := range providerOrder {
		if p == name {
			return i
		}
	}
	return len(providerOrder)
}

// emit writes the table as a sorted cidr spec. Sorting is what makes two runs
// over the same input byte-identical: map iteration order is not stable, and a
// generator whose output churns cannot be diffed or checksummed.
func emit(table map[netip.Prefix]entry, w io.Writer) error {
	out := make([]netip.Prefix, 0, len(table))
	for p := range table {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Addr().Is4() != b.Addr().Is4() {
			return a.Addr().Is4() // v4 block first
		}
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	for _, p := range out {
		e := table[p]
		line := p.String() + " " + e.function + " " + e.provider
		if e.anycast {
			line += " anycast"
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// --- parsers ----------------------------------------------------------------

// parseAWS reads ip-ranges.json. Every prefix is listed once per service it
// belongs to; see the package doc for the precedence that resolves that.
func parseAWS(r io.Reader, emit func(string, entry)) error {
	var doc struct {
		Prefixes []struct {
			IPPrefix string `json:"ip_prefix"`
			Service  string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return err
	}
	add := func(s, service string) {
		e, ok := awsServices[service]
		if !ok {
			e = entry{function: funcCloud} // rank 0: AMAZON and every plain service
		}
		emit(s, e)
	}
	for _, p := range doc.Prefixes {
		add(p.IPPrefix, p.Service)
	}
	for _, p := range doc.IPv6Prefixes {
		add(p.IPv6Prefix, p.Service)
	}
	return nil
}

// parseGoogleCloud reads cloud.json, whose entries carry exactly one of
// ipv4Prefix/ipv6Prefix and a single service value ("Google Cloud").
func parseGoogleCloud(r io.Reader, emit func(string, entry)) error {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return err
	}
	for _, pfx := range doc.Prefixes {
		for _, s := range []string{pfx.IPv4Prefix, pfx.IPv6Prefix} {
			if s == "" {
				continue
			}
			emit(s, entry{function: funcCloud})
		}
	}
	return nil
}

// parseLineList returns a parser for the plain-text one-per-line shape that
// both Cloudflare (CIDR prefixes) and the Tor Project (bare addresses, promoted
// to host routes by ParsePrefix) publish. The whole file carries one
// classification, so it is supplied rather than derived per line.
func parseLineList(e entry) func(io.Reader, func(string, entry)) error {
	return func(r io.Reader, emit func(string, entry)) error {
		sc := bufio.NewScanner(r)
		// A line longer than the 64KB default would otherwise abort the whole
		// run with "token too long", discarding every provider that parsed
		// cleanly — a minified error page is one line. Same bound, and the same
		// reason, as rir-country.
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			emit(line, e)
		}
		if err := sc.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				// Count it and keep the rows that did parse, rather than
				// discarding four good providers over one absurd line.
				emit("", e)
				return nil
			}
			return err
		}
		return nil
	}
}

// parseFastly reads public-ip-list. Fastly documents its edge as anycast.
func parseFastly(r io.Reader, emit func(string, entry)) error {
	var doc struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return err
	}
	for _, list := range [][]string{doc.Addresses, doc.IPv6Addresses} {
		for _, s := range list {
			emit(s, entry{function: funcCDN, anycast: true})
		}
	}
	return nil
}

// --- sources ----------------------------------------------------------------

type source struct {
	name     string // for error messages: the url or file path
	provider string
	r        io.ReadCloser
}

func openSources(name, in string, timeout time.Duration) ([]source, error) {
	var out []source
	if in != "" {
		for _, spec := range strings.Split(in, ",") {
			spec = strings.TrimSpace(spec)
			if spec == "" {
				continue
			}
			prov, path, ok := strings.Cut(spec, "=")
			if !ok {
				closeAll(out)
				return nil, fmt.Errorf("-in wants provider=path, got %q (providers: %s)",
					spec, strings.Join(providerOrder, ", "))
			}
			if _, known := providers[prov]; !known {
				closeAll(out)
				return nil, fmt.Errorf("-in: unknown provider %q (want %s)",
					prov, strings.Join(providerOrder, ", "))
			}
			f, err := os.Open(path)
			if err != nil {
				closeAll(out)
				return nil, err
			}
			out = append(out, source{name: path, provider: prov, r: f})
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("-in named no readable files")
		}
		return out, nil
	}

	names := providerOrder
	if name != "all" {
		names = []string{name}
	}
	for _, prov := range names {
		for _, url := range providers[prov].urls {
			body, err := fetch(url, timeout)
			if err != nil {
				closeAll(out)
				return nil, err
			}
			out = append(out, source{name: url, provider: prov, r: body})
		}
	}
	return out, nil
}

func closeAll(s []source) {
	for _, x := range s {
		x.r.Close()
	}
}

func fetch(url string, timeout time.Duration) (io.ReadCloser, error) {
	client := &http.Client{Transport: &http.Transport{
		// A hand-built Transport has a nil Proxy, which silently ignores
		// HTTPS_PROXY/HTTP_PROXY/NO_PROXY — unlike http.DefaultTransport. The
		// other four generators share the omission (audit B1, 2026-09-21).
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "provider-function-cidr (+github.com/netstar-labs/cidr)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// --- reporting --------------------------------------------------------------

func perSourceTally(per map[string]int) string {
	var b strings.Builder
	for _, p := range providerOrder {
		if n, ok := per[p]; ok {
			fmt.Fprintf(&b, "%s=%d ", p, n)
		}
	}
	return strings.TrimSpace(b.String())
}

// stderrConflicts is how many conflicts are printed before the rest are
// summarised. The summary states the count, so nothing is silently dropped;
// -conflict-log writes every one.
const stderrConflicts = 10

func reportConflicts(w io.Writer, conflicts []conflict, logPath string) {
	if len(conflicts) == 0 {
		return
	}
	for i, c := range conflicts {
		if i == stderrConflicts {
			fmt.Fprintf(w, "provider-function: ... and %d more conflicts\n", len(conflicts)-stderrConflicts)
			break
		}
		fmt.Fprintf(w, "provider-function: conflict %s: %s/%s vs %s/%s -> %s/%s\n",
			c.prefix, c.a.provider, c.a.function, c.b.provider, c.b.function,
			c.winner.provider, c.winner.function)
	}
	if logPath == "" {
		fmt.Fprintln(w, "provider-function: -conflict-log FILE writes every conflict as TSV")
	}
}

func writeConflictLog(path string, conflicts []conflict) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	fmt.Fprintln(bw, "prefix\ta_provider\ta_function\tb_provider\tb_function\twinner_provider\twinner_function")
	for _, c := range conflicts {
		fmt.Fprintf(bw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.prefix,
			c.a.provider, c.a.function, c.b.provider, c.b.function,
			c.winner.provider, c.winner.function)
	}
	return bw.Flush()
}

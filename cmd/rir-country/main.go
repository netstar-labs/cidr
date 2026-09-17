// Command rir-country converts the five Regional Internet Registry "delegated
// extended" statistics files to the cidr spec format — "<cidr> <country>" per
// line, which LoadFunc reads back.
//
// Unlike mm-dbip and mm-geolite2-asn, this reads the *primary* record: the RIRs
// publish these files themselves and every downstream country dataset derives
// from them. No account, no licence key, no vendor.
//
//	rir-country -o rir-country.cidr              # all five registries
//	rir-country -registry arin -o arin.cidr      # one registry
//	rir-country -in arin.txt,ripencc.txt         # local files, comma-separated
//
// The record format is "registry|cc|type|start|value|date|status[|opaque-id]".
// For ipv4, value is an address *count* (not always a power of two, so a record
// decomposes into several prefixes); for ipv6 it is a prefix length. Only
// allocated/assigned ipv4/ipv6 records with a two-letter country are kept —
// asn records, summary lines, the version header, and reserved/available blocks
// are skipped.
//
// # Conflicts
//
// The same prefix can be claimed by two registries with different countries
// (transferred blocks whose records were never reconciled). -conflict selects
// the rule:
//
//	date      the later delegation date wins (default)
//	specific  the more specific source allocation wins
//
// Prefixes of *different* lengths never collide here: the spec keeps both and
// the loader's longest-prefix match resolves them, which is already "most
// specific wins". A conflict is therefore always the same prefix twice.
//
// When the chosen rule cannot separate two records — equal dates, or equally
// specific sources — the lexicographically smaller country code wins so the
// output is reproducible regardless of input order. No conflict is resolved
// silently: stderr carries the first ten and a count of any remainder, and
// -conflict-log FILE writes every one as TSV.
package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"math/bits"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
)

// The five RIR delegated-extended files. Every country dataset in circulation
// derives from these; they are the primary record.
var sources = map[string]string{
	"ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
	"arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
	"lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
	"apnic":   "https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest",
	"afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
}

// registryOrder fixes the fetch and tie-break order. Map iteration is random;
// the output must not be.
var registryOrder = []string{"afrinic", "apnic", "arin", "lacnic", "ripencc"}

// Conflict resolution modes.
const (
	byDate     = "date"
	bySpecific = "specific"
)

// stderrConflicts is how many conflicts are printed to stderr before the rest
// are summarised. The summary states the count, so nothing is silently dropped;
// -conflict-log writes every one.
const stderrConflicts = 10

// Version and Revision are stamped at build time via -ldflags -X (see build/rir-country).
var (
	Version  = "dev"
	Revision = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	registry := flag.String("registry", "all", `registry: "all" or one of afrinic, apnic, arin, lacnic, ripencc`)
	mode := flag.String("conflict", byDate, `conflict rule: "date" (later delegation wins) or "specific" (narrower source allocation wins)`)
	in := flag.String("in", "", "comma-separated local delegated files instead of fetching")
	out := flag.String("o", "", "write to this file instead of stdout")
	conflictLog := flag.String("conflict-log", "", "write every conflict to this file as TSV")
	timeout := flag.Duration("timeout", 30*time.Second, "dial/response-header timeout")
	flag.Parse()

	if *version {
		fmt.Printf("rir-country %s (%s)\n", Version, Revision)
		return
	}
	if *mode != byDate && *mode != bySpecific {
		fmt.Fprintln(os.Stderr, `rir-country: -conflict must be "date" or "specific"`)
		os.Exit(2)
	}
	if *registry != "all" {
		if _, ok := sources[*registry]; !ok {
			fmt.Fprintf(os.Stderr, "rir-country: unknown registry %q (want all, %s)\n",
				*registry, strings.Join(registryOrder, ", "))
			os.Exit(2)
		}
	}
	if *in != "" && *registry != "all" {
		// -in wins. Say so rather than letting -registry look honoured.
		fmt.Fprintf(os.Stderr, "rir-country: -in is set, ignoring -registry %q\n", *registry)
	}
	if err := run(*registry, *mode, *in, *out, *conflictLog, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "rir-country:", err)
		os.Exit(1)
	}
}

// rec is one delegated record reduced to what the spec and the conflict rules need.
type rec struct {
	cc      string // ISO 3166-1 alpha-2, as published
	date    string // YYYYMMDD, as published
	srcBits int    // prefix length of the smallest block covering the source allocation
	reg     string // registry file the record came from
}

type stats struct {
	rows       int // records accepted
	prefixes   int // prefixes written
	malformed  int // lines that looked like records but did not parse
	skipped    int // headers, summaries, asn rows, reserved/available, no country
	conflicts  int // same prefix, differing country
	unresolved int // conflicts the chosen rule could not separate
}

func run(registry, mode, in, out, conflictLog string, timeout time.Duration) error {
	table := map[netip.Prefix]rec{}
	var st stats
	var conflicts []conflict

	readers, err := openSources(registry, in, timeout)
	if err != nil {
		return err
	}
	for _, src := range readers {
		err := collect(src.r, src.name, table, mode, &st, &conflicts)
		src.close()
		if err != nil {
			return err
		}
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
	if err := emit(table, bw, &st); err != nil {
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
	fmt.Fprintf(os.Stderr,
		"rir-country: registries=%d conflict=%s rows=%d prefixes=%d conflicts=%d unresolved=%d malformed=%d skipped=%d -> %s\n",
		len(readers), mode, st.rows, st.prefixes, st.conflicts, st.unresolved, st.malformed, st.skipped, dst)
	return nil
}

// collect parses one delegated file into table, resolving any prefix already
// present according to mode.
func collect(r io.Reader, name string, table map[netip.Prefix]rec, mode string, st *stats, conflicts *[]conflict) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lo, hi, e, ok, malformed := parseLine(sc.Text(), name)
		if !ok {
			if malformed {
				st.malformed++
			} else {
				st.skipped++
			}
			continue
		}
		prefixes := cidr.RangePrefixes(lo, hi)
		if len(prefixes) == 0 {
			st.malformed++ // reversed or mixed-family after arithmetic
			continue
		}
		st.rows++
		for _, p := range prefixes {
			prev, exists := table[p]
			if !exists {
				table[p] = e
				continue
			}
			if prev.cc == e.cc {
				continue // same answer twice; nothing to resolve
			}
			st.conflicts++
			winner, resolved := resolve(prev, e, mode)
			if !resolved {
				st.unresolved++
			}
			*conflicts = append(*conflicts, conflict{
				prefix: p, a: prev, b: e, winner: winner.cc, mode: mode, resolved: resolved,
			})
			table[p] = winner
		}
		// st.prefixes is not accumulated here: conflicts collapse two records
		// onto one prefix, so the only honest count is the table's size, which
		// emit sets.
	}
	return sc.Err()
}

// resolve picks between two records claiming the same prefix. It reports
// whether the chosen rule actually separated them; when it did not, the
// lexicographically smaller country code wins so that output does not depend on
// the order the files were read.
func resolve(a, b rec, mode string) (rec, bool) {
	switch mode {
	case byDate:
		if a.date != b.date {
			if a.date > b.date {
				return a, true
			}
			return b, true
		}
	case bySpecific:
		if a.srcBits != b.srcBits {
			if a.srcBits > b.srcBits {
				return a, true
			}
			return b, true
		}
	}
	if a.cc <= b.cc {
		return a, false
	}
	return b, false
}

// emit writes the table as a sorted cidr spec. Sorting is what makes two runs
// over the same input byte-identical: map iteration order is not stable, and a
// generator whose output churns cannot be diffed or checksummed.
func emit(table map[netip.Prefix]rec, w io.Writer, st *stats) error {
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
	st.prefixes = len(out) // after conflict collapse, not the running total
	for _, p := range out {
		if _, err := fmt.Fprintf(w, "%s %s\n", p, table[p].cc); err != nil {
			return err
		}
	}
	return nil
}

// parseLine reduces one delegated-extended line to a range plus its record.
// ok reports whether the line is a usable ipv4/ipv6 allocation; malformed
// distinguishes "looked like a record but did not parse" from "deliberately
// skipped" (version header, summary, asn row, reserved/available, no country).
func parseLine(line, reg string) (lo, hi netip.Addr, e rec, ok, malformed bool) {
	p := strings.Split(strings.TrimSpace(line), "|")
	if len(p) < 7 {
		return lo, hi, e, false, false // header is 7 fields but fails the type check below
	}
	family, start, value, date, status := p[2], p[3], p[4], p[5], p[6]
	if family != "ipv4" && family != "ipv6" {
		return lo, hi, e, false, false // asn row, or the version header
	}
	if status != "allocated" && status != "assigned" {
		return lo, hi, e, false, false // reserved, available, summary, or empty
	}
	cc := p[1]
	if len(cc) != 2 || !isAlpha(cc) {
		return lo, hi, e, false, false // summary rows carry "*"; unset carries ""
	}

	addr, err := netip.ParseAddr(start)
	if err != nil {
		return lo, hi, e, false, true
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n == 0 {
		return lo, hi, e, false, true
	}

	switch family {
	case "ipv4":
		if !addr.Is4() {
			return lo, hi, e, false, true
		}
		last, ok := addV4(addr, n-1)
		if !ok {
			return lo, hi, e, false, true // count runs past 255.255.255.255
		}
		lo, hi = addr, last
		// The source allocation's specificity: the shortest prefix that covers
		// n addresses. Counts are not always powers of two (763 of them are
		// not, as published), so this rounds up to the covering block.
		e.srcBits = 32 - ceilLog2(n)
	case "ipv6":
		if addr.Is4() || n > 128 {
			return lo, hi, e, false, true
		}
		pfx := netip.PrefixFrom(addr, int(n))
		// A published ipv6 record is prefix-aligned. Masking an unaligned one
		// would silently relocate the allocation to a block the registry did
		// not publish, so it is counted as malformed instead. None of the five
		// files carried an unaligned record when this was written; the check
		// exists so that if one ever appears it is visible rather than absorbed.
		if pfx.Masked() != pfx {
			return lo, hi, e, false, true
		}
		lo = pfx.Addr()
		hi = lastAddr6(pfx)
		e.srcBits = int(n)
	}

	e.cc, e.date, e.reg = strings.ToUpper(cc), date, reg
	return lo, hi, e, true, false
}

// addV4 returns a+n, reporting false on overflow past the v4 space.
func addV4(a netip.Addr, n uint64) (netip.Addr, bool) {
	b := a.As4()
	v := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	sum := v + n
	if sum > 0xFFFFFFFF {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}), true
}

// lastAddr6 returns the highest address inside an IPv6 prefix. It is v6-only on
// purpose: the ipv4 branch of parseLine carries an address *count* and derives
// its bound with addV4, so a v4 prefix never reaches here. A general version
// would be an untested, unreachable path. (The library has an equivalent
// helper at cidr.go, but it is unexported, so package main cannot reach it.)
func lastAddr6(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	for i := p.Bits(); i < 128; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	return netip.AddrFrom16(b)
}

// ceilLog2 returns the smallest k with 2^k >= n, for n >= 1.
func ceilLog2(n uint64) int {
	if n <= 1 {
		return 0
	}
	return bits.Len64(n - 1)
}

func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return false
		}
	}
	return true
}

// conflict records one prefix claimed twice with different countries.
type conflict struct {
	prefix   netip.Prefix
	a, b     rec
	winner   string
	mode     string
	resolved bool
}

func writeConflictLog(path string, conflicts []conflict) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriter(f)
	fmt.Fprintln(bw, "prefix\tcc_a\treg_a\tdate_a\tcc_b\treg_b\tdate_b\twinner\trule\tresolved")
	for _, c := range conflicts {
		fmt.Fprintf(bw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t\n",
			c.prefix, c.a.cc, c.a.reg, c.a.date, c.b.cc, c.b.reg, c.b.date, c.winner, c.mode, c.resolved)
	}
	return bw.Flush()
}

// reportConflicts prints conflicts to stderr. It prints at most stderrConflicts
// of them and then states how many were not shown — a cap that announces itself,
// rather than a truncation that reads like completeness.
func reportConflicts(w io.Writer, conflicts []conflict, logPath string) {
	for i, c := range conflicts {
		if i == stderrConflicts {
			fmt.Fprintf(w, "rir-country: %d more conflict(s) not shown", len(conflicts)-stderrConflicts)
			if logPath == "" {
				fmt.Fprint(w, " (use -conflict-log FILE for all of them)")
			}
			fmt.Fprintln(w)
			break
		}
		how := "resolved"
		if !c.resolved {
			how = "UNRESOLVED by " + c.mode + ", fell back to lower country code"
		}
		fmt.Fprintf(w, "rir-country: conflict %s %s(%s,%s) vs %s(%s,%s) -> %s [%s]\n",
			c.prefix, c.a.cc, c.a.reg, c.a.date, c.b.cc, c.b.reg, c.b.date, c.winner, how)
	}
}

// source is one opened delegated file plus how to close it.
type source struct {
	name  string
	r     io.Reader
	close func()
}

// openSources resolves -in / -registry into readers, in a fixed order.
func openSources(registry, in string, timeout time.Duration) ([]source, error) {
	var out []source
	if in != "" {
		for _, path := range strings.Split(in, ",") {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			f, err := os.Open(path)
			if err != nil {
				closeAll(out)
				return nil, err
			}
			r, closeFn := maybeGunzip(f)
			out = append(out, source{name: baseName(path), r: r, close: closeFn})
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("-in named no readable files")
		}
		return out, nil
	}

	names := registryOrder
	if registry != "all" {
		names = []string{registry}
	}
	for _, name := range names {
		body, err := fetch(sources[name], timeout)
		if err != nil {
			closeAll(out)
			return nil, err
		}
		r, closeFn := maybeGunzip(body)
		out = append(out, source{name: name, r: r, close: closeFn})
	}
	return out, nil
}

func closeAll(srcs []source) {
	for _, s := range srcs {
		s.close()
	}
}

func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:]
	}
	return strings.TrimSuffix(strings.TrimSuffix(path, ".gz"), ".txt")
}

// maybeGunzip wraps rc in a gzip reader when the payload is gzipped.
func maybeGunzip(rc io.ReadCloser) (io.Reader, func()) {
	br := bufio.NewReader(rc)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err == nil {
			return zr, func() { zr.Close(); rc.Close() }
		}
	}
	return br, func() { rc.Close() }
}

// fetch GETs url with dial/response-header deadlines but no whole-body timeout.
func fetch(url string, timeout time.Duration) (io.ReadCloser, error) {
	client := &http.Client{Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rir-country-cidr (+github.com/netstar-labs/cidr)")
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

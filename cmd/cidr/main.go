// Command cidr looks up IP addresses against a CIDR/ASN spec: membership
// (yes/no) and the owning AS/org via longest-prefix match. Addresses come from
// the command line, or from stdin (one per line) when none are given.
//
//	cidr -spec asn.txt 1.1.1.200 8.8.8.8         # look up two addresses (NDJSON)
//	printf '1.1.1.1\n9.9.9.9\n' | cidr -spec asn.txt
//	cidr -spec asn.txt -brief 1.1.1.200          # terse, one line per address
//	cidr -spec block.txt -match < ips.txt        # filter: print only listed addresses
//	cidr -version
//
// The spec is "<cidr> [ASN] [org...]" per line (see the package docs); a plain
// list of CIDRs works too, in which case only membership is meaningful.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
)

// Version and Revision are stamped at build time via -ldflags -X (see
// build/cidr); a plain `go build` leaves the defaults.
var (
	Version  = "dev"
	Revision = "unknown"
)

// result is the per-address answer: membership plus the owning info, if any.
type result struct {
	IP     string     `json:"ip"`
	Member bool       `json:"member"`
	Info   *cidr.Info `json:"info,omitempty"`
}

func main() {
	spec := flag.String("spec", "", "spec file: \"<cidr> [ASN] [org]\" per line, or a refs JSON envelope (required)")
	brief := flag.Bool("brief", false, "terse output instead of NDJSON")
	match := flag.Bool("match", false, "filter mode: print only addresses in the set (exit 1 if none)")
	quiet := flag.Bool("quiet", false, "suppress the stderr tally")
	version := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *version {
		fmt.Printf("cidr %s (%s)\n", Version, Revision)
		return
	}
	if *spec == "" {
		fmt.Fprintln(os.Stderr, "cidr: -spec is required")
		flag.Usage()
		os.Exit(2)
	}

	entries, err := loadSpec(*spec)
	if err != nil {
		fatal(err)
	}
	set, table := build(entries)

	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	start := time.Now()
	var queried, members int

	handle := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || s[0] == '#' {
			return
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			if !*match {
				fmt.Fprintf(os.Stderr, "cidr: skip %q: invalid address\n", s)
			}
			return
		}
		queried++
		res := resolve(set, table, ip)
		if res.Member {
			members++
		}
		switch {
		case *match:
			if res.Member {
				fmt.Fprintln(out, ip.String())
			}
		case *brief:
			fmt.Fprintln(out, formatBrief(res))
		default:
			_ = enc.Encode(res)
		}
	}

	if flag.NArg() > 0 {
		for _, a := range flag.Args() {
			handle(a)
		}
	} else {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			handle(sc.Text())
		}
		if err := sc.Err(); err != nil {
			out.Flush()
			fatal(err)
		}
	}
	out.Flush()

	if !*quiet {
		fmt.Fprintf(os.Stderr, "cidr: spec=%s prefixes=%d intervals=%d queried=%d member=%d elapsed=%s\n",
			*spec, len(entries), set.Len(), queried, members, time.Since(start).Round(time.Microsecond))
	}
	if *match && members == 0 {
		os.Exit(1) // grep-like: nothing matched
	}
}

// loadSpec reads either a text spec ("<cidr> [ASN] [org]" per line) or a refs
// JSON envelope ({"name","version","list":[...]}), picked by sniffing the first
// non-space byte.
func loadSpec(path string) ([]cidr.SpecEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	head, _ := br.Peek(512) // best-effort; short files return io.EOF with the bytes
	if firstNonSpace(head) == '{' {
		rf, err := cidr.ParseRefs(br)
		if err != nil {
			return nil, err
		}
		return rf.Entries(), nil
	}
	return cidr.ParseSpec(br)
}

func firstNonSpace(b []byte) byte {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return c
		}
	}
	return 0
}

func build(entries []cidr.SpecEntry) (*cidr.Set, *cidr.Table[cidr.Info]) {
	return cidr.BuildASN(entries)
}

func resolve(set *cidr.Set, table *cidr.Table[cidr.Info], ip netip.Addr) result {
	res := result{IP: ip.String(), Member: set.Contains(ip)}
	if info, ok := table.Lookup(ip); ok {
		res.Info = &info
	}
	return res
}

// formatBrief renders one aligned line: "<ip> <member|-> [ASN<n> <org>]".
func formatBrief(r result) string {
	if !r.Member {
		return fmt.Sprintf("%-39s -", r.IP)
	}
	if r.Info != nil && r.Info.ASN != 0 {
		return fmt.Sprintf("%-39s member AS%d %s", r.IP, r.Info.ASN, r.Info.Org)
	}
	if r.Info != nil {
		return fmt.Sprintf("%-39s member %s", r.IP, r.Info.Prefix)
	}
	return fmt.Sprintf("%-39s member", r.IP)
}

func usage() {
	fmt.Fprintf(os.Stderr, `cidr %s — look up IP addresses against a CIDR/ASN spec

Usage:
  cidr -spec FILE [flags] [address...]

Addresses are read from the arguments, or from stdin (one per line) if none are
given. Blank lines and lines starting with '#' are ignored.

Flags:
`, Version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Examples:
  cidr -spec asn.txt 1.1.1.200 8.8.8.8
  printf '1.1.1.1\n9.9.9.9\n' | cidr -spec asn.txt -brief
  cidr -spec block.txt -match < ips.txt
`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "cidr:", err)
	os.Exit(1)
}

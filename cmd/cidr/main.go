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
//
// Exit status follows grep: 0 on success (with -match, at least one address
// matched), 1 when -match found nothing, 2 on any error, including a failed
// write to stdout.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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

// Exit codes follow grep: 0 = ok (under -match, something matched), 1 = no
// match (-match only), 2 = error (usage, unreadable spec or stdin, or any
// failure writing the output).
const (
	exitOK      = 0
	exitNoMatch = 1
	exitError   = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the whole command, with its streams injected so the error paths can
// be tested; it returns the process exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cidr", flag.ContinueOnError)
	fs.SetOutput(stderr)
	spec := fs.String("spec", "", "spec file: \"<cidr> [ASN] [org]\" per line, or a refs JSON envelope (required)")
	brief := fs.Bool("brief", false, "terse output instead of NDJSON")
	match := fs.Bool("match", false, "filter mode: print only addresses in the set (exit 1 if none)")
	quiet := fs.Bool("quiet", false, "suppress the stderr tally")
	version := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() { usage(fs, stderr) }
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitError // the flag package already reported it
	}

	if *version {
		if _, err := fmt.Fprintf(stdout, "cidr %s (%s)\n", Version, Revision); err != nil {
			return fatal(stderr, err)
		}
		return exitOK
	}
	if *spec == "" {
		fmt.Fprintln(stderr, "cidr: -spec is required")
		fs.Usage()
		return exitError
	}

	entries, err := loadSpec(*spec)
	if err != nil {
		return fatal(stderr, err)
	}
	set, table := build(entries)

	out := bufio.NewWriter(stdout)
	enc := json.NewEncoder(out)
	start := time.Now()
	var queried, members int

	// handle answers one address. It returns an error only for a failed
	// write, which ends the run.
	handle := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" || s[0] == '#' {
			return nil
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			if !*match {
				fmt.Fprintf(stderr, "cidr: skip %q: invalid address\n", s)
			}
			return nil
		}
		queried++
		res := resolve(set, table, ip)
		if res.Member {
			members++
		}
		switch {
		case *match:
			if res.Member {
				_, err = fmt.Fprintln(out, ip.String())
			}
		case *brief:
			_, err = fmt.Fprintln(out, formatBrief(res))
		default:
			err = enc.Encode(res)
		}
		return err
	}

	if fs.NArg() > 0 {
		for _, a := range fs.Args() {
			if err := handle(a); err != nil {
				return fatal(stderr, fmt.Errorf("write output: %w", err))
			}
		}
	} else {
		sc := bufio.NewScanner(stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if err := handle(sc.Text()); err != nil {
				return fatal(stderr, fmt.Errorf("write output: %w", err))
			}
		}
		if err := sc.Err(); err != nil {
			out.Flush() // best effort: the read error is the one to report
			return fatal(stderr, fmt.Errorf("read input: %w", err))
		}
	}
	if err := out.Flush(); err != nil {
		return fatal(stderr, fmt.Errorf("write output: %w", err))
	}

	if !*quiet {
		fmt.Fprintf(stderr, "cidr: spec=%s prefixes=%d intervals=%d queried=%d member=%d elapsed=%s\n",
			*spec, len(entries), set.Len(), queried, members, time.Since(start).Round(time.Microsecond))
	}
	if *match && members == 0 {
		return exitNoMatch // grep-like: nothing matched
	}
	return exitOK
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

func usage(fs *flag.FlagSet, w io.Writer) {
	fmt.Fprintf(w, `cidr %s — look up IP addresses against a CIDR/ASN spec

Usage:
  cidr -spec FILE [flags] [address...]

Addresses are read from the arguments, or from stdin (one per line) if none are
given. Blank lines and lines starting with '#' are ignored.

Flags:
`, Version)
	fs.SetOutput(w)
	fs.PrintDefaults()
	fmt.Fprintf(w, `
Examples:
  cidr -spec asn.txt 1.1.1.200 8.8.8.8
  printf '1.1.1.1\n9.9.9.9\n' | cidr -spec asn.txt -brief
  cidr -spec block.txt -match < ips.txt

Exit status: 0 ok (with -match: something matched), 1 no match (-match only),
2 error (bad usage, unreadable spec or input, failed write).
`)
}

// fatal reports err on w and returns the error exit code.
func fatal(w io.Writer, err error) int {
	fmt.Fprintln(w, "cidr:", err)
	return exitError
}

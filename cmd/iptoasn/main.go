// Command iptoasn fetches the iptoasn.com IP-to-ASN table, converts each
// start/end address range to its minimal set of CIDR prefixes, and writes
// cidr spec lines. Three output modes:
//
//	  -output asn (default): "<cidr> <ASN> <org>" — load with LoadASN / cidr.
//	  -output country:       "<cidr> <country>" — pipe to mmdb-write -db-type GeoLite2-Country.
//	  -country:              "<cidr> <ASN> <country> <org>" — load with LoadASN / cidr, country prepended to org.
//
//		iptoasn                                   # fetch combined v4+v6 -> stdout
//		iptoasn -family v4 -o ip2asn-v4.cidr      # just IPv4, to a file
//		iptoasn -in ip2asn-combined.tsv.gz        # convert a local (gzipped) TSV
//		iptoasn -unrouted -country                # keep AS0 rows and prepend country
//
// The output file is replaced atomically and only when at least one row was
// converted; on any failure (fetch, stall, corrupt input, zero rows) the
// previous file is left untouched and the exit status is 1.
//
// The source is the tab-separated table published at
// https://iptoasn.com/data/ (range_start, range_end, AS_number, country,
// AS_description); AS0 "Not routed" rows are dropped unless -unrouted is set.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
	"github.com/netstar-labs/cidr/internal/feedio"
)

const source = "https://iptoasn.com/data/ip2asn-%s.tsv.gz"

// Version and Revision are stamped at build time via -ldflags -X (see build/iptoasn).
var (
	Version  = "dev"
	Revision = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	family := flag.String("family", "combined", `iptoasn dataset: "v4", "v6", or "combined"`)
	url := flag.String("url", "", "source URL (overrides -family)")
	in := flag.String("in", "", "read a local TSV (optionally .gz) instead of fetching")
	out := flag.String("o", "", `write to this file (atomically; "-" or empty is stdout)`)
	unrouted := flag.Bool("unrouted", false, `include AS0 "Not routed" rows`)
	output := flag.String("output", "asn", `output format: "asn" (<cidr> <ASN> <org>) or "country" (<cidr> <country>)`)
	country := flag.Bool("country", false, "prepend the country code to the org field (asn output only)")
	timeout := flag.Duration("timeout", 30*time.Second, "fetch timeout: dial/TLS/response-header limit, and the idle period after which a download that stops sending bytes fails")
	flag.Parse()

	if *version {
		fmt.Printf("iptoasn %s (%s)\n", Version, Revision)
		return
	}
	if *output != "asn" && *output != "country" {
		fmt.Fprintf(os.Stderr, `iptoasn: -output must be "asn" or "country"`)
		os.Exit(2)
	}

	opts := options{unrouted: *unrouted, outputMode: *output, country: *country}
	if err := run(*family, *url, *in, *out, *timeout, opts); err != nil {
		fmt.Fprintln(os.Stderr, "iptoasn:", err)
		os.Exit(1)
	}
}

func run(family, url, in, out string, timeout time.Duration, opts options) error {
	// Source: a local file or an HTTP fetch. Opened before any output exists.
	var src io.ReadCloser
	if in != "" {
		f, err := os.Open(in)
		if err != nil {
			return err
		}
		src = f
	} else {
		if url == "" {
			switch family {
			case "v4", "v6", "combined":
				url = fmt.Sprintf(source, family)
			default:
				return fmt.Errorf("unknown -family %q (want v4, v6, or combined)", family)
			}
		}
		body, err := feedio.Fetch(url, "iptoasn-cidr (+github.com/netstar-labs/cidr)", timeout, timeout)
		if err != nil {
			return err
		}
		src = body
	}
	defer src.Close()

	// Decompress if the payload is gzip (the fetched files always are; a local
	// -in may be either). A corrupt gzip is an error, never read as text.
	r, err := feedio.MaybeGunzip(src)
	if err != nil {
		return err
	}

	// Destination: a temp file beside -o (published only on success) or stdout.
	o, err := feedio.Create(out)
	if err != nil {
		return err
	}
	defer o.Abort()

	st, err := convert(r, o, opts)
	if err != nil {
		return err
	}
	if st.rows == 0 {
		return fmt.Errorf("no usable rows (malformed=%d unrouted=%d); nothing published, previous output left untouched",
			st.malformed, st.unrouted)
	}
	if err := o.Commit(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "iptoasn: rows=%d prefixes=%d unrouted=%d malformed=%d -> %s\n",
		st.rows, st.prefixes, st.unrouted, st.malformed, o.Name())
	return nil
}

type options struct {
	unrouted   bool
	outputMode string // "asn" or "country"
	country    bool   // prepend country to org (asn output only)
}

type stats struct {
	rows, prefixes, unrouted, malformed int
}

// convert streams the iptoasn TSV from r, decomposing each range into CIDR
// prefixes and writing spec lines. In "asn" mode (default) the format is
// "<cidr> <ASN> <org>"; in "country" mode it is "<cidr> <country>" and all
// rows (including AS0) are emitted.
func convert(r io.Reader, w io.Writer, opts options) (stats, error) {
	var st stats
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	isCountry := opts.outputMode == "country"
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		// range_start \t range_end \t AS_number \t country \t AS_description
		cols := strings.Split(line, "\t")
		if len(cols) < 5 {
			st.malformed++
			continue
		}
		lo, err1 := netip.ParseAddr(cols[0])
		hi, err2 := netip.ParseAddr(cols[1])
		if err1 != nil || err2 != nil {
			st.malformed++
			continue
		}

		if isCountry {
			cc := cols[3]
			if cc == "" || cc == "None" {
				continue
			}
			prefixes := cidr.RangePrefixes(lo, hi)
			if len(prefixes) == 0 {
				st.malformed++ // invalid range: mixed family or reversed (lo > hi)
				continue
			}
			for _, p := range prefixes {
				if _, err := fmt.Fprintf(w, "%s %s\n", p, cc); err != nil {
					return st, err
				}
				st.prefixes++
			}
			st.rows++
			continue
		}

		// asn mode
		asn, err := strconv.ParseUint(cols[2], 10, 32)
		if err != nil {
			st.malformed++
			continue
		}
		if asn == 0 && !opts.unrouted {
			st.unrouted++
			continue
		}
		org := cols[4]
		if opts.country && cols[3] != "" && cols[3] != "None" {
			org = cols[3] + " " + org
		}
		prefixes := cidr.RangePrefixes(lo, hi)
		if len(prefixes) == 0 {
			st.malformed++ // invalid range: mixed family or reversed (lo > hi)
			continue
		}
		for _, p := range prefixes {
			if _, err := fmt.Fprintf(w, "%s %d %s\n", p, asn, org); err != nil {
				return st, err
			}
			st.prefixes++
		}
		st.rows++
	}
	return st, sc.Err()
}

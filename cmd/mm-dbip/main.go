// Command mm-dbip converts a DB-IP Lite database (db-ip.com, CC BY 4.0) to the
// cidr spec format. DB-IP Lite CSVs are range-based (start,end,...), so each
// range is decomposed into its minimal set of CIDR prefixes.
//
//	-db country -> "<cidr> <country>"      (default; load with LoadFunc)
//	-db asn     -> "<cidr> <ASN> <org>"    (load with LoadASN)
//
//	mm-dbip -o dbip-country.cidr                       # current month's country lite
//	mm-dbip -db asn -o dbip-asn.cidr
//	mm-dbip -in dbip-country-lite-2025-07.csv.gz       # convert a local file
//
// The output file is replaced atomically and only when the whole input was read
// cleanly and produced at least one row; on any failure the previous file is
// left untouched and the exit status is 1.
//
// Without -in or -url the current month's file is fetched from
// https://download.db-ip.com/free/dbip-<db>-lite-<YYYY-MM>.csv.gz.
package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
	"github.com/netstar-labs/cidr/internal/feedio"
)

const source = "https://download.db-ip.com/free/dbip-%s-lite-%s.csv.gz"

// Version and Revision are stamped at build time via -ldflags -X (see build/mm-dbip).
var (
	Version  = "dev"
	Revision = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	db := flag.String("db", "country", `dataset: "country" or "asn"`)
	month := flag.String("month", "", "dataset month YYYY-MM (default: current UTC month)")
	url := flag.String("url", "", "override the download URL")
	in := flag.String("in", "", "local DB-IP CSV (.csv/.csv.gz) instead of fetching")
	out := flag.String("o", "", `write to this file (atomically; "-" or empty is stdout)`)
	timeout := flag.Duration("timeout", 30*time.Second, "fetch timeout: dial/TLS/response-header limit, and the idle period after which a download that stops sending bytes fails")
	flag.Parse()

	if *version {
		fmt.Printf("mm-dbip %s (%s)\n", Version, Revision)
		return
	}
	if *db != "country" && *db != "asn" {
		fmt.Fprintln(os.Stderr, `mm-dbip: -db must be "country" or "asn"`)
		os.Exit(2)
	}
	if err := run(*db, *month, *url, *in, *out, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "mm-dbip:", err)
		os.Exit(1)
	}
}

func run(db, month, url, in, out string, timeout time.Duration) error {
	if in == "" && url == "" {
		if month == "" {
			month = time.Now().UTC().Format("2006-01")
		}
		url = fmt.Sprintf(source, db, month)
	}
	// Open (and for a URL, connect to) the source before any output exists.
	r, closeFn, err := open(in, url, timeout)
	if err != nil {
		return err
	}
	defer closeFn()

	// The converted rows go to a temp file beside -o and are published only
	// when the whole input was read cleanly and produced at least one row.
	o, err := feedio.Create(out)
	if err != nil {
		return err
	}
	defer o.Abort()

	st, err := convert(r, o, db)
	if err != nil {
		return err
	}
	if st.rows == 0 {
		return fmt.Errorf("no usable rows (malformed=%d); nothing published, previous output left untouched", st.malformed)
	}
	if err := o.Commit(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "mm-dbip: db=%s rows=%d prefixes=%d malformed=%d -> %s\n",
		db, st.rows, st.prefixes, st.malformed, o.Name())
	return nil
}

type stats struct{ rows, prefixes, malformed int }

// convert streams a range-based DB-IP CSV and writes CIDR lines: "<cidr>
// <country>" for -db country, "<cidr> <asn> <org>" for -db asn.
func convert(r io.Reader, w io.Writer, db string) (stats, error) {
	var st stats
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Only a per-line CSV syntax error is recoverable. Any other error
			// (a truncated gzip, a failed read) repeats on every call: skipping
			// it never advances, so it must stop the run.
			var pe *csv.ParseError
			if errors.As(err, &pe) {
				st.malformed++
				continue
			}
			return st, err
		}
		if len(rec) < 3 {
			st.malformed++
			continue
		}
		lo, e1 := netip.ParseAddr(strings.TrimSpace(rec[0]))
		hi, e2 := netip.ParseAddr(strings.TrimSpace(rec[1]))
		if e1 != nil || e2 != nil {
			st.malformed++
			continue
		}
		prefixes := cidr.RangePrefixes(lo, hi)
		if len(prefixes) == 0 {
			st.malformed++ // invalid range: mixed family or reversed (lo > hi)
			continue
		}
		switch db {
		case "country":
			cc := strings.TrimSpace(rec[2])
			for _, p := range prefixes {
				if _, err := fmt.Fprintf(w, "%s %s\n", p, cc); err != nil {
					return st, err
				}
			}
		case "asn":
			if len(rec) < 4 {
				st.malformed++
				continue
			}
			asn, org := strings.TrimSpace(rec[2]), strings.TrimSpace(rec[3])
			for _, p := range prefixes {
				if _, err := fmt.Fprintf(w, "%s %s %s\n", p, asn, org); err != nil {
					return st, err
				}
			}
		}
		st.prefixes += len(prefixes)
		st.rows++
	}
	return st, nil
}

// open returns a reader over a local file or a fetched URL, transparently
// decompressing a gzip payload, plus a cleanup func.
func open(in, url string, timeout time.Duration) (io.Reader, func() error, error) {
	var src io.ReadCloser
	if in != "" {
		f, err := os.Open(in)
		if err != nil {
			return nil, nil, err
		}
		src = f
	} else {
		body, err := feedio.Fetch(url, "mm-dbip-cidr (+github.com/netstar-labs/cidr)", timeout, timeout)
		if err != nil {
			return nil, nil, err
		}
		src = body
	}
	r, err := feedio.MaybeGunzip(src)
	if err != nil {
		src.Close()
		return nil, nil, err
	}
	return r, src.Close, nil
}

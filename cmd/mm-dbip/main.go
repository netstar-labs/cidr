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
// Without -in or -url the current month's file is fetched from
// https://download.db-ip.com/free/dbip-<db>-lite-<YYYY-MM>.csv.gz.
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
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
	out := flag.String("o", "", "write to this file instead of stdout")
	timeout := flag.Duration("timeout", 30*time.Second, "dial/response-header timeout")
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
	r, closeFn, err := open(in, url, timeout)
	if err != nil {
		return err
	}
	defer closeFn()

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

	st, err := convert(r, bw, db)
	if err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	dst := "stdout"
	if out != "" {
		dst = out
	}
	fmt.Fprintf(os.Stderr, "mm-dbip: db=%s rows=%d prefixes=%d malformed=%d -> %s\n",
		db, st.rows, st.prefixes, st.malformed, dst)
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
			st.malformed++
			continue // recoverable per-line CSV error
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
		body, err := fetch(url, timeout)
		if err != nil {
			return nil, nil, err
		}
		src = body
	}
	br := bufio.NewReader(src)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			src.Close()
			return nil, nil, err
		}
		return zr, func() error { zr.Close(); return src.Close() }, nil
	}
	return br, src.Close, nil
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
	req.Header.Set("User-Agent", "mm-dbip-cidr (+github.com/netstar-labs/cidr)")
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

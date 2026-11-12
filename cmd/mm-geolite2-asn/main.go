// Command mm-geolite2-asn converts the MaxMind GeoLite2 ASN database to the cidr
// spec format — "<cidr> <ASN> <org>" per line — that LoadASN reads back. The
// GeoLite2-ASN CSV is already CIDR-native (a "network" column), so no range
// decomposition is needed.
//
//	mm-geolite2-asn -license YOUR_KEY -o geolite2-asn.cidr   # download + convert
//	mm-geolite2-asn -in GeoLite2-ASN-CSV.zip                 # convert a local zip
//	mm-geolite2-asn -in GeoLite2-ASN-Blocks-IPv4.csv         # or a single CSV (.csv/.csv.gz)
//
// The output file is replaced atomically and only when at least one row was
// converted; on any failure (fetch, stall, bad header, corrupt input, zero rows)
// the previous file is left untouched and the exit status is 1.
//
// Downloading needs a free MaxMind account's license key. The download is a zip
// holding GeoLite2-ASN-Blocks-IPv4.csv and -IPv6.csv, both with the header
// "network,autonomous_system_number,autonomous_system_organization".
package main

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
	"github.com/netstar-labs/cidr/internal/feedio"
)

const downloadURL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=%s&suffix=zip"

// Version and Revision are stamped at build time via -ldflags -X (see
// build/mm-geolite2-asn).
var (
	Version  = "dev"
	Revision = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	license := flag.String("license", "", "MaxMind license key (or $MAXMIND_LICENSE_KEY)")
	family := flag.String("family", "both", `which blocks to emit: "v4", "v6", or "both"`)
	url := flag.String("url", "", "override the download URL")
	in := flag.String("in", "", "local GeoLite2-ASN CSV (.csv/.csv.gz) or the CSV zip")
	out := flag.String("o", "", `write to this file (atomically; "-" or empty is stdout)`)
	timeout := flag.Duration("timeout", 30*time.Second, "download timeout: dial/TLS/response-header limit, and the idle period after which a download that stops sending bytes fails")
	flag.Parse()

	if *version {
		fmt.Printf("mm-geolite2-asn %s (%s)\n", Version, Revision)
		return
	}
	// The license may come from the environment so systemd can supply it via a
	// mode-600 EnvironmentFile instead of exposing it on the command line.
	if *license == "" {
		*license = os.Getenv("MAXMIND_LICENSE_KEY")
	}

	if err := run(*license, *family, *url, *in, *out, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "mm-geolite2-asn:", err)
		os.Exit(1)
	}
}

func run(license, family, url, in, out string, timeout time.Duration) error {
	// Acquire the whole source first; no output exists until it is in hand. conv
	// then converts it into the (temp) output.
	var conv func(w io.Writer) (stats, error)
	switch {
	case in != "" && strings.HasSuffix(strings.ToLower(in), ".zip"):
		data, err := os.ReadFile(in)
		if err != nil {
			return err
		}
		conv = func(w io.Writer) (stats, error) { return processZip(data, family, w) }
	case in != "":
		rc, err := openFile(in)
		if err != nil {
			return err
		}
		defer rc.Close()
		conv = func(w io.Writer) (stats, error) { return convertCSV(rc, w) }
	default: // download the zip
		if url == "" {
			if license == "" {
				return errors.New("need -license (or -url, or -in)")
			}
			url = fmt.Sprintf(downloadURL, license)
		}
		data, err := fetchBytes(url, timeout)
		if err != nil {
			return err
		}
		conv = func(w io.Writer) (stats, error) { return processZip(data, family, w) }
	}

	o, err := feedio.Create(out)
	if err != nil {
		return err
	}
	defer o.Abort()

	st, err := conv(o)
	if err != nil {
		return err
	}
	if st.rows == 0 {
		return fmt.Errorf("no usable rows (skipped=%d); nothing published, previous output left untouched", st.malformed)
	}
	if err := o.Commit(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "mm-geolite2-asn: prefixes=%d skipped=%d -> %s\n", st.rows, st.malformed, o.Name())
	return nil
}

type stats struct{ rows, malformed int }

// wantHeader is the GeoLite2-ASN blocks header; the three columns are read by
// position, so a file whose columns are reordered or renamed must be rejected
// rather than converted into a wrong feed.
var wantHeader = []string{"network", "autonomous_system_number", "autonomous_system_organization"}

// convertCSV reads one GeoLite2-ASN blocks CSV and writes "<cidr> <asn> <org>".
// The first record must be the header (network, autonomous_system_number,
// autonomous_system_organization, in that order); anything else is an error. A
// row whose network is not a prefix, whose ASN is empty, or that is short or has
// a CSV syntax error is counted as malformed and skipped. Any other read error
// is returned.
func convertCSV(r io.Reader, w io.Writer) (stats, error) {
	var st stats
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1

	hdr, err := cr.Read()
	if errors.Is(err, io.EOF) {
		return st, errors.New("empty CSV: no header row")
	}
	if err != nil {
		return st, fmt.Errorf("header: %w", err)
	}
	if err := checkHeader(hdr); err != nil {
		return st, err
	}

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
		p, perr := cidr.ParsePrefix(rec[0])
		if perr != nil {
			st.malformed++ // not a prefix
			continue
		}
		asn := strings.TrimSpace(rec[1])
		if asn == "" {
			st.malformed++
			continue
		}
		if _, err := fmt.Fprintf(w, "%s %s %s\n", p, asn, strings.TrimSpace(rec[2])); err != nil {
			return st, err
		}
		st.rows++
	}
	return st, nil
}

// checkHeader reports whether rec starts with the expected GeoLite2-ASN columns.
func checkHeader(rec []string) error {
	if len(rec) >= len(wantHeader) {
		ok := true
		for i, want := range wantHeader {
			got := strings.TrimSpace(rec[i])
			if i == 0 {
				got = strings.TrimPrefix(got, "\ufeff") // BOM from a spreadsheet round-trip
			}
			if !strings.EqualFold(got, want) {
				ok = false
			}
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("unexpected header %q, want %q", rec, wantHeader)
}

// processZip converts every GeoLite2-ASN blocks CSV in the zip that matches the
// requested family.
func processZip(data []byte, family string, w io.Writer) (stats, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return stats{}, err
	}
	var total stats
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".csv") || !matchFamily(f.Name, family) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return total, err
		}
		st, err := convertCSV(rc, w)
		rc.Close()
		if err != nil {
			return total, err
		}
		total.rows += st.rows
		total.malformed += st.malformed
	}
	return total, nil
}

func matchFamily(name, family string) bool {
	switch family {
	case "v4":
		return strings.Contains(name, "IPv4")
	case "v6":
		return strings.Contains(name, "IPv6")
	default:
		return strings.Contains(name, "IPv4") || strings.Contains(name, "IPv6")
	}
}

// openFile opens a local CSV, transparently decompressing a gzip payload. A
// corrupt gzip is an error.
func openFile(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	r, err := feedio.MaybeGunzip(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return struct {
		io.Reader
		io.Closer
	}{r, f}, nil
}

// fetchBytes downloads url into memory; a body idle for timeout is an error.
func fetchBytes(url string, timeout time.Duration) ([]byte, error) {
	body, err := feedio.Fetch(url, "mm-geolite2-asn-cidr (+github.com/netstar-labs/cidr)", timeout, timeout)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}

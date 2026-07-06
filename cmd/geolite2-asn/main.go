// Command geolite2-asn converts the MaxMind GeoLite2 ASN database to the cidr
// spec format — "<cidr> <ASN> <org>" per line — that LoadASN reads back. The
// GeoLite2-ASN CSV is already CIDR-native (a "network" column), so no range
// decomposition is needed.
//
//	geolite2-asn -license YOUR_KEY -o geolite2-asn.cidr   # download + convert
//	geolite2-asn -in GeoLite2-ASN-CSV.zip                 # convert a local zip
//	geolite2-asn -in GeoLite2-ASN-Blocks-IPv4.csv         # or a single CSV (.csv/.csv.gz)
//
// Downloading needs a free MaxMind account's license key. The download is a zip
// holding GeoLite2-ASN-Blocks-IPv4.csv and -IPv6.csv, both with the header
// "network,autonomous_system_number,autonomous_system_organization".
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/netstar-labs/cidr"
)

const downloadURL = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=%s&suffix=zip"

func main() {
	license := flag.String("license", "", "MaxMind license key (to download)")
	family := flag.String("family", "both", `which blocks to emit: "v4", "v6", or "both"`)
	url := flag.String("url", "", "override the download URL")
	in := flag.String("in", "", "local GeoLite2-ASN CSV (.csv/.csv.gz) or the CSV zip")
	out := flag.String("o", "", "write to this file instead of stdout")
	timeout := flag.Duration("timeout", 30*time.Second, "dial/response-header timeout for the download")
	flag.Parse()

	if err := run(*license, *family, *url, *in, *out, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "geolite2-asn:", err)
		os.Exit(1)
	}
}

func run(license, family, url, in, out string, timeout time.Duration) error {
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

	var st stats
	var err error
	switch {
	case in != "" && strings.HasSuffix(strings.ToLower(in), ".zip"):
		var data []byte
		if data, err = os.ReadFile(in); err == nil {
			st, err = processZip(data, family, bw)
		}
	case in != "":
		var rc io.ReadCloser
		if rc, err = openFile(in); err == nil {
			st, err = convertCSV(rc, bw)
			rc.Close()
		}
	default: // download the zip
		if url == "" {
			if license == "" {
				return errors.New("need -license (or -url, or -in)")
			}
			url = fmt.Sprintf(downloadURL, license)
		}
		var data []byte
		if data, err = fetchBytes(url, timeout); err == nil {
			st, err = processZip(data, family, bw)
		}
	}
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
	fmt.Fprintf(os.Stderr, "geolite2-asn: prefixes=%d skipped=%d -> %s\n", st.rows, st.malformed, dst)
	return nil
}

type stats struct{ rows, malformed int }

// convertCSV reads a GeoLite2-ASN blocks CSV and writes "<cidr> <asn> <org>".
// The header row and any unparseable network are skipped.
func convertCSV(r io.Reader, w io.Writer) (stats, error) {
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
		p, perr := cidr.ParsePrefix(rec[0])
		if perr != nil {
			continue // header ("network") or junk
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

// openFile opens a local CSV, transparently decompressing a gzip payload.
func openFile(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(f)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			f.Close()
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{zr, f}, nil
	}
	return struct {
		io.Reader
		io.Closer
	}{br, f}, nil
}

func fetchBytes(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "geolite2-asn-cidr (+github.com/netstar-labs/cidr)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

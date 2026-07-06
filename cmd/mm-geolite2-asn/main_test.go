package main

import (
	"archive/zip"
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

// GeoLite2-ASN-Blocks CSV: a header row then network,asn,org (org may be quoted).
const sampleCSV = `network,autonomous_system_number,autonomous_system_organization
1.0.0.0/24,13335,"Cloudflare, Inc."
8.8.8.0/24,15169,Google LLC
2001:200::/32,2500,WIDE Project
not,a,prefix
`

func TestConvertCSV(t *testing.T) {
	var buf bytes.Buffer
	st, err := convertCSV(strings.NewReader(sampleCSV), &buf)
	if err != nil {
		t.Fatal(err)
	}
	want := "1.0.0.0/24 13335 Cloudflare, Inc.\n" +
		"8.8.8.0/24 15169 Google LLC\n" +
		"2001:200::/32 2500 WIDE Project\n"
	if buf.String() != want {
		t.Errorf("output:\n%q\nwant:\n%q", buf.String(), want)
	}
	if st.rows != 3 {
		t.Errorf("rows = %d, want 3", st.rows)
	}
}

func TestProcessZipAndFamily(t *testing.T) {
	// build a zip like MaxMind's, with v4 and v6 blocks files
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	v4, _ := zw.Create("GeoLite2-ASN-CSV_20260101/GeoLite2-ASN-Blocks-IPv4.csv")
	v4.Write([]byte("network,autonomous_system_number,autonomous_system_organization\n8.8.8.0/24,15169,Google LLC\n"))
	v6, _ := zw.Create("GeoLite2-ASN-CSV_20260101/GeoLite2-ASN-Blocks-IPv6.csv")
	v6.Write([]byte("network,autonomous_system_number,autonomous_system_organization\n2001:200::/32,2500,WIDE Project\n"))
	zw.Close()

	// -family v4 emits only the IPv4 block
	var out bytes.Buffer
	if _, err := processZip(zbuf.Bytes(), "v4", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "8.8.8.0/24") || strings.Contains(out.String(), "2001:200") {
		t.Errorf("v4-only output wrong:\n%s", out.String())
	}

	// both families round-trips through the spec loader
	out.Reset()
	if _, err := processZip(zbuf.Bytes(), "both", &out); err != nil {
		t.Fatal(err)
	}
	_, table, err := cidr.LoadASN(&out)
	if err != nil {
		t.Fatal(err)
	}
	if info, ok := table.Lookup(netip.MustParseAddr("8.8.8.8")); !ok || info.ASN != 15169 {
		t.Errorf("8.8.8.8 = %+v (ok=%v)", info, ok)
	}
	if info, ok := table.Lookup(netip.MustParseAddr("2001:200::1")); !ok || info.ASN != 2500 {
		t.Errorf("2001:200::1 = %+v (ok=%v)", info, ok)
	}
}

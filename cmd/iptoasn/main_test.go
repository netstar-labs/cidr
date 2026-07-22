package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

// sampleTSV mimics the iptoasn.com table: start, end, ASN, country, description.
var sampleTSV = strings.Join([]string{
	"1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET",
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed",
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE",
	"2001:db8::\t2001:db8::ffff\t64502\tZZ\tDOC",
	"bad line",
}, "\n") + "\n"

func TestConvert(t *testing.T) {
	var buf bytes.Buffer
	st, err := convert(strings.NewReader(sampleTSV), &buf, options{})
	if err != nil {
		t.Fatal(err)
	}
	want := "1.0.0.0/24 13335 CLOUDFLARENET\n" +
		"8.8.8.0/24 15169 GOOGLE\n" +
		"2001:db8::/112 64502 DOC\n"
	if buf.String() != want {
		t.Errorf("output:\n%q\nwant:\n%q", buf.String(), want)
	}
	if st.rows != 3 || st.prefixes != 3 || st.unrouted != 1 || st.malformed != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestConvertOptions(t *testing.T) {
	var buf bytes.Buffer
	// keep AS0 rows and prepend the country code
	_, err := convert(strings.NewReader(sampleTSV), &buf, options{unrouted: true, country: true})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "US CLOUDFLARENET") {
		t.Error("expected country-prefixed org")
	}
	// the AS0 range decomposes to 1.0.1.0/24 + 1.0.2.0/23
	for _, want := range []string{"1.0.1.0/24 0 Not routed", "1.0.2.0/23 0 Not routed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing unrouted line %q", want)
		}
	}
}

// TestConvertCountry tests the "country" output mode, which outputs only the prefix and country code.
func TestConvertCountry(t *testing.T) {
	var buf bytes.Buffer
	st, err := convert(strings.NewReader(sampleTSV), &buf, options{outputMode: "country"})
	if err != nil {
		t.Fatal(err)
	}
	want := "1.0.0.0/24 US\n" +
		"8.8.8.0/24 US\n" +
		"2001:db8::/112 ZZ\n"
	if buf.String() != want {
		t.Errorf("output:\n%q\nwant:\n%q", buf.String(), want)
	}
	// 3 rows, 3 prefixes, no unrouted/malformed (AS0 with "None" country is skipped)
	if st.rows != 3 || st.prefixes != 3 || st.unrouted != 0 || st.malformed != 1 {
		t.Errorf("stats = %+v", st)
	}
}

// TestRoundTrip converts the sample, then loads the result back with the cidr
// spec loader and queries it — the full iptoasn -> spec -> table pipeline.
func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if _, err := convert(strings.NewReader(sampleTSV), &buf, options{}); err != nil {
		t.Fatal(err)
	}
	_, table, err := cidr.LoadASN(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if info, ok := table.Lookup(netip.MustParseAddr("1.0.0.5")); !ok || info.ASN != 13335 {
		t.Errorf("1.0.0.5 = %+v (ok=%v), want ASN 13335", info, ok)
	}
	if info, ok := table.Lookup(netip.MustParseAddr("2001:db8::1")); !ok || info.ASN != 64502 {
		t.Errorf("2001:db8::1 = %+v (ok=%v), want ASN 64502", info, ok)
	}
	if _, ok := table.Lookup(netip.MustParseAddr("9.9.9.9")); ok {
		t.Error("9.9.9.9 should miss")
	}
}

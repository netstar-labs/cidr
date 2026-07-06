package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

func TestConvertCountry(t *testing.T) {
	// DB-IP country lite: start,end,country_code
	const csv = "1.0.0.0,1.0.0.255,US\n" +
		"8.8.8.0,8.8.8.255,US\n" +
		"2001:db8::,2001:db8::ffff,ZZ\n"
	var buf bytes.Buffer
	st, err := convert(strings.NewReader(csv), &buf, "country")
	if err != nil {
		t.Fatal(err)
	}
	want := "1.0.0.0/24 US\n8.8.8.0/24 US\n2001:db8::/112 ZZ\n"
	if buf.String() != want {
		t.Errorf("output:\n%q\nwant:\n%q", buf.String(), want)
	}
	if st.rows != 3 || st.prefixes != 3 {
		t.Errorf("stats = %+v", st)
	}
}

func TestConvertASN(t *testing.T) {
	// DB-IP asn lite: start,end,as_number,as_organization
	const csv = "1.1.1.0,1.1.1.255,13335,\"Cloudflare, Inc.\"\n"
	var buf bytes.Buffer
	if _, err := convert(strings.NewReader(csv), &buf, "asn"); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "1.1.1.0/24 13335 Cloudflare, Inc.\n" {
		t.Errorf("output = %q", got)
	}
}

// TestRoundTrip converts a range that is not a single CIDR and confirms the
// pieces load back and answer membership across the whole range.
func TestRoundTrip(t *testing.T) {
	const csv = "192.0.2.0,192.0.2.130,US\n" // -> 192.0.2.0/25 + 192.0.2.128/31
	var buf bytes.Buffer
	if _, err := convert(strings.NewReader(csv), &buf, "country"); err != nil {
		t.Fatal(err)
	}
	set, err := cidr.LoadSet(&buf)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{"192.0.2.0", "192.0.2.130"} {
		if !set.Contains(netip.MustParseAddr(in)) {
			t.Errorf("%s should be covered", in)
		}
	}
	if set.Contains(netip.MustParseAddr("192.0.2.131")) {
		t.Error("192.0.2.131 should be outside the range")
	}
}

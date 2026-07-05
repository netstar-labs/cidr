package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
)

const spec = `
1.1.1.0/24     13335 Cloudflare, Inc.
1.1.1.128/25   99999 Customer Sub-block
8.8.8.0/24     15169 Google LLC
10.0.0.0/8
`

func TestResolveAndBrief(t *testing.T) {
	entries, err := cidr.ParseSpec(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	set, table := build(entries)

	cases := []struct {
		ip    string
		want  bool
		asn   uint32
		brief string
	}{
		{"1.1.1.10", true, 13335, "1.1.1.10                                member AS13335 Cloudflare, Inc."},
		{"1.1.1.200", true, 99999, "1.1.1.200                               member AS99999 Customer Sub-block"}, // nested /25 wins
		{"10.5.5.5", true, 0, "10.5.5.5                                member 10.0.0.0/8"},                      // member, no ASN
		{"9.9.9.9", false, 0, "9.9.9.9                                 -"},
	}
	for _, c := range cases {
		r := resolve(set, table, netip.MustParseAddr(c.ip))
		if r.Member != c.want {
			t.Errorf("%s member = %v, want %v", c.ip, r.Member, c.want)
		}
		if c.asn != 0 && (r.Info == nil || r.Info.ASN != c.asn) {
			t.Errorf("%s asn = %+v, want %d", c.ip, r.Info, c.asn)
		}
		if got := formatBrief(r); got != c.brief {
			t.Errorf("brief(%s)\n got %q\nwant %q", c.ip, got, c.brief)
		}
	}
}

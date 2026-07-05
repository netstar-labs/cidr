package cidr

import (
	"strings"
	"testing"
)

// FuzzParseSpec drives the text parser and the full build+query path with
// arbitrary input: none of it may panic, and a parse that returns entries must
// build a queryable Set and Table.
func FuzzParseSpec(f *testing.F) {
	f.Add("1.1.1.0/24 13335 Cloudflare, Inc.")
	f.Add("not a prefix at all")
	f.Add("::1")
	f.Add("10.0.0.0/8\n# comment\n\n2001:db8::/32 AS64500 org name")
	f.Add("0.0.0.0/0\n255.255.255.255\n1.1.1.128/25 1 x\n1.1.1.0/24 2 y")

	f.Fuzz(func(t *testing.T, s string) {
		entries, err := ParseSpec(strings.NewReader(s))
		if err != nil {
			return
		}
		sb := NewBuilder()
		tb := NewTableBuilder[Info]()
		for _, e := range entries {
			sb.Add(e.Prefix)
			tb.Add(e.Prefix, Info{Prefix: e.Prefix.String(), ASN: e.ASN, Org: e.Org})
		}
		set := sb.Freeze()
		table := tb.Freeze()
		for _, probe := range []string{"1.1.1.1", "255.255.255.255", "2001:db8::1", "::"} {
			a := mustAddr(probe)
			set.Contains(a)
			table.Lookup(a)
		}
	})
}

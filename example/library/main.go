// Command library is a runnable tour of the cidr package used directly: a
// membership Set (yes/no), a value Table returning a struct (yes+data), the
// same lookup returning a compact encoded uint64, longest-prefix match over a
// nested block, and IPv6 — all from one in-memory spec.
//
//	go run ./example/library                 # queries a built-in demo set
//	go run ./example/library 1.1.1.200 8.8.8.8 2001:db8::1
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/netstar-labs/cidr"
)

// demoSpec is a small IP-to-ASN spec: "<cidr> <ASN> <org...>". Note the nested
// 1.1.1.128/25 with a different ASN — longest-prefix match must prefer it.
const demoSpec = `
1.1.1.0/24     13335 Cloudflare, Inc.
1.1.1.128/25   99999 Cloudflare Customer Sub-block
8.8.8.0/24     15169 Google LLC
10.0.0.0/8     64496 Demo Private-ish Net
203.0.113.0/24 64501 TEST-NET-3 Demo
2001:db8::/32  64502 Documentation v6
`

func main() {
	// Parse the spec once; build a membership Set and a value Table[Info].
	entries, err := cidr.ParseSpec(strings.NewReader(demoSpec))
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}
	set, table, _ := cidr.LoadASN(strings.NewReader(demoSpec))

	// A separate Table[uint64] shows the compact encoded-value path: each
	// prefix's value is EncodeASN(asn, orgID, flags); orgID indexes orgs.
	tb := cidr.NewTableBuilder[uint64]()
	orgs := make([]string, len(entries))
	for i, e := range entries {
		orgs[i] = e.Org
		tb.Add(e.Prefix, cidr.EncodeASN(e.ASN, uint32(i), 0))
	}
	encoded := tb.Freeze()

	fmt.Printf("# loaded %d prefixes (set: %d merged intervals)\n\n", len(entries), set.Len())

	targets := os.Args[1:]
	if len(targets) == 0 {
		targets = []string{"1.1.1.10", "1.1.1.200", "8.8.8.8", "203.0.113.5", "2001:db8::1", "9.9.9.9"}
	}

	for _, s := range targets {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			fmt.Printf("%-16s  invalid address\n", s)
			continue
		}

		// 1. Membership — yes/no, the cheapest question.
		member := set.Contains(ip)

		// 2. Value lookup — yes+data, most-specific prefix wins.
		info, ok := table.Lookup(ip)

		// 3. The same answer as a compact uint64, then decoded back.
		var asnLine string
		if code, ok := encoded.Lookup(ip); ok {
			asn, orgID, flags := cidr.DecodeASN(code)
			asnLine = fmt.Sprintf("code=0x%016x -> AS%d %q flags=%d", code, asn, orgs[orgID], flags)
		} else {
			asnLine = "code=—"
		}

		fmt.Printf("%-16s member=%-5v ", ip, member)
		if ok {
			fmt.Printf("AS%d %q via %s\n", info.ASN, info.Org, info.Prefix)
		} else {
			fmt.Printf("(no value)\n")
		}
		fmt.Printf("%-16s   %s\n", "", asnLine)
	}

	// Show one full JSON Info record for the nested-match case.
	fmt.Println("\n# JSON Info for 1.1.1.200 (the nested /25 wins):")
	if info, ok := table.Lookup(netip.MustParseAddr("1.1.1.200")); ok {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
	}
}

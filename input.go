package cidr

import (
	"bufio"
	"encoding/json"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// A spec is a whitespace-delimited text stream, one prefix per line:
//
//	<cidr>[ <ASN>[ <org...>]]
//
//	10.0.0.0/8
//	1.1.1.0/24 13335 Cloudflare, Inc.
//	8.8.8.0/24 AS15169 Google LLC
//	203.0.113.7 64500 Example Org        # a bare address is a host route (/32)
//
// The ASN field is optional and may carry a leading "AS"; everything after it
// is the organisation name. Blank lines and lines beginning with '#' are
// ignored. It is the shape of a typical IP-to-ASN table, and a plain list of
// CIDRs (no ASN/org) is a valid degenerate case.

// Info is the value attached to a prefix loaded from a spec: the origin AS
// number and organisation name, alongside the matched prefix in CIDR form. It
// is the value type of the Table that LoadASN builds, and encodes to compact
// JSON for the service examples.
type Info struct {
	Prefix string `json:"prefix"`
	ASN    uint32 `json:"asn,omitempty"`
	Org    string `json:"org,omitempty"`
}

// SpecEntry is one parsed spec line.
type SpecEntry struct {
	Prefix netip.Prefix
	ASN    uint32
	Org    string
}

// ParseSpec reads a spec (see the package example) from r into entries. Lines
// whose first field is not a valid CIDR or address are skipped, so an
// occasional junk line in a large feed does not fail the load; only an
// underlying read error is returned.
func ParseSpec(r io.Reader) ([]SpecEntry, error) {
	var out []SpecEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if e, ok := parseSpecLine(sc.Text()); ok {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// parseSpecLine parses one "<cidr> [ASN] [org...]" line into a SpecEntry. It
// returns ok=false for a blank line, a '#'-comment, or a line whose first field
// is not a valid prefix.
func parseSpecLine(line string) (SpecEntry, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return SpecEntry{}, false
	}
	fields := strings.Fields(line)
	p, err := ParsePrefix(fields[0])
	if err != nil {
		return SpecEntry{}, false
	}
	e := SpecEntry{Prefix: p}
	if len(fields) > 1 {
		if asn, ok := parseASN(fields[1]); ok {
			e.ASN = asn
			e.Org = strings.Join(fields[2:], " ")
		} else {
			e.Org = strings.Join(fields[1:], " ")
		}
	}
	return e, true
}

// parseASN parses a decimal AS number with an optional case-insensitive "AS"
// prefix ("13335" or "AS13335").
func parseASN(s string) (uint32, bool) {
	if len(s) >= 2 && (s[0] == 'A' || s[0] == 'a') && (s[1] == 'S' || s[1] == 's') {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// buildSet compiles entries into a membership Set, ignoring ASN/org.
func buildSet(entries []SpecEntry) *Set {
	b := NewBuilder()
	for _, e := range entries {
		b.Add(e.Prefix)
	}
	return b.Freeze()
}

// BuildASN compiles already-parsed entries into a membership Set plus an LPM value
// Table[Info] in one pass — the "entries → Set + Table" step LoadASN wraps, exported so a
// caller that parsed the entries itself (to count or filter them first) can build both
// without re-parsing.
func BuildASN(entries []SpecEntry) (*Set, *Table[Info]) {
	sb := NewBuilder()
	tb := NewTableBuilder[Info]()
	for _, e := range entries {
		sb.Add(e.Prefix)
		tb.Add(e.Prefix, Info{Prefix: e.Prefix.String(), ASN: e.ASN, Org: e.Org})
	}
	return sb.Freeze(), tb.Freeze()
}

// LoadSet reads a spec (or a plain CIDR list) from r and compiles a membership
// Set, ignoring any ASN/org fields.
func LoadSet(r io.Reader) (*Set, error) {
	entries, err := ParseSpec(r)
	if err != nil {
		return nil, err
	}
	return buildSet(entries), nil
}

// LoadFunc reads a line-oriented stream and builds a Table[V], delegating the
// format to the caller: parse maps a line's whitespace-separated fields to a
// prefix and value, returning ok=false to skip the line. Blank lines and
// '#'-comments are dropped before parse is called. This is the generic loader
// for any "<cidr-or-prefix> <data...>" feed whose value is not an ASN — see the
// user guide for a worked example.
func LoadFunc[V any](r io.Reader, parse func(fields []string) (netip.Prefix, V, bool)) (*Table[V], error) {
	tb := NewTableBuilder[V]()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		fields := strings.Fields(line) // always >= 1: line is trimmed and non-empty here
		if p, v, ok := parse(fields); ok {
			tb.Add(p, v)
		}
	}
	return tb.Freeze(), sc.Err()
}

// LoadASN reads a spec from r and compiles both a membership Set (yes/no) and an
// LPM value Table[Info] (yes+data). One pass builds both, so a caller can answer
// "is this address listed?" and "which AS/org owns it?" from the same input.
func LoadASN(r io.Reader) (*Set, *Table[Info], error) {
	entries, err := ParseSpec(r)
	if err != nil {
		return nil, nil, err
	}
	set, table := BuildASN(entries)
	return set, table, nil
}

// Refs is the common refs resource envelope — a named, versioned list of spec
// lines — as published at refs.netstar.dev and similar feeds:
//
//	{"name": "parked", "version": 20260705, "list": ["1.2.3.0/24", ...]}
//
// Each list entry uses the same grammar as a ParseSpec line ("<cidr> [ASN]
// [org...]"), so a bare CIDR list and an IP-to-ASN list are both valid bodies.
type Refs struct {
	Name    string   `json:"name"`
	Version int      `json:"version"` // yyyymmdd
	List    []string `json:"list"`
}

// ParseRefs decodes a refs JSON envelope from r.
func ParseRefs(r io.Reader) (*Refs, error) {
	var rf Refs
	if err := json.NewDecoder(r).Decode(&rf); err != nil {
		return nil, err
	}
	return &rf, nil
}

// Entries parses the refs list into spec entries, skipping blank/comment lines
// and any entry whose first field is not a valid prefix.
func (rf *Refs) Entries() []SpecEntry {
	out := make([]SpecEntry, 0, len(rf.List))
	for _, line := range rf.List {
		if e, ok := parseSpecLine(line); ok {
			out = append(out, e)
		}
	}
	return out
}

// LoadRefsSet reads a refs JSON envelope and compiles a membership Set — the
// JSON analogue of LoadSet.
func LoadRefsSet(r io.Reader) (*Set, error) {
	rf, err := ParseRefs(r)
	if err != nil {
		return nil, err
	}
	return buildSet(rf.Entries()), nil
}

// LoadRefsASN reads a refs JSON envelope and compiles a membership Set plus an
// LPM value Table[Info] — the JSON analogue of LoadASN.
func LoadRefsASN(r io.Reader) (*Set, *Table[Info], error) {
	rf, err := ParseRefs(r)
	if err != nil {
		return nil, nil, err
	}
	set, table := BuildASN(rf.Entries())
	return set, table, nil
}

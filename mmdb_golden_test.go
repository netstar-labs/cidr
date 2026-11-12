package cidr

import (
	"fmt"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
)

// The MMDB reader's output is an API contract with every service that type-asserts
// a decoded value — rec["autonomous_system_number"].(uint64) — and such services
// upgrade this module independently of the databases they read. If the reader
// changed the Go type it returns for a wire type, that assertion would fail and
// the comma-ok form would quietly yield zero. This golden pins, for the committed
// fixtures (bytes built by cmd/mmdb-write), the metadata and the records the
// reader returns, with the Go type of every value, and the search-tree record
// decoding at each record size.

// goValue renders a decoded value as GoType(value), maps with sorted keys. Keys in
// typeOnly render their type (and, for a map, its keys) without values, to keep
// the eight-language country names out of the golden.
func goValue(v any, typeOnly bool) string {
	switch x := v.(type) {
	case map[string]any:
		parts := make([]string, 0, len(x))
		for k, e := range x {
			parts = append(parts, k+"="+goValue(e, typeOnly || k == "names"))
		}
		slices.Sort(parts)
		return "map{" + strings.Join(parts, ", ") + "}"
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			parts = append(parts, goValue(e, typeOnly))
		}
		return "slice[" + strings.Join(parts, ", ") + "]"
	case *big.Int:
		if typeOnly {
			return "*big.Int"
		}
		return "*big.Int(" + x.String() + ")"
	}
	if typeOnly {
		return fmt.Sprintf("%T", v)
	}
	return fmt.Sprintf("%T(%q)", v, fmt.Sprint(v))
}

func mmdbGoldens(t *testing.T) []struct{ name, got string } {
	t.Helper()
	render := func(file string, ips ...string) string {
		db, err := OpenMMDB("testdata/" + file)
		if err != nil {
			t.Fatalf("OpenMMDB(%s): %v", file, err)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "metadata %s\n", goValue(db.Metadata(), false))
		for _, ip := range ips {
			rec, ok, err := db.Lookup(net.ParseIP(ip))
			if err != nil {
				fmt.Fprintf(&b, "%s error\n", ip)
				continue
			}
			fmt.Fprintf(&b, "%s ok=%v %s\n", ip, ok, goValue(rec, false))
		}
		return b.String()
	}
	// A search-tree node read at each record size, from bytes whose every nibble is
	// distinct. The fixtures cannot pin this: their record values are all below 2^24,
	// so the 28-bit high nibbles and the 32-bit high byte are always zero there and a
	// nibble swap passes every fixture lookup.
	node := func(recordSize uint, b ...byte) string {
		m := &MMDB{data: b, nodeCount: 1, recordSize: recordSize, nodeSize: recordSize / 4, treeSize: recordSize / 4}
		l, errL := m.record(0, false)
		r, errR := m.record(0, true)
		if errL != nil || errR != nil {
			return "error"
		}
		return fmt.Sprintf("left=%#x right=%#x", l, r)
	}
	asnIPs := []string{"1.0.0.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111", "::1.0.0.1", "203.0.113.1", "2001:db8::1"}
	return []struct{ name, got string }{
		{"test-asn.mmdb", render("test-asn.mmdb", asnIPs...)},
		{"test-asn28.mmdb", render("test-asn28.mmdb", asnIPs...)},
		{"test-asn32.mmdb", render("test-asn32.mmdb", asnIPs...)},
		{"test-country.mmdb", render("test-country.mmdb", "1.0.0.1", "8.8.8.8", "81.2.69.1", "2001:67c:2e8::1", "203.0.113.1")},
		{"node/24", node(24, 0x12, 0x34, 0x56, 0x9a, 0xbc, 0xde)},
		{"node/28", node(28, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde)},
		{"node/32", node(32, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1)},
	}
}

// recordedMMDB holds what the reader returns for the committed fixtures, produced
// by TestPrintMMDBGoldens and pasted here deliberately — a golden the test
// computes from the code under test is not a golden, it is a tautology.
var recordedMMDB = map[string]string{
	"test-asn.mmdb":     "metadata map{binary_format_major_version=uint64(\"2\"), binary_format_minor_version=uint64(\"0\"), build_epoch=uint64(\"1784859347\"), database_type=string(\"GeoLite2-ASN\"), description=map{en=string(\"IPtoASN\")}, ip_version=uint64(\"6\"), languages=slice[string(\"en\")], node_count=uint64(\"242\"), record_size=uint64(\"24\")}\n1.0.0.1 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n8.8.8.8 ok=true map{autonomous_system_number=uint64(\"15169\"), autonomous_system_organization=string(\"GOOGLE\")}\n9.9.9.9 ok=true map{autonomous_system_number=uint64(\"19281\"), autonomous_system_organization=string(\"QUAD9\")}\n2606:4700:4700::1111 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n::1.0.0.1 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n203.0.113.1 ok=false map{}\n2001:db8::1 ok=false map{}\n",
	"test-asn28.mmdb":   "metadata map{binary_format_major_version=uint64(\"2\"), binary_format_minor_version=uint64(\"0\"), build_epoch=uint64(\"1784859625\"), database_type=string(\"GeoLite2-ASN\"), description=map{en=string(\"IPtoASN\")}, ip_version=uint64(\"6\"), languages=slice[string(\"en\")], node_count=uint64(\"242\"), record_size=uint64(\"28\")}\n1.0.0.1 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n8.8.8.8 ok=true map{autonomous_system_number=uint64(\"15169\"), autonomous_system_organization=string(\"GOOGLE\")}\n9.9.9.9 ok=true map{autonomous_system_number=uint64(\"19281\"), autonomous_system_organization=string(\"QUAD9\")}\n2606:4700:4700::1111 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n::1.0.0.1 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n203.0.113.1 ok=false map{}\n2001:db8::1 ok=false map{}\n",
	"test-asn32.mmdb":   "metadata map{binary_format_major_version=uint64(\"2\"), binary_format_minor_version=uint64(\"0\"), build_epoch=uint64(\"1784859625\"), database_type=string(\"GeoLite2-ASN\"), description=map{en=string(\"IPtoASN\")}, ip_version=uint64(\"6\"), languages=slice[string(\"en\")], node_count=uint64(\"242\"), record_size=uint64(\"32\")}\n1.0.0.1 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n8.8.8.8 ok=true map{autonomous_system_number=uint64(\"15169\"), autonomous_system_organization=string(\"GOOGLE\")}\n9.9.9.9 ok=true map{autonomous_system_number=uint64(\"19281\"), autonomous_system_organization=string(\"QUAD9\")}\n2606:4700:4700::1111 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n::1.0.0.1 ok=true map{autonomous_system_number=uint64(\"13335\"), autonomous_system_organization=string(\"CLOUDFLARENET\")}\n203.0.113.1 ok=false map{}\n2001:db8::1 ok=false map{}\n",
	"test-country.mmdb": "metadata map{binary_format_major_version=uint64(\"2\"), binary_format_minor_version=uint64(\"0\"), build_epoch=uint64(\"1784859581\"), database_type=string(\"GeoLite2-Country\"), description=map{en=string(\"GeoLite2-Country\")}, ip_version=uint64(\"6\"), languages=slice[string(\"en\")], node_count=uint64(\"232\"), record_size=uint64(\"24\")}\n1.0.0.1 ok=true map{continent=map{code=string(\"NA\"), geoname_id=uint64(\"6255149\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, country=map{geoname_id=uint64(\"6252001\"), iso_code=string(\"US\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, registered_country=map{geoname_id=uint64(\"6252001\"), iso_code=string(\"US\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}}\n8.8.8.8 ok=true map{continent=map{code=string(\"NA\"), geoname_id=uint64(\"6255149\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, country=map{geoname_id=uint64(\"6252001\"), iso_code=string(\"US\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, registered_country=map{geoname_id=uint64(\"6252001\"), iso_code=string(\"US\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}}\n81.2.69.1 ok=true map{continent=map{code=string(\"EU\"), geoname_id=uint64(\"6255148\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, country=map{geoname_id=uint64(\"2635167\"), iso_code=string(\"GB\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, registered_country=map{geoname_id=uint64(\"2635167\"), iso_code=string(\"GB\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}}\n2001:67c:2e8::1 ok=true map{continent=map{code=string(\"EU\"), geoname_id=uint64(\"6255148\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, country=map{geoname_id=uint64(\"2921044\"), is_in_european_union=bool(\"true\"), iso_code=string(\"DE\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}, registered_country=map{geoname_id=uint64(\"2921044\"), is_in_european_union=bool(\"true\"), iso_code=string(\"DE\"), names=map{de=string, en=string, es=string, fr=string, ja=string, pt-BR=string, ru=string, zh-CN=string}}}\n203.0.113.1 ok=false map{}\n",
	"node/24":           "left=0x123456 right=0x9abcde",
	"node/28":           "left=0x7123456 right=0x89abcde",
	"node/32":           "left=0x12345678 right=0x9abcdef1",
}

// TestPrintMMDBGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recordedMMDB.
//
//	go test -run TestPrintMMDBGoldens -v .
func TestPrintMMDBGoldens(t *testing.T) {
	for _, g := range mmdbGoldens(t) {
		t.Logf("\t%q: %q,", g.name, g.got)
	}
}

// TestMMDBReaderGolden pins the metadata and records (values and Go types) the
// reader returns for each committed fixture.
func TestMMDBReaderGolden(t *testing.T) {
	gs := mmdbGoldens(t)
	if len(gs) != len(recordedMMDB) {
		t.Fatalf("%d golden cases but %d recorded: a case was added or removed without recording it", len(gs), len(recordedMMDB))
	}
	for _, g := range gs {
		want, ok := recordedMMDB[g.name]
		if !ok {
			t.Errorf("%s: no recorded golden", g.name)
			continue
		}
		if g.got != want {
			t.Errorf("%s:\n got  %q\n want %q\n\n"+
				"MMDB READER OUTPUT CHANGED for a fixed database. This is a decode-contract break. "+
				"Services read these maps by key and type-assert the values; they upgrade this module "+
				"independently of the databases they read. A different Go type for the same wire type "+
				"(uint64 to uint32, map to struct) fails their assertion, and the comma-ok form turns that "+
				"into a zero ASN or a missing country — silently. A different value or found/not-found "+
				"for the same bytes is a wrong answer. If the decoded shape must change it needs a NEW "+
				"API, not a new shape for Lookup/Metadata. Do not re-record this golden to make the test pass.",
				g.name, g.got, want)
		}
	}
}

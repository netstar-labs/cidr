package main

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/netstar-labs/cidr"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/oschwald/maxminddb-golang/v2/mmdbdata"
)

// The .mmdb bytes themselves are laid out by the third-party mmdbwriter (tree
// shape, pointer dedup, node count), and the MMDB format is self-describing and
// versioned, so a conforming reader is indifferent to that layout. What this
// command owns, and what a reader at another version depends on, is the database
// it describes: the metadata it sets, which network maps to which record, and
// each record's keys and MMDB wire types. That is what the golden pins, through
// an independent reader (maxminddb-golang), with the wire type of every value.

// typed renders one MMDB value with its wire kind: Uint32(13335), String("x"),
// Map{k=..., ...} with keys sorted. Keys listed in redact render their kind (and,
// for a map, its keys) but not their values, for data that is refreshed from
// outside (Wikidata names and GeoNames ids in countries.json) or chosen by the
// writer library (node_count) — a change there is not a format change.
type typed struct {
	s      string
	redact map[string]bool
}

func (t *typed) UnmarshalMaxMindDB(d *mmdbdata.Decoder) error {
	s, err := dumpValue(d, t.redact, false)
	t.s = s
	return err
}

func dumpValue(d *mmdbdata.Decoder, redact map[string]bool, hide bool) (string, error) {
	k, err := d.PeekKind()
	if err != nil {
		return "", err
	}
	var v any
	switch k {
	case mmdbdata.KindMap:
		it, _, err := d.ReadMap()
		if err != nil {
			return "", err
		}
		var parts []string
		for key, err := range it {
			if err != nil {
				return "", err
			}
			ks := string(key)
			s, err := dumpValue(d, redact, hide || redact[ks])
			if err != nil {
				return "", err
			}
			parts = append(parts, ks+"="+s)
		}
		slices.Sort(parts)
		return "Map{" + strings.Join(parts, ", ") + "}", nil
	case mmdbdata.KindSlice:
		it, _, err := d.ReadSlice()
		if err != nil {
			return "", err
		}
		var parts []string
		for err := range it {
			if err != nil {
				return "", err
			}
			s, err := dumpValue(d, redact, hide)
			if err != nil {
				return "", err
			}
			parts = append(parts, s)
		}
		return "Slice[" + strings.Join(parts, ", ") + "]", nil
	case mmdbdata.KindString:
		v, err = d.ReadString()
	case mmdbdata.KindUint16:
		v, err = d.ReadUint16()
	case mmdbdata.KindUint32:
		v, err = d.ReadUint32()
	case mmdbdata.KindUint64:
		v, err = d.ReadUint64()
	case mmdbdata.KindInt32:
		v, err = d.ReadInt32()
	case mmdbdata.KindBool:
		v, err = d.ReadBool()
	case mmdbdata.KindFloat64:
		v, err = d.ReadFloat64()
	case mmdbdata.KindFloat32:
		v, err = d.ReadFloat32()
	case mmdbdata.KindBytes:
		v, err = d.ReadBytes()
	case mmdbdata.KindUint128:
		var hi, lo uint64
		hi, lo, err = d.ReadUint128()
		v = fmt.Sprintf("%016x%016x", hi, lo)
	default:
		return "", fmt.Errorf("unexpected kind %v", k)
	}
	if err != nil {
		return "", err
	}
	if hide {
		return k.String(), nil
	}
	return fmt.Sprintf("%v(%q)", k, fmt.Sprint(v)), nil
}

// renderMMDB writes spec through writeMMDB (fixed build epoch, the default IPv6
// tree and 24-bit records) and renders the metadata and every network with data.
func renderMMDB(t *testing.T, spec, dbType string, isCountry bool) string {
	t.Helper()
	entries, err := cidr.ParseSpec(strings.NewReader(spec))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, _, err := writeMMDB(&buf, entries, dbType, "golden", 1700000000, 6, 24, isCountry); err != nil {
		t.Fatal(err)
	}
	db := buf.Bytes()
	redact := map[string]bool{"names": true, "geoname_id": true, "node_count": true}

	var out strings.Builder
	marker := []byte("\xab\xcd\xefMaxMind.com")
	i := bytes.LastIndex(db, marker)
	if i < 0 {
		t.Fatal("no metadata marker")
	}
	meta, err := dumpValue(mmdbdata.NewDecoder(db[i+len(marker):], 0), redact, false)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&out, "metadata %s\n", meta)

	r, err := maxminddb.OpenBytes(db)
	if err != nil {
		t.Fatal(err)
	}
	for res := range r.Networks() {
		v := typed{redact: redact}
		if err := res.Decode(&v); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&out, "%s %s\n", res.Prefix(), v.s)
	}
	return out.String()
}

func goldens(t *testing.T) []struct{ name, got string } {
	t.Helper()
	// Sorted as the generators write it (covering prefix before nested), with an
	// AS0 row, an empty org, a host route, a 4-byte ASN and an IPv4-mapped prefix.
	const asnSpec = "1.0.0.0/24 13335 Cloudflare, Inc.\n" +
		"10.0.0.0/8 64500 Ten\n" +
		"10.1.0.0/16 64501 Ten One\n" +
		"192.0.2.0/24 0 Unrouted\n" +
		"198.51.100.0/24 64502\n" +
		"203.0.113.7 64503 Host\n" +
		"::ffff:100.64.0.0/106 64504 Mapped\n" +
		"2001:db8::/32 4200000000 DOC\n"
	// A non-EU and an EU country, a v6 prefix, and pseudo-codes that are skipped.
	const countrySpec = "1.0.0.0/24 AU\n" +
		"2.0.0.0/16 FR\n" +
		"5.0.0.0/24 EU\n" +
		"5.0.1.0/24 ZZ\n" +
		"2001:db8::/32 JP\n"
	return []struct{ name, got string }{
		{"GeoLite2-ASN", renderMMDB(t, asnSpec, "GeoLite2-ASN", false)},
		{"GeoLite2-Country", renderMMDB(t, countrySpec, "GeoLite2-Country", true)},
	}
}

// recorded holds the rendered databases, produced by TestPrintGoldens and pasted
// here deliberately — a golden the test computes from the code under test is not
// a golden, it is a tautology.
var recorded = map[string]string{
	"GeoLite2-ASN":     "metadata Map{binary_format_major_version=Uint16(\"2\"), binary_format_minor_version=Uint16(\"0\"), build_epoch=Uint64(\"1700000000\"), database_type=String(\"GeoLite2-ASN\"), description=Map{en=String(\"golden\")}, ip_version=Uint16(\"6\"), languages=Slice[String(\"en\")], node_count=Uint32, record_size=Uint16(\"24\")}\n1.0.0.0/24 Map{autonomous_system_number=Uint32(\"13335\"), autonomous_system_organization=String(\"Cloudflare, Inc.\")}\n10.0.0.0/16 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n10.1.0.0/16 Map{autonomous_system_number=Uint32(\"64501\"), autonomous_system_organization=String(\"Ten One\")}\n10.2.0.0/15 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n10.4.0.0/14 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n10.8.0.0/13 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n10.16.0.0/12 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n10.32.0.0/11 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n10.64.0.0/10 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n10.128.0.0/9 Map{autonomous_system_number=Uint32(\"64500\"), autonomous_system_organization=String(\"Ten\")}\n100.64.0.0/10 Map{autonomous_system_number=Uint32(\"64504\"), autonomous_system_organization=String(\"Mapped\")}\n192.0.2.0/24 Map{autonomous_system_number=Uint32(\"0\"), autonomous_system_organization=String(\"Unrouted\")}\n198.51.100.0/24 Map{autonomous_system_number=Uint32(\"64502\"), autonomous_system_organization=String(\"\")}\n203.0.113.7/32 Map{autonomous_system_number=Uint32(\"64503\"), autonomous_system_organization=String(\"Host\")}\n2001:db8::/32 Map{autonomous_system_number=Uint32(\"4200000000\"), autonomous_system_organization=String(\"DOC\")}\n",
	"GeoLite2-Country": "metadata Map{binary_format_major_version=Uint16(\"2\"), binary_format_minor_version=Uint16(\"0\"), build_epoch=Uint64(\"1700000000\"), database_type=String(\"GeoLite2-Country\"), description=Map{en=String(\"golden\")}, ip_version=Uint16(\"6\"), languages=Slice[String(\"en\")], node_count=Uint32, record_size=Uint16(\"24\")}\n1.0.0.0/24 Map{continent=Map{code=String(\"OC\"), geoname_id=Uint32, names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}, country=Map{geoname_id=Uint32, iso_code=String(\"AU\"), names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}, registered_country=Map{geoname_id=Uint32, iso_code=String(\"AU\"), names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}}\n2.0.0.0/16 Map{continent=Map{code=String(\"EU\"), geoname_id=Uint32, names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}, country=Map{geoname_id=Uint32, is_in_european_union=Bool(\"true\"), iso_code=String(\"FR\"), names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}, registered_country=Map{geoname_id=Uint32, is_in_european_union=Bool(\"true\"), iso_code=String(\"FR\"), names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}}\n2001:db8::/32 Map{continent=Map{code=String(\"AS\"), geoname_id=Uint32, names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}, country=Map{geoname_id=Uint32, iso_code=String(\"JP\"), names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}, registered_country=Map{geoname_id=Uint32, iso_code=String(\"JP\"), names=Map{de=String, en=String, es=String, fr=String, ja=String, pt-BR=String, ru=String, zh-CN=String}}}\n",
}

// TestPrintGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recorded.
//
//	(cd cmd/mmdb-write && go test -run TestPrintGoldens -v .)
func TestPrintGoldens(t *testing.T) {
	for _, g := range goldens(t) {
		t.Logf("\t%q: %q,", g.name, g.got)
	}
}

// TestMMDBOutputGolden pins the metadata, network-to-record mapping and record
// schema (keys and wire types) of the databases mmdb-write builds.
func TestMMDBOutputGolden(t *testing.T) {
	gs := goldens(t)
	if len(gs) != len(recorded) {
		t.Fatalf("%d golden cases but %d recorded: a case was added or removed without recording it", len(gs), len(recorded))
	}
	for _, g := range gs {
		want, ok := recorded[g.name]
		if !ok {
			t.Errorf("%s: no recorded golden", g.name)
			continue
		}
		if g.got != want {
			t.Errorf("%s:\n got  %q\n want %q\n\n"+
				"MMDB-WRITE OUTPUT CHANGED. This is a format break. Consumers read these databases "+
				"by key name and wire type and upgrade independently of this command: a renamed key "+
				"reads as absent and a changed wire type (Uint32 to Uint64, String to Map) fails a "+
				"typed decode or a type assertion, which most readers turn into a zero value — a "+
				"wrong ASN or no country, silently. A different network-to-record mapping is a "+
				"different answer for the same address. If the schema must change it needs a NEW "+
				"database_type, not a new shape for this one; if only the mmdbwriter version "+
				"changed, this golden is designed not to notice, so look again at what did. Do not "+
				"re-record this golden to make the test pass.",
				g.name, g.got, want)
		}
	}
}

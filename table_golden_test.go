package cidr

import (
	"fmt"
	"testing"
)

// asnGoldens runs EncodeASN/DecodeASN over fixed inputs. Each field gets a
// distinct, high-bit-set value so that swapping, widening or narrowing any field
// changes the output. The overflow case pins that an org id wider than 24 bits
// is truncated, not spilled into the flags byte; its flags are 0 because a set
// flag bit would hide the spill (the first version of this case did exactly that,
// and the mask-removal mutation passed).
func asnGoldens() []struct{ name, got string } {
	enc := func(asn, org uint32, flags uint8) string {
		return fmt.Sprintf("%016x", EncodeASN(asn, org, flags))
	}
	dec := func(v uint64) string {
		asn, org, flags := DecodeASN(v)
		return fmt.Sprintf("asn=%d org=%d flags=%d", asn, org, flags)
	}
	return []struct{ name, got string }{
		{"Encode/zero", enc(0, 0, 0)},
		{"Encode/typical", enc(13335, 42, 0)},
		{"Encode/distinct-fields", enc(0x11223344, 0x556677, 0x88)},
		{"Encode/asn-high-bit", enc(0x80000000, 0, 0)},
		{"Encode/org-high-bit", enc(0, 0x800000, 0)},
		{"Encode/flags-high-bit", enc(0, 0, 0x80)},
		{"Encode/all-ones", enc(0xffffffff, 0xffffff, 0xff)},
		{"Encode/org-overflow-truncated", enc(1, 0x1abcdef, 0)}, // flags 0: a spilled bit 56 must show
		{"Decode/distinct-bytes", dec(0x0123456789abcdef)},
		{"Decode/all-ones", dec(0xffffffffffffffff)},
	}
}

// recordedASN holds the EncodeASN/DecodeASN outputs, produced by
// TestPrintASNGoldens and pasted here deliberately — a golden the test computes
// from the code under test is not a golden, it is a tautology.
var recordedASN = map[string]string{
	"Encode/zero":                   "0000000000000000",
	"Encode/typical":                "0000002a00003417",
	"Encode/distinct-fields":        "8855667711223344",
	"Encode/asn-high-bit":           "0000000080000000",
	"Encode/org-high-bit":           "0080000000000000",
	"Encode/flags-high-bit":         "8000000000000000",
	"Encode/all-ones":               "ffffffffffffffff",
	"Encode/org-overflow-truncated": "00abcdef00000001",
	"Decode/distinct-bytes":         "asn=2309737967 org=2311527 flags=1",
	"Decode/all-ones":               "asn=4294967295 org=16777215 flags=255",
}

// TestPrintASNGoldens is how the golden is produced. It is not a regression test
// and always passes; run it with -v and paste the lines into recordedASN.
//
//	go test -run TestPrintASNGoldens -v .
func TestPrintASNGoldens(t *testing.T) {
	for _, g := range asnGoldens() {
		t.Logf("\t%q: %q,", g.name, g.got)
	}
}

// TestASNEncodingGolden pins the EncodeASN bit layout: ASN in bits 0-31, org id
// in bits 32-55, flags in bits 56-63.
func TestASNEncodingGolden(t *testing.T) {
	gs := asnGoldens()
	if len(gs) != len(recordedASN) {
		t.Fatalf("%d golden cases but %d recorded: a case was added or removed without recording it", len(gs), len(recordedASN))
	}
	for _, g := range gs {
		want, ok := recordedASN[g.name]
		if !ok {
			t.Errorf("%s: no recorded golden", g.name)
			continue
		}
		if g.got != want {
			t.Errorf("%s:\n got  %s\n want %s\n\n"+
				"EncodeASN/DecodeASN LAYOUT CHANGED. This is a format break. The uint64 carries no "+
				"version: a code packed by the old layout (held in a Table[uint64], a cache, a file, or "+
				"sent to a service built against another version of this module) decodes under the new "+
				"one as a wrong ASN, org id or flags value — silently, with no error. If a new layout "+
				"is needed it needs a NEW pair of functions (e.g. EncodeASN2/DecodeASN2), not a new "+
				"shape for these. Do not re-record this golden to make the test pass.",
				g.name, g.got, want)
		}
	}
}

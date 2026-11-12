package cidr

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// These tests pin the header decode of the MaxMind DB data section against the
// format rules (MaxMind DB File Format Specification v2), with every expected
// value written out as a literal derived from the spec, not from the decoder:
//
//	control byte: type = top 3 bits (0 = extended: real type = 7 + next byte),
//	              size = low 5 bits.
//	pointer (type 1): SS = ctrl bits 3-4, VVV = ctrl bits 0-2.
//	  SS=0: p = VVV<<8 | b0
//	  SS=1: p = (VVV<<16 | b0<<8 | b1) + 2048
//	  SS=2: p = (VVV<<24 | b0<<16 | b1<<8 | b2) + 526336
//	  SS=3: p = b0<<24 | b1<<16 | b2<<8 | b3   (VVV ignored, no bias)
//	  A pointer is relative to the start of the data section (ptrBase).
//	size: <29 literal; 29 -> 29+b0; 30 -> 285+(b0<<8|b1); 31 -> 65821+(b0<<16|b1<<8|b2).

// ptrBuf builds a buffer holding the pointer header hdr at offset 0 and the
// 2-byte string "ok" at offset ptrBase+target. Everything else is zero.
func ptrBuf(hdr []byte, ptrBase, target int) []byte {
	buf := make([]byte, ptrBase+target+3)
	copy(buf, hdr)
	copy(buf[ptrBase+target:], []byte{0x42, 'o', 'k'}) // string, size 2
	return buf
}

func TestDecodeMMDBPointerWidths(t *testing.T) {
	cases := []struct {
		name   string
		hdr    []byte // ctrl byte then the pointer's value bytes
		target int    // expected pointer value, as a literal from the spec
		big    bool   // allocates a large buffer; skipped under -short
	}{
		// SS=0 (ctrl 0b001_00_VVV): 11-bit pointer, no bias.
		{"ss0/zero", []byte{0x20, 0x00}, 0, false},
		{"ss0/b0=5", []byte{0x20, 0x05}, 5, false},
		{"ss0/vvv=3,b0=0x21", []byte{0x23, 0x21}, 801, false}, // 3*256 + 33
		{"ss0/max", []byte{0x27, 0xff}, 2047, false},          // 7*256 + 255

		// SS=1 (ctrl 0b001_01_VVV): 19-bit pointer + 2048.
		{"ss1/zero", []byte{0x28, 0x00, 0x00}, 2048, false},
		{"ss1/b0=1", []byte{0x28, 0x01, 0x00}, 2304, false},         // 256 + 2048
		{"ss1/vvv=1,b=2,3", []byte{0x29, 0x02, 0x03}, 68099, false}, // 65536 + 515 + 2048
		{"ss1/max", []byte{0x2f, 0xff, 0xff}, 526335, false},        // 524287 + 2048

		// SS=2 (ctrl 0b001_10_VVV): 27-bit pointer + 526336.
		{"ss2/zero", []byte{0x30, 0x00, 0x00, 0x00}, 526336, false},
		{"ss2/b1=1", []byte{0x30, 0x00, 0x01, 0x00}, 526592, false},    // 256 + 526336
		{"ss2/vvv=1", []byte{0x31, 0x00, 0x00, 0x00}, 17303552, false}, // 16777216 + 526336
		{"ss2/max", []byte{0x37, 0xff, 0xff, 0xff}, 134744063, true},   // 134217727 + 526336

		// SS=3 (ctrl 0b001_11_xxx): 32-bit big-endian pointer, VVV ignored, no bias.
		{"ss3/b3=0x40", []byte{0x38, 0x00, 0x00, 0x00, 0x40}, 64, false},
		{"ss3/vvv-ignored", []byte{0x3f, 0x00, 0x00, 0x00, 0x40}, 64, false}, // VVV=7 must not matter
		{"ss3/b2=1", []byte{0x38, 0x00, 0x00, 0x01, 0x00}, 256, false},
		{"ss3/b1=1", []byte{0x38, 0x00, 0x01, 0x00, 0x00}, 65536, false},
		{"ss3/b0=1", []byte{0x3a, 0x01, 0x00, 0x00, 0x00}, 16777216, false}, // VVV=2 ignored
	}
	for _, c := range cases {
		for _, base := range []int{16, 100} {
			t.Run(fmt.Sprintf("%s/base=%d", c.name, base), func(t *testing.T) {
				if c.big && testing.Short() {
					t.Skip("allocates a ~135 MB buffer")
				}
				buf := ptrBuf(c.hdr, base, c.target)
				v, off, err := decodeTest(buf, 0, base, 0)
				if err != nil {
					t.Fatalf("decodeMMDB: %v", err)
				}
				if v != "ok" {
					t.Errorf("value = %#v, want \"ok\" (pointer %d not followed to ptrBase+%d)", v, c.target, c.target)
				}
				// The returned offset is just past the pointer header, not the target.
				if off != len(c.hdr) {
					t.Errorf("offset = %d, want %d (just past the pointer)", off, len(c.hdr))
				}
			})
		}
	}
}

// A pointer is relative to ptrBase and nothing else: with the pointer itself
// placed mid-buffer, the target is still ptrBase+p, not off+p.
func TestDecodeMMDBPointerRelativeToBase(t *testing.T) {
	buf := make([]byte, 64)
	buf[10], buf[11] = 0x20, 0x05                 // pointer, p=5, at offset 10
	copy(buf[30+5:], []byte{0x42, 'o', 'k'})      // ptrBase=30 -> target 35
	copy(buf[10+5:], []byte{0x43, 'b', 'a', 'd'}) // a decoy where off+p would land
	v, off, err := decodeTest(buf, 10, 30, 0)
	if err != nil || v != "ok" || off != 12 {
		t.Fatalf("got (%#v, %d, %v), want (\"ok\", 12, nil)", v, off, err)
	}
}

// Pointer targets outside the buffer are errors, never panics.
func TestDecodeMMDBPointerOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
	}{
		{"ss0/past-end", []byte{0x27, 0xff, 0x42, 'o', 'k'}},                               // p=2047, buf is 5 bytes
		{"ss1/past-end", []byte{0x2f, 0xff, 0xff, 0x42, 'o', 'k'}},                         // p=526335
		{"ss2/past-end", []byte{0x37, 0xff, 0xff, 0xff, 0x42, 'o', 'k'}},                   // p=134744063
		{"ss3/max", []byte{0x3f, 0xff, 0xff, 0xff, 0xff, 0x42, 'o', 'k'}},                  // p=4294967295
		{"ss3/lands-on-short-value", []byte{0x38, 0x00, 0x00, 0x00, 0x06, 0x42, 'o', 'k'}}, // p=6 hits 'k' (0x6b: a double needing 8 bytes)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if v, _, err := decodeTest(c.buf, 0, 0, 0); err == nil {
				t.Fatalf("decodeMMDB = %#v, want an error", v)
			}
		})
	}
}

// stringBuf returns a string header (ctrl|size bytes in hdr) followed by n 'x' bytes.
func stringBuf(hdr []byte, n int) []byte {
	return append(append([]byte(nil), hdr...), bytes.Repeat([]byte{'x'}, n)...)
}

func TestDecodeMMDBExtendedSizes(t *testing.T) {
	cases := []struct {
		name string
		hdr  []byte // string (type 2 -> ctrl 0b010_sssss = 0x40|sssss) + size bytes
		n    int    // expected string length, a literal from the spec
		big  bool
	}{
		{"literal/0", []byte{0x40}, 0, false},
		{"literal/28", []byte{0x5c}, 28, false}, // largest literal size
		// size code 29: 29 + b0
		{"29/b0=0", []byte{0x5d, 0x00}, 29, false},
		{"29/b0=1", []byte{0x5d, 0x01}, 30, false},
		{"29/b0=255", []byte{0x5d, 0xff}, 284, false},
		// size code 30: 285 + (b0<<8 | b1)
		{"30/0,0", []byte{0x5e, 0x00, 0x00}, 285, false},
		{"30/0,255", []byte{0x5e, 0x00, 0xff}, 540, false},
		{"30/1,0", []byte{0x5e, 0x01, 0x00}, 541, false},       // 285 + 256
		{"30/255,255", []byte{0x5e, 0xff, 0xff}, 65820, false}, // 285 + 65535
		// size code 31: 65821 + (b0<<16 | b1<<8 | b2)
		{"31/0,0,0", []byte{0x5f, 0x00, 0x00, 0x00}, 65821, false},
		{"31/0,1,0", []byte{0x5f, 0x00, 0x01, 0x00}, 66077, false},  // 65821 + 256
		{"31/1,0,0", []byte{0x5f, 0x01, 0x00, 0x00}, 131357, false}, // 65821 + 65536
		{"31/0,0,255", []byte{0x5f, 0x00, 0x00, 0xff}, 66076, false},
		// the maximum would be 65821+16777215 = 16843036: allocate it once
		{"31/255,255,255", []byte{0x5f, 0xff, 0xff, 0xff}, 16843036, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.big && testing.Short() {
				t.Skip("allocates a ~16 MB buffer")
			}
			buf := stringBuf(c.hdr, c.n)
			v, off, err := decodeTest(buf, 0, 0, 0)
			if err != nil {
				t.Fatalf("decodeMMDB: %v", err)
			}
			s, ok := v.(string)
			if !ok {
				t.Fatalf("value is %T, want string", v)
			}
			if len(s) != c.n {
				t.Errorf("len(value) = %d, want %d", len(s), c.n)
			}
			if off != len(c.hdr)+c.n {
				t.Errorf("offset = %d, want %d", off, len(c.hdr)+c.n)
			}
			// one byte short of the claimed length must be truncation, not a panic
			if _, _, err := decodeTest(buf[:len(buf)-1], 0, 0, 0); c.n > 0 && !errors.Is(err, errTrunc) {
				t.Errorf("one byte short: err = %v, want errTrunc", err)
			}
		})
	}
}

// The extended-type header: ctrl type bits 0, next byte = type-7.
func TestDecodeMMDBExtendedType(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		want any
		off  int
	}{
		{"int32/0-bytes", []byte{0x00, 0x01}, int32(0), 2},                       // type 8, size 0
		{"int32/-1", []byte{0x04, 0x01, 0xff, 0xff, 0xff, 0xff}, int32(-1), 6},   // type 8, size 4
		{"uint64/1", []byte{0x01, 0x02, 0x01}, uint64(1), 3},                     // type 9, size 1
		{"bool/true", []byte{0x01, 0x07}, true, 2},                               // type 14, size 1
		{"bool/false", []byte{0x00, 0x07}, false, 2},                             // type 14, size 0
		{"float/1.0", []byte{0x04, 0x08, 0x3f, 0x80, 0x00, 0x00}, float32(1), 6}, // type 15
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, off, err := decodeTest(c.buf, 0, 0, 0)
			if err != nil || v != c.want || off != c.off {
				t.Fatalf("got (%#v, %d, %v), want (%#v, %d, nil)", v, off, err, c.want, c.off)
			}
		})
	}
}

// Truncation at every byte boundary of every multi-byte header must be an error
// (errTrunc for the pointer and size bytes), never a panic or a short read.
func TestDecodeMMDBHeaderTruncation(t *testing.T) {
	headers := []struct {
		name string
		hdr  []byte
		ext  bool // first header byte is an extended-type ctrl: the cut after it is "truncated extended type"
	}{
		{"ptr/ss0", []byte{0x27, 0xff}, false},
		{"ptr/ss1", []byte{0x2f, 0xff, 0xff}, false},
		{"ptr/ss2", []byte{0x37, 0xff, 0xff, 0xff}, false},
		{"ptr/ss3", []byte{0x3f, 0xff, 0xff, 0xff, 0xff}, false},
		{"size/29", []byte{0x5d, 0xff}, false},
		{"size/30", []byte{0x5e, 0xff, 0xff}, false},
		{"size/31", []byte{0x5f, 0xff, 0xff, 0xff}, false},
		// extended type (array, type 11 = 7+4) with each extended size
		{"ext-size/29", []byte{0x1d, 0x04, 0xff}, true},
		{"ext-size/30", []byte{0x1e, 0x04, 0xff, 0xff}, true},
		{"ext-size/31", []byte{0x1f, 0x04, 0xff, 0xff, 0xff}, true},
	}
	for _, h := range headers {
		t.Run(h.name, func(t *testing.T) {
			if _, _, err := decodeTest(nil, 0, 0, 0); err == nil {
				t.Error("empty buffer: want an error")
			}
			for k := 1; k < len(h.hdr); k++ {
				_, _, err := decodeTest(h.hdr[:k], 0, 0, 0)
				if err == nil {
					t.Errorf("cut at %d of %d bytes: want an error", k, len(h.hdr))
					continue
				}
				if h.ext && k == 1 {
					continue // "truncated extended type", a distinct error
				}
				if !errors.Is(err, errTrunc) {
					t.Errorf("cut at %d of %d bytes: err = %v, want errTrunc", k, len(h.hdr), err)
				}
			}
		})
	}
	// An extended ctrl byte with no type byte after it.
	if _, _, err := decodeTest([]byte{0x00}, 0, 0, 0); err == nil {
		t.Error("lone extended ctrl byte: want an error")
	}
}

// Header complete but the payload is short: also truncation, for each type that
// carries a payload.
func TestDecodeMMDBPayloadTruncation(t *testing.T) {
	cases := map[string][]byte{
		"string":  {0x43, 'a', 'b'},
		"bytes":   {0x83, 'a', 'b'}, // type 4 (0b100)
		"double":  {0x68, 1, 2, 3, 4, 5, 6, 7},
		"uint16":  {0xa2, 1},          // type 5
		"uint32":  {0xc2, 1},          // type 6
		"uint64":  {0x03, 0x02, 1, 2}, // extended type 9, size 3, two bytes
		"int32":   {0x02, 0x01, 1},
		"uint128": {0x03, 0x03, 1, 2},
		"float":   {0x04, 0x08, 1, 2, 3},
		"array":   {0x03, 0x04},      // extended array of 3 elements, none present
		"map":     {0xe1, 0x41, 'k'}, // 1 entry, key but no value
	}
	for name, buf := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeTest(buf, 0, 0, 0); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// Only extended type bytes 1..8 (types 8..15) are valid: 0 would be type 7 (map, which
// has its own non-extended code) and anything above 8 is past the last type. The type
// must not wrap: 0xFB is 258, not string; 0xFA is 257, not pointer.
func TestDecodeMMDBExtendedTypeRange(t *testing.T) {
	for _, ext := range []byte{0x00, 0x09, 0x0a, 0x7f, 0xf9, 0xfa, 0xfb, 0xfc, 0xff} {
		if v, _, err := decodeTest([]byte{0x00, ext, 0x00, 0x00}, 0, 0, 0); err == nil {
			t.Errorf("extended type byte 0x%02x: got %#v, want an error", ext, v)
		}
	}
	if v, _, err := decodeTest([]byte{0x00, 0x01}, 0, 0, 0); err != nil || v != int32(0) {
		t.Errorf("extended type byte 0x01 (int32): got (%#v, %v)", v, err)
	}
	if v, _, err := decodeTest([]byte{0x04, 0x08, 0, 0, 0, 0}, 0, 0, 0); err != nil || v != float32(0) {
		t.Errorf("extended type byte 0x08 (float): got (%#v, %v)", v, err)
	}
}

// The budget: a value costs valueCost, a string its payload too; running out is an
// error, and a budget is per decode, not shared.
func TestDecodeMMDBBudget(t *testing.T) {
	buf := append(hdr(2, 1000), bytes.Repeat([]byte{'a'}, 1000)...)
	if _, _, err := decodeMMDB(buf, 0, 0, 0, &budget{left: valueCost + 999}); err != errBudget {
		t.Errorf("one unit short: err = %v, want errBudget", err)
	}
	if _, _, err := decodeMMDB(buf, 0, 0, 0, &budget{left: valueCost + 1000}); err != nil {
		t.Errorf("exact budget: err = %v, want nil", err)
	}
	if got := newBudget(0).left; got != 1<<20 {
		t.Errorf("newBudget(0) = %d, want the 1<<20 floor", got)
	}
	if got := newBudget(1 << 20).left; got != 4<<20 {
		t.Errorf("newBudget(1<<20) = %d, want 4*len", got)
	}
}

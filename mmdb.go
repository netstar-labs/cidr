package cidr

// Stdlib-only MaxMind DB (.mmdb) reader — the read companion to the mmdb-write
// command (which uses the third-party maxmind/mmdbwriter, isolated in its own
// module). Keeping the reader here, dependency-free, lets downstream consumers
// read cidr-produced databases (ASN, country, or any custom schema) through a
// first-party API with zero third-party transitive dependencies.
//
// Format: MaxMind DB File Format Specification v2
// (https://maxmind.github.io/MaxMind-DB/). A file is a binary search tree, a
// 16-byte separator, a data section, and — after the "\xab\xcd\xefMaxMind.com"
// marker — the metadata (itself encoded in the data format).

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"os"
)

var metaMarker = []byte("\xab\xcd\xefMaxMind.com")

// MMDB is an opened MaxMind DB held in memory, safe for concurrent lookups.
type MMDB struct {
	data       []byte
	nodeCount  uint
	recordSize uint
	ipVersion  int
	nodeSize   uint // bytes per node = recordSize*2/8
	treeSize   uint // bytes
	dataStart  int  // treeSize + 16; pointer base for the data section
	metadata   map[string]any
}

// OpenMMDB reads and parses the MaxMind DB at path.
func OpenMMDB(path string) (*MMDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return OpenMMDBBytes(data)
}

// OpenMMDBBytes parses an in-memory MaxMind DB. The slice is retained (not
// copied) and must not be mutated while the MMDB is in use.
func OpenMMDBBytes(data []byte) (*MMDB, error) {
	idx := bytes.LastIndex(data, metaMarker)
	if idx < 0 {
		return nil, errors.New("cidr: mmdb: metadata marker not found (not a MaxMind DB)")
	}
	meta, _, err := decodeMMDB(data[idx+len(metaMarker):], 0, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("cidr: mmdb metadata: %w", err)
	}
	mm, ok := meta.(map[string]any)
	if !ok {
		return nil, errors.New("cidr: mmdb: metadata is not a map")
	}
	recordSize := uintOf(mm["record_size"])
	if recordSize != 24 && recordSize != 28 && recordSize != 32 {
		return nil, fmt.Errorf("cidr: mmdb: unsupported record_size %d", recordSize)
	}
	nodeCount := uintOf(mm["node_count"])
	nodeSize := recordSize * 2 / 8 // 6, 7, or 8 (recordSize validated above)
	// bound node_count against the file: nodeCount*nodeSize must fit, tested with a
	// division so a crafted node_count cannot overflow the multiply and wrap treeSize
	// small/negative (which would defeat this guard and yield a garbage dataStart).
	if len(data) < 16 || nodeCount > (uint(len(data))-16)/nodeSize {
		return nil, errors.New("cidr: mmdb: truncated (search tree exceeds file)")
	}
	treeSize := nodeCount * nodeSize
	return &MMDB{
		data:       data,
		nodeCount:  nodeCount,
		recordSize: recordSize,
		ipVersion:  int(uintOf(mm["ip_version"])),
		nodeSize:   nodeSize,
		treeSize:   treeSize,
		dataStart:  int(treeSize) + 16,
		metadata:   mm,
	}, nil
}

// Metadata returns the decoded metadata map (node_count, record_size,
// ip_version, database_type, description, build_epoch, …).
func (m *MMDB) Metadata() map[string]any { return m.metadata }

// Close is a no-op: the database is a plain in-memory buffer, reclaimed by GC once the
// MMDB is unreferenced. It exists for API symmetry (and a future mmap backend) and does
// NOT release the buffer, so it is safe to call concurrently with in-flight Lookups.
func (m *MMDB) Close() error { return nil }

// Lookup returns the record for ip as a decoded map (the shape depends on the
// database's schema: ASN, country, or any custom fields the producer packed).
// ok is false when ip has no record.
func (m *MMDB) Lookup(ip net.IP) (record map[string]any, ok bool, err error) {
	v, found, err := m.lookupValue(ip)
	if err != nil || !found {
		return nil, found, err
	}
	mp, _ := v.(map[string]any)
	return mp, true, nil
}

// lookupValue walks the tree for ip and decodes the pointed-to data value.
func (m *MMDB) lookupValue(ip net.IP) (any, bool, error) {
	addr := m.normalize(ip)
	if addr == nil {
		return nil, false, fmt.Errorf("cidr: mmdb: %v cannot be looked up in an IPv%d database", ip, m.ipVersion)
	}
	node := uint(0)
	for i := 0; i < len(addr)*8; i++ {
		if node >= m.nodeCount {
			break
		}
		bit := (addr[i>>3] >> (7 - uint(i&7))) & 1
		rec, err := m.record(node, bit == 1)
		if err != nil {
			return nil, false, err
		}
		node = rec
	}
	switch {
	case node == m.nodeCount:
		return nil, false, nil // the empty record: no data
	case node < m.nodeCount:
		return nil, false, nil // ran out of address bits inside the tree
	}
	off := int(m.treeSize) + int(node-m.nodeCount) // == dataStart + (node - nodeCount - 16)
	v, _, err := decodeMMDB(m.data, off, m.dataStart, 0)
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

// normalize renders ip as the byte width the database indexes on. An IPv4
// address in an IPv6 database is placed under ::/96 (12 zero bytes + v4), the
// location mmdbwriter/GeoLite2 use for the IPv4 subtree.
func (m *MMDB) normalize(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		if m.ipVersion == 4 {
			return v4
		}
		b := make([]byte, 16)
		copy(b[12:], v4)
		return b
	}
	if m.ipVersion == 4 {
		return nil // an IPv6 address cannot be found in a v4-only database
	}
	return ip.To16()
}

// record reads the left (right==false) or right record value of a tree node.
func (m *MMDB) record(node uint, right bool) (uint, error) {
	base := node * m.nodeSize
	if int(base)+int(m.nodeSize) > int(m.treeSize) {
		return 0, errors.New("cidr: mmdb: node index out of range")
	}
	b := m.data[base:]
	switch m.recordSize {
	case 24:
		if !right {
			return uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2]), nil
		}
		return uint(b[3])<<16 | uint(b[4])<<8 | uint(b[5]), nil
	case 28:
		if !right {
			return uint(b[3]>>4)<<24 | uint(b[0])<<16 | uint(b[1])<<8 | uint(b[2]), nil
		}
		return uint(b[3]&0x0f)<<24 | uint(b[4])<<16 | uint(b[5])<<8 | uint(b[6]), nil
	default: // 32
		if !right {
			return uint(binary.BigEndian.Uint32(b[0:4])), nil
		}
		return uint(binary.BigEndian.Uint32(b[4:8])), nil
	}
}

// maxMMDBDepth bounds recursion through the data section — pointer chains and nested
// containers alike. A .mmdb is untrusted input; without this a self-referencing pointer,
// a pointer cycle, or a deeply nested container recurses until the goroutine stack
// overflows (an unrecoverable fatal error). Real databases nest only a few levels.
const maxMMDBDepth = 512

// decodeMMDB decodes one value from buf at off. ptrBase is the offset pointers are
// relative to (the data-section start for tree data; 0 for the self-contained metadata
// section). depth guards against runaway pointer/container recursion on malformed input.
// Returns the value and the offset just past it. All lengths read from buf are treated as
// untrusted: bounds are compared as (len(buf)-off) so off+size cannot overflow, and a
// container's element count cannot exceed the bytes that remain.
func decodeMMDB(buf []byte, off, ptrBase, depth int) (any, int, error) {
	if depth > maxMMDBDepth {
		return nil, 0, errors.New("cidr: mmdb: max pointer/nesting depth exceeded")
	}
	if off < 0 || off >= len(buf) {
		return nil, 0, errors.New("cidr: mmdb: offset out of range")
	}
	ctrl := buf[off]
	off++
	typ := ctrl >> 5
	if typ == 0 { // extended type
		if off >= len(buf) {
			return nil, 0, errors.New("cidr: mmdb: truncated extended type")
		}
		typ = buf[off] + 7
		off++
	}

	if typ == 1 { // pointer
		ss := (ctrl >> 3) & 0x03
		var ptr int
		switch ss {
		case 0:
			if off+1 > len(buf) {
				return nil, 0, errTrunc
			}
			ptr = int(ctrl&0x07)<<8 | int(buf[off])
			off++
		case 1:
			if off+2 > len(buf) {
				return nil, 0, errTrunc
			}
			ptr = (int(ctrl&0x07)<<16 | int(buf[off])<<8 | int(buf[off+1])) + 2048
			off += 2
		case 2:
			if off+3 > len(buf) {
				return nil, 0, errTrunc
			}
			ptr = (int(ctrl&0x07)<<24 | int(buf[off])<<16 | int(buf[off+1])<<8 | int(buf[off+2])) + 526336
			off += 3
		default: // 3
			if off+4 > len(buf) {
				return nil, 0, errTrunc
			}
			ptr = int(binary.BigEndian.Uint32(buf[off : off+4]))
			off += 4
		}
		v, _, err := decodeMMDB(buf, ptrBase+ptr, ptrBase, depth+1)
		return v, off, err
	}

	size := int(ctrl & 0x1f)
	switch {
	case size < 29:
	case size == 29:
		if off+1 > len(buf) {
			return nil, 0, errTrunc
		}
		size = 29 + int(buf[off])
		off++
	case size == 30:
		if off+2 > len(buf) {
			return nil, 0, errTrunc
		}
		size = 285 + int(buf[off])<<8 + int(buf[off+1])
		off += 2
	default: // 31
		if off+3 > len(buf) {
			return nil, 0, errTrunc
		}
		size = 65821 + int(buf[off])<<16 + int(buf[off+1])<<8 + int(buf[off+2])
		off += 3
	}

	avail := len(buf) - off // bytes remaining; guards below avoid off+size overflow
	switch typ {
	case 2: // UTF-8 string
		if size > avail {
			return nil, 0, errTrunc
		}
		return string(buf[off : off+size]), off + size, nil
	case 3: // double (IEEE-754 64-bit)
		if avail < 8 {
			return nil, 0, errTrunc
		}
		return math.Float64frombits(binary.BigEndian.Uint64(buf[off : off+8])), off + 8, nil
	case 4: // bytes
		if size > avail {
			return nil, 0, errTrunc
		}
		return append([]byte(nil), buf[off:off+size]...), off + size, nil
	case 5, 6, 9: // uint16 / uint32 / uint64
		if size > 8 || size > avail { // reject a width beyond the fixed type (wrong value)
			return nil, 0, errTrunc
		}
		return beUint(buf[off : off+size]), off + size, nil
	case 7: // map
		if size > avail { // each entry needs >= 1 byte: reject an amplified count
			return nil, 0, errTrunc
		}
		m := make(map[string]any, min(size, 4096)) // pre-size capped; grows to the real count
		o := off
		for i := 0; i < size; i++ {
			k, no, err := decodeMMDB(buf, o, ptrBase, depth+1)
			if err != nil {
				return nil, 0, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, 0, errors.New("cidr: mmdb: non-string map key")
			}
			v, no2, err := decodeMMDB(buf, no, ptrBase, depth+1)
			if err != nil {
				return nil, 0, err
			}
			m[ks] = v
			o = no2
		}
		return m, o, nil
	case 8: // int32 (two's complement, up to 4 bytes)
		if size > 4 || size > avail {
			return nil, 0, errTrunc
		}
		return int32(uint32(beUint(buf[off : off+size]))), off + size, nil
	case 10: // uint128
		if size > 16 || size > avail {
			return nil, 0, errTrunc
		}
		return new(big.Int).SetBytes(buf[off : off+size]), off + size, nil
	case 11: // array
		if size > avail { // each element needs >= 1 byte: reject an amplified count
			return nil, 0, errTrunc
		}
		arr := make([]any, 0, min(size, 4096)) // pre-size capped; grows to the real count
		o := off
		for i := 0; i < size; i++ {
			v, no, err := decodeMMDB(buf, o, ptrBase, depth+1)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			o = no
		}
		return arr, o, nil
	case 14: // boolean (size is 0 or 1)
		return size != 0, off, nil
	case 15: // float (IEEE-754 32-bit)
		if avail < 4 {
			return nil, 0, errTrunc
		}
		return math.Float32frombits(binary.BigEndian.Uint32(buf[off : off+4])), off + 4, nil
	}
	return nil, 0, fmt.Errorf("cidr: mmdb: unknown data type %d", typ)
}

var errTrunc = errors.New("cidr: mmdb: truncated data section")

// beUint reads up to 8 big-endian bytes as a uint64.
func beUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// uintOf coerces a decoded metadata number (always a uint64 from the decoder) to
// a uint; anything else yields 0.
func uintOf(v any) uint {
	if u, ok := v.(uint64); ok {
		return uint(u)
	}
	return 0
}

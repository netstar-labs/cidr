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
	dataLen    int  // bytes in the data section (sizes the per-Lookup decode budget)
	metadata   map[string]any

	// v4Start is the node reached after the 96 zero bits that prefix an IPv4 address in an
	// IPv6 tree (::/96), computed once at open so a v4 lookup starts there instead of
	// walking those bits every time. v4StartOK is false (and lookups walk all 128 bits) for
	// an IPv4 tree, or if that walk failed: a malformed file then behaves as it always did.
	v4Start   uint
	v4StartOK bool
}

// v4PrefixBits is the number of leading zero bits of an IPv4-mapped-in-IPv6 address.
const v4PrefixBits = 96

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
	metaBuf := data[idx+len(metaMarker):]
	meta, _, err := decodeMMDB(metaBuf, 0, 0, 0, newBudget(len(metaBuf)))
	if err != nil {
		return nil, fmt.Errorf("cidr: mmdb metadata: %w", err)
	}
	mm, ok := meta.(map[string]any)
	if !ok {
		return nil, errors.New("cidr: mmdb: metadata is not a map")
	}
	// Only major version 2 of the format is understood (a missing key is as invalid as a
	// different value), and a database indexes either IPv4 or IPv6 addresses.
	major, err := uintOf(mm, "binary_format_major_version")
	if err != nil {
		return nil, err
	}
	if major != 2 {
		return nil, fmt.Errorf("cidr: mmdb: unsupported binary_format_major_version %v (want 2)", mm["binary_format_major_version"])
	}
	ipVersion, err := uintOf(mm, "ip_version")
	if err != nil {
		return nil, err
	}
	if ipVersion != 4 && ipVersion != 6 {
		return nil, fmt.Errorf("cidr: mmdb: unsupported ip_version %v (want 4 or 6)", mm["ip_version"])
	}
	recordSize, err := uintOf(mm, "record_size")
	if err != nil {
		return nil, err
	}
	if recordSize != 24 && recordSize != 28 && recordSize != 32 {
		return nil, fmt.Errorf("cidr: mmdb: unsupported record_size %d", recordSize)
	}
	nodeCount, err := uintOf(mm, "node_count")
	if err != nil {
		return nil, err
	}
	nodeSize := recordSize * 2 / 8 // 6, 7, or 8 (recordSize validated above)
	// bound node_count against the file: nodeCount*nodeSize must fit, tested with a
	// division so a crafted node_count cannot overflow the multiply and wrap treeSize
	// small/negative (which would defeat this guard and yield a garbage dataStart).
	if len(data) < 16 || nodeCount > (uint(len(data))-16)/nodeSize {
		return nil, errors.New("cidr: mmdb: truncated (search tree exceeds file)")
	}
	treeSize := nodeCount * nodeSize
	m := &MMDB{
		data:       data,
		nodeCount:  nodeCount,
		recordSize: recordSize,
		ipVersion:  int(ipVersion),
		nodeSize:   nodeSize,
		treeSize:   treeSize,
		dataStart:  int(treeSize) + 16,
		dataLen:    max(0, idx-int(treeSize)-16), // 0 if the tree runs into the metadata: no data
		metadata:   mm,
	}
	if m.ipVersion == 6 {
		m.v4Start, m.v4StartOK = m.walkZeros(v4PrefixBits)
	}
	return m, nil
}

// walkZeros follows the left (zero-bit) record from the root for up to n bits, stopping
// early at a leaf or data record exactly as a lookup of an address of zero bits would.
// ok is false if reading a node failed.
func (m *MMDB) walkZeros(n int) (node uint, ok bool) {
	for i := 0; i < n && node < m.nodeCount; i++ {
		rec, err := m.record(node, false)
		if err != nil {
			return 0, false
		}
		node = rec
	}
	return node, true
}

// Metadata returns the decoded metadata map (node_count, record_size,
// ip_version, database_type, description, build_epoch, …). The map (and the nested
// maps and slices inside it) is the database's own, not a copy: it is shared by every
// caller and by concurrent lookups, so it must be treated as read-only. Writing to it
// is a data race and corrupts what later callers see; copy it first if you need to change it.
func (m *MMDB) Metadata() map[string]any { return m.metadata }

// Close is a no-op: the database is a plain in-memory buffer, reclaimed by GC once the
// MMDB is unreferenced. It exists for API symmetry (and a future mmap backend) and does
// NOT release the buffer, so it is safe to call concurrently with in-flight Lookups.
func (m *MMDB) Close() error { return nil }

// Lookup returns the record for ip as a decoded map (the shape depends on the
// database's schema: ASN, country, or any custom fields the producer packed).
// ok is false when ip has no record. A record that is not a map (legal in the
// format, though no cidr writer produces one) is reported as record == nil with
// ok == true: the address has a record, but it is not representable as a map.
func (m *MMDB) Lookup(ip net.IP) (record map[string]any, ok bool, err error) {
	v, found, err := m.lookupValue(ip)
	if err != nil || !found {
		return nil, found, err
	}
	mp, _ := v.(map[string]any)
	return mp, true, nil
}

// lookupNode walks the tree for ip and returns the record value it ends on (see
// lookupValue for how to read it).
func (m *MMDB) lookupNode(ip net.IP) (uint, error) {
	var buf [16]byte
	addr, v4 := m.normalize(ip, &buf)
	if addr == nil {
		return 0, fmt.Errorf("cidr: mmdb: %v cannot be looked up in an IPv%d database", ip, m.ipVersion)
	}
	node, i := uint(0), 0
	if v4 && m.v4StartOK {
		node, i = m.v4Start, v4PrefixBits // the first 96 bits are known: skip them
	}
	for ; i < len(addr)*8; i++ {
		if node >= m.nodeCount {
			break
		}
		bit := (addr[i>>3] >> (7 - uint(i&7))) & 1
		rec, err := m.record(node, bit == 1)
		if err != nil {
			return 0, err
		}
		node = rec
	}
	return node, nil
}

// lookupValue walks the tree for ip and decodes the pointed-to data value.
func (m *MMDB) lookupValue(ip net.IP) (any, bool, error) {
	node, err := m.lookupNode(ip)
	if err != nil {
		return nil, false, err
	}
	switch {
	case node <= m.nodeCount:
		// node == nodeCount is the empty record (no data); node < nodeCount means the
		// address ran out of bits inside the tree. Either way: no record.
		return nil, false, nil
	case node-m.nodeCount < 16:
		// A data pointer is (node - nodeCount) = 16 + offset into the data section;
		// values 1..15 would point into the 16-byte zero separator, which is not data.
		return nil, false, errors.New("cidr: mmdb: record points into the data-section separator")
	}
	// rel is the offset into the data section. Test it as a uint BEFORE converting to int:
	// a 32-bit node can exceed MaxInt32, and int(node)-int(nodeCount) would wrap.
	rel := node - m.nodeCount - 16
	if rel >= uint(m.dataLen) {
		return nil, false, errors.New("cidr: mmdb: record points past the data section")
	}
	off := m.dataStart + int(rel)
	v, _, err := decodeMMDB(m.data, off, m.dataStart, 0, newBudget(m.dataLen))
	if err != nil {
		return nil, false, err
	}
	return v, true, nil
}

// normalize renders ip as the byte width the database indexes on, using buf for the
// 16-byte form so a lookup does not allocate; v4 reports that ip is an IPv4 address (in
// an IPv6 database it is placed under ::/96: 12 zero bytes + v4, the location
// mmdbwriter/GeoLite2 use for the IPv4 subtree). It returns nil for an IPv6 address in
// an IPv4 database or an invalid ip.
func (m *MMDB) normalize(ip net.IP, buf *[16]byte) (addr []byte, v4 bool) {
	if a := ip.To4(); a != nil {
		if m.ipVersion == 4 {
			return a, true
		}
		*buf = [16]byte{}
		copy(buf[12:], a)
		return buf[:], true
	}
	if m.ipVersion == 4 {
		return nil, false // an IPv6 address cannot be found in a v4-only database
	}
	return ip.To16(), false
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

// A decode's total work and output are bounded by a budget, because recursion depth alone
// is not enough: a data DAG whose every level is an array of two pointers to the level
// below (~6 bytes per level) decodes in 2^levels time and memory, and N pointers to one
// large string copy that string N times. Every decoded value (a pointer follow included)
// costs valueCost units, a string, bytes or uint128 value also costs its payload bytes,
// and a container is charged for its FULL declared count (elemCost per array slot,
// mapEntryCost per map entry, plus mapBaseCost per map) before anything is allocated, so
// the budget bounds both the number of values built and the memory they occupy. A budget
// is per top-level decode (one for the metadata, one per Lookup) and threaded through
// decodeMMDB explicitly — never package state, since lookups run concurrently.
//
// A unit buys at most about 1.3 bytes of heap (measured by TestMMDBBudgetBytesPerUnit over
// the worst shapes: 0.15 B/unit for pointers to empty maps up to 1.26 B/unit for empty
// arrays, 0.5–1.15 for pointers to small boxed scalars, up to 1.08 for 9–16-byte uint128
// values, which are charged bigIntCost for their *big.Int), so one decode allocates on the
// order of its budget in bytes: at most ~42 MB at the maxDecodeCost ceiling, ~4*sectionLen
// bytes below it. That is per Lookup: concurrent lookups multiply it by the number in flight.
const (
	valueCost     = 16               // fixed units charged per decoded value
	elemCost      = 16               // extra units per array slot (an interface: 16 B)
	mapEntryCost  = 48               // extra units per map entry (a string key and an interface, plus table overhead)
	mapBaseCost   = 8 * mapEntryCost // extra units per map: about Go's smallest map allocation
	bigIntCost    = 48               // extra units per uint128: a *big.Int and its word slice
	minDecodeCost = 1 << 20          // floor of a budget, so tiny sections still decode
	maxDecodeCost = 1 << 25          // ceiling of a budget: admits the largest single value the format allows
)

var errBudget = errors.New("cidr: mmdb: decode budget exceeded")

// budget is the remaining work/output allowance of one top-level decode.
type budget struct{ left int }

// newBudget sizes a budget from the section being decoded: 4*sectionLen, held between
// a floor (1<<20, so tiny sections with internal repetition still decode) and a ceiling
// (1<<25, so a huge hostile file cannot buy a proportionally huge decode per Lookup).
// The ceiling still admits the largest single value the format can express (a string
// of 65821+2^24-1 bytes), and leaves wide headroom: the costliest record in a real
// 1.4 GB DB-IP database used under 10,000 units.
func newBudget(sectionLen int) *budget {
	// 4*sectionLen is only formed below the ceiling's quarter: on a 32-bit int it would wrap.
	if sectionLen >= maxDecodeCost/4 {
		return &budget{left: maxDecodeCost}
	}
	return &budget{left: max(minDecodeCost, 4*sectionLen)}
}

// charge spends n units, failing once the allowance is exhausted. n may be any
// non-negative int: it is compared, not subtracted blindly, so it cannot wrap left.
func (b *budget) charge(n int) error {
	if n > b.left {
		b.left = -1
		return errBudget
	}
	b.left -= n
	return nil
}

// chargeEach spends count*unit units. count comes from the file (up to the bytes that
// remain, which on a 32-bit int times a cost can exceed MaxInt32), so the product is
// formed only once it is known to fit in the remaining allowance.
func (b *budget) chargeEach(count, unit int) error {
	if count > b.left/unit {
		b.left = -1
		return errBudget
	}
	return b.charge(count * unit)
}

// decodeMMDB decodes one value from buf at off. ptrBase is the offset pointers are
// relative to (the data-section start for tree data; 0 for the self-contained metadata
// section). depth guards against runaway pointer/container recursion on malformed input.
// Returns the value and the offset just past it. All lengths read from buf are treated as
// untrusted: bounds are compared as (len(buf)-off) so off+size cannot overflow, and a
// container's element count cannot exceed the bytes that remain. bud bounds the total work
// and output of the whole top-level decode (see budget); it is shared down the recursion.
func decodeMMDB(buf []byte, off, ptrBase, depth int, bud *budget) (any, int, error) {
	if depth > maxMMDBDepth {
		return nil, 0, errors.New("cidr: mmdb: max pointer/nesting depth exceeded")
	}
	if off < 0 || off >= len(buf) {
		return nil, 0, errors.New("cidr: mmdb: offset out of range")
	}
	if err := bud.charge(valueCost); err != nil {
		return nil, 0, err
	}
	ctrl := buf[off]
	off++
	typ := int(ctrl >> 5)
	if typ == 0 { // extended type: 7 + the next byte, which must land in 8..15
		if off >= len(buf) {
			return nil, 0, errors.New("cidr: mmdb: truncated extended type")
		}
		typ = int(buf[off]) + 7 // an int: a byte would wrap 0xFB to string and 0xFA to pointer
		if typ < 8 || typ > 15 {
			return nil, 0, fmt.Errorf("cidr: mmdb: invalid extended type %d", typ)
		}
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
		// The target must be inside buf, and must not itself be a pointer: the format
		// forbids a pointer to a pointer, and allowing it lets a chain of pointers
		// stand in for a loop.
		if ptr < 0 || ptr >= len(buf)-ptrBase {
			return nil, 0, errors.New("cidr: mmdb: offset out of range")
		}
		if buf[ptrBase+ptr]>>5 == 1 {
			return nil, 0, errors.New("cidr: mmdb: pointer to a pointer")
		}
		v, _, err := decodeMMDB(buf, ptrBase+ptr, ptrBase, depth+1, bud)
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
		if err := bud.charge(size); err != nil {
			return nil, 0, err
		}
		return string(buf[off : off+size]), off + size, nil
	case 3: // double (IEEE-754 64-bit): exactly 8 bytes
		if size != 8 {
			return nil, 0, errWidth
		}
		if avail < 8 {
			return nil, 0, errTrunc
		}
		return math.Float64frombits(binary.BigEndian.Uint64(buf[off : off+8])), off + 8, nil
	case 4: // bytes
		if size > avail {
			return nil, 0, errTrunc
		}
		if err := bud.charge(size); err != nil {
			return nil, 0, err
		}
		return append([]byte(nil), buf[off:off+size]...), off + size, nil
	case 5, 6, 9: // uint16 / uint32 / uint64: at most 2 / 4 / 8 bytes (fewer = leading zeros)
		if size > uintMaxWidth[typ] {
			return nil, 0, errWidth
		}
		if size > avail {
			return nil, 0, errTrunc
		}
		return beUint(buf[off : off+size]), off + size, nil
	case 7: // map
		if size > avail { // each entry needs >= 1 byte: reject an amplified count
			return nil, 0, errTrunc
		}
		// charge the full declared count before allocating (chargeEach is overflow-safe)
		if err := bud.charge(mapBaseCost); err != nil {
			return nil, 0, err
		}
		if err := bud.chargeEach(size, mapEntryCost); err != nil {
			return nil, 0, err
		}
		m := make(map[string]any, size)
		o := off
		for i := 0; i < size; i++ {
			k, no, err := decodeMMDB(buf, o, ptrBase, depth+1, bud)
			if err != nil {
				return nil, 0, err
			}
			ks, ok := k.(string)
			if !ok {
				return nil, 0, errors.New("cidr: mmdb: non-string map key")
			}
			v, no2, err := decodeMMDB(buf, no, ptrBase, depth+1, bud)
			if err != nil {
				return nil, 0, err
			}
			m[ks] = v
			o = no2
		}
		return m, o, nil
	case 8: // int32 (two's complement, up to 4 bytes)
		if size > 4 {
			return nil, 0, errWidth
		}
		if size > avail {
			return nil, 0, errTrunc
		}
		return int32(uint32(beUint(buf[off : off+size]))), off + size, nil
	case 10: // uint128
		if size > 16 {
			return nil, 0, errWidth
		}
		if size > avail {
			return nil, 0, errTrunc
		}
		if err := bud.charge(bigIntCost + size); err != nil {
			return nil, 0, err
		}
		return new(big.Int).SetBytes(buf[off : off+size]), off + size, nil
	case 11: // array
		if size > avail { // each element needs >= 1 byte: reject an amplified count
			return nil, 0, errTrunc
		}
		// charge the full declared count before allocating (chargeEach is overflow-safe)
		if err := bud.chargeEach(size, elemCost); err != nil {
			return nil, 0, err
		}
		arr := make([]any, 0, size)
		o := off
		for i := 0; i < size; i++ {
			v, no, err := decodeMMDB(buf, o, ptrBase, depth+1, bud)
			if err != nil {
				return nil, 0, err
			}
			arr = append(arr, v)
			o = no
		}
		return arr, o, nil
	case 14: // boolean: the value is the size, which is 0 or 1 (no payload)
		if size > 1 {
			return nil, 0, errWidth
		}
		return size == 1, off, nil
	case 15: // float (IEEE-754 32-bit): exactly 4 bytes
		if size != 4 {
			return nil, 0, errWidth
		}
		if avail < 4 {
			return nil, 0, errTrunc
		}
		return math.Float32frombits(binary.BigEndian.Uint32(buf[off : off+4])), off + 4, nil
	}
	return nil, 0, fmt.Errorf("cidr: mmdb: unknown data type %d", typ)
}

// uintMaxWidth is the widest payload of the unsigned integer types, indexed by type number.
var uintMaxWidth = [...]int{5: 2, 6: 4, 9: 8}

var (
	errTrunc = errors.New("cidr: mmdb: truncated data section")
	errWidth = errors.New("cidr: mmdb: invalid size for the value's type")
)

// beUint reads up to 8 big-endian bytes as a uint64.
func beUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// uintOf reads the metadata number mm[key] (always a uint64 from the decoder) as a uint.
// An absent or non-numeric value yields 0 (each caller validates the value it needs); a
// value above math.MaxInt is an error, not truncated (a uint is 32 bits on some platforms,
// and everything built from these numbers is converted to int).
func uintOf(mm map[string]any, key string) (uint, error) {
	u, ok := mm[key].(uint64)
	if !ok {
		return 0, nil
	}
	if u > math.MaxInt {
		return 0, fmt.Errorf("cidr: mmdb: metadata %s %d out of range", key, u)
	}
	return uint(u), nil
}

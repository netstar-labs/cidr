// Command ipfold reads an unorganized list of IP addresses (mixed IPv4/IPv6,
// one per line), sorts and de-duplicates them, and folds runs of consecutive
// addresses into the minimal set of CIDR prefixes — e.g. x.x.x.12, .13, .14, .15
// collapse to x.x.x.12/30. IPv4 and IPv6 are handled separately and emitted in
// order (v4 block, then v6).
//
//	ipfold < ips.txt                 # fold stdin -> stdout
//	ipfold -in ips.txt -o cidrs.txt
//	ipfold -4 < ips.txt              # only IPv4 output
//
// Scale: the IPv4 side is built for very large inputs (100M+ unique). Addresses
// accumulate in a slice until a threshold, then switch to a fixed 2^32-bit
// bitmap (512 MiB) that sorts, de-duplicates, and bounds memory regardless of
// how much the input repeats. Folding is then one linear scan. IPv6 sorts a
// netip.Addr slice (v6 address lists are small in practice).
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"

	"github.com/netstar-labs/cidr"
)

// v4SwitchAt is the number of accumulated IPv4 addresses past which the slice is
// abandoned for the bitmap. Below it, a sort is cheaper than a 512 MiB alloc;
// above it (or with heavily duplicated input) the bitmap bounds memory. Kept
// low so the pre-switch slice stays small and does not coexist with the bitmap
// as a large transient. It is a var so tests can force the bitmap path.
var v4SwitchAt = 1 << 21 // ~2M

// Version and Revision are stamped at build time via -ldflags -X (see build/ipfold).
var (
	Version  = "dev"
	Revision = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	in := flag.String("in", "", "input file (default stdin), one IP per line")
	out := flag.String("o", "", "output file (default stdout)")
	only4 := flag.Bool("4", false, "emit only IPv4 CIDRs")
	only6 := flag.Bool("6", false, "emit only IPv6 CIDRs")
	flag.Parse()

	if *version {
		fmt.Printf("ipfold %s (%s)\n", Version, Revision)
		return
	}

	r := io.Reader(os.Stdin)
	if *in != "" {
		f, err := os.Open(*in)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		r = f
	}
	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		w = f
	}

	st, err := run(r, w, *only4, *only6)
	if err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "ipfold: lines=%d v4=%d v6=%d malformed=%d -> v4cidrs=%d v6cidrs=%d\n",
		st.lines, st.v4in, st.v6in, st.malformed, st.v4cidrs, st.v6cidrs)
}

type stats struct {
	lines, v4in, v6in, malformed, v4cidrs, v6cidrs int
}

func run(r io.Reader, w io.Writer, only4, only6 bool) (stats, error) {
	var st stats
	a4 := &v4agg{}
	var a6 []netip.Addr

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 256<<10), 4<<20)
	for sc.Scan() {
		st.lines++
		// Parse from the scanner's []byte, not sc.Text(): at 100M+ lines a
		// string per line is 100M+ allocations of GC churn.
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		// tolerate trailing fields: take the first whitespace/comma token
		if i := bytes.IndexAny(line, " \t,"); i >= 0 {
			line = line[:i]
		}
		// fast path: a bare IPv4 dotted-quad parsed straight from bytes, no alloc
		if x, ok := parseV4(line); ok {
			a4.add(x)
			st.v4in++
			continue
		}
		// v6 or IPv4-in-IPv6: fall back to netip (allocates a string; rare at scale)
		a, err := netip.ParseAddr(string(line))
		if err != nil {
			st.malformed++
			continue
		}
		a = a.Unmap()
		if a.Is4() {
			a4.add(to32(a))
			st.v4in++
		} else {
			a6 = append(a6, a)
			st.v6in++
		}
	}
	if err := sc.Err(); err != nil {
		return st, err
	}

	cw := &cidrWriter{w: bufio.NewWriter(w)}
	if !only6 {
		a4.fold(cw)
		st.v4cidrs = cw.n
	}
	cw.n = 0
	if !only4 {
		foldV6(a6, cw)
		st.v6cidrs = cw.n
	}
	if cw.err != nil {
		return st, cw.err
	}
	return st, cw.w.Flush()
}

// cidrWriter emits prefixes without a per-line string allocation (AppendTo into
// a reused buffer) — the hot path when output runs to tens of millions of lines.
// pfx is a reused scratch slice for AppendRangePrefixes so multi-address runs
// fold without a per-run allocation.
type cidrWriter struct {
	w   *bufio.Writer
	buf []byte
	pfx []netip.Prefix
	n   int
	err error
}

func (cw *cidrWriter) emit(p netip.Prefix) {
	if cw.err != nil {
		return
	}
	cw.buf = p.AppendTo(cw.buf[:0])
	cw.buf = append(cw.buf, '\n')
	if _, err := cw.w.Write(cw.buf); err != nil {
		cw.err = err
		return
	}
	cw.n++
}

// emitRange folds [lo, hi] to CIDRs and writes them. A single-address run (the
// common case for scattered hosts) is emitted as a /32 or /128 directly, with
// no allocation; wider runs reuse the pfx scratch buffer.
func (cw *cidrWriter) emitRange(lo, hi netip.Addr) {
	if lo == hi {
		cw.emit(netip.PrefixFrom(lo, lo.BitLen()))
		return
	}
	cw.pfx = cidr.AppendRangePrefixes(cw.pfx[:0], lo, hi)
	for _, p := range cw.pfx {
		cw.emit(p)
	}
}

// ---- IPv4 aggregator ---------------------------------------------------------

type v4agg struct {
	slice  []uint32
	bitmap []uint64 // 1<<26 words = 2^32 bits = 512 MiB; nil until v4SwitchAt
}

func (a *v4agg) add(x uint32) {
	if a.bitmap != nil {
		a.bitmap[x>>6] |= 1 << (x & 63)
		return
	}
	a.slice = append(a.slice, x)
	if len(a.slice) >= v4SwitchAt {
		a.bitmap = make([]uint64, 1<<26)
		for _, y := range a.slice {
			a.bitmap[y>>6] |= 1 << (y & 63)
		}
		a.slice = nil
	}
}

// fold emits the sorted, de-duplicated, run-folded CIDRs.
func (a *v4agg) fold(cw *cidrWriter) {
	emit := func(lo, hi uint32) { cw.emitRange(from32(lo), from32(hi)) }
	if a.bitmap != nil {
		a.foldBitmap(emit)
	} else {
		a.foldSlice(emit)
	}
}

func (a *v4agg) foldSlice(emit func(lo, hi uint32)) {
	s := a.slice
	slices.Sort(s)
	for i := 0; i < len(s); {
		lo, hi := s[i], s[i]
		j := i + 1
		for j < len(s) {
			switch {
			case s[j] == hi: // duplicate
			case hi != ^uint32(0) && s[j] == hi+1: // consecutive
				hi = s[j]
			default:
				goto emit
			}
			j++
		}
	emit:
		emit(lo, hi)
		i = j
	}
}

// foldBitmap scans the 512 MiB bitmap word by word, coalescing maximal runs of
// set bits into ranges. Zero words are skipped and all-ones words extend the
// current run without per-bit work, so dense regions cost O(words), not O(bits).
func (a *v4agg) foldBitmap(emit func(lo, hi uint32)) {
	bm := a.bitmap
	inRun := false
	var runStart uint32
	for wi := 0; wi < len(bm); wi++ {
		w := bm[wi]
		base := uint32(wi) << 6
		switch {
		case w == 0:
			if inRun {
				emit(runStart, base-1)
				inRun = false
			}
		case w == ^uint64(0):
			if !inRun {
				inRun = true
				runStart = base
			}
		default:
			for j := 0; j < 64; j++ {
				i := base + uint32(j)
				set := (w>>uint(j))&1 == 1
				if set && !inRun {
					inRun = true
					runStart = i
				} else if !set && inRun {
					emit(runStart, i-1)
					inRun = false
				}
			}
		}
	}
	if inRun {
		emit(runStart, ^uint32(0)) // run reaches 255.255.255.255
	}
}

// ---- IPv6 aggregator ---------------------------------------------------------

// foldV6 sorts, de-duplicates, and folds a slice of IPv6 addresses.
func foldV6(a []netip.Addr, cw *cidrWriter) {
	if len(a) == 0 {
		return
	}
	slices.SortFunc(a, func(x, y netip.Addr) int { return x.Compare(y) })
	for i := 0; i < len(a); {
		lo, hi := a[i], a[i]
		j := i + 1
		for j < len(a) {
			if a[j] == hi { // duplicate
				j++
				continue
			}
			if nx := hi.Next(); nx.IsValid() && a[j] == nx { // consecutive
				hi = a[j]
				j++
				continue
			}
			break
		}
		cw.emitRange(lo, hi)
		i = j
	}
}

// parseV4 parses a bare dotted-quad from bytes into a big-endian uint32 without
// allocating. It returns false for anything that is not exactly four decimal
// octets (v6, IPv4-in-IPv6, or junk), which the caller then routes to netip.
func parseV4(b []byte) (uint32, bool) {
	var ip, octet uint32
	parts, digits := 0, 0
	for _, c := range b {
		switch {
		case c == '.':
			if digits == 0 || parts == 3 {
				return 0, false
			}
			ip = ip<<8 | octet
			octet, digits, parts = 0, 0, parts+1
		case c >= '0' && c <= '9':
			octet = octet*10 + uint32(c-'0')
			if digits++; digits > 3 || octet > 255 {
				return 0, false
			}
		default:
			return 0, false
		}
	}
	if parts != 3 || digits == 0 {
		return 0, false
	}
	return ip<<8 | octet, true
}

func to32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func from32(x uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ipfold:", err)
	os.Exit(1)
}

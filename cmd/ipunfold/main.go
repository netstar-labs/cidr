// Command ipunfold is the inverse of ipfold: it reads CIDR prefixes (one per
// line) and expands each into the individual addresses it covers, one per line
// — e.g. x.x.x.12/30 unfolds to x.x.x.12, .13, .14, .15. A bare address is
// accepted as its own /32 or /128, so an ipfold output round-trips, and only
// the first whitespace/comma-separated field of a line is read, so a full
// `<cidr> <ASN> <org>` spec expands too.
//
//	ipunfold < cidrs.txt              # expand stdin -> stdout
//	ipunfold -in cidrs.txt -o ips.txt
//	ipunfold -4 < cidrs.txt           # only IPv4 prefixes
//	ipunfold -count < cidrs.txt       # how many addresses would this be?
//
// Expansion streams in input order — nothing is buffered, sorted, or
// de-duplicated, so overlapping input prefixes emit overlapping addresses (pipe
// through ipfold to normalize). Output is unbounded by nature: a single /8 is
// 16.7M addresses and a v6 /64 is 1.8e19. Check first with -count, and use
// -max in scripts to abort rather than run away.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/netip"
	"os"
	"strings"

	"github.com/netstar-labs/cidr"
)

// Version and Revision are stamped at build time via -ldflags -X (see build/ipunfold).
var (
	Version  = "dev"
	Revision = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print version and exit")
	in := flag.String("in", "", "input file (default stdin), one CIDR or IP per line")
	out := flag.String("o", "", "output file (default stdout)")
	only4 := flag.Bool("4", false, "expand only IPv4 prefixes")
	only6 := flag.Bool("6", false, "expand only IPv6 prefixes")
	count := flag.Bool("count", false, "print the address count the input would expand to, and exit")
	max := flag.Uint64("max", 0, "abort before any prefix that would push output past this many addresses (0: no limit)")
	flag.Parse()

	if *version {
		fmt.Printf("ipunfold %s (%s)\n", Version, Revision)
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

	st, err := run(r, w, opts{only4: *only4, only6: *only6, count: *count, max: *max})
	// The tally is printed either way: on a -max abort it reports how far the
	// run got before stopping.
	fmt.Fprintf(os.Stderr, "ipunfold: lines=%d prefixes=%d malformed=%d v4=%d v6=%d -> addrs=%s\n",
		st.lines, st.prefixes, st.malformed, st.v4pfx, st.v6pfx, st.total)
	if err != nil {
		fatal(err)
	}
}

type opts struct {
	only4, only6 bool
	count        bool
	max          uint64
}

type stats struct {
	lines, prefixes, malformed, v4pfx, v6pfx int
	// total is the address count written (or, under -count, the count the
	// input would expand to). It is a big.Int because a single IPv6 /0 is
	// 2^128 — no fixed-width integer covers the counting case.
	total *big.Int
}

func run(r io.Reader, w io.Writer, o opts) (stats, error) {
	st := stats{total: new(big.Int)}
	var maxN *big.Int
	if o.max > 0 {
		maxN = new(big.Int).SetUint64(o.max)
	}

	bw := bufio.NewWriterSize(w, 256<<10)
	aw := &addrWriter{w: bw}
	// Every abort flushes first: an aborted run still hands back the addresses
	// it had already written, up to the prefix it stopped on.
	fail := func(err error) (stats, error) {
		bw.Flush()
		return st, err
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		st.lines++
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		// tolerate trailing fields: take the first whitespace/comma token, so a
		// `<cidr> <ASN> <org>` spec feeds straight in
		if i := strings.IndexAny(line, " \t,"); i >= 0 {
			line = line[:i]
		}
		// ParsePrefix accepts a CIDR or a bare address (promoted to /32 or
		// /128) and returns it masked, so host bits in the input are harmless.
		p, err := cidr.ParsePrefix(line)
		if err != nil {
			st.malformed++
			continue
		}
		st.prefixes++
		is4 := p.Addr().Is4()
		if is4 {
			st.v4pfx++
		} else {
			st.v6pfx++
		}
		if (o.only4 && !is4) || (o.only6 && is4) {
			continue
		}

		sz := prefixSize(p)
		if maxN != nil && !o.count {
			if new(big.Int).Add(st.total, sz).Cmp(maxN) > 0 {
				return fail(fmt.Errorf("-max %d exceeded: %s holds %s addresses, %s already written",
					o.max, p, sz, st.total))
			}
		}
		st.total.Add(st.total, sz)
		if o.count {
			continue
		}

		if is4 {
			lo := to32(p.Addr())
			aw.expandV4(lo, lo|hostMask4(p.Bits()))
		} else {
			aw.expandV6(p.Addr(), lastV6(p))
		}
		if aw.err != nil {
			return fail(aw.err)
		}
	}
	if err := sc.Err(); err != nil {
		return fail(err)
	}
	if o.count {
		fmt.Fprintln(bw, st.total)
	}
	return st, bw.Flush()
}

// addrWriter formats addresses into a reused buffer rather than through
// Addr.String — at tens of millions of output lines a string per address is
// pure GC churn.
type addrWriter struct {
	w   *bufio.Writer
	buf []byte
	err error
}

func (aw *addrWriter) line() {
	aw.buf = append(aw.buf, '\n')
	if _, err := aw.w.Write(aw.buf); err != nil {
		aw.err = err
	}
}

// expandV4 writes every address in the inclusive range [lo, hi]. The hi test
// sits at the bottom of the loop so a range ending at 255.255.255.255
// terminates instead of wrapping to 0.
func (aw *addrWriter) expandV4(lo, hi uint32) {
	for x := lo; aw.err == nil; x++ {
		aw.buf = appendV4(aw.buf[:0], x)
		aw.line()
		if x == hi {
			return
		}
	}
}

// expandV6 is the same walk over IPv6. Next() on the last address returns the
// invalid zero Addr, which the guard catches; in practice the hi test fires
// first.
func (aw *addrWriter) expandV6(lo, hi netip.Addr) {
	for a := lo; aw.err == nil && a.IsValid(); a = a.Next() {
		aw.buf = a.AppendTo(aw.buf[:0])
		aw.line()
		if a == hi {
			return
		}
	}
}

func appendV4(dst []byte, x uint32) []byte {
	dst = appendOctet(dst, byte(x>>24))
	dst = append(dst, '.')
	dst = appendOctet(dst, byte(x>>16))
	dst = append(dst, '.')
	dst = appendOctet(dst, byte(x>>8))
	dst = append(dst, '.')
	return appendOctet(dst, byte(x))
}

func appendOctet(dst []byte, v byte) []byte {
	if v >= 100 {
		dst = append(dst, '0'+v/100)
	}
	if v >= 10 {
		dst = append(dst, '0'+(v/10)%10)
	}
	return append(dst, '0'+v%10)
}

// prefixSize is the number of addresses p covers: 2^(host bits).
func prefixSize(p netip.Prefix) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
}

// hostMask4 has the low 32-bits host bits set. Go defines a shift at or past
// the operand width as zero, so /32 yields the empty mask without a special case.
func hostMask4(bits int) uint32 { return ^uint32(0) >> uint(bits) }

// lastV6 returns the all-host-bits-set address of an IPv6 prefix, filling in
// whole bytes from the right and a partial byte at the mask boundary.
func lastV6(p netip.Prefix) netip.Addr {
	b := p.Addr().As16()
	for i, h := 15, 128-p.Bits(); h > 0; i-- {
		n := min(h, 8)
		b[i] |= byte(0xff) >> (8 - n)
		h -= n
	}
	return netip.AddrFrom16(b)
}

func to32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ipunfold:", err)
	os.Exit(1)
}

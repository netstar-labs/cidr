// Command unix serves a cidr set over a Unix domain socket as a line protocol:
// send one address per line, read back one NDJSON result per line (membership
// plus the owning AS/org when present). The connection stays open, so it
// doubles as an interactive probe.
//
//	go run ./example/unix -socket /tmp/cidr.sock                # built-in demo spec
//	go run ./example/unix -socket /tmp/cidr.sock -spec asn.txt  # your own spec
//
// Then, from another shell:
//
//	printf '1.1.1.200\n8.8.8.8\n9.9.9.9\n' | nc -U /tmp/cidr.sock
//	# or interactively:
//	nc -U /tmp/cidr.sock
//	> 1.1.1.1            (type an address, press enter, read the JSON line back)
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/netstar-labs/cidr"
)

const demoSpec = `
1.1.1.0/24     13335 Cloudflare, Inc.
1.1.1.128/25   99999 Cloudflare Customer Sub-block
8.8.8.0/24     15169 Google LLC
10.0.0.0/8     64496 Demo Private-ish Net
203.0.113.0/24 64501 TEST-NET-3 Demo
2001:db8::/32  64502 Documentation v6
`

type result struct {
	IP     string     `json:"ip"`
	Member bool       `json:"member"`
	Info   *cidr.Info `json:"info,omitempty"`
}

func main() {
	socket := flag.String("socket", "/tmp/cidr.sock", "unix socket path")
	spec := flag.String("spec", "", "path to a <cidr> <ASN> <org> spec file (default: built-in demo)")
	flag.Parse()

	set, table, count, err := load(*spec)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	// A stale socket file from a previous run would block the bind.
	if err := os.Remove(*socket); err != nil && !os.IsNotExist(err) {
		log.Fatalf("removing stale socket: %v", err)
	}
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer func() { ln.Close(); os.Remove(*socket) }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; ln.Close(); os.Remove(*socket); os.Exit(0) }()

	log.Printf("cidr on unix://%s (%d prefixes, %d intervals)", *socket, count, set.Len())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err) // listener closed on shutdown
			return
		}
		go serve(conn, set, table)
	}
}

// serve handles one connection: each inbound line is an address, each outbound
// line is its result.
func serve(conn net.Conn, set *cidr.Set, table *cidr.Table[cidr.Info]) {
	defer conn.Close()
	enc := json.NewEncoder(conn) // writes a newline after each value
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		ip, err := netip.ParseAddr(line)
		if err != nil {
			_ = enc.Encode(map[string]string{"ip": line, "error": "invalid address"})
			continue
		}
		res := result{IP: ip.String(), Member: set.Contains(ip)}
		if info, ok := table.Lookup(ip); ok {
			res.Info = &info
		}
		if err := enc.Encode(res); err != nil {
			return // peer gone
		}
	}
}

func load(path string) (*cidr.Set, *cidr.Table[cidr.Info], int, error) {
	src := strings.NewReader(demoSpec)
	var entries []cidr.SpecEntry
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, 0, err
		}
		defer f.Close()
		if entries, err = cidr.ParseSpec(f); err != nil {
			return nil, nil, 0, err
		}
	} else {
		entries, _ = cidr.ParseSpec(src)
	}
	set, table := cidr.BuildASN(entries)
	return set, table, len(entries), nil
}

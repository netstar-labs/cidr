// Command http exposes a cidr set over a small HTTP REST API: membership
// (yes/no) and value lookup (yes+data, the owning AS/org), for single
// addresses and newline-batched streams.
//
//	go run ./example/http -addr :8080                 # built-in demo spec
//	go run ./example/http -addr :8080 -spec asn.txt   # your own <cidr> <ASN> <org> file
//
// Endpoints:
//
//	GET  /healthz                 -> "ok"
//	GET  /stats                   -> {prefixes, intervals}
//	GET  /contains?ip=1.1.1.1     -> {"ip":"1.1.1.1","member":true}
//	GET  /lookup?ip=1.1.1.1       -> {"ip":...,"member":true,"info":{"prefix":...,"asn":...,"org":...}}
//	POST /lookup                  -> NDJSON, one result per input line
//	         body: newline-delimited addresses
//
// Examples:
//
//	curl -s 'localhost:8080/lookup?ip=1.1.1.200' | jq .
//	printf '8.8.8.8\n1.1.1.1\n9.9.9.9\n' | curl -s --data-binary @- localhost:8080/lookup
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"

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

// result is the unified answer: membership plus the owning info when present.
type result struct {
	IP     string     `json:"ip"`
	Member bool       `json:"member"`
	Info   *cidr.Info `json:"info,omitempty"`
}

type api struct {
	set   *cidr.Set
	table *cidr.Table[cidr.Info]
	count int // number of prefixes loaded
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	spec := flag.String("spec", "", "path to a <cidr> <ASN> <org> spec file (default: built-in demo)")
	flag.Parse()

	a, err := load(*spec)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /stats", a.handleStats)
	mux.HandleFunc("GET /contains", a.handleContains)
	mux.HandleFunc("GET /lookup", a.handleLookup)
	mux.HandleFunc("POST /lookup", a.handleBatch)

	log.Printf("cidr API on %s (%d prefixes, %d intervals)", *addr, a.count, a.set.Len())
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func load(path string) (*api, error) {
	r := strings.NewReader(demoSpec)
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		entries, err := cidr.ParseSpec(f)
		if err != nil {
			return nil, err
		}
		set, table, _ := buildFrom(entries)
		return &api{set: set, table: table, count: len(entries)}, nil
	}
	entries, _ := cidr.ParseSpec(r)
	set, table, _ := buildFrom(entries)
	return &api{set: set, table: table, count: len(entries)}, nil
}

// buildFrom compiles parsed entries into a Set + Table[Info].
func buildFrom(entries []cidr.SpecEntry) (*cidr.Set, *cidr.Table[cidr.Info], error) {
	sb := cidr.NewBuilder()
	tb := cidr.NewTableBuilder[cidr.Info]()
	for _, e := range entries {
		sb.Add(e.Prefix)
		tb.Add(e.Prefix, cidr.Info{Prefix: e.Prefix.String(), ASN: e.ASN, Org: e.Org})
	}
	return sb.Freeze(), tb.Freeze(), nil
}

// lookup resolves one address into a result.
func (a *api) resolve(ip netip.Addr) result {
	res := result{IP: ip.String(), Member: a.set.Contains(ip)}
	if info, ok := a.table.Lookup(ip); ok {
		res.Info = &info
	}
	return res
}

func (a *api) handleStats(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]int{"prefixes": a.count, "intervals": a.set.Len()})
}

func (a *api) handleContains(w http.ResponseWriter, r *http.Request) {
	ip, err := parseIP(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip.String(), "member": a.set.Contains(ip)})
}

func (a *api) handleLookup(w http.ResponseWriter, r *http.Request) {
	ip, err := parseIP(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, a.resolve(ip))
}

// handleBatch reads newline-delimited addresses from the body and streams one
// NDJSON result per line, flushing as it goes.
func (a *api) handleBatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	sc := bufio.NewScanner(r.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		ip, err := netip.ParseAddr(line)
		if err != nil {
			_ = enc.Encode(map[string]string{"ip": line, "error": "invalid address"})
		} else {
			_ = enc.Encode(a.resolve(ip))
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func parseIP(r *http.Request) (netip.Addr, error) {
	s := strings.TrimSpace(r.URL.Query().Get("ip"))
	if s == "" {
		return netip.Addr{}, errMsg(`missing "ip" query parameter`)
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, errMsg("invalid address: " + s)
	}
	return ip, nil
}

type errMsg string

func (e errMsg) Error() string { return string(e) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

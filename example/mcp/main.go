// Command mcp is a Model Context Protocol server that exposes a cidr set as
// tools an LLM agent can call. It speaks MCP over stdio — newline-delimited
// JSON-RPC 2.0 on stdin/stdout, diagnostics on stderr — implemented directly
// on encoding/json, so like the rest of the examples it needs nothing beyond
// the standard library and this package.
//
// Tools:
//
//	cidr_stats         — set size (no arguments)
//	cidr_contains      — membership test; args {ip}
//	cidr_lookup        — owning AS/org for an address; args {ip}
//	cidr_lookup_batch  — lookup several; args {ips[]}
//
// Register it with an MCP client (e.g. Claude Code):
//
//	claude mcp add cidr -- go run ./example/mcp -spec asn.txt
//
// Or drive it by hand:
//
//	printf '%s\n%s\n' \
//	  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
//	  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cidr_lookup","arguments":{"ip":"1.1.1.200"}}}' \
//	  | go run ./example/mcp
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/netstar-labs/cidr"
)

const protocolVersion = "2024-11-05"

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
	spec := flag.String("spec", "", "path to a <cidr> <ASN> <org> spec file (default: built-in demo)")
	flag.Parse()
	log.SetOutput(os.Stderr) // stdout is the JSON-RPC channel; keep it clean

	set, table, count, err := load(*spec)
	if err != nil {
		log.Fatalf("load spec: %v", err)
	}
	s := &server{set: set, table: table, count: count, out: bufio.NewWriter(os.Stdout)}
	if err := s.serve(os.Stdin); err != nil {
		log.Fatalf("mcp: %v", err)
	}
}

type server struct {
	set   *cidr.Set
	table *cidr.Table[cidr.Info]
	count int
	out   *bufio.Writer
}

// JSON-RPC 2.0 envelopes. A request with no id is a notification (no reply).
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *server) serve(r *os.File) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			s.reply(response{ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		s.dispatch(req)
	}
	return sc.Err()
}

func (s *server) dispatch(req request) {
	notification := len(req.ID) == 0
	switch req.Method {
	case "initialize":
		s.reply(s.ok(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "cidr", "version": "1.0.0"},
		}))
	case "notifications/initialized", "notifications/cancelled":
		// acknowledged; notifications get no response
	case "ping":
		s.reply(s.ok(req.ID, map[string]any{}))
	case "tools/list":
		s.reply(s.ok(req.ID, map[string]any{"tools": toolList()}))
	case "tools/call":
		s.reply(s.callTool(req.ID, req.Params))
	default:
		if !notification {
			s.reply(response{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{-32601, "method not found: " + req.Method}})
		}
	}
}

func (s *server) ok(id json.RawMessage, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *server) reply(resp response) {
	if len(resp.ID) == 0 {
		return // nothing to send for a notification
	}
	resp.JSONRPC = "2.0"
	b, err := json.Marshal(resp)
	if err != nil {
		log.Printf("marshal response: %v", err)
		return
	}
	s.out.Write(b)
	s.out.WriteByte('\n')
	s.out.Flush()
}

func (s *server) callTool(id, params json.RawMessage) response {
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			IP  string   `json:"ip"`
			IPs []string `json:"ips"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return response{ID: id, Error: &rpcError{-32602, "invalid params: " + err.Error()}}
	}

	switch p.Name {
	case "cidr_stats":
		return s.ok(id, toolText(map[string]int{"prefixes": s.count, "intervals": s.set.Len()}))
	case "cidr_contains":
		ip, err := netip.ParseAddr(strings.TrimSpace(p.Arguments.IP))
		if err != nil {
			return s.ok(id, toolError("invalid address"))
		}
		return s.ok(id, toolText(map[string]any{"ip": ip.String(), "member": s.set.Contains(ip)}))
	case "cidr_lookup":
		ip, err := netip.ParseAddr(strings.TrimSpace(p.Arguments.IP))
		if err != nil {
			return s.ok(id, toolError("invalid address"))
		}
		return s.ok(id, toolText(s.resolve(ip)))
	case "cidr_lookup_batch":
		if len(p.Arguments.IPs) == 0 {
			return s.ok(id, toolError(`"ips" must be a non-empty array`))
		}
		out := make([]result, 0, len(p.Arguments.IPs))
		for _, raw := range p.Arguments.IPs {
			if ip, err := netip.ParseAddr(strings.TrimSpace(raw)); err == nil {
				out = append(out, s.resolve(ip))
			}
		}
		return s.ok(id, toolText(out))
	default:
		return response{ID: id, Error: &rpcError{-32602, "unknown tool: " + p.Name}}
	}
}

func (s *server) resolve(ip netip.Addr) result {
	res := result{IP: ip.String(), Member: s.set.Contains(ip)}
	if info, ok := s.table.Lookup(ip); ok {
		res.Info = &info
	}
	return res
}

func toolText(v any) map[string]any {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return toolError("encoding result: " + err.Error())
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}
}

func toolError(msg string) map[string]any {
	return map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": msg}}}
}

func toolList() []map[string]any {
	ipProp := map[string]any{"type": "string", "description": "an IPv4 or IPv6 address, e.g. 1.1.1.1"}
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	return []map[string]any{
		{
			"name":        "cidr_stats",
			"description": "Return the size of the loaded set: number of prefixes and merged intervals.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "cidr_contains",
			"description": "Membership test: is the address covered by any prefix in the set? Returns yes/no.",
			"inputSchema": obj(map[string]any{"ip": ipProp}, "ip"),
		},
		{
			"name":        "cidr_lookup",
			"description": "Longest-prefix lookup: the AS number and organisation owning the most-specific prefix that covers the address.",
			"inputSchema": obj(map[string]any{"ip": ipProp}, "ip"),
		},
		{
			"name":        "cidr_lookup_batch",
			"description": "Look up several addresses at once; returns an array of results.",
			"inputSchema": obj(map[string]any{
				"ips": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "addresses to look up"},
			}, "ips"),
		},
	}
}

func load(path string) (*cidr.Set, *cidr.Table[cidr.Info], int, error) {
	var entries []cidr.SpecEntry
	var err error
	if path != "" {
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil, nil, 0, ferr
		}
		defer f.Close()
		entries, err = cidr.ParseSpec(f)
	} else {
		entries, err = cidr.ParseSpec(strings.NewReader(demoSpec))
	}
	if err != nil {
		return nil, nil, 0, err
	}
	sb := cidr.NewBuilder()
	tb := cidr.NewTableBuilder[cidr.Info]()
	for _, e := range entries {
		sb.Add(e.Prefix)
		tb.Add(e.Prefix, cidr.Info{Prefix: e.Prefix.String(), ASN: e.ASN, Org: e.Org})
	}
	return sb.Freeze(), tb.Freeze(), len(entries), nil
}

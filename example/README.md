# Examples

Four ways to drive the [`cidr`](..) package — membership (yes/no) and value
lookup (yes+data, the owning AS/org) — each a self-contained `main.go` with no
dependency beyond the standard library and this package.

| Example | What it shows | Run |
|---|---|---|
| [`library/`](library) | the package used directly: a `Set`, a `Table[Info]`, the compact encoded-`uint64` path, longest-prefix match over a nested block, and IPv6 | `go run ./example/library` |
| [`http/`](http) | an HTTP REST API — single membership/value lookups and an NDJSON batch stream | `go run ./example/http -addr :8080` |
| [`unix/`](unix) | a Unix-domain-socket line service: an address per line in, one JSON line out | `go run ./example/unix -socket /tmp/cidr.sock` |
| [`mcp/`](mcp) | an MCP (Model Context Protocol) stdio server exposing the set as agent tools | `go run ./example/mcp` |

Each service example loads a small **built-in demo spec** so it runs with no
setup, or reads your own `<cidr> <ASN> <org>` file with `-spec`:

```sh
go run ./example/http -addr :8080 -spec my-asn-table.txt
```

The demo spec includes a nested block — `1.1.1.128/25` sits inside
`1.1.1.0/24` with a different ASN — so every example demonstrates that the
**most-specific prefix wins**.

## The two questions

Every example answers the same pair, and returns the same shape:

```json
{
  "ip": "1.1.1.200",
  "member": true,
  "info": { "prefix": "1.1.1.128/25", "asn": 99999, "org": "Cloudflare Customer Sub-block" }
}
```

- `member` — `Set.Contains`: is the address in the set at all? (yes/no)
- `info` — `Table[Info].Lookup`: the most-specific prefix's AS/org, omitted on a
  miss. (yes+data)

## library

A guided tour printed to stdout — membership, value lookup, the same answer as a
compact `uint64` (via `EncodeASN`/`DecodeASN`), the nested-match case, and IPv6.

```sh
go run ./example/library                        # a set of demo addresses
go run ./example/library 1.1.1.200 8.8.8.8 2001:db8::1
```

## http

```sh
go run ./example/http -addr :8080 &

curl -s 'localhost:8080/contains?ip=8.8.8.8' | jq .
curl -s 'localhost:8080/lookup?ip=1.1.1.200' | jq .          # the nested /25 wins
printf '8.8.8.8\n1.1.1.10\n9.9.9.9\n' | \
  curl -s --data-binary @- localhost:8080/lookup             # NDJSON stream
curl -s localhost:8080/stats | jq .
```

Endpoints: `GET /healthz`, `GET /stats`, `GET /contains?ip=`, `GET /lookup?ip=`,
`POST /lookup` (newline-delimited body → NDJSON).

## unix

```sh
go run ./example/unix -socket /tmp/cidr.sock &
printf '1.1.1.200\n8.8.8.8\n9.9.9.9\n' | nc -U /tmp/cidr.sock
# or interactively:
nc -U /tmp/cidr.sock
> 1.1.1.1        (type an address, press enter, read the JSON line back)
```

## mcp

```sh
# register with an MCP client
claude mcp add cidr -- go run ./example/mcp -spec my-asn-table.txt

# or exercise it by hand
printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cidr_lookup","arguments":{"ip":"1.1.1.200"}}}' \
  | go run ./example/mcp
```

Tools: `cidr_stats`, `cidr_contains {ip}`, `cidr_lookup {ip}`,
`cidr_lookup_batch {ips[]}`.

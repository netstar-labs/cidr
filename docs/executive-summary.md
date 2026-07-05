# cidr — Executive Summary

## What it is

`cidr` is a small Go library for **IP address lookups against a set of CIDR
prefixes**, with **zero external dependencies** (standard library only). It is an
embeddable library — not a server — that you build once from a list of prefixes
and then query many times.

It answers the two questions such lookups actually take:

- **Membership** — is an address inside any prefix in the set? A yes/no test.
- **Value lookup** — which value is attached to the most-specific prefix covering
  an address? The yes-plus-data case: the owning AS number and organisation for
  an IP-to-ASN table, a country for a geo table, a category for a policy feed.

## What it does

- **`Set`** — a membership set. Overlapping and adjacent prefixes are merged, so
  it is the smallest, fastest representation of "these ranges."
- **`Table[V]`** — a value table generic over the payload `V`. Nested prefixes
  are resolved into **longest-prefix match** (the most-specific wins) at build
  time, so a lookup returns the right value in a single step.
- **Both IPv4 and IPv6**, through one `net/netip` code path.
- **A spec loader** — `LoadASN` / `LoadSet` turn a `<cidr> <ASN> <org>` text
  stream (the shape of a public IP-to-ASN feed) directly into a queryable
  structure.
- **Compact value encoding** — `EncodeASN`/`DecodeASN` pack an AS number, an
  organisation id, and flags into a single `uint64` for a `Table[uint64]` when a
  small, copyable value is wanted instead of a struct.

## Why it matters

The obvious data structure for prefix lookups is a trie, and a general-purpose
routing library will give you one. But a trie is engineered for a *routing
table*: millions of prefixes that change continuously while being queried, where
you need cheap single-prefix insert and delete. A blocklist, an IP-to-ASN table,
or a firewall feed is the opposite: **static, rebuilt wholesale on a schedule,
and queried far more than it is changed.**

For that workload a sorted array of address ranges wins on every axis that
matters:

| Concern | this library's answer |
|---|---|
| Query speed | a binary search over contiguous memory — ~2× a trie on IPv4, and it stays cache-resident |
| Allocation | **zero** per query; the trie allocates on each lookup |
| Memory | a flat array is ~8–60× smaller than the equivalent trie node graph |
| Values | `Table[V]` returns any payload; longest-prefix match is baked in at build time |
| Concurrency | immutable after `Freeze`, so many goroutines query without a lock |
| Dependencies | standard library only |

The trade-off it accepts — no cheap incremental mutation under live queries — is
exactly the capability a static, wholesale-rebuilt set does not use.

## Status

Implemented and tested: `Set`, `Table[V]`, the spec loader, and the ASN
encoding, with randomized parity tests against a linear-scan oracle over both
IPv4 and IPv6, and benchmarks. Four integration examples — a library tour, an
HTTP API, a Unix-socket service, and an MCP server — build and run against a
built-in demo set. See [architecture.md](architecture.md) for the design and
[userguide.md](userguide.md) to use it.

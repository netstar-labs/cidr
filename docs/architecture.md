# cidr — Architecture

This document describes how the package works, the algorithms behind the two
structures, their cost, and the design trade-off against a prefix trie.

## The core idea

An IP address is an unsigned integer (32-bit for IPv4, 128-bit for IPv6), and a
CIDR prefix is a contiguous **range** of those integers — `1.1.1.0/24` is exactly
`[1.1.1.0, 1.1.1.255]`. So a set of prefixes is a set of integer intervals, and
"is this address covered?" is interval membership.

The whole library rests on one representation: **sorted arrays of address
ranges, searched with binary search.** Addresses are `net/netip.Addr` values —
comparable, fixed-size, and heap-free — so a range array is one contiguous block
of memory with no pointers to chase and no per-query allocation.

IPv4 and IPv6 are kept in separate arrays within each structure; a query is
routed to one by address family, then binary-searched.

## Set — membership

`Set` answers yes/no, so overlap is irrelevant: `1.1.1.0/24` and a nested
`1.1.1.128/25` both just mean "covered." `Builder.Freeze` therefore **merges**
the input:

1. Convert each prefix to a `[lo, hi]` range.
2. Sort by `lo`.
3. Coalesce overlapping or adjacent ranges into maximal disjoint intervals.

The result is the smallest possible array of intervals. `Contains` binary-
searches for the last interval whose `lo ≤ addr` and checks `addr ≤ hi`:

```
i := first interval with lo > addr      // sort.Search
covered := i > 0 && addr <= ranges[i-1].hi
```

## Table[V] — value lookup (longest-prefix match)

`Table[V]` answers "what value belongs to the address?" and here nesting is the
whole point: an IP can be covered by several prefixes, and the answer is the
value of the **most specific** (longest) one — longest-prefix match (LPM), the
same rule a router uses.

Rather than search a nested structure at query time, the table resolves all
nesting **at build time** into disjoint segments, each labelled with the value
that wins there. A lookup is then the same single binary search as membership,
returning the value directly.

### The build-time sweep

`Freeze` runs a line sweep over the prefix boundaries:

1. For each prefix emit two events: **open** at `lo`, **close** just past `hi`.
2. Sort events by address.
3. Sweep left to right. A small counter array tracks, per mask length, how many
   prefixes of that length are currently active. At each boundary the **winner**
   is the active prefix of greatest mask length (the most specific). Emit a
   segment starting at that boundary carrying the winner's value — or a gap
   marker if nothing is active.
4. Collapse consecutive segments that carry the same value.

Because two distinct prefixes of the *same* length can never overlap, at most
one prefix is active per length at any point, so "greatest active length" is an
unambiguous scan of ≤129 counters. The output is a sorted array of `(start,
value-index)` segments; `Lookup` binary-searches it and returns the value (or
"not found" for a gap).

### Duplicate prefixes

If the same prefix is added more than once with different values, the winner
must be deterministic. The build **deduplicates identical prefixes, keeping the
last-added value** (documented on `Add`). Distinct prefixes are untouched.

### Values

`V` is whatever the caller needs. `Table[Info]` returns the prefix, ASN, and org
as a struct; `Table[string]` returns a label; `Table[uint64]` returns a compact
code built with `EncodeASN` (ASN in the low 32 bits, a 24-bit org id, 8 flag
bits) and recovered with `DecodeASN`. The value lives in a side table indexed by
a 32-bit segment field, so segments stay small regardless of `V`'s size.

## Complexity

Let `P` be the number of prefixes and `S ≤ 2P+1` the number of segments.

| | build | query |
|---|---|---|
| `Set` | `O(P log P)` sort + merge | `O(log P)` binary search |
| `Table[V]` | `O((P+S) log P)` sweep | `O(log S)` binary search |

Queries allocate nothing. Build allocates the arrays once.

## Memory

A `Set` interval is two `netip.Addr` values; a `Table` segment is one `Addr`
plus a 32-bit index. Both are flat, contiguous arrays — no per-node object, no
child pointers, no interface headers. In practice this is **roughly 8–60× less
memory than the equivalent path-compressed trie**, whose every node carries
parent and child pointers, a mask, and an entry interface. The exact ratio grows
with set size and with how much the input merges.

Because the arrays are flat and pointer-free, they also serialise trivially
(e.g. to a memory-mappable blob) — though for the sizes these sets typically
reach, an in-memory rebuild from the source text is fast enough that persistence
is rarely worth the complexity.

## Benchmarks

On an Apple M2 Pro (Go 1.25), both queries are a single binary search with no
allocation:

```
BenchmarkSetContains-10    ~88 ns/op    0 B/op    0 allocs/op
BenchmarkTableLookup-10    ~88 ns/op    0 B/op    0 allocs/op
```

Against a path-compressed trie on the same data, the IPv4 range array is about
**2× faster** and allocation-free where the trie allocates once per query, and
the gap widens as the set grows: the trie pointer-chases a node graph that falls
out of cache, while the array stays contiguous and its cost grows only as
`log N`. A specialised IPv4-only `uint32` range array (not shipped here, to keep
one clean dual-family path) is faster still — roughly 3–4× the trie — and is the
option to reach for only if the lookup itself ever becomes a measured hot spot.

## The trie trade-off — when a trie wins

A prefix trie is the right structure when the workload is different from the one
this library targets:

- **Incremental mutation under live queries.** A sorted array costs `O(P)` to
  insert or delete one prefix (or a full rebuild); a trie is `O(address-width)`
  per change with no rebuild. If the set changes continuously *while being
  queried* — a live router FIB, a firewall taking rule edits per second — the
  trie wins. A set that is rebuilt wholesale on a schedule never pays this cost.
- **Enumerating every covering prefix.** If a query must return *all* prefixes
  containing an address (a `/8`, a `/16`, and a `/24` each with distinct
  metadata), the merged/segmented array has discarded that structure; a trie
  walks the ancestor chain. This library answers membership and single
  most-specific value, which is what blocklists and IP-to-ASN lookups need.

For static, wholesale-rebuilt, membership-or-single-value sets — the workloads in
[the executive summary](executive-summary.md) — the array dominates at every
size, so that is what the package implements. Size alone is never the reason to
switch; the workload is.

## IPv4 / IPv6

Every input prefix is masked to its network and split into the v4 or v6 array by
family. Query addresses are `Unmap`ped first, so an IPv4-in-IPv6 form
(`::ffff:1.2.3.4`) is treated as the IPv4 address it represents and matched
against the v4 array. The two families never cross.

## Immutability & concurrency

`Builder` and `TableBuilder` are single-threaded and mutable. `Freeze` produces
a `Set` / `Table[V]` that is never modified afterward, so it is safe for
unsynchronised concurrent reads: build once at startup (or on each scheduled
refresh, swapping the pointer), then query from any number of goroutines without
a lock.

## Limitations

- **No incremental mutation.** There is no `Remove`; to change the set, rebuild
  and swap. This is deliberate (see the trie trade-off).
- **No all-covering enumeration.** `Table.Lookup` returns the single
  most-specific value, not every covering prefix.
- **Build cost is wholesale.** Adding one prefix to a large set means rebuilding
  it. For the target workloads that rebuild is cheap and happens off the query
  path.

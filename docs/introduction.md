# Meet cidr — the address table that merges, sorts, and answers in a single binary search

The internet's address space is one long number line. Every IPv4 address is a
point between `0` and `2³²−1`; every IPv6 address a point on a line `2¹²⁸` long.
A CIDR block — `1.1.1.0/24`, `2001:db8::/32` — is not a bag of individual
addresses but a single contiguous stretch of that line, and that is exactly what
its slash-notation name says: a range with a start and a width. `cidr` takes the
notation at its word. It lays every prefix you give it down as an interval on the
line, fuses the intervals that touch, sorts what remains, and from then on every
question you can ask — *is this address inside anything?*, *what owns this
address?* — is answered the same way a point is located on a sorted line: one
binary search.

Concretely, it is a small Go library with two structures. A `Builder` collects
prefixes and `Freeze`s into a `Set` — an immutable, sorted array of merged
`[lo, hi]` address intervals whose `Contains` is a single `sort.Search`. A
`TableBuilder[V]` collects `(prefix, value)` pairs and `Freeze`s into a
`Table[V]`, whose `Lookup` returns the value carried by the *most specific*
prefix covering an address. Both are backed by contiguous `net/netip.Addr`
arrays with no pointers to chase, no interface dispatch, and no per-query
allocation. Addresses arrive as strings through `ParsePrefix`, as
whitespace-delimited spec text or a refs JSON envelope through the `Load*`
loaders, or as start/end ranges through `AddRange` — the shapes real IP-to-ASN,
geo, and blocklist feeds actually ship in.

The move that earns its keep is in `Table[V]`. Nesting — a `/25` sitting inside a
`/24` with a different owner — is the whole difficulty of value lookup, and the
usual answer is to walk a trie at query time. `cidr` instead runs a line sweep
over the prefix boundaries *once, at build time*, and precomputes the
longest-prefix-match winner for every disjoint segment of the line. What the
build hands back is flat: the router's most-specific-wins rule, resolved into the
very same sorted array that membership uses, so a value lookup costs exactly what
a yes/no test costs — one binary search, zero allocation — over a structure
roughly `8–60×` smaller than the equivalent trie (see
[architecture](architecture.md) for the measurements). The value type `V` is
yours: a struct, a string, or a compact `uint64` packed by `EncodeASN`.

What you keep, plainly, is a build-once contract. The set is immutable after
`Freeze`, so any number of goroutines query it without a lock — and there is no
`Remove`. You refresh by building a new value from the current feed and swapping
the pointer, on whatever cadence you choose; the trade this makes — no cheap
incremental edit under live queries — is the one a static, wholesale-rebuilt set
never needs. And `Lookup` answers with the single most-specific value, not every
covering prefix: the right answer for a blocklist or an IP-to-ASN table, and a
deliberate limit if you needed the whole ancestor chain. Everything past the
`Freeze` is under your control; nothing inside it moves.

---

Build it once, freeze it, and every question — *is this address in?*, *who owns
it?* — becomes a point located on a sorted line: one binary search, zero
allocation. Refresh by swapping the whole structure; nothing inside it ever moves.

**Read next** — [Executive summary](executive-summary.md) ·
[Architecture](architecture.md) · [User guide](userguide.md) ·
[Examples](../example/README.md)

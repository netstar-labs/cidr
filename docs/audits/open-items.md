# Open items · `cidr`

Ranked by what it costs to be wrong about, not by effort. An item's **absence** from this
page means somebody decided, not that nobody looked — see the table at the foot.

*Opened 2026-09-17 by the `rir-country` audit pass
([`audit-findings.md`](audit-findings.md)).*

## Open

### 1. `lastAddr` is duplicated between the library and `cmd/rir-country`

**Cost of being wrong:** low, and slow-acting. Two copies of one calculation; a fix to
either does not reach the other. Neither is complex and both are tested, so the realistic
failure is drift over years rather than a defect next week.

`cidr.go:66` has an unexported `lastAddr` covering both families.
`cmd/rir-country/main.go` has `lastAddr6` covering v6 only, because `package main` cannot
reach the library's private helper.

**The decision that is actually open:** whether to export
`cidr.LastAddr(netip.Prefix) netip.Addr`. It is a genuinely useful primitive that
`netip` does not provide, and callers building ranges by hand will want it. Against: the
library's whole proposition is a small, frozen surface, and every exported symbol is a
promise that outlives its motivation. Deferred out of a feature PR on purpose — widening
a public API is not a side effect of adding a command.

**What would settle it:** a second in-repo caller needing the same helper, or an outside
consumer asking for it. Either turns "nice primitive" into "demonstrated need".

### 2. `fetch` / gzip handling is duplicated across all four converters

**Cost of being wrong:** low. Four copies of ~25 lines of HTTP-with-timeouts.

Assessed and left alone in this pass ([`audit-dedup.md`](audit-dedup.md) B1): it is the
repo's deliberate convention, and it keeps each command self-contained and separately
`go install`-able.

**What would settle it:** a change that must be applied to all four at once — a proxy
setting, a retry policy, a User-Agent requirement. At that point the shared internal
package pays for itself; before it, the indirection costs more than it saves.

## Deliberately not open

Re-raising one of these should cost a lookup, not an afternoon.

| Question | Settled | Why |
|---|---|---|
| Should `rir-country` also produce region/city? | Yes — no | The delegated files carry **country only**. Region/city is a WHOIS-database problem with a different format, and two of five registries publish no comparable source. Out of reach of this data, not merely out of scope. |
| Should the conflict fallback be registry precedence instead of lowest country code? | Yes — no | Registry precedence encodes an authority ranking the RIRs do not have. Lowest country code is arbitrary but *disclosed and deterministic*, and every fallback is printed. A defensible-looking arbitrary rule is worse than an obviously arbitrary one. |
| Should unresolved conflicts fail the run? | Yes — no | Two prefixes out of 333,485 would block a daily regeneration over an ambiguity that does not affect them. They are reported loudly and counted; an operator can gate on `unresolved=` if they want to. |
| Should the output merge adjacent same-country prefixes? | Yes — no | `Set`/`Table` already merge and resolve at build time, and the spec is more useful unmerged: it maps 1:1 onto the published records, so a disagreement can be traced to a registry line. |
| Should `rir-country` replace `mm-dbip -db country`? | Yes — no | Different trade-offs, both kept. The RIR file is the primary record; DB-IP adds vendor curation and corrections. A consumer should be able to pick, or diff the two. |

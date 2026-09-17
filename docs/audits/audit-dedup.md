# B — duplication · `cmd/rir-country`

*2026-09-17. Report-only pass; verdicts assigned by the skeptic pass in
[`audit-findings.md`](audit-findings.md).*

## B1 — `fetch` duplicated across every converter — **REFUTED**

`rir-country` carries its own `fetch` with the same dial/response-header timeout shape as
`iptoasn`, `mm-geolite2-asn` and `mm-dbip`.

Refuted as a finding. Verified by inspection that **all four** converters already do this,
so it is the repo's convention rather than an oversight introduced here. The convention
buys something concrete: each command is independently `go install`-able and reads
top-to-bottom without a shared internal package, which is what makes
`go install github.com/netstar-labs/cidr/cmd/<name>@latest` a complete instruction.

Hoisting the four copies into an internal package is a repo-wide refactor with its own
blast radius; it is not this change's business, and doing it for one of four would leave
the duplication *and* add an indirection.

## B2 — `lastAddr6` duplicates the library's unexported `lastAddr` — **PLAUSIBLE**

`cidr.go:66` already implements exactly this, for both families, with tests. It is
unexported, so `package main` under `cmd/` cannot reach it.

Genuine duplication, and the skeptic could not refute it: the logic is identical in
intent, and a bug fixed in one would not reach the other.

Not acted on here. The only real fix is to export a new public symbol from the library —
`cidr.LastAddr(netip.Prefix) netip.Addr` — which is a deliberate API-surface decision. The
library is pre-1.0 and its API is described as "stable in practice, not yet promised"; a
feature PR is the wrong place to widen it, because an exported symbol is a commitment that
outlives the reason it was added.

→ [`open-items.md`](open-items.md).

## B3 — `maybeGunzip` duplicates `mm-dbip`'s `open` — **REFUTED**

Same rationale as B1, plus the two have already diverged for reasons intrinsic to the
commands: `mm-dbip.open` resolves one source and returns an `error`; `maybeGunzip` is
called per source by `openSources`, which handles several files and cleans up partial
opens on failure. Merging them would mean parameterising away the difference that
motivated writing the second one.

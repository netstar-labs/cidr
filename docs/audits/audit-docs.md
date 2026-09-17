# D — doc-vs-code drift · `cmd/rir-country`

*2026-09-17. Report-only pass; verdicts assigned by the skeptic pass in
[`audit-findings.md`](audit-findings.md). Every claim checked against the real code and,
where it is a measurement, against the real data.*

## D1 — undated measurements in the docs — **CONFIRMED, fixed**

Two figures were written as standing facts:

- "763 of the published counts are not powers of two"
- "as published today there are exactly two such prefixes"

Both are true measurements of the five delegated files on 2026-09-17, and both are
properties of a dataset the RIRs republish **daily**. Written undated they read as
invariants, and the first reader to find three conflicts instead of two has no way to
tell whether the tool broke or the world moved.

Fixed: both now carry "as published on 2026-09-17", and the conflict count is phrased as
"a handful at any time" with the dated figure in parentheses. The claim survives the data
changing.

This is the same failure the repo has been bitten by before — a precise number outliving
its measurement — so it is worth stating the rule: **a measured figure in prose carries
the date it was measured, or it is not a figure, it is a hostage.**

## D2 — package doc understated the conflict cap — **CONFIRMED, fixed**

The doc comment said conflicts are reported on stderr "the first few otherwise". The code
caps at exactly `stderrConflicts = 10` and prints a count of the remainder.

"A few" is not checkable. Fixed to state the number, matching the constant. The
handbook's rule against silent caps is about the *program*; the doc has to state the cap
too, or the reader cannot tell that the program obeys it.

## D3 — `cmd/README.md` program count — **CONFIRMED, fixed**

Said "Eight programs built on the `cidr` package". Adding `rir-country` makes nine.
Verified by counting `cmd/*/` — nine directories. Fixed, and the table gained its row.

A count in prose is drift-prone by construction; it is kept because the reader uses it to
tell whether the table below is complete.

## D4 — `docs/userguide.md` converter count — **CONFIRMED, fixed**

"Three tools under `cmd/` fetch a provider's table and write the cidr spec directly" —
now four. Fixed, and the sentence changed from "a provider's table" to "a source's
table", because `rir-country` reads the registries' own record rather than a provider's
repackaging of it, and the old wording quietly asserted otherwise.

## New documentation added by this change

Checked against the shipped flags and behaviour rather than against intent:

| Location | Content | Verified against |
|---|---|---|
| `cmd/rir-country/main.go` package doc | format, filters, conflict rules, fallback, cap | the code, line by line |
| `cmd/README.md` § `rir-country` | flags, conflict semantics, determinism | `flag` declarations; `TestDeterministicOutput` |
| `docs/userguide.md` § data sources | new table row, primary-record framing | the five source URLs in `sources` |
| `docs/userguide.md` § fetch/convert | worked examples, conflict rule table | run against live data, output checked |
| `docs/userguide.md` § scheduled generation | `build/rir-country --generator`, daily | `build/rir-country` `TIMER` value |

Every flag named in the docs exists; every flag that exists is named in the docs. The
`-conflict` default stated in prose (`date`) matches the `flag.String` default.

## Deliberate non-change

`README.md:58` already said the library "ingests start/end address ranges (iptoasn, RIR
delegated files) directly" — written before any RIR converter existed. It is now more
true than when written, and needs no edit.

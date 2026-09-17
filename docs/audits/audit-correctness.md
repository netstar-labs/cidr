# C — correctness + optimization · `cmd/rir-country`

*2026-09-17. Report-only pass; verdicts assigned by the skeptic pass in
[`audit-findings.md`](audit-findings.md). Correctness findings carry a reproduction run
against a copy, never the repo source.*

## C1 — unaligned ipv6 record silently relocated — **CONFIRMED, fixed**

`netip.PrefixFrom(addr, n).Masked()` rounds the start address down to the prefix
boundary. A published record of `2001:db8::1/32` was stored as `2001:db8::/32` — an
allocation the registry never made — and counted as a *good* row, so no tally moved.

```
input : ripencc|DE|ipv6|2001:db8::1|32|20200101|allocated|a
before: 2001:db8::/32 DE     rows=1 malformed=0
after : (nothing)            rows=0 malformed=1
```

**Live impact: zero.** All five delegated files were scanned: **0** unaligned ipv6
records. No shipped byte changes.

It was still fixed rather than deferred, because the defect is not "wrong output today",
it is "a malformed record is absorbed instead of reported". The value of the malformed
tally is that it is trustworthy; a parser that quietly repairs its input has a tally that
means nothing. Regression: `TestUnalignedV6IsMalformed`.

## C2 — `-in` silently overrode `-registry` — **CONFIRMED, fixed**

`rir-country -registry arin -in ripencc.txt` read RIPE's file and said nothing about
ARIN. Both flags validate, one is discarded. Fixed: stderr now states that `-registry`
was ignored. No behaviour change, only disclosure.

## C3 — order-independence of three-way conflict resolution — **CONFIRMED safe**

`collect` resolves pairwise as records arrive, and the registry files are read in
sequence, so a three-way claim resolves as `resolve(resolve(r1,r2), r3)`. If the rules
were not commutative, the answer would depend on read order — and the whole point of the
sorted output is that two runs agree.

Each rule reduces to a commutative and associative operation:

| Rule | Reduces to |
|---|---|
| `date` | `max` over the date string |
| `specific` | `max` over `srcBits` |
| fallback | `min` over the country code |

Mixed cases converge too: a pair that ties on the rule falls back to `min` country code,
and the survivor carries the tying key forward, so a later record compares against the
same key regardless of which of the tied pair survived.

Pinned by `TestThreeWayConflictOrderIndependent` — all six permutations, both modes.

## Verified correct (checked, not findings)

- **IPv4 count overflow.** `arin|US|ipv4|255.255.255.0|512|…` would run past the v4 space.
  `addV4` returns `false` and the record is counted malformed rather than wrapping to a
  low address. Covered by `TestMalformedVsSkipped`.
- **Over-long line.** Scanner capped at 1 MB; a longer line returns `bufio.ErrTooLong`
  from `sc.Err()` and aborts the run. It does not truncate and continue.
- **`ZZ` country code.** Appears in the data only on `reserved`/`available` rows — the
  status filter already excludes every one. A country denylist (as the comparable Python
  pipeline carries) would be dead code here. Verified across all five files.
- **Non-power-of-two ipv4 counts.** 763 records as published. Handled by decomposing via
  `RangePrefixes`; `TestNonPowerOfTwoCount` pins the real afrinic
  `164.146.0.0|393216` row, whose minimal cover is `/15 + /14` — note *not* `/14 + /15`,
  since `164.146.0.0` is not `/14`-aligned.

## Optimization

None pursued. The full five-registry run parses 770,225 lines into 333,485 prefixes in a
few seconds, against a data source that republishes daily. There is no hot path here: the
program runs once per day from a systemd timer and writes a file.

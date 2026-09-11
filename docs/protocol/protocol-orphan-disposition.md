# Protocol Orphan Family Disposition (AutoPilot + Remote)

Disposition-only triage of the **21 directional unmatched-family
entries** identified by
[`four-set-protocol-census.md`](four-set-protocol-census.md) (AP
RX-only 8, Remote RX-only 1, Remote TX-only 9, AP TX-only 3). Does not
reopen the proven core protocol. Existing evidence first; a few tiny
bounded lookups this session (disasm/xrefs/a raw byte scan) only for
the explicitly flagged priority cases.

**Machine-readable companion (authoritative)**:
[`research/generated/protocol-orphan-disposition.json`](../../research/generated/protocol-orphan-disposition.json).

## Disposition counts (21 total)

| Disposition | Count |
|---|---:|
| REQUIRED_FOR_REPLACEMENT | 0 |
| REQUIRED_PARSER_COMPATIBILITY | 2 |
| REQUIRED_TX_COMPATIBILITY | 0 |
| LEGACY_OR_OTHER_PRODUCT | 5 |
| DORMANT_OR_UNREACHED | 10 |
| VARIANT_OR_FRAMING_MISMATCH | 1 |
| WEAK_EVIDENCE_ONLY | 1 |
| UNRESOLVED_PRESERVE_AS_GAP | 2 |

## Priority cases

### `D` — REQUIRED_PARSER_COMPATIBILITY

AutoPilot-side behavior is **fully execution-confirmed**: real RX
parse, write into the persisted config buffer, flash persistence at
`0x12000`, and a real fresh-boot reload of the exact value with zero
commands re-sent. No Remote-side sender was found, despite the
existing static survey's own explicit search. Per instruction, absence
from the manual and an unconfirmed producer do **not** make this
unnecessary — the behavior is real, deliberate, cheap to keep, and
some real client (a service tool, a different Remote build, or an
unlocated UI path) may depend on it. **Keep accepting `D` for
compatibility.**

### bare `W` — VARIANT_OR_FRAMING_MISMATCH

Re-examined this session (disasm `0x85c8`-`0x8650`). The `'W'` check is
reached for any message starting with `W`; the second byte is then
compared to `'0'` (→ dedicated W0 handler) and `'1'` (→ dedicated W1
handler). When it's **neither** — exactly what a bare `"W|"` frame
supplies — execution falls through into a **shared, generic tail
block** (also reached from unrelated contexts), not into W0/W1's own
logic and not a hard error either. **Precise characterization**: a
real framing gap, not a parser bug or silent data loss. A replacement
must not treat bare `W` as equivalent to either `W0` or `W1`, and
should decide deliberately what a malformed/short `W` frame does.

### `IX` — WEAK_EVIDENCE_ONLY (downgraded this pass)

Found the literal `"IX|\0"` by direct byte scan (`mando868` flash
`0x1cba2`). Checked for any code reference: **zero xrefs anywhere in
the image**. This is a *stronger, more negative* finding than the
prior "xref not yet resolved" — no instruction anywhere loads a
pointer to this string. Very likely inert build/string-table debris,
not a real, sendable command. **Not recommended for any replacement
compatibility work.**

### `B_UNKNOWN` — REQUIRED_PARSER_COMPATIBILITY

A real, non-trivial Remote-inbound branch (leading `'B'` byte) that
calls the **same shared response parser** (`FUN_0000c440`) used for
the proven `S`/`!` "P..." responses. No AutoPilot producer exists
anywhere in the 18-event dispatcher, `MT`, or `T`. Already documented
(not newly discovered) as grouped with the `'a'-'x'` reconnect-rearm
dispatch, but its *own* payload semantics (reusing the P-response
parser) are separate and unresolved. Reusing a proven mechanism
suggests a real, designed alternate entry point (a different AutoPilot
variant or protocol revision) rather than dead code — **preserve this
parser branch for compatibility.**

### AP events 8/9, M1/M2/M3 — DORMANT_OR_UNREACHED

Events 8 and 9: real builder shapes exist, no producer found on either
side, and an earlier firmware-version hypothesis for event 8 was
already downgraded once `&|`→`V01R39` was proven as the real
firmware-version path — no remaining working hypothesis. `M1`/`M2`/`M3`
(events 11/12/14): **doubly orphaned** — re-confirmed this session by
direct decompile that the Remote's inbound `'M'` branch handles only
`'S'` (`MS`) and `'T'` (`MT`) as the second byte; there is no
`'M'`→digit case at all, so the Remote could not react even if these
were ever sent. Best-supported dormant/legacy finding of the group.

## The rest, briefly

- **AP-RX-only** (`Y`, `B2`, `W0`, `R1`, `LH1-4`, `A`, `T_OTHER`): all
  real, executable parser branches, each structurally paired with a
  proven sibling (B0/B1, W1, R0/R2, LL1/LL2, the radio-ID probe, or the
  shared ack mechanism) but with no confirmed Remote producer —
  `DORMANT_OR_UNREACHED`.
- **Remote-TX-only, legacy-leaning** (`V`, `MS` piped, `MR`, `KK`,
  `E1`): real sends with no AutoPilot dispatch match. `E1` has the
  strongest legacy signal (adjacent UI text explicitly references
  cablecam/IR). `KK`'s "bridge-related initialization" context is
  plausibly the USB-C bootloader handshake — a different subsystem
  entirely, not chased further. **`MS` (piped) is a NAME COLLISION**
  with the unrelated, matched AutoPilot→Remote family (literal `MS`,
  no pipe) — do not conflate.
- **`MM` and `N`** are deliberately **not** classified legacy: both
  sit in the same shared UI mechanisms as proven, currently-active
  commands (`MM` near the live Set-Limits workflow; `N` via the same
  settings widget as confirmed `B0`/`TR0`) — `UNRESOLVED_PRESERVE_AS_GAP`.

## Report

- **Corrected unmatched-entry count**: **21** (8 + 1 + 9 + 3), not "12"
  — 12 is the separate, unrelated `AutoPilot TX ∩ Remote RX` matched
  count.
- **Deduplicated semantic-gap count**: also **21** — checked for
  shared-letter/opposite-direction coincidences (`B2`/`B_UNKNOWN`,
  piped `MS`/matched `MS`); none collapse into fewer real gaps.
- Every family has been assigned exactly one disposition; none left
  silently unclassified.

## See also

[`four-set-protocol-census.md`](four-set-protocol-census.md),
[`command-inventory.md`](command-inventory.md).

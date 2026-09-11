# Mando868 Counterpart Audit against the AutoPilot Behavioral Contract

**Purpose**: determine what Remote (Mando868) behavior a replacement
AutoPilot must remain compatible with — what it sends, expects, retries,
stores, or displays for each externally-visible AutoPilot behavior
already established in
[`autopilot-gap-audit.md`](autopilot-gap-audit.md) /
[`autopilot-replacement-gaps.json`](../../research/generated/autopilot-replacement-gaps.json).
This is **not** a semantic classification pass over Mando868's 300+
residual functions — it is a targeted counterpart audit built from
existing evidence first.

**Machine-readable companion**: [`research/generated/mando868-counterpart-audit.json`](../../research/generated/mando868-counterpart-audit.json).

## Method

Built primarily from canonical docs already covering the Remote side in
detail — `docs/ui/action-command-map.md`, `docs/protocol/command-
inventory.md`, `docs/protocol/bidirectional-protocol.md`,
`docs/investigations/manual-mode-and-limits.md`,
`docs/investigations/auto-mode-and-plus-command.md`,
`docs/investigations/motor-config-persistence.md`,
`docs/investigations/protocol-pipeline.md` — cross-checked against the
existing Mando868 census/Ghidra cache. Two items had a genuinely missing
fact and received exactly one bounded, existing-tooling investigation
each (see "New investigations," below); every other item was closed
from documents already in the repo.

## Contract matrix (19 items)

| # | Item | Status |
|---|---|---|
| 1 | G transaction | PROVEN |
| 2 | S / P transaction | PROVEN |
| 3 | ! transaction | PROVEN |
| 4 | I transaction | PROVEN |
| 5 | short I9 / I1 forms | PROVEN |
| 6 | interactive `+` | PROVEN |
| 7 | bulk mode-0x62 re-arm | PROVEN |
| 8 | Manual Mode 0xF0 / 0xE0 | PROVEN |
| 9 | MC / motor configuration | PROVEN |
| 10 | MT / Quick Setup initiation and completion | PROVEN |
| 11 | Auto Mode program representation / editing | PROVEN_WITH_ASSUMPTION |
| 12 | programmed-position storage on the Remote | **MISSING** |
| 13 | channel selection / jog semantics | PROVEN_WITH_ASSUMPTION |
| 14 | retry / timeout behavior (cross-cutting) | PROVEN_WITH_ASSUMPTION |
| 15 | malformed / unexpected response behavior | PROVEN_WITH_ASSUMPTION |
| 16 | known protocol quirks | PROVEN |
| 17 | reconnect / startup synchronization | PROVEN |
| 18 | radio TX/RX packet boundary | PROVEN_WITH_ASSUMPTION |
| 19 | Remote expectations relevant to persistence/configuration | PROVEN_WITH_ASSUMPTION |

**12 PROVEN, 6 PROVEN_WITH_ASSUMPTION, 1 MISSING, 0 NOT_APPLICABLE.**

Full per-item detail (AutoPilot behavior, Remote producer/consumer,
exact wire form, retry/timeout, Remote state updated, UI trigger,
compatibility requirement, evidence refs) is in the JSON companion, not
duplicated here.

## Tightened areas (per this task's explicit focus)

### Interactive `+` vs bulk re-arm

The Remote-side lifecycle is now fully distinguished, not assumed:

- **Interactive `+`** (mode `0x00`/`0x14`) fires from 4 exact call sites
  in `FUN_0000e670` (screens 5/9/10), each gated behind a real
  confirm/select wait. It writes only the Remote's own **local**
  per-channel record — never a bulk push, never `MC4`.
- **Bulk mode-`0x62` push** fires from **two distinct** mechanisms, not
  one: `FUN_0000c440`'s tail (gated on a clean `S|`→`P...` round trip
  *and* a UI-set "has real programmed data" flag, `0x20000fa0`, that the
  boot sequence itself never sets) — this is the one path that also
  sends `MC4`; and a **structurally separate** periodic pusher,
  `FUN_0000b6f0` (called from the UI pump roughly every 250 ticks once
  first-sync is done), which pushes `'+'` but **never** sends `MC4`. The
  two must not be conflated — a replacement watching for "bulk push
  events" needs to handle both, but only treat `FUN_0000c440`'s as an
  `MC4`-bearing event.
- This session's AutoPilot-side concrete result (Gap Resolution A) is
  now cross-confirmed from the Remote-intent side: three of the four
  interactive call sites are explicitly local point-recording actions,
  consistent with — not merely compatible with — the proof that
  interactive `+` cannot arm a target.

### Manual Mode

- **Send cadence**: every UI pump tick, unconditionally, for as long as
  the jog wheel is not clicked — including idle/heartbeat frames with
  zero records.
- **Channel/sign/magnitude encoding**: fully decoded (channel nibble at
  byte 6, sign+23-bit magnitude at bytes 7-9), byte-identical between
  `0xF0` and `0xE0` per this session's AutoPilot-side confirmation.
- **F0 vs E0 selection — newly resolved this pass**: `FUN_0000be94`
  compares `*0x200018e7` (the same screen/context-state byte that also
  selects the `I9` vs `I1` short forms) against the literal `3`: `==3`
  selects mode `2` (`0xE0`); any other value selects mode `1` (`0xF0`).
  Which specific UI screen sets that byte to `3` was not traced (one hop
  beyond this bounded check, left as the item's residual `missing_fact`).
- **What the Remote does on release**: stops sending, full stop — no
  explicit stop/zero-rate command exists on the wire. No AutoPilot-side
  dead-man timeout was invented or assumed here; none has been found on
  either side of this protocol.

### Retry/timeouts (consolidated)

| Family | Retry/timeout |
|---|---|
| G, interactive `+` (sites C/D) | Shared `0xb59c`-style ack-wait; exact retry count/timeout not uniformly cited |
| `I9`/`I1` | 6 retries, ~1000-3000 ticks total, then silent give-up |
| `S`/`!`/bulk-push gate | "any clean response within ~200 ticks" |
| `MC`/`MC4`/`LL1`/`LL2` | Sent 3x, **no ack wait at all** |

### Protocol defects (facts, not fixes)

- **`!` leaves field 11 unconsumed**: the Remote's parser calls its
  field parser exactly 10 times then unconditionally marks itself done;
  field 11 and its trailing comma are left byte-for-byte unconsumed in
  the real RX ring buffer (confirmed by direct pointer inspection). No
  error, assert, or crash on either side.
- **`I9` is a genuine dead end**: decodes to channel index 8, outside
  the AutoPilot's 4-channel scan; the Remote's query (6 retries,
  ~1000-3000 ticks) simply times out with no error surfaced. Its parsed
  result slot (`0x200027f0`) has zero readers anywhere in the image —
  discarded even on the rare chance it succeeded.

A replacement wishing strict Remote compatibility should reproduce both
as-is, per this project's own standing caution against "fixing" observed
firmware discrepancies in a harness or replacement.

### Radio boundary

Stopped exactly where instructed: the Remote's logical-packet ↔
radio-transport boundary (TX wrapper `0x58a8`, RX ring buffer
`0x20001773` with read/write pointers, LoRa/SPI driver chain
`0xb440→0x11830→0x11326/0x112e8`) is characterized from existing
evidence. Exact Remote-side SX127x register configuration (mode,
frequency, sync word, CRC, payload length) is **not** established and is
recorded as a separate, explicitly non-blocking item (item 18) — the
same class of gap already flagged and marked non-blocking on the
AutoPilot side.

## New investigations performed (both bounded, existing tooling only)

1. **Item 8 (Manual Mode `0xF0`/`0xE0` mode selection)** — bounded
   decompile of `FUN_0000be94` itself (`tools/ghidra/aptrace_ghidra.py
   decompile mando868 0xbe94`), no additional hop needed. Found the
   exact selection condition (`*0x200018e7 == 3`).
2. **Item 12 (programmed-position storage on the Remote)** — one
   existing-census xref query (`tools/ghidra/aptrace_ghidra.py xrefs
   mando868 0x20000b20`). Found only already-known UI/push consumers,
   no distinct boot-time loader function. Left `MISSING` per this pass's
   one-hop bound, consistent with the investigation rule ("then stop").

No other Mando868 code was inspected. No residual function was
classified.

## Requirements not yet present in the AutoPilot replacement contract

Two items surface real Remote-side facts worth folding into the
replacement contract that weren't explicit there before:

1. **MC/MC4/LL1/LL2 expect no acknowledgement at all** (sent 3x,
   fire-and-forget) — the AutoPilot replacement contract's "motor
   configuration" and "Quick Setup / MC / MT" sections don't currently
   state this explicitly; a replacement that tries to synchronously ack
   these would be over-engineering against a Remote that never waits.
2. **The bulk mode-`0x62` push has two distinct real-world triggers**
   (boot AND a ~5000-tick communication-gap reconnect), not one — the
   existing AutoPilot-side "Auto Mode" contract entry already captures
   the arm/no-arm distinction but does not enumerate both Remote-side
   trigger conditions by name; worth a one-line addition for
   implementers timing their own reconnect-detection logic.

Everything else in this audit reinforces, rather than adds to, the
existing AutoPilot replacement contract.

## Conclusion

Ready for the Mando868-vs-Mando915 differential audit: this pass
establishes a concrete Mando868 behavioral baseline (mirroring how
AutoPilot868 served as the baseline for the 868-vs-915 audit), and no
open item here blocks that comparison — the one `MISSING` item (Remote
NVM loader function) and the `PROVEN_WITH_ASSUMPTION` items are all
independent of whatever RF-band-specific differences Mando915 might
introduce.

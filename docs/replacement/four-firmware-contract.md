# Four-Firmware Cross-Reconciliation

**Purpose**: consolidate the four independent audits already completed
this session into one normalized cross-firmware contract. **This is a
consolidation pass only — no new reverse engineering, no Ghidra, no
Unicorn, no re-interpretation of already-closed findings.**

**Machine-readable companion**: [`research/generated/four-firmware-contract.json`](../../research/generated/four-firmware-contract.json).

**Inputs consolidated**:
[`autopilot-gap-audit.md`](autopilot-gap-audit.md) /
[`autopilot-replacement-gaps.json`](../../research/generated/autopilot-replacement-gaps.json),
[`autopilot-868-vs-915-audit.md`](autopilot-868-vs-915-audit.md) /
[`autopilot-868-vs-915-diff.json`](../../research/generated/autopilot-868-vs-915-diff.json),
[`mando868-counterpart-audit.md`](mando868-counterpart-audit.md) /
[`mando868-counterpart-audit.json`](../../research/generated/mando868-counterpart-audit.json),
[`mando-868-vs-915-audit.md`](mando-868-vs-915-audit.md) /
[`mando-868-vs-915-diff.json`](../../research/generated/mando-868-vs-915-diff.json).

## Top-level findings

- **One common AutoPilot contract covers both builds** — the two
  70,768-byte images differ in exactly one 4-byte RF center-frequency
  `.data` constant; everything else is byte-identical.
- **One common Remote contract covers both builds** — no logic/behavior
  difference was found anywhere sampled; the large raw-byte diff
  resolves entirely to one link-time address-relocation artifact plus
  two cosmetic strings (RF-band label, build timestamp).

## Reconciliation matrix (19 requirements)

| ID | Behavior | AP868 | AP915 | Mando868 | Mando915 | Confidence |
|---|---|---|---|---|---|---|
| R1 | G transaction | SAME | SAME | SAME | SAME | PROVEN |
| R2 | S / P | SAME | SAME | SAME | SAME | PROVEN |
| R3 | ! | SAME | SAME | SAME | SAME | PROVEN |
| R4 | I | SAME | SAME | SAME | SAME | PROVEN |
| R5 | I9 / I1 | SAME | SAME | SAME | SAME | PROVEN |
| R6 | interactive `+` | SAME | SAME | SAME | SAME | PROVEN |
| R7 | bulk mode-`0x62` re-arm | SAME | SAME | SAME | SAME | PROVEN |
| R8 | Manual `F0`/`E0` | SAME | SAME | SAME | SAME | PROVEN |
| R9 | MC / MC4 | SAME | SAME | SAME | SAME | PROVEN |
| R10 | MT / Quick Setup | SAME | SAME | SAME | SAME | PROVEN |
| R11 | reconnect / startup sync | SAME | SAME | SAME | SAME | PROVEN |
| R12 | retries/timeouts | SAME | SAME | SAME | SAME | PROVEN_WITH_ASSUMPTION |
| R13 | program state | SAME | SAME | SAME | SAME | PROVEN_WITH_ASSUMPTION |
| R14 | trigger behavior | SAME | SAME | N/A | N/A | PROVEN |
| R15 | motor configuration (AP hardware effect) | SAME | SAME | N/A | N/A | PROVEN_WITH_ASSUMPTION |
| R16 | persistence expectations | SAME | SAME | SAME | SAME | PROVEN_WITH_ASSUMPTION |
| R17 | radio transport boundary | DIFFERENT* | DIFFERENT* | SAME | SAME | PROVEN_WITH_ASSUMPTION |
| R18 | protocol quirks/defects | SAME | SAME | SAME | SAME | PROVEN |
| R19 | RF/build differences (summary row) | DIFFERENT | DIFFERENT | DIFFERENT† | DIFFERENT† | PROVEN |

\* AutoPilot's radio transport *code* is identical; only its
center-frequency constant differs — see below.
† Remote's *behavioral* code is identical; only display/timestamp
strings differ — see below.

Full per-row detail (`behavior`, `cross_device_contract`,
`variant_specific`, `evidence_refs`, `remaining_unknown`) is in the JSON
companion, not duplicated here.

## RF / build differences (recorded explicitly)

**AutoPilot:**
- 868 build center frequency = **864 MHz**
- 915 build center frequency = **915 MHz**
- Stored as a 4-byte `.data` constant (RAM `0x20000000`, flash source
  `0x14c40`-`0x14c43`), consumed by `radio_bringup__THIRD_PARTY`. This
  is the **entire** byte-level difference between the two AutoPilot
  images.

**Remote:**
- Behavioral contract **identical** between builds.
- Display string differs: `"868MHz band"` / `"915MHz band"` (Info
  screen, cosmetic).
- Build timestamp string also differs (`"12:22:42"` / `"12:20:52"`) —
  a compile artifact, not functional.
- Exact RF frequency-register setup **remains unresolved equally on
  both builds** — no isolated frequency constant was found in Mando
  the way AutoPilot's was; this does not block contract closure on
  either build.

## Cross-device contract (Remote → AutoPilot)

Every wire-level requirement (R1–R11, R18) crosses device boundaries
identically regardless of RF-band variant: the same Remote sender
functions, the same AutoPilot receiver/dispatch logic, the same
retry/ack shapes, and the same two documented protocol quirks apply to
**all four firmware images** without exception.

## Preserved, unsolved facts (not resolved by this pass)

| Fact | Status |
|---|---|
| Remote local NVM loader for `0x20000b20` | open |
| PA22 physical identity | open |
| Physical Motor1-4 connector mapping | open |
| DIR polarity vs. physical direction | open |
| External STEP/DIR implementation details | open (one candidate checked, ruled out) |
| Status LED GPIO path | open (one candidate checked, ruled out) |
| Exact Remote RF register setup | open (equally unresolved on both Remote builds) |
| Product decisions about vendor quirks | open (explicitly a product decision, not an evidence gap) |

None of these were investigated or advanced in this pass, per its own
scope instruction.

---

# Manual/UI Mapping Audit (gap list only)

Compared `docs/ui/user-guide-workflows.md` and
`docs/ui/action-command-map.md` against the reconciled four-firmware
contract above and `docs/hardware/hardware-reference.md`. **No rewrite
performed** — output is a gap list only, in
[`research/generated/manual-traceability-gap-list.json`](../../research/generated/manual-traceability-gap-list.json).

## Gap categories found

1. **Rows already complete** — workflows/commands with a full,
   closed-loop evidence chain (string → input → wire bytes → AutoPilot
   effect) that the four-firmware contract now additionally confirms
   variant-independent. Examples: `&|`→`V01R39` (workflow 9), `G`
   acknowledgement (workflow 5/7), Quick Setup's `MT`→Choose-Type→`MC4`
   chain (workflow 2), the Auto-Mode `'+'` screen-5 recording dialog
   (workflow 5).
2. **Rows now stale** — text written before this session's findings
   that a reader could mis-read as still-open. The clearest case:
   `user-guide-workflows.md`/`action-command-map.md` describe the
   interactive `'+'` screens' AutoPilot-side consequence as "remains
   the working hypothesis, unproven" — now proven (this session, both
   directions: it does *not* arm a target). Similarly, any residual
   phrasing that treats Mando915/AutoPilot915 as unaudited is now
   stale.
3. **Rows missing firmware-path linkage** — manual-only claims
   (`[user manual]` tag) with no `[firmware string]`/`[firmware,
   CONFIRMED]` counterpart at all. Examples: external STEP/DIR
   passthrough (workflow 8), status LED behavior (mentioned only as a
   panel feature), "Return speed" governs an actual return-to-reference
   move (workflow 8, explicitly flagged `[inferred]` already).
4. **Rows where manual and firmware disagree or diverge** — none found
   as outright contradictions; the closest is the manual's implied
   "Quick Setup config persists across power-off" claim, which R16
   confirms has no independently-verified AutoPilot-side persistence
   mechanism connecting it to the flash-backed config — not a
   contradiction, but an unconfirmed claim the docs already flag as
   such.
5. **Rows requiring hardware/physical evidence** — every row in the
   "preserved, unsolved facts" table above that touches a UI/manual
   claim: physical Motor1-4 connector identity (workflow 2's "Motor
   <N>" labels), DIR polarity vs. the manual's "direction can be
   inverted" claim, external STEP/DIR RJ45 pin behavior, status LED
   patterns.

Exact row-by-row detail is in the JSON companion.

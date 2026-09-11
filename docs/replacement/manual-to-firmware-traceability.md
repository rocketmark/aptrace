# Manual → Firmware Traceability (Performing Rigs AutoPilot + Remote)

**Purpose**: map user-visible manual/UI actions to the firmware paths
and hardware effects already proven across all four firmware images,
producing stable requirement IDs suitable for a later LID/spec process.
**This is a documentation/reconciliation pass — no new reverse
engineering was performed.**

**Machine-readable companion (authoritative)**: [`research/generated/manual-to-firmware-traceability.json`](../../research/generated/manual-to-firmware-traceability.json), 50 atomic requirements (a later bounded closure pass split CLEAR into `MAN-AUTO-006`/`MAN-AUTO-009` — see "Unresolved core Auto Mode edges," below).

## Method

Built from the four-firmware behavioral contract
([`four-firmware-contract.md`](four-firmware-contract.md) /
[`.json`](../../research/generated/four-firmware-contract.json)), the
AutoPilot replacement contract
([`autopilot-gap-audit.md`](autopilot-gap-audit.md) /
[`.json`](../../research/generated/autopilot-replacement-gaps.json)),
the Mando counterpart contract
([`mando868-counterpart-audit.md`](mando868-counterpart-audit.md)), and
the existing manual/UI mapping docs
(`docs/ui/user-guide-workflows.md`, `docs/ui/action-command-map.md`).
Each of `user-guide-workflows.md`'s 13 numbered workflows was split into
atomic user actions only where the existing evidence already
distinguishes them (e.g. "rotate jog wheel" vs. "click to stop" vs.
"double-click to cycle channel" — three already-distinct firmware facts,
not an invented decomposition).

## Status distribution (50 requirements)

| Status | Count |
|---|---|
| `FULL_PATH_PROVEN` | 22 |
| `PARTIAL_PATH_PROVEN` | 10 |
| `NO_FIRMWARE_EVIDENCE` | 6 |
| `REMOTE_LOCAL_ONLY` | 6 |
| `AUTOPILOT_LOCAL_ONLY` | 4 |
| `MANUAL_FIRMWARE_DISAGREEMENT` | 1 |
| `HARDWARE_PHYSICAL` | 1 |

A later bounded closure pass (Remote UI Command Tree — Unresolved Core
Edge Closure) resolved `MAN-AUTO-005` (TEST) from `NO_FIRMWARE_EVIDENCE`
to `PARTIAL_PATH_PROVEN` and `MAN-AUTO-006` (CLEAR A-B) from
`NO_FIRMWARE_EVIDENCE` to `REMOTE_LOCAL_ONLY`, and split off a new
`MAN-AUTO-009` (CLEAR ALL/M1-M4) also at `REMOTE_LOCAL_ONLY` — using
only pre-existing evidence plus one bounded disassembly check each. See
[`docs/ui/remote-ui-command-tree.md`](../ui/remote-ui-command-tree.md)'s
"Unresolved UI → command edges" section for the finding.

**Every requirement carries exactly one status — none were forced into
`FULL_PATH_PROVEN`.**

## Requirement ID namespace

`MAN-STARTUP-*` (3) · `MAN-QUICKSETUP-*` (4) · `MAN-MOTORCFG-*` (5) ·
`MAN-MANUAL-*` (5) · `MAN-AUTO-*` (9) · `MAN-RECONNECT-*` (3) ·
`MAN-PERSIST-*` (4) · `MAN-SETTINGS-*` (2) · `MAN-TRIGGER-*` (3) ·
`MAN-EXTSTEPDIR-*` (1) · `MAN-INFO-*` (3) · `MAN-LIMITS-*` (5) ·
`MAN-UPDATE-*` (1) · `MAN-QUIRK-*` (2)

Full per-row detail (manual claim, Remote path, wire form, AutoPilot
path/state, hardware effect, persistence, retry/timeout, evidence,
discrepancy, replacement requirement, external unknown) is in the JSON
companion — not duplicated in this document.

## Current truths incorporated (not re-investigated)

- **Interactive `+`**: updates Remote-local program/segment state and
  writes the wire-supplied delta into the AutoPilot's record; does
  **not** arm/commit a target and does **not** dirty persistence by
  itself (MAN-AUTO-002, MAN-AUTO-004). The bulk mode-`0x62` push is the
  proven arming/persist mechanism (MAN-RECONNECT-001/002/003).
- **Manual Mode `0xF0`/`0xE0`**: share channel + sign/23-bit-magnitude
  layout; `0xE0` additionally maintains the at-limit suppression
  latch/cache; no proven AutoPilot frame-loss dead-man timeout exists
  (MAN-MANUAL-002).
- **MC/MC4**: sent 3x fire-and-forget, no ack expected
  (MAN-QUICKSETUP-003/004). CURRENT and MICRO-STEPPING are
  received/stored/displayed with no confirmed driver-hardware effect
  (MAN-MOTORCFG-001/003 — both flagged `MANUAL_FIRMWARE_DISAGREEMENT`-shaped
  via their `discrepancy` field, though categorized `AUTOPILOT_LOCAL_ONLY`
  since the wire path itself is fully proven). STEPS/S MAX has a real
  `24,000,000/value` step-period effect (MAN-MOTORCFG-002). RETURN SPEED
  is a table-index lookup into a currently-blank backing table
  (MAN-MOTORCFG-004).
- **Quick Setup**: AutoPilot initiates `MT` during boot setup
  (MAN-QUICKSETUP-001); probe order A, C, B, D; `MC0-3` on leaving an
  edited numeric row (MAN-QUICKSETUP-003); `MC4` on `Continue` once all
  four types are set (MAN-QUICKSETUP-004).
- **Reconnect**: both proven bulk-`0x62` triggers recorded distinctly —
  Remote boot (MAN-RECONNECT-001) and the ~5000-tick communication-gap
  re-arm (MAN-RECONNECT-002) — plus the structurally separate periodic
  push that never sends `MC4` (MAN-RECONNECT-003).
- **Protocol quirks**: `!`'s 11-vs-10 field mismatch (MAN-QUIRK-001) and
  `I9`'s out-of-range dead end (MAN-QUIRK-002) are recorded as behavior
  only — this pass does not decide whether a replacement should preserve
  them.
- **Hardware mappings**: STEP (PB10/PA08/PB12/PA10) and DIR
  (PB11/PA09/PB13/PA11) per channel, driver-control pins
  (PB16/PB17/PB06/PB07) — recorded in MAN-MOTORCFG-005 without claiming
  physical Motor1-4 connector identity, DIR polarity, or PA22's physical
  meaning.
- **External STEP/DIR and status LED**: preserved as valid
  `NO_FIRMWARE_EVIDENCE` outcomes (MAN-EXTSTEPDIR-001,
  MAN-STARTUP-003) — the manual/hardware requirement exists; no firmware
  linkage was found (one candidate each was checked and ruled out in
  earlier sessions, not re-checked here).
- **Terminology**: "startup reference/input routine gated on PA22" used
  throughout (MAN-STARTUP-001); "homing" not used.

## Manual/UI mapping doc updates made this pass

Targeted corrections only, per the STALE items already identified in
`manual-traceability-gap-list.json`:

- `docs/ui/action-command-map.md` — the `'+'` row's "remains the working
  hypothesis, unproven" hedge (interactive `'+'`'s AutoPilot-side
  consequence) updated to reflect this session's concrete proof that it
  does not arm/commit a target.
- `docs/investigations/manual-mode-and-limits.md`'s "UNKNOWN" tag on the
  `0xE0` field layout is **not** edited by this pass (out of the two
  files this task authorized for update); the current-truth correction
  is carried instead in this traceability artifact (MAN-MANUAL-002) and
  was already noted as stale in the gap list.
- `docs/ui/user-guide-workflows.md`'s motor-configuration-fields hedge
  ("remains PROBABLE, not proven") is carried forward as current truth
  in MAN-MOTORCFG-001..004 rather than rewritten in place, to keep this
  pass's file edits minimal and targeted.

## What remains open

- 6 `NO_FIRMWARE_EVIDENCE` rows (TEST M1-M4, most RF/settings screens,
  factory reset, "Surpass limits", external STEP/DIR) — no wire command
  or firmware path was ever traced for these; a future bounded
  investigation could target them individually. (TEST A-B/B-C/C-D and
  CLEAR were resolved by a later closure pass — see above.)
- 1 `MANUAL_FIRMWARE_DISAGREEMENT` (MAN-PERSIST-002: Quick Setup
  persistence claim vs. no confirmed mechanism).
- 10 `PARTIAL_PATH_PROVEN` rows each carry one precise
  `external_unknown` (e.g. exact UI-label-to-call-site mappings, the
  `0xe234` outcome branch, DIR polarity).
- Physical/hardware unknowns (PA22 identity, Motor1-4 connector mapping,
  DIR polarity, status LED GPIO, external STEP/DIR mechanism, exact
  Remote RF register setup) are preserved, not solved, per this pass's
  explicit scope.

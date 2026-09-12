# Macaw Static Analysis Layer

The `aptrace` CLI's Macaw-based static-discovery pipeline: a Cortex-M-safe
Macaw census, a normalization/fixpoint expansion on top of it, and an
APTrace-owned semantic classification layer over Macaw's own `ParsedCall`
terminator. This is the Haskell/Macaw side (`src/APTrace/Macaw*.hs`,
`aptrace macaw-census`/`aptrace macaw-census-expand`) — a different tool
from the Python `aptrace census` (`tools/census/`, see
[`census.md`](census.md)), which is a Ghidra/Unicorn-driven evidence
database. `macaw_compare.py` (also under `tools/census/`) is the bridge
between the two: it reads this pipeline's JSON output and cross-checks it
against the Ghidra-driven database.

See [`tool-selection.md`](tool-selection.md) for when to reach for Macaw at
all versus Ghidra/Unicorn/Crucible; this page documents current behavior of
the Macaw layer itself, not how it was built.

## Cortex-M safety: two distinct fixes

Cortex-M has no ARM (A32) execution state — it is Thumb-only. Macaw's
generic AArch32 backend does not know this and can mis-derive `PSTATE_T`
(Thumb-mode) in two different, independent ways (see
[`tool-selection.md`](tool-selection.md)'s "Tool disagreements" for the
original `0x801c` discovery of this class of bug). APTrace's normal
discovery path applies two separate fixes, neither of which replaces the
other:

- **`macawCortexMEntry`** (`APTrace.FirmwareLoader`) — ORs the low bit into
  any address APTrace hands to Macaw as a discovery-root entry point.
  Macaw derives a fresh root's initial `PSTATE_T` from that bit alone; this
  makes every APTrace-seeded root Thumb, matching the Thumb-bit convention
  every real vector-table word and interworking function pointer already
  carries.
- **`armCortexMInfo`** (`APTrace.FirmwareLoader`) — an `ArchitectureInfo`
  built from Macaw's own `ARM.arm_linux_info`, overriding only two hooks:
  it forces `PSTATE_T=True` in `mkInitialAbsState` (fixing a same-state
  direct `BL` callee's even instruction address being mis-seeded as A32)
  and forces `PSTATE_T=True` whenever `extractBlockPrecond` fails to fold a
  post-call continuation's Thumb state to a precise value. Both overrides
  assert a fact that's always true on this target rather than deriving it;
  everything else (disassembly, classifiers, call identification) is
  unmodified upstream Macaw.

Both fixes are load-bearing for every command below; without them, some
region of a normal Cortex-M discovery can silently decode as impossible A32
code.

## CLI commands

Both are in `app/Main.hs`:

```sh
aptrace macaw-census FIRMWARE.bin [FLASH_BASE_HEX]
aptrace macaw-census-expand FIRMWARE.bin [FLASH_BASE_HEX]
```

- **`macaw-census`** — the vector-root-only base census: parses the vector
  table, seeds Macaw discovery at every handler through `macawCortexMEntry`
  with `armCortexMInfo`, and dumps the discovered functions/blocks/edges/
  calls as JSON.
- **`macaw-census-expand`** — builds the same base state, then runs a
  normalization fixpoint on top of it (below) and emits the *final expanded*
  graph in the same shape `macaw-census` does (so `macaw_compare.py`
  consumes either output identically), plus small `base`/`expanded`
  coverage-summary metadata, `normalization_rounds`, per-round
  `resolutions`, and `residual_classify_failures`.

## JSON relations

Emitted by `censusToValue` (`APTrace.MacawCensus`):

| Key | What it is |
|---|---|
| `functions`, `basic_blocks`, `edges`, `calls` | Base Macaw evidence — unmodified, as Macaw's own discovery classified it. No `provenance` field; this is the implicit `macaw-base` tier every additive layer below is layered on top of, never mutated by it. |
| `incomplete_or_unresolved_terminators` | Terminators Macaw's own classifier could not resolve (`ClassifyFailure`, an unresolved `ParsedCall`, etc.), preserved rather than dropped. |
| `normalized_terminators` | Recovered concrete targets for a `classify_failure` terminator, via `APTrace.MacawNormalize`'s one supported algebraic identity, `mux(c, mux(c,A,B), C) -> mux(c,A,C)`. Tagged `provenance: "macaw-normalized"`. |
| `normalized_transfers` | The same identity applied to `ParsedCall` terminators whose curIP has the same nested-mux shape (e.g. a misclassified `CBZ`). Carries `semantic_kind` (below) so a recovered conditional-branch target is never implied to be a recovered *call* target. Tagged `provenance: "macaw-normalized"`. This superseded an earlier `normalized_calls` relation of the same shape, which always meant "call" — renamed once evidence showed some of those sites were not calls at all. |
| `call_classifications` | The ISA-level semantic classification of every `ParsedCall` terminator (below). Tagged `provenance: "aptrace-isa-classification"`. |

## Why `ParsedCall` must not be read as "this is a call"

Macaw's AArch32 classifier routes several distinct Thumb terminator shapes
through the same `ParsedCall` constructor — not just `BL`/`BLX`. Auditing
every `kind="indirect"` `ParsedCall` site on `firmware_autopilot868.bin`
found Macaw's raw classification measurably over-inclusive: alongside
genuine register-indirect calls, it also produced `ParsedCall` for `BX`
tail-branches, `CBZ`/`CBNZ` conditional branches, `TBB`/`TBH` jump tables,
and a direct `LDR`-into-`PC` computed jump — none of which are calls.
`APTrace.MacawIsaClassify` is a purely additive interpretation layer over
the exact same lifted block (reading Macaw's own `MC.InstructionStart`
statement — Macaw's own disassembler-output text for the terminating
instruction, never re-decoded or taken from Ghidra) that recovers the real
category. It never mutates `ParsedCall`/`CallInfo`; base evidence is
untouched.

Current audited categories, all 48 `kind="indirect"` `ParsedCall` sites on
AutoPilot868:

| `semantic_kind` | Count | Real shape |
|---|---:|---|
| `true_indirect_call` | 23 | `BLX_r_T1`, LR freshly set to a return address |
| `tail_call` | 8 | `BX_T1`, no return address |
| `conditional_branch` | 11 | `CBZ_T1`/`CBNZ_T1` |
| `table_branch` | 5 | `TBB_T1`/`TBH_T1` |
| `computed_jump` | 1 | `LDR` directly into `PC` |
| `ambiguous` | 0 | (none on this audited set) |

## Ghidra-vs-Macaw comparison discipline

`tools/census/macaw_compare.py` reads a `macaw-census`/`macaw-census-expand`
JSON file and cross-checks it against the same firmware's Ghidra-driven
census database: function/block coverage, CFG edges (jump-like, and
call-return kept separate from Ghidra's `fallthrough` edge), calls, and
`normalized_terminators`' recovered targets. A "genuine disagreement" is
reserved for a site where *both* sides resolved a target but with nothing
in common — never simply Ghidra having an extra target from an adjacent
instruction sharing the same block range. After correcting the
comparison's fallthrough handling, this cross-check finds **zero genuine
normalized-target disagreements** between Macaw's recovered targets and
Ghidra's independent static resolution. (`normalized_transfers` and
`call_classifications` are not yet wired into this comparison script — it
currently only cross-checks the older `normalized_terminators` relation.)

## Current AutoPilot868 expanded-census headline numbers

From `aptrace macaw-census-expand`'s final expanded graph:

- 233 functions
- 3,368 blocks
- 26,014 bytes covered
- 136 normalized terminators
- 39 residual classify failures

## Related

- [`tool-selection.md`](tool-selection.md) — when to reach for Macaw versus
  Ghidra/Unicorn/Crucible, and the original `0x801c` A32 tool-disagreement
  case this Cortex-M safety work grew out of.
- [`census.md`](census.md) — the separate Python/Ghidra/Unicorn evidence
  database this pipeline's output is cross-checked against.
- [`docs/investigations/boot-and-hardware-bringup.md`](../investigations/boot-and-hardware-bringup.md) —
  the EIC/EXTINT dispatch finding that motivated the semantic
  classification layer (one physical `ParsedCall` dispatch site shared by
  16 vectors, correctly classified `true_indirect_call`).

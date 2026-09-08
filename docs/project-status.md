# APTrace — Project Status

**This is the single authoritative source for current project state.** It
replaces the old chronological `progress.md` (now
[`docs/history/progress.md`](history/progress.md)) as the place to check
before starting new work. If anything elsewhere in the repo conflicts with
this document, this document wins — and if you find such a conflict, it's a
bug in the docs; fix it here.

Last updated: 2026-09-07.

## Current milestone

**Goal**: a single, complete AutoPilot-only transaction, fully verified
through APTrace's own pipeline:

```
"&" command
    -> real receive/parser path (unmodified compiled firmware)
    -> event 5 scheduled
    -> outbound TX hook (0x8c10 / 0x7f84)
    -> observed string == "V01R39"
```

**Status: not yet complete.** See "Current blockers" below for exactly
what's missing and why.

**Explicit rule**: do not start on the Remote (`firmware_mando868.bin` /
`firmware_mando915.bin`) firmware until the above AutoPilot-only transaction
works end to end. Nothing in the Remote firmware has been touched by APTrace
code yet; this rule has held throughout the project.

## Known-good capabilities (proven, reusable)

These have been demonstrated on real, unmodified AutoPilot firmware and are
safe to build on without re-proving:

- **Raw firmware loading** — Macaw `Memory` built directly from a flat
  `.bin`, no ELF wrapper (`APTrace.FirmwareLoader.buildMemory`).
- **Vector table parsing** — `tools/vector_scan.py` and
  `APTrace.VectorTable`; validated against all four firmware images.
- **Thumb-2 lifting via Macaw's AArch32 backend** — zero decode/lift
  failures across ~1500 real instructions in the firmware's interrupt
  handlers, including the large `Reset_Handler`.
- **Macaw code discovery / CFG recovery** — including from arbitrary seeded
  entry points not reachable via the vector table (used to seed the
  protocol dispatcher directly).
- **Crucible execution of lifted Macaw IR**, both single-block
  (`APTrace.SymbolicRunner.checkBranchModel`) and whole-function
  (`APTrace.ProtocolHarness.runPacketTransaction`).
- **What4/Z3 solving** for reachability and input-value queries, including
  registering models named for what they represent.
- **Symbolic MMIO / symbolic register branching** — a real memory-mapped
  peripheral status register modeled as symbolic, with Z3 producing correct
  path conditions for both branch directions (see
  [`docs/harness/symbolic-execution-results.md`](harness/symbolic-execution-results.md)).
- **Single-block symbolic protocol checks**, solver-confirmed against the
  real compiled dispatcher (not hand-derived): a fixed register holding the
  packet's first byte, checked against each command's real comparison
  instruction, reaches the correct handler exactly when set to that
  command's ASCII value:

  | Command | Solver-confirmed value |
  |---|---|
  | `&` | `0x26` |
  | `G` | `0x47` |
  | `!` | `0x21` |
  | `S` | `0x53` |

  See [`docs/harness/protocol-harness-results.md`](harness/protocol-harness-results.md).
- **A reusable diagnostic**: a custom Crucible `ExecutionFeature`
  (`APTrace.ProtocolHarness.debugFeature`) that logs the visited program
  location every N simulator steps. This is a supported capability, not a
  one-off hack — it's what turns an opaque hang into "stuck cycling through
  addresses X, Y, Z," and it's what found both bugs described below. Reuse
  it whenever a whole-function run doesn't terminate as expected.

## Confirmed findings

- **Target firmware**: Performing Rigs AutoPilot / Remote firmware
  (`firmware_autopilot868.bin`, `firmware_autopilot915.bin`,
  `firmware_mando868.bin`, `firmware_mando915.bin`). See
  [`docs/firmware/firmware-inventory.md`](firmware/firmware-inventory.md) for
  hashes and provenance.
- **MCU/platform**: Microchip/Atmel **ATSAMD51 (Cortex-M4F)**, Arduino +
  Adafruit SAMD board-package lineage (v1.7.11), application image loaded at
  flash `0x4000` (behind a 16KB Adafruit-style bootloader). See
  [`docs/firmware/firmware-layout.md`](firmware/firmware-layout.md).
- **The real caller into the protocol dispatch region** is
  `0x8a34 -> 0x8259` (a genuine, Macaw-call-classified `BL`, not a
  tail-jump). See [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).
- **The opaque-call handling had a real, now-fixed bug**: the original
  function-call override substituted fresh symbolic values for *every*
  register on every call, including R4-R11, which AAPCS makes callee-saved
  (a real ARM function call must not touch them). This corrupted a loop's
  own counter/table-pointer state and produced a hang that looked like
  firmware complexity but wasn't. Fixed by only substituting the genuinely
  caller-saved registers (R0-R3, R12) via `MS.updateReg`, confirmed by
  direct register tracing. See
  [`docs/harness/execution-model.md`](harness/execution-model.md).

## Corrections to earlier findings

- **The "flat parser chain" model of `0x8258` is no longer fully trusted.**
  `research/autopilot_static_inventory/parser-dispatch.md` (v0.1, a purely
  static pass) modeled the AutoPilot dispatcher as a simple if/else-if scan
  over the packet's leading byte. Symbolic execution found the real entry
  sequence runs through a nontrivial indexed-lookup loop first (reading
  `[R5+1]`, `[R4+6..9]`, indexing `[R7 + R0*4]`), and the region Macaw
  discovers from that entry point is one large (~340-block) unit, not a
  small self-contained function. The individual character-level branches
  (`&`, `G`, `!`, `S`) still check out — see the confirmed-values table
  above — but the overall shape does not. Current understanding:
  [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **`0x801c` (on the path that sets up the dispatcher's R0 argument) is lifted
  by Macaw as ARM/A32-mode code** (`BL_i_A1`, `BX_A1`, `PSTATE_T => 0`),
  which is architecturally impossible on Cortex-M4F (M-profile has no ARM
  execution state at all). **Treat this as a discovery/mode anomaly, not
  trusted semantics** — do not derive conclusions about real firmware
  behavior from this specific lifted region without independent
  confirmation. See
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).

## Current blockers

**Primary blocker**: the whole-function replay of the AutoPilot dispatcher
with a real in-memory `&` packet still does not terminate, even after fixing
the calling-convention bug above. Diagnosis (via the same execution-tracing
technique): the loop's real termination does not depend on the packet
content or on the caller's R0 argument (both were tested directly and ruled
out). Current best hypothesis: `0x5274` and `0x5448` (real per-channel
"motor state" functions, called from inside the loop) very plausibly have
memory side effects — e.g. marking a channel processed — that the loop's
exit condition depends on. They are currently **opaquely stubbed** (treated
as black boxes with fresh symbolic register results and zero memory
effects), so if the real exit condition depends on such a write, it can
never be satisfied under the current approximation. This is believed to be a
**concrete execution / memory-side-effect modeling gap in the harness**, not
evidence of a real infinite loop in the firmware. See
[`docs/harness/protocol-harness-results.md`](harness/protocol-harness-results.md)
("Follow-up session") for the full diagnostic trail.

## Tooling gaps

- No lazy real-CFG execution for called functions yet — calls are either
  fully opaque (current) or would require manually lifting the whole
  transitive call graph up front. The supported middle ground
  (`MS.LookupFunctionHandle`'s lazy-registration mechanism, building a real
  CFG for a callee on first call) is understood but not implemented.
- No static-analysis tool (Ghidra) integrated yet — all cross-referencing
  and structure recovery so far has been either manual (the
  `autopilot_static_inventory` pass) or via Macaw's own discovery. See
  "Planned tool roles" in [`docs/architecture.md`](architecture.md).
- No concrete-execution engine (Unicorn) integrated yet — there is currently
  no fast way to concretely run firmware to a checkpoint and snapshot state
  for seeding a subsequent symbolic run; everything goes through
  Crucible/What4, which is precise but comparatively heavyweight for pure
  concrete replay.
- No independent disassembler cross-check of the Thumb-2 decode yet
  (arm-none-eabi-objdump / Capstone; neither installed on the dev machine as
  of this writing). Not currently blocking anything, but listed in
  [`docs/firmware/cortexm-assessment.md`](firmware/cortexm-assessment.md) as
  an open item.

## Open research questions

Protocol-level (see [`docs/protocol/open-questions.md`](protocol/open-questions.md)
for the full, curated list): naming event-7's 11 fields, resolving the
`I<channel><mode>` numeric semantic, naming the `a0/a1/a2` states, whether
events 2/3/8/9/11/12/14 are truly unreachable, reconciling Remote-transmitted
packets (`MS|`, `MR|`, `N|`, `KK|`, ...) that don't fit the previously-assumed
dispatch tree.

Harness-level: what `0x5274`/`0x5448` actually do and whether they need to be
genuinely executed (not stubbed) to unblock the whole-function replay; whether
the `0x801c` ARM-mode anomaly is a Macaw/dismantle decode limitation worth
reporting upstream, or reflects genuinely dead/unreachable code.

## Explicit do-not-start-yet items

- **Do not move to the Remote (`mando`) firmware** until the AutoPilot-only
  `&` -> event 5 -> `V01R39` transaction works end to end (see "Current
  milestone").
- **Do not start Ghidra or Unicorn integration** until the current
  Macaw/Crucible-only blocker above is either resolved or explicitly
  deprioritized in favor of bringing in another tool for this specific gap.
- **Do not resume the parser/dispatcher symbolic-execution experiment**
  itself without first deciding, deliberately, whether to (a) implement
  lazy real-CFG calling for `0x5274`/`0x5448`, or (b) pursue a different
  approach — this was an explicit pause point, not an oversight.

## Next 3-5 concrete steps

1. Decide how to unblock the whole-function replay: implement lazy real-CFG
   execution for called functions (architecturally correct, more
   implementation work), or find a narrower workaround specific to
   `0x5274`/`0x5448` once their real behavior is understood.
2. Once the loop terminates: confirm `pending[5]` becomes 1 from a real
   in-memory `&` packet run through the *unmodified* whole dispatcher
   function (not just the isolated `0x888c` block).
3. Hook outbound transmission at `0x8c10`/`0x7f84` and verify the emitted
   bytes equal `V01R39` for the `&` transaction — this closes the AutoPilot
   milestone.
4. Independently verify `G`/`!`/`S`'s handlers perform their claimed
   event-scheduling writes (currently only handler-entry *reachability* is
   solver-verified for these three; the writes themselves were read
   statically from `pending-writes.csv`, not independently confirmed via
   the harness).
5. Only after (1)-(3): begin the Remote (`mando`) firmware work per
   [`docs/harness/roadmap.md`](harness/roadmap.md).

## Project direction: APTrace as a workbench, not a monolith

APTrace is moving toward wrapping specialized tools rather than forcing
Macaw/Crucible to do everything a full RE workflow needs. Planned roles
(not yet implemented beyond Macaw/Crucible/What4/Z3):

| Tool | Role |
|---|---|
| Ghidra | static RE / decompiler / xrefs / tables / structures / MMIO naming |
| Macaw | independent CFG and machine-code lifting |
| Unicorn | concrete Thumb execution and state snapshots |
| Crucible + What4 + Z3 | targeted symbolic reachability / input solving |
| APTrace | orchestration, evidence model, scenarios, traces, UI/workbench |

See [`docs/architecture.md`](architecture.md) for the fuller rationale and
how this reframes the earlier, more Macaw-centric assessment.

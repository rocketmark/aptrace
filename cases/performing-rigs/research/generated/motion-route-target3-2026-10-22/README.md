# Target3 — motion sink and route inventory

[Report](../../../docs/investigations/motion-initiation-route-coverage.md).
Case-owned APTrace operator evidence; original868 image; no hardware operations,
framework changes or formal model edits. Native output writes are simulated
requests, not actual movement.

## Reproduction and evidence

Run recorded commands individually from repository root, using the documented
direct CLI, into a **new output directory**. Preserve historical packet files.
Do not use a Python subprocess comparison wrapper or change security context.

- `concrete-commands.json`:23 exact commands, exit0, inputs and scope.5 original
  reset runs plus the additional nonzero W1 run make6 continuous runs;17 local
  helper/handler/fragment runs are separately labeled. Full negative guards stop
  at14M; local bounds1000/10000/20000 and stop points are in each command.
- `B1-full-reset.json`: only B1 RX packet, inactive ADC, no program/MC4/motion-
  state seed. TC0 enables while setup1 and markerff. Guard injections in
  `B1-latch-blocked.json`/`B1-busy-blocked.json` prevent start within14M.
- `G-to-enable.json`: prior HIGH-trigger G witness continued past0x6fd8 into
  the common profile/evaluator and ENABLE/live writes.
- `W1-to-enable.json`: earlier zero-timing program frame; timer initiation with
  no external acceptance or G. `W1-nonzero-to-enable.json` uses the original
  Remote-built nonzero timing/ramp profile and independently reaches the sink.
- `enable-ch*.json`: selected timer/auxiliary dispatch, plus invalid4 control.
- `period-*.json`: actual pulse/position increment when COUNT200>period100;
  equal/below controls do not pulse. Synthetic synchronized read completion and
  pin/delta/divisor state disclosed. CTRLA remains0 in these calls.
- `group-*.json`: original group fragment with primary0 and secondary1; ratio0
  and raised threshold suppress secondary. No natural group arming claimed.
- `handler-ch*.json`: original TC0..3 and auxiliary handler bodies called
  directly. No automatic IRQ delivery, timer clock or physical pulse assumed.
- `outcomes.json`, `checks.json`, `check-artifacts.py`:110/110 artifact checks.
  From root: `python3 cases/performing-rigs/research/generated/motion-route-target3-2026-10-22/check-artifacts.py`.
  This script only compares artifacts; it does not execute or interpret firmware.
- `sink-inventory.json`, `routes.json`, `graph-coverage.json`: inventory and
  evidence strength. A scheduler/state edge is not mislabeled a direct call.
- `macaw-expanded.json`: fresh independent vector-root expansion, no Ghidra
  seeds.263 functions/3521 blocks;199 incomplete terminators/48 residual failures.
  `macaw-route-extract.json` retains relevant calls/coverage.53 indirect-call
  records at31 sites include switch tables and overlapping owners, not53 proven
  callbacks. `group-macaw-assisted.txt` is explicitly assisted discovery seeded
  at0x5994 from native evidence.
- Ghidra `.txt` queries: sink/caller/handler/native-instruction and pointer
  evidence, including missing standalone functions at tail/group targets. Unknown
  function names are not absence proofs. Function ownership may overlap.
- `enable-effects-ch0.*`: rejected whole-helper abstract coverage; TBB became an
  opaque computed call and zero writes were simulated. Raw status“complete” is
  not instruction completeness; the agent adapter already marks computed-call
  coverage bounded.
- `enable-arm-effects.*`: finite complete0x5820 suffix, no calls, literal/count /
  CTRLA reads and writes with TRUE guards. Solver queries are smoke/range facts,
  not an unauthorized-motion theorem. Original instructions/controls validate the
  actual selected arm. No new SMT harness is introduced.
- `static-commands.json`, `reused-evidence.json`, `manifest.json`,
  `artifact-hashes.json`: reproduction/provenance, including unchanged models.

Timer-start and output-emission are different boundaries. A callback/group or
period-maintenance pulse can occur without a new ENABLE transition. Control GPIO
and TMC power/configuration requests remain distinct from motor STEP generation.
Auxiliary PB22 is not established as a fifth motor. Graph completeness, natural
completion/re-arm and timer/IRQ/STOP behavior remain unresolved.

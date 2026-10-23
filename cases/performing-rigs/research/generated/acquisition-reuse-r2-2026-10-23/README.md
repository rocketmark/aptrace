# Acquisition-reuse R2 evidence packet

**RESEARCH ONLY — NOT FOR HARDWARE DEPLOYMENT.**

The [report](../../../docs/investigations/stateful-patch-acquisition-reuse.md)
explains the policy, implementation, two rejected iterations, results and gaps.
This final image passes3,979 artifact checks across73 matrix records with no
failures/pending cases. It reduces median whole analog live poll work501→409
instructions (18.4%), while digital busy work rises158→210 (32.9%). Analog
recognition is10 modeled ticks later. This is a bounded analog improvement,
not a generally faster or deployable replacement.

## Identity and contents

- Image: `RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_reuse_r2.bin`,71,904 bytes,
  SHA-256 `f20e2004830c1daad818bdfd6155917fe2ab05205fb7c688be1a5358c7ea128a`.
- Source/packager: `reuse.S`, `generate-patch.py`; exact original image and
  displaced bytes are asserted. `modification-manifest.json` records the40 changed
  original bytes in nine ranges,1,136-byte extension and64-byte reservation.
- `manifest.json`: final file/hash inventory, compressed and decompressed trace
  identities, execution counts and protected baseline identities.
- `outcomes.json`, `checks.json`: saved-artifact comparisons, workload, latency,
  profile ages, every sampled CC0 calculation, driver requests and test verdicts.
- `optimized-*.json.gz`:31 freshly executed candidate matrix histories.
- 32 public CLI support outputs: G/W1/B1, reset/allocator, two native frame checks,
  three frozen evaluator controls and22 classifier/policy fragments.
- `prefix-frame-digital.json.gz`: additional20M-instruction natural W/return
  witness with pre-phase fallback frame observations.
- `ghidra-build.txt`, `ghidra-meta.json`, `inserted-disassembly.txt`: independent
  decoding and analysis identity. Original acquisition/caller/xref listings remain
  in the immutable [initial packet](../acquisition-reuse-2026-10-23/).

The initial packet is **REJECTED**: early return LOW causes2 starts where Phase3
has1. [R1](../acquisition-reuse-r1-2026-10-23/) is **REJECTED**: its conservative
eligibility predicate misses a fresh500 input (1 start versus Phase3's2).
Both checkers retain their expected failing assertion and all witnesses. Do not
substitute either image for R2. R2 uses a fresh pre-phase fallback where W/return
can change eligibility; it adds no eligibility rule and skips duplicate policy
updates in that poll. Ordinary analog qualification requires actual raw ADC and
paired native filtered result; cached-only returns invalidate pending state.
Digital busy release retains a bounded fallback read. Final fresh gate and
50 inactive /50 active /20 maximum-gap policy remain.

## Reproduce

Run from the repository root with the installed APTrace environment. Native runs
need the reviewed execution context documented in the report; sandbox-only Unicorn
execution has an established host SIGILL limitation. No new dependency or emulator
is needed. Saved runs use Python3.9.6, Unicorn2.1.4, Ghidra12.1.3 and installed
Apple clang21. Exact Ghidra/script identities are in `ghidra-meta.json`.

Set a shell variable for convenience:

```sh
packet=cases/performing-rigs/research/generated/acquisition-reuse-r2-2026-10-23
python3 "$packet/generate-patch.py"
tools/unicorn/.venv/bin/python3 "$packet/run-experiments.py" --image optimized --case digital-500
tools/unicorn/.venv/bin/python3 "$packet/run-experiments.py" --image optimized --case analog-500
tools/unicorn/.venv/bin/python3 "$packet/return-edge.py" --image optimized
tools/unicorn/.venv/bin/python3 "$packet/return-edge-late.py" --image optimized
tools/unicorn/.venv/bin/python3 "$packet/run-batch.py" 0
tools/unicorn/.venv/bin/python3 "$packet/run-batch.py" 1
tools/unicorn/.venv/bin/python3 "$packet/run-batch.py" 2
tools/unicorn/.venv/bin/python3 "$packet/run-support.py"
tools/unicorn/.venv/bin/python3 "$packet/prefix-frame.py" --image optimized
python3 "$packet/check-artifacts.py"
```

The four explicit histories plus27 batched cases constitute31 candidate matrix
runs. `batches.json` records the split. All native public CLI argument lists for
support controls are preserved in `support-commands.json` and component command
files; `run-support.py` only invokes them. Input recipes call existing
ConcreteMachine/CLI parser operations; they supply inputs, disclosed adversarial
memory/time perturbations and watch points. They do not implement firmware policy
or replace an APTrace backend. `check-artifacts.py` checks saved evidence only.
Ghidra commands are recorded in `static-commands.txt`.

The checker deliberately reads immutable controls from the initial packet
(11 original and30 Phase3 histories) and R1 (one additional Phase3 late-edge
history), giving73 records including31 fresh R2 histories. These controls were
executed for this experiment, not replayed again for each correction. Their
source recipes and image hashes are checked. Do not rerun this final recipe with
`--image phase3` into R2 and claim those are the recorded controls: original
fixtures, provenance tags and exact seeds remain in their baseline packets.

Default instruction-paced time adds one millis tick per4,000 guest instructions;
SysTick/ADC/radio/TC-ready stand-ins match the disclosed prior recipes. Main runs
are bounded16M instructions, held/repress/release-motion65M, return-edge and prefix
witnesses20M. This does not validate physical500ms latency or continuous STEP/NVIC.
Mode/cache/gap tests include explicit state perturbations; seeded fragment and
frozen evaluator controls establish local native behavior, not natural provenance.
Frozen evaluator calls bypass admission solely to compare equal elapsed/feedback.
Full register/IRQ/writer closure, flash ownership and physical motor preservation
remain open. No hardware was flashed and no framework, apfw2, formal model or
completed gate was modified.

`protected-baselines.json` pins prior images, Phase3/timing evidence, models/gates,
and both rejected packets. R2's generator was rerun after all native executions
and produced the identical image hash. `manifest.json` excludes its own hash;
all other packet files are inventoried. Re-execution can replace R2 outputs, so
archive this packet before conducting a different experiment.

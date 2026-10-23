# Stateful motor-timing investigation packet

**Simulation-only evidence. Existing research firmware remains NOT FOR HARDWARE
DEPLOYMENT. No new or modified firmware is present in this packet.**

Interpretation: [motor-timing report](../../../docs/investigations/stateful-patch-motor-timing-preservation.md).
`baseline-identities.json` pins original915, first patch, Phase3 stateful binary,
assembly, generator, modification manifest and original input recipe. The final
`manifest.json` inventories commands/artifacts, decompressed snapshot hashes and
verification of prior protected evidence. All commands run from repository root.

## Primary matched executions

`observe.py` is an observation-only extension of the immutable Phase3 recipe.
It uses existing public ConcreteMachine/CLI parsing, unchanged input waveforms,
modeled GPIO/ADC/RX and native application instructions. It adds sparse register/
memory observations and helper-entry counts; no shadow controller, firmware
calculation, interpreter or new clock implementation is supplied. Run each image
with each case:

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/observe.py --image original --case digital-500
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/observe.py --image first --case digital-500
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/observe.py --image stateful --case digital-500
```

Repeat these three commands with `--case analog-500` for the analog witnesses.
Default `--period 4000` increments the firmware millis counter every4,000 guest
instructions. Each ordinary bound is16M instructions; two analog runs report a
three-instruction overrun in the existing engine. Snapshot names encode image,
case and tick parameter. Full instruction coordinates, clocks and watched globals
are in `*.json.gz`; `analysis.json` presents timelines, aligned CC0 samples,
workload, prepared-state comparisons and frozen/continuation control results.

The observation-only extension preserves original input edges and first TC0 values
from Phase3. All MMIO readiness, radio-ID, DWT and no-autonomous-NVIC assumptions
remain. GPIO-helper entry totals include other pins. Count/position feedback is0;
no physical waveform or CPU-cycle calibration is implied.

## Native state and clock controls

Three `capture-start.py` runs (same image/case arguments as above) stop at native
`0x6362`, capturing complete RAM, TC0 and SysTick/PPB state for provenance. Their
names start `capture-`. These are separately initialized, actual native runs.

`frozen-commands.json` contains exact structured public CLI argument arrays for
nine native `0x6338(0)` calls. All images receive the same captured original
prepared global region `[0x20000000,0x20005400)`, TC0 and clock state. The counter
selects profile age51/52/53ms and is then held fixed. These are disclosed seeded
evaluator controls, not end-to-end trigger acceptance. Execute them with:

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/run-frozen.py
```

`run-frozen.py` only invokes recorded public CLI commands. It implements no firmware
semantics. At equivalent input age all three images match, including ordered TC0
writes. Changing age reproduces every disputed first CC0 value.

For ongoing-scheduling controls, `resume.py` starts normally with4000-instruction
ticks, stops before `0x635e`, saves `resume-prefix-*.json.gz`, then uses the existing
`fresh=False` native continuation with SP preserved on the same machine. Only a
labeled clock-counter seed (profile origin+3ms) and the chosen tick period change.
CPU/FPU/RAM/MMIO remain native. Each continuation lasts2M instructions.

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/resume.py --image original --case digital-500 --period 4000
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/resume.py --image stateful --case digital-500 --period 4000
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/resume.py --image original --case digital-500 --period 2000
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/resume.py --image stateful --case digital-500 --period 2000
```

The controls align first evaluator age, not every absolute UI/scheduler deadline.
They deliberately reset the instruction-count epoch used by the fake tick; this
is a diagnostic model intervention, not a physical-time measurement.

Two `observe.py --period 2000` runs from reset (original/stateful) never reach the
runtime setup boundary within16M. They are retained and excluded from motor
comparisons. They show why changing all startup timing is not a clean control.

## Static evidence and arithmetic checks

`static-commands.txt` preserves the APTrace Ghidra and p-code invocations. Use the
installed Java environment shown there. Ghidra version12.1.3, Unicorn2.1.4 and
Python3.9.6 were used. `pcode-initial.json` preserves an unsupported request at a
store that does not define R0; `pcode-dataflow.json` contains the corrected local
origins. P-code does not close cross-function floating-point semantics; native
registers and scalar arithmetic checks supply the finite witnesses.

```sh
python3 cases/performing-rigs/research/generated/stateful-motor-timing-2026-10-23/analyze.py
```

The analyzer reads saved snapshots only, checks their observed polynomial/raw
period/scaled CC0 relationships, compares frozen outputs and prepared motion
regions, and emits `analysis.json`/`checks.json`. It neither executes firmware nor
replaces APTrace analysis. See those outputs for the exact check total/verdict.

## Failed attempts and execution context

Three broad-observation snapshots and their source are retained under
`watch-cap-attempts/`: watching a common GPIO helper filled100,000 watch hits
before startup finished. They are incomplete, not successful motor traces.
Sparse watches/counting corrected the observation scope, with no binary change.

A sandboxed frozen-CLI launch terminated with host SIGILL before guest evidence.
The already-established reviewed native execution context succeeded; no framework,
toolchain, security-setting or hardware change was made. Reproduction may require
that execution context. Read the report for capability gaps and remaining unknowns.

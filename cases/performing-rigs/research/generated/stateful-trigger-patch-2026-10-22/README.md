# Stateful trigger patch — evidence packet

**SIMULATION RESEARCH ONLY. All firmware/ELF artifacts are NOT FOR HARDWARE
DEPLOYMENT. No physical flash-space, bootloader or release compatibility approval.**

The [Phase 3 report](../../../docs/investigations/stateful-trigger-qualification-phase3.md)
is the interpretation and limitation record. `modification-manifest.json` specifies
all five original-region replacements, the616-byte extension, symbols, source/
output hashes and64-byte explicit BSS/heap reservation. `stateful.S` is the actual
firmware implementation, not a harness policy. `stateful.o` is its intermediate
Thumb ELF object. Exact915 only; the original and first patch remain immutable.

From repository root, using existing installed tools:

```sh
python3 cases/performing-rigs/research/generated/stateful-trigger-patch-2026-10-22/generate-patch.py
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-trigger-patch-2026-10-22/run-experiments.py --image original --suite
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-trigger-patch-2026-10-22/run-experiments.py --image first --suite
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/stateful-trigger-patch-2026-10-22/run-experiments.py --image stateful --suite
python3 cases/performing-rigs/research/generated/stateful-trigger-patch-2026-10-22/check-artifacts.py
```

An individual recipe accepts `--image original|first|stateful --case digital-500`
(or another checked-in case name). Suites overwrite their own generated snapshots;
preserve this packet before modifying recipes or candidates. Do not change the
recipe or binary during a campaign. The timed runner initially encountered host
SIGILL132 in the default sandbox before guest execution; the same command worked
in the reviewed execution context. This is not a guest failure. No installation
or toolchain modification was used to resolve it.

`run-experiments.py` uses the existing public APTrace ConcreteMachine and CLI
argument parser, with case-owned sparse GPIO/ADC/RX hooks. It reuses the first
patch packet's `intentional-original-command.txt`. Inputs are delivered at logged
native PCs/ticks; native firmware executes all trigger qualification and motion
choices. Ordinary cases16M guest instructions; held-W/repress-W65M. One tick per
4,000 guest instructions, not a calibrated physical millisecond. All cases start
fresh from reset with the established DWT, radio-ID and MMIO readiness stand-ins.
The recipe logs every changed external input and supplied command, initial image
and fixture hashes, milestone times and bounded poll cadence. Only `invalid-state`
intentionally corrupts policy memory. `*-before-commit` and `*-pc-transient` are
explicit PC-phase interventions, not captured physical waveforms.

The matrix has11 core cases across3 images plus7 additional stateful probes.
`*-*.json.gz` snapshots preserve native register/memory/write evidence and
`external_fixture` provenance. `outcomes.json` presents counts/timing/streams;
`checks.json` records saved-artifact assertions. Those assertions are regression
checks against bounded intended results, not independent universal verification.
Watch `0x8f9c` for true acceptance: new `0x8f98` is only an attempt that can veto.
Rejected cases have no rate/TC0-enable/live boundary in their full executed bound.
Watch-hit/no-drop checks constrain recorded coverage; unobserved producers remain
outside scope. The checker does not execute or emulate firmware.

`*-command.txt` files preserve exact public CLI invocations for intentional smoke,
caller-frame, reset, B1/G/W1 controls. Direct command comparisons reuse historical
original915 baselines from the first-patch packet; they are not newly rerun original
controls. `original-heap-allocator.json` and `reserved-heap-allocator.json` preserve
the direct original/patched allocator probes. Full qualification-state write
ownership is captured in the intentional CLI smoke, not asserted as an exhaustive
whole-program alias proof. Allocator command reconstruction is recorded in
`allocator-commands.txt`.

Independent static evidence is provided in `original-boundaries.txt`,
`startup-allocation.txt`, `heap-boundary-listing.txt`, `allocator-contract.txt`,
`prologue-listing.txt`, `reject-epilogue.txt`, `program-boundary.txt`,
`config-boundary.txt`, `inserted-disassembly.txt`, `accept-detour-disassembly.txt`
and `reset-reservation-disassembly.txt`. Existing APTrace/Ghidra commands:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py --help
```

Use the case `autopilot915` or additive `autopilot915_stateful_research` registry
key with the corresponding decompile/disasm/build operations described by that
CLI. Do not run simultaneous operations against the same Ghidra project.

`execution-manifest.json` records local engine versions, command provenance and
artifact identities (compressed and decompressed snapshots). Reproduction uses
Python3.9.6, Unicorn2.1.4, installed clang21.0.0 and Ghidra12.1.3 in this execution
environment. This packet contains no forced-counter continuation, no physical
flashing instructions and no Gate5 or new gate campaign. See the report for the
sustained-fault counterexample, post-commit limit, extra acquisition overhead,
timer-period/write-stream differences and unresolved continuous STEP output.

Fixture correction: the initial X2 positive-control recipe used a225-count resting
level, active in X2, and correctly never armed. The saved initial source is
`run-experiments-initial.py`; the original witness is
`stateful-analog-x2-invalid-resting225.json.gz`. The final `run-experiments.py`
changes only that case's resting level to517 and reruns only that case. Earlier
snapshots identify the initial source hash; the corrected X2 snapshot identifies
the final hash. `checks-before-x2-fixture-correction.json` preserves the partial
checker's two failed positive-control expectations. No candidate binary changed.

Final matrix:40 executions;261/261 saved-artifact checks pass, no pending cases.
Generator reproduction matches the recorded image hash. Supporting snapshots and
the preserved invalid-resting X2 witness remain separate from these40 matrix cases.

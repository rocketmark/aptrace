# Recovered Noxon trigger behavior — bounded descriptive model

2026-10-22. This package models the original AutoPilot868 software path;
[the proposed controller](../trigger-acceptance/README.md) is unchanged.
The [investigation report](../../docs/investigations/noxon-trigger-state-machine.md)
is the principal assessment. No universal firmware proof or physical reliability
claim follows from these checks.

## Contents and reproduction

- `NoxonTrigger.tla`: channel0 acquisition/classification, native eligibility,
  accepted reload, profile-rate call, timer enable and live-state transitions.
- `NativeFixtures.tla`: generated finite native histories and **independent output
  checkpoints**. `trace-correspondence.json` maps each formal input/checkpoint
  index to the original PC/instruction. `outcomes.json` gives compact witnesses.
- `DirectG.tla` / `DirectFixtures.tla`: separate fresh-sequence G branch and
  target-minus-current request boundary, with four native endpoint comparisons.
- `ReferenceReplay.tla`: imports the unchanged proposed controller and supplies
  the same acquisition histories, under explicitly optimistic adapter/validator
  assumptions. It does not impose Noxon's gates on the reference controller.
- `verification/*.log`: complete TLC runs/counterexamples, including mutation
  controls. `verification/initial/` preserves meaningful modeling mistakes.
- `project-fixtures.py`: read-only artifact projection, not a firmware runner,
  numerical filter implementation or replacement trigger controller.

From this directory:

```sh
python3 project-fixtures.py
./check-models.sh
./check-comparisons.sh
```

Use the existing pinned TLC jar/Java from `verification/toolchain.json`; scripts
accept `TLA_JAR` and `TLA_JAVA`. They do not download/install anything. Expected
exit12/13 counterexamples are successful **experiments**, not safety passes.
`check-models.sh` checks both status and diagnostic. `check-comparisons.sh`
requires exit0/no-error for both models. No deadlock claim is made; terminal
replay states legitimately stutter. Weak fairness of replay advancement proves
completion of the finite histories, not physical timing.

The native execution commands remain in the original source packets listed by
`trace-correspondence.json` and the report. Reproduce them individually through
APTrace's documented direct CLI, into a **new output directory**. Do not overwrite
historical evidence or use the macOS subprocess comparison wrapper. This task
reused the fixed-hook native witnesses; it did not rerun or alter the binaries.

## Abstraction contract

This is a finite, trace-conditioned descriptive transition model, **not a
binary-to-TLA refinement proof or an arbitrary-waveform verifier**. Initial
state starts at the previously established volatile trigger-subsystem boundary;
program, MC4, X and TR transitions enter at their native observed boundaries.
Upper-layer producers are not reimplemented. The mode comes from original boot
selection. All principal profiles use one valid nonzero motor record.

Current MMIO input, actual ADC acquisition (`0x42d4`), returned filtered integer
(`0x8e7a`), sampled digital register (`0x922c`), classification, acceptance and
initiation are separate. Float arithmetic/clock deadlines are native oracles:
there is no claim to verify alpha, rounding or elapsed time inside TLC. Cached
returns retain their acquisition serial. The due profile-rate opportunity is
also a native oracle at `0x5f8c`: the model checks that it follows prepared
profile state, but **does not independently predict its deadline, rate or
whether an arbitrary accepted profile will ever reach it**. The timer-enable
and live-write actions are scheduled by native call/PC observations; terminal
TC0 ENABLE/live values and intermediate software state are compared independently.
Thus initiation correspondence is conditional on the recovered evaluator/call
schedule, not an independently computed motion simulation.

The formal classifier/gates/reload outputs are not read from expected counts.
Those counts and native channel/idle/live/ENABLE values only enter checkpoint
assertions. Three deliberately wrong models fail correspondence. This gives
useful falsifiability without overstating completeness. Deterministic histories
have no exploration of extra electrical interleavings. Passing them is replay
validation within bounds, never an exhaustive original-firmware safety proof.

Unknown completion, natural eligibility restoration, STOP and reset while moving
are deliberately absent. Their properties are **unresolved**, not passing because
there is no such action. Direct G ends at `0x6fd8` entry; profile initiation ends
after ENABLE/live writes. Neither means physical movement.

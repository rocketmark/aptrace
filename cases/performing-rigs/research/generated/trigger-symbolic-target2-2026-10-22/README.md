# Target2 — feasible digital binary reachability

[Report](../../../docs/investigations/trigger-symbolic-reachability-target2.md).
Original868 image, existing APTrace operator interfaces only. No implementation,
firmware, proposed controller or hardware changes.

## Evidence and reproduction

Run commands from repository root into **new output locations**. The symbolic
command has fixed `/tmp/aptrace_crosscheck_*` filenames; archive one run before
another uses them. Do not run two instances concurrently.

```sh
external/macaw/dist-newstyle/build/aarch64-osx/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace trigger-crosscheck cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin
```

- `crosscheck-868.log`, `solver-results.json`: two SAT/eight UNSAT results. A/B
  cover0x9202→0x9226 with symbolic seven-state cells and fixed r5/r6. C covers
  captured-R0 branch0x922c→0x8f98. No GPIO/float/profile helper is symbolically
  executed. Positive SAT anchors guard against vacuous negatives.
- `aptrace_crosscheck_*.smt2.gz`:16 lossless standalone/interaction dumps for
  the eight gate queries. `solver-artifacts.json` stores source names, lengths
  and decompressed SHA256. Uncompress a standalone file to a new scratch path
  and run installed `z3 -T:30 PATH`. Positive and TR-exclusion standalone
  replays/logs are preserved. C's preset interface does not expose a dump path;
  reproduce it through the command/source hashes.
- `gate-smt-pcs.json`: original location comments; initial odd locations reflect
  the explicit Thumb seed, not new native instruction addresses.
- `concrete-commands.json`, `additional-concrete-commands.json`:22 final native
  fragment commands and stop expectations, including initial three unmapped
  GPIO-seed failures. The corrected existing MMIO geometry is disclosed.
  These are injected-entry tests, not normal full-reset/motion witnesses.
- `concrete-checks.json`:22/22 exact boundary checks. Pre-read state negatives,
  captured-register controls, byte-width idle control, analog band endpoints,
  and an artificial post-read invalid-state control. All final runs exit0.
- `digital-native.txt`, `digitalRead-native.txt`, `analog-native.txt`,
  `X-writers-native.txt`, `analog-pointers.txt`, `digitalRead.txt`: public
  Ghidra queries; instructions take precedence over decompiler guesses.
- `native-correspondence.json`: ten hash-bound existing continuous witnesses
  joining normal startup/program, sampled/filter decision, reload and profile
  initiation. They are reused, not rerun or overwritten.
- `commands.json`, `manifest.json`, `artifact-hashes.json`: complete query /
  tool/source provenance. The proposed and descriptive TLA+ sources remain
  unchanged; this task performs no new TLC run or binary-refinement proof.

## Interpretation

The local digital condition is seven guards **before** digitalRead and
capturedR0=0 **after** it. Current GPIO and guard cells are not rechecked in the
post-read block. The invalid-post-state experiment proves that instruction fact;
it does not establish a natural interrupt/command race. The model's combined
classification/gate step assumes no intervening eligibility writer.

Analog classification has static/native controls, not a new arbitrary-history
SMT proof. Existing public commands cannot express the requested analog slice
with appropriate pointer/state inputs; existing internal support is not treated
as an exposed operator capability. Filter history and profile evaluator timing
remain native evidence/oracle boundaries. No Target3 route audit is performed.

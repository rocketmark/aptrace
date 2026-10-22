# Startup baseline dependency — Target1

See [report](../../../docs/investigations/startup-voltage-learning.md).

Seven normal-reset original868/915 runs compare startup225 versus900 with the
same subsequent225 input. Two RAM result-cell crossovers and a filter-only
control separate the causes. No firmware/hardware/framework change was made.

- `commands.json`: exact direct CLI commands, exit0, snapshot hashes and input /
  intervention descriptions. Run from repository root into **new output paths**;
  do not overwrite this packet. Do not execute them through a Python subprocess
  comparison wrapper or change macOS security context.
- Named native JSON snapshots: original filter/acquisition, baseline-return,
  acceptance and profile timer-initiation boundaries, address-based CPU writes.
- `outcomes.json`: values, PCs/instruction indices, counts and derived outcomes.
- `check-artifacts.py`, `checks.json`: artifact comparisons/checks,44/44 pass.
  No instruction decoder, filter simulator or firmware runner is implemented.
  From repository root: `python3 cases/performing-rigs/research/generated/startup-baseline-2026-10-22/check-artifacts.py`.
- `baseline-*868.txt`, `baseline-path-915.txt`, `input-path-868.txt`, xref files,
  pointer table: normal APTrace Ghidra queries. `baseline-915.txt` is the empty
  initial query output before the915 project existed; successful build and
  follow-up output are retained separately.
- `baseline-forward-use.json`: public p-code driver returns MEMORY_ESCAPE for
  average/low flag origins. It does not follow stored memory/aliases. Initial
  scratch-directory error is retained; final query succeeds.
- `baseline-effects.*`, `trigger-effects.*`: public Macaw/Crucible/What4/Z3
  effects operations. Raw statuses partial/bounded, not complete proofs.
  `symbolic-assessment.json` keeps assumptions, coverage and query results.
  Baseline enrichment includes one UNKNOWN and completes normally. Trigger
  guard/refutation UNSAT pairs are not an accepted feasibility/nondependence
  proof. No relational baseline-independence query was performed.
- `macaw-coverage.json`: bounded extraction from prior independent expanded
  census, not a fresh discovery run. Source hash/path included.
- `variant-region-identity.json`: read-only byte equality for targeted routine
  regions. Does not establish whole-image or physical equivalence.
- `static-and-symbolic-commands.json`, `manifest.json`, `artifact-hashes.json`:
  reproducibility and provenance. Historical artifacts and binaries unchanged.

MCU ADC counts are not source/jack volts. PA02-selected modes are not assigned
relay/12V/24V product labels. An ENABLE/live write is not physical movement.
Absence of an ordinary xref is not a whole-program memory-alias theorem.

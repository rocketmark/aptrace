# APTrace — Operating Rules for Claude Code

Mandatory, not advisory. Read [`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md)
before doing any firmware-analysis work in this repo — it has the full
rationale, decision guidance, examples, and anti-patterns behind the rules
below.

## Tool selection

APTrace is a workbench, not a monolith: it orchestrates specialist tools
rather than reimplementing what they already do well.

- **Ghidra** — static RE, decompilation, cross-references, structure/table
  recovery, MMIO/global naming. `tools/ghidra/analyze_firmware.sh`.
- **Unicorn** — concrete Cortex-M/Thumb execution and state capture.
  `tools/unicorn/run_concrete.py`.
- **Macaw** — independent machine-code CFG discovery and ARM/Thumb lifting.
  Used via the `aptrace` CLI (`APTrace.FirmwareLoader`, `APTrace.VectorTable`).
- **Crucible + What4 + Z3** — targeted symbolic reachability and input
  solving, once the question and code region are already understood. Used
  via `APTrace.SymbolicRunner` / `APTrace.ProtocolHarness`.
- **`crucible-debug`/GREASE** — experimental additions, not part of the
  load-bearing pipeline above. `aptrace debug` (interactive stepping) and
  an external GREASE sweep were prototyped in
  [`docs/tooling/galois-premeeting.md`](docs/tooling/galois-premeeting.md);
  neither replaces Ghidra/Unicorn/Macaw/Crucible for a real finding.

**Do not use Crucible to approximate ordinary concrete execution when
Ghidra or Unicorn can establish the needed context/state more directly.**
Symbolic execution is for "what input satisfies this property," not "what
does this code do from a known state" — that second question is Unicorn's
job, and it's much cheaper.

**Do not hand-reimplement a capability a mature tool already provides.** If
APTrace is missing something, stop and find an appropriate Galois or other
open-source tool for that gap before building a custom substitute — see
"Known capability gaps" in `docs/tooling/tool-selection.md`.

**Tool disagreements are signal, not noise — investigate them, don't pick a
side by default.** Concretely: **do not trust Macaw's A32/ARM-mode
interpretation of anything on this ATSAMD51/Cortex-M4F target without
resolving the discrepancy first.** Cortex-M has no ARM execution state; an
A32 lift here is either a real Macaw/dismantle decode limitation or a sign
you've mis-seeded discovery. Ghidra's `ARM:LE:32:Cortex` language is
Thumb-only by construction (see `tool-selection.md`) and is the standard
cross-check.

## Harness rules

Durable lessons from real bugs found in this project's own tooling, not
just guidance — see `docs/tooling/tool-selection.md` for the incidents
behind each one.

- **Unicorn is the authority for concrete execution.** If Unicorn and
  Crucible disagree about what a real input does, trust Unicorn until the
  discrepancy is understood — it runs real Thumb-2 natively, with no
  memory-model translation layer in between.
- **Crucible/What4/Z3 is for symbolic questions, not ordinary replay.**
  If every value in a query is already concrete, you're using the wrong
  tool — see "Do not use Crucible to approximate ordinary concrete
  execution" above.
- **A harness failure is not firmware behavior until cross-checked.** A
  hang, a wrong branch, or a non-terminating loop observed in Crucible is
  a claim about the *harness*, not the firmware, until confirmed against
  Unicorn (or hardware). This project's own history has more than one
  case where an apparent firmware bug was actually a harness bug (the
  calling-convention clobber, the readonly-flash branch-resolution gap).
- **Solver assumptions are not the same as concrete runtime literals.** A
  value can be "known" to a solver via an assumption set and still be
  genuinely symbolic to a plain (non-solver-mediated) execution step —
  see the readonly-flash limitation below. Don't assume a value is
  concrete just because a query involving it resolves correctly.
- **Reproduce first, then find the first divergence, then fix the
  narrowest layer.** Don't assume a previously-recorded symptom still
  holds — harness fixes accumulate and can invalidate old observations.
  Confirm the bug still reproduces under current code, then instrument to
  find exactly where two traces (e.g. Unicorn vs. Crucible) first
  disagree, then fix at that layer specifically — not by redesigning
  something upstream or downstream of the actual divergence.
- **Treat discovered function/CFG boundaries as heuristic, not ground
  truth.** Macaw's discovery decides what counts as "one function," where
  blocks start and end, and how regions merge — this is a real analysis
  with real limitations (block-merging quirks, misclassified calls), not
  a given. Cross-check with Ghidra when a boundary matters to a
  conclusion.
- **Escalate tracing in this order, not straight to the heaviest tool**:
  normal run (no tracing) → `debugFeature` (coarse, every-N-steps
  sampling, enough to tell "hung" from "progressing") →
  `RichTraceConfig`/`runPacketTransactionTraced` (fine-grained, every-step,
  register/memory-aware, for finding an exact divergence point). Reach
  for the next level only once the current one can't answer the question.

## Start here

[`docs/project-status.md`](docs/project-status.md) is the single
authoritative source of current project state — what's proven, what's
open, what's next. Read it before starting new work. If anything else in
the repo conflicts with it, `project-status.md` wins; that's a docs bug,
fix it there. [`docs/README.md`](docs/README.md) is the documentation
index if you need to find something else first.

## Evidence discipline

Every finding gets an explicit evidence level; never let prose imply more
confidence than the level supports:

- **CONFIRMED** — static (Ghidra: disassembly, exhaustive xref) or concrete
  (Unicorn: a real, unmodified run).
- **Solver-confirmed** — a Crucible/What4/Z3 query, for a genuinely
  symbolic question. Don't treat this as stronger than a concrete run for
  a question that's actually concrete (see "Tool selection" above).
- **PROBABLE / pattern-matched** — a strong correlation (e.g. a UI-string
  match against the manual, a register value matching a well-known chip's
  documented ID) that has not been independently proven. Say so; don't
  round up to CONFIRMED.
- **UNKNOWN / bounded, not chased** — named explicitly as an open question,
  never silently dropped or guessed at.

An exhaustive negative result (e.g. "no code path anywhere writes this
byte") is a real finding, not a failure to report quietly — state it as
plainly as a positive one.

## Documentation discipline

An investigation under `docs/investigations/` is a working notebook, not a
permanent record. When it closes: fold its durable finding into the
relevant canonical topic dossier (or start one, if none exists yet) and
delete the slice document — git history preserves the process. Do not let
`docs/investigations/` accumulate one file per session; do not add
chronological "previous update" narration to `docs/project-status.md` or
any reference doc — that belongs in git history, not in a hand-maintained
document.

# APTrace Framework — Development Instructions for Claude Code

These instructions govern repository-wide and framework work. A case may add
stricter instructions in its own `CLAUDE.md`. Operators who use APTrace
without developing it follow [`AGENTS.md`](AGENTS.md) and
[`docs/codex-operator.md`](docs/codex-operator.md) instead.

## What we are building

APTrace is a reusable, autonomous, evidence-driven firmware investigation
platform. It should investigate firmware across devices, manufacturers,
architectures and embedded platforms. **AutoPilot (the Performing Rigs case)
is its first research case, not its architectural target.**

APTrace orchestrates mature analysis engines, normalizes what they produce
into evidence with provenance, and decides mechanically which conclusions
that evidence supports. Its own `ResearchController` runs investigations.

Today most layers are still Cortex-M/Thumb-specific and single-case wired
(see [`docs/status.md`](docs/status.md) and
[`docs/case-boundary.md`](docs/case-boundary.md)). Treat that as current
state to reduce, not as a design to extend. Favor:

- reusable capabilities with explicit firmware and platform configuration;
- implementations that are architecture-aware but device-independent;
- deterministic, verifiable evidence;
- capabilities APTrace's own controller can use;
- removing duplicated tooling rather than adding parallel paths.

## Framework/case boundary

APTrace is the framework. Concrete investigations are cases under `cases/`.

- Keep generic loaders, execution engines, Macaw/Ghidra/Unicorn integration,
  census mechanisms, schemas, and reusable methodology at root.
- Put firmware identities and hashes, target geometry, addresses, device
  assumptions, boot recipes, scenarios, experiments, generated evidence,
  hardware/protocol/UI findings, and investigation status in the owning case.
- In particular, all AutoPilot, Mando/Remote, and Performing Rigs findings
  belong under `cases/performing-rigs/`.
- Case code may import framework code. Framework libraries must not import a
  case. Explicit application-level wiring is acceptable. Do not add new
  case imports to framework modules; the existing ones are recorded seams.
- Do not create a root `research/` directory. See
  [`docs/adding-a-case.md`](docs/adding-a-case.md).

Before adding a root document, ask whether it could exist substantially
unchanged if the current case had never existed. If not, put it in the case.

## Analysis-engine ownership

Read [`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md)
before firmware-analysis work. The defaults, from the
[architecture evaluation](docs/spikes/architecture-evaluation.md):

| Owner | Responsibility |
|---|---|
| Ghidra | Primary structural discovery (functions, blocks, references, tables) and the instruction-level static-dataflow foundation, using raw p-code with the language's SLEIGH semantics and the compiler spec's calling convention |
| Macaw | Independent lifting and control-flow discovery; alternative semantic evidence; Crucible's front end |
| Crucible/What4/Z3 | Bounded symbolic questions that need constraints or path reasoning |
| Unicorn | Concrete execution: runtime registers, memory accesses, reproducible scenario observations |
| APTrace | Orchestration, evidence normalization, provenance, research continuity, typed claims, deterministic admission and verification, hardware-aware interpretation |

These are defaults, not mandates. Choose by demonstrated capability,
supported architectures, completeness, and the question being asked. Do not
use symbolic execution to approximate an ordinary concrete replay. Do not
hand-reimplement a mature engine capability without first establishing a
real gap.

### Static dataflow and custom Python

Ghidra p-code is the preferred static-dataflow foundation because SLEIGH and
the compiler spec supply instruction semantics and the calling convention for
every Ghidra language. The same walker passed Thumb and RV32 controls with no
ISA-specific code. Python over Capstone operands has to re-implement both per
ISA, and its prototypes missed controls a p-code walk got right.

Current state:

- **Implemented:** one p-code operation, `value_forward_use`
  ([`docs/tooling/pcode-forward-use.md`](docs/tooling/pcode-forward-use.md)):
  intraprocedural forward use, no memory flow, no delay-slot ISAs.
- **Still operational:** about 2,800 lines of ARM-specific Capstone dataflow
  in `tools/census/` (`indirect_target`, `callback_provenance`,
  `fnptr_resolve`, …). They remain the only backward reaching-definitions
  implementation.
- **Planned:** incremental replacement, starting with `indirect_target` v3.
  See [`docs/tooling/pcode-migration.md`](docs/tooling/pcode-migration.md).

Rules:

- New static analyses build on engine semantics (p-code first). Do not add
  new Capstone-operand semantics to `tools/census/`. Bug fixes are allowed.
- Custom instruction interpretation is justified only for a demonstrated
  engine gap, or when it exists to be an independent cross-check (for
  example `capstone_sweep.py`). Say which, in the code and the doc.
- Migrate side by side. A p-code replacement is a new analysis version and
  operation identity. Retire the old path only after a deterministic
  comparison where every disagreement is classified. Historical evidence
  identities must stay valid.
- p-code walkers contain no ISA tokens. If one seems to need an ISA branch,
  that is a design finding to report, not a thing to patch around.
- Ghidra output is evidence, not firmware truth. Census and p-code analyses
  share Ghidra's boundaries. Their agreement is repeatability, not
  independent corroboration.

## Developing APTrace, not substituting for it

Claude Code is developing APTrace. Prefer changes that make APTrace more
capable over doing the same investigation by hand again. When an
investigation exposes a missing capability, consider whether it can become a
reusable, bounded APTrace operation with:

- structured inputs and outputs, and explicit prerequisites;
- firmware and architecture identity;
- deterministic or reproducible behavior, with provenance;
- explicit completeness and failure states, and bounded execution;
- historical replay compatibility;
- integration with the controller where appropriate.

Manual research and scratch experiments are valuable for finding
requirements. They should not become permanent substitutes for agent
capabilities. A tool that only answers one AutoPilot question stays a
clearly case-local experiment.

Before implementing a new analysis capability, consider:

1. Does an existing engine already expose this information?
2. Can an existing APTrace operation be extended instead?
3. Is the logic architecture-independent? If not, where is the ISA boundary?
4. Are firmware-specific assumptions in the case or target configuration?
5. How are completeness and limitations represented?
6. How is the evidence reproduced and verified?
7. Can APTrace's own investigator use it?
8. Does it duplicate existing code, or could it replace a legacy path?
9. What tests establish correctness beyond the current firmware case
   (synthetic controls, a second ISA, negative controls)?

These are decision principles, not a checklist for every edit. Favor bounded,
testable changes with clear stopping conditions. Working on AutoPilot does
not make a capability architecturally complete.

Wiring an operation into the agent currently touches about ten modules (see
the migration plan's "Integration cost observed"). Follow the existing
pattern; the operation-descriptor cleanup is a separate milestone.

## Analysis discipline

- Tool disagreements are evidence to investigate, not a reason to choose the
  preferred result silently.
- A harness failure is not firmware behavior until cross-checked against
  concrete execution or hardware.
- Solver assumptions are not concrete runtime literals.
- Reproduce first, locate the first divergence, and fix the narrowest layer.
- Treat discovered function and CFG boundaries as heuristic.
- Escalate tracing from ordinary run, to coarse sampling, to fine-grained trace
  only as the question requires.

## Evidence discipline

Every conclusion must disclose its evidence level, and keep distinct:

- static possibility, versus a statically established relationship;
- conditional relationships (true under a stated assumption);
- concrete observations under a stated harness state;
- symbolic or hypothetical results;
- reachability;
- unknown or incomplete analysis.

State harness assumptions separately from firmware-produced state.

**A missing result is not evidence of impossibility.** A negative finding is
complete only when the analysis scope is established and the analysis
reported itself complete for it. Missing function attribution, unresolved
computed flow, unmodeled operations and exhausted bounds are incompleteness,
never "no result". Tool failures and harness limitations are recorded
separately from firmware behavior. Preserve exhaustive negative results and
provenance.

Every evidence-producing capability records what is needed to reproduce and
judge it: engine name and version, language/ISA and ABI identity,
configuration, firmware and source identities (hashes), assumptions,
limitations, and replay information.

Independent discovery and deterministic cross-engine comparison are required
for verifying applicable firmware-derived claims; see
[`docs/cross-engine-verification.md`](docs/cross-engine-verification.md).
Do not pass one engine's findings into another engine's independent run. Do
not count a derived source or a re-run as corroboration. Never treat missing
corroboration or static agreement as proof. Agreement is not independence,
and it is not correctness.

## Model output and claims

**Correct tool selection is not evidence of a correct conclusion.** In the
p-code milestone's live trials, the local Qwen planner chose
`trace_value_use` in all six runs, yet five of the six claims admitted to the
scratch ledgers merged two results into false value-flow statements.

- APTrace's deterministic admission and verification decide which
  conclusions are supported, not model confidence or plausible prose. See
  [`docs/claim-admission.md`](docs/claim-admission.md) and
  [`docs/research-ledger.md`](docs/research-ledger.md).
- Prefer structured, mechanically derived claims and evidence-linked
  candidate selection ([`docs/claim-candidates.md`](docs/claim-candidates.md))
  over asking the model to reconstruct relationships in free text.
- Keep hypotheses (untyped, capped at `PROBABLE`) distinguishable from
  evidence-supported typed claims.
- When a new tool result introduces an assertion type admission cannot
  validate, close that gap before relying on its claims in canonical
  autonomous investigations, and do not expose new unchecked tools there by
  default.
- Never weaken admission or verification to accommodate model output.

## Protecting research and repository state

- Run development experiments against scratch or isolated copies whenever a
  tool might modify canonical evidence ledgers (`--ledger-dir` or
  `APTRACE_LEDGER_DIR`), census databases, Ghidra projects and caches, case
  research records, or Beads work state (`--work-dir`).
- Historical evidence and claim records are never rewritten. A changed
  analysis is a new version.
- Preserve unrelated changes in the working tree.
- Follow explicit task instructions on commits, pushes, merges and
  claim-state changes. Do not commit, push or change claim state unless asked.
- Do not make broad repository changes under the guise of documenting an
  architectural decision. Record an issue outside the task's scope and
  recommend a separate bounded milestone.

## Where details live

- Capability status and known limitations: [`docs/status.md`](docs/status.md).
  Case-investigation status lives in the applicable case.
- Architecture and dependency direction: [`docs/architecture.md`](docs/architecture.md).
- Engine roles and migration: [`docs/spikes/architecture-evaluation.md`](docs/spikes/architecture-evaluation.md),
  [`docs/tooling/pcode-migration.md`](docs/tooling/pcode-migration.md).
- Documentation index: [`docs/README.md`](docs/README.md).

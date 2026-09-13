# APTrace Framework — Operating Rules for Claude Code

These instructions govern repository-wide and framework work. A case may add
stricter instructions in its own `CLAUDE.md`.

## Framework/case boundary

APTrace is the reusable analysis framework. Concrete investigations are cases
under `cases/`.

- Keep generic loaders, execution engines, Macaw/Ghidra/Unicorn integration,
  census mechanisms, schemas, and reusable methodology at root.
- Put firmware identities and hashes, target geometry, addresses, device
  assumptions, scenarios, experiments, generated evidence, hardware/protocol/UI
  findings, and investigation status in the owning case.
- In particular, all AutoPilot, Mando/Remote, and Performing Rigs findings
  belong under `cases/performing-rigs/`.
- Case code may import framework code. Framework libraries must not import a
  case. Explicit application-level wiring is acceptable.
- Do not create a root `research/` directory. See
  [`docs/adding-a-case.md`](docs/adding-a-case.md).

Before adding a root document, ask whether it could exist substantially
unchanged if the current case had never existed. If not, put it in the case.

## Tool selection

Read [`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md) before
firmware-analysis work. APTrace orchestrates specialist tools:

- Ghidra for static reverse engineering and structure recovery.
- Unicorn for concrete Cortex-M/Thumb execution and state capture.
- Macaw for independent control-flow discovery and machine-code lifting.
- Crucible, What4, and Z3 for targeted symbolic reachability/input questions.

Do not use symbolic execution to approximate an ordinary concrete replay. Do
not hand-reimplement mature tool capabilities without first establishing a real
gap.

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

Every conclusion must disclose its evidence level: static, concrete,
solver-confirmed, probable/pattern-matched, or unknown/bounded. State harness
assumptions separately from firmware-produced state. Preserve exhaustive
negative results and provenance.

Framework capability status lives in [`docs/status.md`](docs/status.md).
Case-investigation status lives in the applicable case.

# Tool Selection

APTrace coordinates specialist tools. Choose the cheapest tool that directly
answers the question and disclose the resulting evidence level.

| Question | Primary tool | Evidence |
|---|---|---|
| What code/data structure is present? | Ghidra | static |
| Where does a value flow inside a function (instruction-level dataflow)? | Ghidra p-code ([`pcode-forward-use.md`](pcode-forward-use.md)) | static |
| What does this known input do? | Unicorn | concrete for that modeled state |
| What control flow does an independent lifter recover? | Macaw | static/discovery |
| What input satisfies this bounded property? | Crucible + What4 + Z3 | solver-confirmed |

## Engine ownership

The ownership below was chosen in the
[architecture evaluation](../spikes/architecture-evaluation.md) (decision B).
These are defaults, not mandates. Choose by demonstrated capability,
supported architecture, completeness and the question being asked.

| Engine | Role | Current state |
|---|---|---|
| Ghidra | Primary structural discovery. Instruction semantics and intraprocedural dataflow over raw p-code, with the calling convention from the compiler spec. | Census structure: implemented. P-code dataflow: one operation, `value_forward_use`. Backward reaching definitions are still in Capstone-based census modules. |
| Ghidra decompiler | A cross-check and a stack-resolution aid. It is not primary evidence: its output depends on heuristics and on configuration such as memory permissions. | Used to show C text only. |
| Macaw | Independent discovery and lifting, and alternative semantic evidence. Its value is independence, so it is not the primary dataflow engine. | Upstream AArch32 discovery needs APTrace's `MacawExpand` repair. |
| Crucible/What4/Z3 | Bounded input and reachability questions over Macaw. | `function_effects` still uses unrepaired Macaw discovery, so it fails early on functions it cannot classify (for example, an early `cbz`). |
| Unicorn | Concrete observation under a stated harness state. It cannot establish an absence. | ARM Thumb/M-class mode is hard-coded; the architecture should become a parameter. |
| APTrace | Orchestration, policy (shape and closing rules, verdicts, completeness), evidence normalization, provenance, comparison, admission and verification. | Engine-neutral ledger envelope. |

### Custom instruction analysis

About 2,800 lines in `tools/census/` interpret ARM instructions over Capstone
operands, with hard-coded AAPCS sets. That is a second, ISA-specific semantics
engine. Its retirement plan is [`pcode-migration.md`](pcode-migration.md).

- New static analyses use engine semantics, p-code first.
- Existing Python resolvers stay in service until a side-by-side comparison
  establishes parity, or classifies every difference. A replacement is a new
  analysis version; historical evidence keeps its identity.
- Custom instruction interpretation is justified for a demonstrated engine
  gap, or when its purpose is an independent cross-check of Ghidra's decoder
  (`capstone_sweep.py`). Record which.
- Agreement between Ghidra-derived paths shares Ghidra's boundaries. It is
  repeatability, not independent corroboration.

## Operating rules

- Use Ghidra for decompilation, references, tables, strings, globals, and MMIO
  naming. Cross-check material function/CFG boundaries.
- Use Ghidra p-code for instruction-level dataflow; the language's SLEIGH
  spec and the compiler spec supply instruction semantics and the calling
  convention. Do not add new Capstone-operand semantics to `tools/census/`;
  its dataflow modules are scheduled for migration
  ([`pcode-migration.md`](pcode-migration.md)).
- Use Unicorn for concrete replay and state capture. A peripheral stand-in is a
  harness assumption, not firmware-produced evidence.
- Use Macaw as an independent machine-code discovery/lifting path. Cortex-M is
  Thumb-only; investigate any A32 interpretation rather than accepting it.
- Use symbolic execution only after the region and property are bounded. It is
  not a substitute for ordinary concrete replay.
- When tools disagree, reproduce the same input/state, locate the first
  divergence, and fix the narrowest responsible layer.
- Choosing a tool for a question is the agent's decision; the corroboration a
  claim needs before promotion is not. Verification policy, analysis
  independence, and cross-engine comparison are defined in
  [`../cross-engine-verification.md`](../cross-engine-verification.md).
  Agreement between static engines is corroboration, not proof of runtime
  behavior.

Escalate observability from a normal run, to coarse sampling, to fine-grained
tracing. Treat failures of a harness as harness findings until independently
confirmed.

The Performing Rigs cases that produced several of these durable lessons are
preserved in
[`tool-selection-case-notes.md`](../../cases/performing-rigs/docs/investigations/tool-selection-case-notes.md).

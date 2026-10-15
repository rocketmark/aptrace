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

# Tool Selection

APTrace coordinates specialist tools. Choose the cheapest tool that directly
answers the question and disclose the resulting evidence level.

| Question | Primary tool | Evidence |
|---|---|---|
| What code/data structure is present? | Ghidra | static |
| What does this known input do? | Unicorn | concrete for that modeled state |
| What control flow does an independent lifter recover? | Macaw | static/discovery |
| What input satisfies this bounded property? | Crucible + What4 + Z3 | solver-confirmed |

## Operating rules

- Use Ghidra for decompilation, references, tables, strings, globals, and MMIO
  naming. Cross-check material function/CFG boundaries.
- Use Unicorn for concrete replay and state capture. A peripheral stand-in is a
  harness assumption, not firmware-produced evidence.
- Use Macaw as an independent machine-code discovery/lifting path. Cortex-M is
  Thumb-only; investigate any A32 interpretation rather than accepting it.
- Use symbolic execution only after the region and property are bounded. It is
  not a substitute for ordinary concrete replay.
- When tools disagree, reproduce the same input/state, locate the first
  divergence, and fix the narrowest responsible layer.

Escalate observability from a normal run, to coarse sampling, to fine-grained
tracing. Treat failures of a harness as harness findings until independently
confirmed.

The Performing Rigs cases that produced several of these durable lessons are
preserved in
[`tool-selection-case-notes.md`](../../cases/performing-rigs/docs/investigations/tool-selection-case-notes.md).

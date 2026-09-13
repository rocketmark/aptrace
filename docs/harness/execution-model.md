# Symbolic Harness Execution Model

APTrace translates bounded Macaw regions into Crucible CFGs and uses What4/Z3
to answer reachability and input-model questions.

A query supplies the firmware memory image, target function/block, concrete
pointer/register overrides, bounded concrete memory overlays, symbolic input
locations, and the target property. Large default RAM regions are represented
compactly; only relevant overlays become explicit terms.

## Correctness rules

- Seed stack and pointer state explicitly when the queried block reads or writes
  through them.
- Keep solver assumptions distinct from values that plain execution can consume
  as concrete literals.
- Do not infer firmware behavior from a nonterminating or divergent harness.
- Validate concrete instances against Unicorn before relying on a symbolic
  generalization.
- Prefer isolated blocks or already-understood regions to speculative
  whole-function replay.

Reusable implementation lives in `APTrace.SymbolicRunner` and
`APTrace.ProtocolHarness`. The concrete investigations and harness bugs that
established these rules are preserved in
[`symbolic-harness-results.md`](../../cases/performing-rigs/docs/investigations/symbolic-harness-results.md).

# APTrace Architecture

APTrace is a workbench for analyzing raw bare-metal Cortex-M firmware. It
coordinates specialist tools and provides reusable loading, discovery,
execution, and evidence mechanisms.

## Component model

```text
raw firmware + case recipe
          |
          v
   APTrace framework
    |      |      |
    |      |      +-- Unicorn concrete execution
    |      +--------- Ghidra static analysis
    +---------------- Macaw discovery/lifting
                          |
                          v
                 Crucible / What4 / Z3
```

- `APTrace.FirmwareLoader` constructs Macaw memory from caller-supplied image
  and memory geometry.
- `APTrace.VectorTable` parses Cortex-M vector roots.
- `APTrace.Macaw*` modules perform discovery, normalization, semantic
  classification, expansion, and refinement.
- `APTrace.SymbolicRunner` and `APTrace.ProtocolHarness` provide bounded
  Crucible/What4 execution machinery.
- `tools/ghidra/`, `tools/unicorn/`, and `tools/census/` provide reusable
  backend and evidence tooling.

Tool roles and selection guidance are in
[`tooling/tool-selection.md`](tooling/tool-selection.md).

## Framework and case dependency direction

The framework owns engines. A case owns recipes and evidence.

```text
case application / scripts
          |
          v
APTrace framework and tools
```

Case modules may depend on framework modules; framework modules must not depend
on a case. The application layer may explicitly connect the two. Target memory
geometry, firmware registries, known addresses, boot assumptions, and experiment
definitions therefore live under `cases/<name>/` even when a generic engine
executes them.

This keeps the root repository coherent if every case is removed and avoids
mistaking one investigation's conclusions for framework capabilities.

## Repository layout

```text
src/APTrace/       reusable Haskell modules (namespace retained deliberately)
app/               CLI composition root and explicit case wiring
tools/             reusable backends and analysis machinery
docs/              framework architecture, status, and methodology
test/              reusable framework tests
cases/             target-specific configuration, code, tests, and evidence
```

See [`adding-a-case.md`](adding-a-case.md) for ownership guidance and
[`status.md`](status.md) for implemented framework capabilities.

# Census and Evidence Database

`tools/census/` builds a mechanical evidence database from static exports and
optional dynamic execution coverage. It keeps collection and reduction
deterministic so an analyst can inspect why an item was included, excluded, or
prioritized.

## Framework responsibilities

The reusable census layer provides:

- schema and ingestion for firmware metadata, functions, basic blocks, CFG
  edges, vectors, RAM/MMIO references, and dynamic coverage;
- discovery comparison and normalized control-transfer records;
- fingerprint and reference-corpus matching;
- reachability reduction, residual prioritization, and component grouping;
- query/report commands with explicit provenance and warnings.

Firmware registries, boot recipes, hardware interpretations, target-specific
roots, and captured run databases are case inputs. They do not belong to the
census engine.

## Typical flow

```text
case firmware registry
        |
        v
Ghidra/Macaw static exports ----+
                                +--> census database --> deterministic reports
case concrete-run coverage -----+
```

Run `python3 tools/census/aptrace_census.py --help` for the current command
surface. A case should document its exact build/reduce commands and own the
resulting database under its `research/runs/` tree.

The detailed history, outcomes, and target-specific recipes from the Performing
Rigs application are preserved in
[`cases/performing-rigs/docs/investigations/census-results.md`](../../cases/performing-rigs/docs/investigations/census-results.md).

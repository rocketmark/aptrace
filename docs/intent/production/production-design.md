---
node: production
---

# Production (sub-HLD, skeleton)

**Status: skeleton.** It will stay one until the consolidated mapping audit
(`docs/arrows/mapping-report.md`) has been reviewed. Not approved
architecture.

**Scope:** the engines and operations that produce observations.

| Leaf | Prefix | LLD |
|---|---|---|
| target-loading | PROD-TGT | `target-loading/target-loading-design.md` |
| structural-discovery | PROD-DISC | `structural-discovery/structural-discovery-design.md` |
| census | PROD-CENSUS | `census/census-design.md` |
| static-dataflow | PROD-DFLOW | `static-dataflow/static-dataflow-design.md` |
| symbolic-execution | PROD-SYM | `symbolic-execution/symbolic-execution-design.md` |
| concrete-execution | PROD-CONC | `concrete-execution/concrete-execution-design.md` |

**Engine ownership** (approved intent; CLAUDE.md "Analysis-engine ownership"):

| Engine | Role |
|---|---|
| Ghidra | Structural discovery and the p-code dataflow foundation |
| Macaw | Independent lifting |
| Crucible, What4, Z3 | Bounded symbolic questions |
| Unicorn | Concrete execution |

**Cross-segment findings to resolve before this document is written:** see
`docs/arrows/cross-segment-findings.md`, entries X1, X2, X3, X11, X22 and
X24.

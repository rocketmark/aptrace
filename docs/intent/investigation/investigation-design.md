---
node: investigation
---

# Investigation (sub-HLD, skeleton)

**Status: skeleton.** It will stay one until the consolidated mapping audit
(`docs/arrows/mapping-report.md`) has been reviewed. Not approved
architecture.

**Scope:** model-directed research, and its continuation over time.

| Leaf | Prefix | LLD |
|---|---|---|
| controller | INV-CTRL | `controller/controller-design.md` |
| continuity | INV-CONT | `continuity/continuity-design.md` |
| work | INV-WORK | `work/work-design.md` |

**Approved intent:**
- APTrace's own `ResearchController` runs investigations (CLAUDE.md).
- Work state never changes claim state (`docs/work-store.md`).

**Cross-segment findings to resolve before this document is written:** see
`docs/arrows/cross-segment-findings.md`, entries X4, X20 and X21.

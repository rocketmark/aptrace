---
node: claims
---

# Claims (sub-HLD, skeleton)

**Status: skeleton.** It will stay one until the consolidated mapping audit
(`docs/arrows/mapping-report.md`) has been reviewed. Not approved
architecture.

**Scope:** typed claims, and the deterministic decisions about them.

| Leaf | Prefix | LLD |
|---|---|---|
| claim-semantics | CLAIMS-SEM | `claim-semantics/claim-semantics-design.md` |
| admission | CLAIMS-ADMIT | `admission/admission-design.md` |
| verification | CLAIMS-VERIFY | `verification/verification-design.md` |
| audit | CLAIMS-AUDIT | `audit/audit-design.md` |

**Approved intent** (CLAUDE.md "Model output and claims"):
- Deterministic admission and verification decide support.
- Never weaken them to accommodate model output.

**Cross-segment findings to resolve before this document is written:** see
`docs/arrows/cross-segment-findings.md`, entries X6, X10, X12, X13, X14, X15,
X16 and X18.

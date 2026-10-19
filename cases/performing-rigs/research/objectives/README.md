# Objective specs

Structured objectives for objective-bounded `aptrace-agent research` runs
(framework contract: [`docs/objective-bounded-investigation.md`](../../../../docs/objective-bounded-investigation.md)).
Each file restates one investigation's verbatim question with its relations,
constraints and relevance terms, all case-owned.

| File | Restates | Use |
|---|---|---|
| `remote-to-motor-2026-10-17.objective.json` | objective of `runs/agent/remote-to-motor-2026-10-17.json` | regression and live comparison |
| `remote-to-motor-focused-2026-10-19.objective.json` | objective of `runs/agent/remote-to-motor-focused-2026-10-19.json` | regression and live comparison |

The relation endpoints come from the operator-authored
[causal graph](../generated/remote-to-motor-causal-graph.json). They state
what to investigate, not what is established. `R0` names the Remote image
(`mando868`) and is never resolved against the AutoPilot image.

Comparison and live runs:
[`docs/investigations/objective-bounded-investigation-v1.md`](../../docs/investigations/objective-bounded-investigation-v1.md).

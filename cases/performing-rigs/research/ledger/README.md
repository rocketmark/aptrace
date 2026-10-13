# Performing Rigs research ledger

Canonical, append-only store of investigation runs, typed tool invocations,
content-addressed evidence, versioned claims, audits, verifications, and
lifecycle events for this case. Records are written once by APTrace
(`aptrace-agent`); do not edit them by hand. Format and semantics:
[`docs/research-ledger.md`](../../../../docs/research-ledger.md).

`blobs-large/` (results above 4 MB, e.g. full function-effects records) is
not version-controlled; `aptrace-agent replay` re-derives those results and
checks them against the recorded hashes.

Human-readable view (generated, never canonical):
[`../generated/research-ledger.md`](../generated/research-ledger.md).
Known-answer benchmark fixtures: [`../benchmarks/ledger-v0/`](../benchmarks/ledger-v0/).

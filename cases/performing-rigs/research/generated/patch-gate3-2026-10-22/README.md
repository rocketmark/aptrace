# Gate 3 adversarial evidence

Report: [trigger-patch-gate3.md](../../../docs/investigations/trigger-patch-gate3.md).
Research only; hardware deployment NOT APPROVED. Gate 3 FAIL within modeled scope.

Nine fresh firmware runs use existing `tools/unicorn/run_concrete.py` directly.
Each `*-command.txt` is an executable CLI invocation from repository root, with
`--out` pointing into this packet. Invoke the command directly; sourcing it in
a compound shell context produced native initialization failures in this run.
Do not overwrite the snapshots on reproduction: select another output path.

| Recipe | Purpose / result |
|---|---|
| `late-release-patched` | Historical post-read release reproduced; acceptance and executed TC0 ENABLE-containing store despite current HIGH. |
| `held-w-patched`, `held-w-original` | Historical continuous LOW/completion/W history; two initiations in both images. |
| `release-fresh-w-patched` | Historical release/repress control reproduced; subsequent initiation preserved. |
| `analog-x1-patched`, `analog-x2-patched` | Historical analog positive/negative pair reproduced without entering digital patch. |
| `release-before-new-read` | Change late-release force PC from1547c to15478; add branch watches. 230 fresh-HIGH rejections, no initiation through14M. |
| `release-after-new-compare` | Change release PC to1547e; same added watches. Acceptance and TC0 enable persist. |
| `held-no-w-patched` | Remove only three6056 W-delivery arguments from held/W recipe. One start; completion and idle2 through60M. |

The six historical replays change only output paths. They are byte-identical to
the corresponding decompressed authoring snapshots. `observations.json` extracts
native fields, relevant watch events, selected stores and raw/gzip digests. It
contains no newly implemented firmware or safety semantics. The three variations
use the same public CLI/environment; no harness or tests were added.

`doctor-branch.json` is an existing documented868 branch diagnostic, not another
AutoPilot915 safety test. It reaches8890 after3 instructions. Its direct command:

```
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py --firmware cases/performing-rigs/research/firmware/vendor-package/firmware_autopilot868.bin --entry 0x888c --reg r3=0x26 --stop-at 0x8890 --stop-at 0x889e --out cases/performing-rigs/research/generated/patch-gate3-2026-10-22/doctor-branch.json
```

Fresh public Ghidra queries, using the established JAVA_HOME/JAVA_TOOL_OPTIONS
environment from Gate1:

```
python3 tools/ghidra/aptrace_ghidra.py disasm autopilot915_freshness_research 0x15470 0x1548c
python3 tools/ghidra/aptrace_ghidra.py decompile autopilot915_freshness_research 0x607c 0x5be8
python3 tools/ghidra/aptrace_ghidra.py xrefs autopilot915_freshness_research 0x200000d8
python3 tools/ghidra/aptrace_ghidra.py xrefs autopilot915_freshness_research 0x20002524
python3 tools/ghidra/aptrace_ghidra.py disasm autopilot915_freshness_research 0x5afe 0x5b22
```

Named Ghidra outputs were copied from its normal scratch files after successful
queries. Xref observations relevant here: idle WRITE5b1a in service5be8;
channel-state accesses in that service are READ records. This is not an exhaustive
alias/interrupt effects certificate. `ghidra-service-idle-store.txt` confirms
the byte store writes1. Static writer feasibility remains unresolved.

## Failure and provenance record

Three initial commands `source .../late-release-patched-command.txt`,
`source .../held-w-patched-command.txt`, and `source .../held-w-original-command.txt`
each returned exit132 with no output or snapshot. They are initialization
failures, not firmware counterexample outcomes. A host crash report inspected at
`~/Library/Logs/DiagnosticReports/Python-2026-10-22-1901222.ips` reports SIGILL /
EXC_BAD_INSTRUCTION with frames init_cache_info, machine_initialize,
uc_init_engine, uc_mem_map. This agrees with the documented macOS native
initialization failure class; the exact security decision was not established.
Direct documented invocations succeeded without environment/security changes.

All nine final firmware commands returned exit0. Eight stop at instruction
budgets; analogX1 stops at5fa6. No guest errors, write drops or watch-cap stops.
No run-time/resource measurements were emitted by APTrace, so none is claimed.
An attempted `ps` inspection returned operation-not-permitted. An optional
wildcard search for ISR files had no match; `rg --files` located existing
handler evidence. Neither inspection failure affects firmware results.

No new symbolic queries or ledger claims; no Gate4. Existing Gate1/2 and
Target1/2/3 evidence is reused with scope in the report. Historical artifacts,
firmware, implementation and models were preserved. `artifact-hashes.json`
records this packet's files except itself.

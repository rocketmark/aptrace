# Original Remote / AutoPilot lifecycle evidence

2026-10-22. [Investigation report](../../../docs/investigations/remote-autopilot-execution-lifecycle-phase1.md).
Partial lifecycle reconstruction; no patch/model/framework implementation.

`commands.json` contains the exact new native CLI recipes, run from the
repository root. Reproduce by invoking a recipe directly and choosing a new
`--out` path; preserve the recorded evidence. Do not source a compound wrapper
as a substitute for the documented direct CLI invocation. The installed venv
is the existing Unicorn environment. No installation was performed.

`execution-summary.json` projects instruction counts, stop reasons, mode and
selected registers from the native JSON. It adds no firmware semantics.
All nine processes exited0, without guest errors. These are bounded fragments
and explicitly seeded/stubbed controls, not continuous reset-based peer runs.
Two additional full-reset AutoPilot continuation recipes are recorded separately
below; neither executes a coupled Remote UI or RF link.

| Snapshot | Inputs / result |
|---|---|
| remote-w-six | Direct original915 call591c(0); stub transport58a8, delay168d0 and button17200. Six transport stub hits. Watching the stub entry gives no watch hits because stubs are intercepted first. |
| remote-w-six-arguments | Same inputs; observe caller5930. Six r0=1c598 observations with literal `W\|` bytes. Button stub leaves r0=45, so this is one disclosed nonzero-button helper history, not physical button execution. |
| remote-w-flag | Enter RUNNING continuationd028 with local register binding; stub service/button, supply button return0 and exit word1. Reaches591c with argument0 in15 instructions. |
| remote-w-wait | Same, exit word0. Stops atd042 in12 instructions instead of reaching W. Bounded guard exclusion, not an infinite wait proof. |
| remote-w-button | Exit word0, supplied button return1. Reaches591c(0) in15 instructions. |
| remote-x-exit-flag | Enter recognized-X suffix10e22, supply RX-empty return; default signed accumulator0. Writes exit word1, stops before clock call10e42 in15 instructions. Does not demonstrate RX or natural X production. |
| phase-one-stop-request | Enter phase service8e18 with phase1, valid record and live0 channel byte1 explicitly seeded. Reaches5274 with r0=0/r1=4 in24 instructions, before that helper executes. |
| autopilot-queued-at | Seed one pending index1 event, priority table and count; clock stub preserves supplied100. Reaches single-character sender7f84 with r0=0x40 in53 instructions. No natural queue producer or actual transport execution. |
| autopilot-queued-x | Same for index0. Reaches7f84 with r0=0x58 in52 instructions. Queue is supplied, not produced by completion. |
| original-release-repress-w | Original915 Gate3 held/W recipe, changing output and adding GPIO HIGH at8f98 and LOW at9088. First completion52,125,562; second acceptance52,167,777; second live52,400,358;60M budget, no guest error or dropped watched writes. HIGH recurs on every acceptance, so the second acquisition is also a sampled-LOW/current-HIGH history. |
| original868-release-repress-w | Original868 VVR released/W recipe, changing output and supplying ADC900 at9088. Original225 release at each8f98 remains. Exact recipe is in the named command file. |

Both full-reset continuations exit0 at60M with no guest error or dropped watched
writes and two live-store entries. The analog run matches the released control
through completion52,246,833 / first idle9 boundary52,289,719, then crosses
effective587 and accepts again52,428,031; second live52,660,283. Phase3 writes
idle9 repeatedly: fifteen same-value900 external ADC writes at9088 precede the
second acceptance, not fifteen electrical edges. Acceptance supplies225 again;
the second live checkpoint has effective355. These details are recorded in
`execution-summary.json` and the original native snapshots.

The new fragments do not seed or modify files containing original images.
They supply RAM/register state inside disposable execution instances, as
disclosed above. Continuations use the established RX, radio-ID, MMIO completion,
fake-tick and DWT-delay assumptions; only external GPIO/ADC changes and captured
protocol bytes are added, not application idle/live/phase overrides.
Historical continuous completion/held/released/W fixtures
are reused from the VVR and Gate3 packets, not rerun or overwritten here.

## Static reproduction

Use public `tools/ghidra/aptrace_ghidra.py`. Commands requiring Ghidra use the
existing environment:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py decompile mando915 0xcfc8 0xde3c 0xfd7c 0x10cf4 0x591c 0x58a8
```

That query produces `remote-w-paths.txt`. Other saved public queries:

| Output | Operation after the script name |
|---|---|
| autopilot-lifecycle.txt | decompile autopilot915 0x8258 0x8e18 0x5fac 0x5958 |
| autopilot-preparation.txt | decompile autopilot915 0x6b50 0x6338 |
| status-stop.txt | decompile autopilot915 0x693c 0x77f8 0x7868 |
| autopilot-stop.txt | decompile autopilot915 0x54e0 |
| autopilot-status.txt | decompile autopilot915 0x8a80 |
| autopilot-tx.txt | decompile autopilot915 0x5dd0 0x8c10 |
| autopilot-status-producers.txt | decompile autopilot915 0x9268 0x8ddc 0x8c70 |
| autopilot-events.txt | decompile autopilot915 0x7f38 0x541c 0x5274 |
| autopilot-input-events.txt | decompile autopilot915 0x4480 0x4440 |
| autopilot-queue.txt | decompile autopilot915 0x8cc0 (no function; retained negative result) |
| remote-encoder.txt | decompile mando915 0xd988 (heuristic output runs into adjacent tails; not a whole-function semantic certificate) |
| remote-completion-listing.txt | disasm mando915 0xcfc8 0xd0b8 |
| remote-completion-flag.txt | disasm mando915 0x10e18 0x10e60 |
| remote-w-listing.txt | disasm mando915 0x591c 0x5970 |
| autopilot-w-listing.txt | disasm autopilot915 0x8620 0x8668 |
| autopilot-w-stop-tail.txt | disasm autopilot915 0x541c 0x54e0 |
| autopilot-queue-helper.txt | disasm autopilot915 0x81d0 0x8258 |
| autopilot-phase-listing.txt | disasm autopilot915 0x8f68 0x9110 |
| autopilot-idle-xrefs.txt | xrefs autopilot915 0x200000d8 |
| remote-w-callers.txt | callers mando915 0x591c |
| remote-exit-xrefs.txt | xrefs mando915 0x20000ff4 |
| remote-running-callers.txt | callers mando915 0xcfc8 |
| remote868-w-callers.txt | callers mando868 0x591c |
| remote868-exit-xrefs.txt | xrefs mando868 0x20000ff4 |
| remote-command-literals.txt | dump mando915 0x1c598 --length 32 |

Copied `*-ghidra-meta.json` bind queries to image hashes, Ghidra12.1.3,
analysis version and script identities. `artifact-hashes.json` records packet
files except itself. The report records operational failures and limitations.
No new solver results, model checks, admitted claims or gate verdicts.
`variant-region-comparison.json` is a mechanical byte/hash comparison of three
specified original AutoPilot ranges; it is not a new instruction interpreter or
whole-image behavioral equivalence proof.

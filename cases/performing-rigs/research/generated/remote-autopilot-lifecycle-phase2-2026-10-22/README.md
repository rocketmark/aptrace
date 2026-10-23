# Phase 2 original Remote / AutoPilot lifecycle evidence

2026-10-22. [Report](../../../docs/investigations/remote-autopilot-execution-lifecycle-phase2.md).
No patch, model, framework, hardware or verification-gate changes.

## Native reproduction

`commands.json` and16 `*-command.txt` files contain the exact public CLI recipes,
run from repository root with the existing Python3.9.6/Unicorn venv. Invoke a
command directly and choose a new `--out` path; preserve these snapshots.
No installation, permission escalation or security change was performed.

`execution-summary.json` projects native stop state, watch counts, selected
events and queue writes. `message-transfers.json` records payload provenance
and externally supplied delivery/interaction boundaries. These files implement
no instruction semantics or emulator behavior.

| Native artifact | Purpose / result |
|---|---|
| held-no-command-queue | Original868 VVR held-completion recipe; add full pending-counter write watch, queue snapshots and byte-send/idle2 observations; increase write cap.65M, one start, idle2, no X. |
| held915-no-command-queue | Original915 Gate3 held/W recipe, remove three completion-time W RX writes;65M, full queue/byte-send observations. One start, idle2, no X. |
| released-no-command | Original868 VVR released/W recipe, remove W RX writes; add queue/byte-send observations;65M. Raw225 at each acceptance; one start, effective225/idle2. |
| fresh-no-command | Same, add raw900 at completion6056. One start, effective900/idle2. Reactivation is at completion because no autonomous rearm occurs. |
| first-natural-string-message | Original868 held/no-command queue recipe,14M cap; stop at string-send wrapper8c10 and capture64 bytes at firmware-computed r0. Stops13,155,568, r0=20001fcc, `a0\0`. |
| remote-at-entry | Initial @ protocol probe: actual915 parser/RX ring, radio-pollb440 stub; reaches RUNNINGcfc8 in81 instructions, page9, exit flag0. |
| remote915-x-parser-control | Explicit X in actual915 RX ring, availability/read/parser instructions, poll stub.92 instructions, consumes X, exit word1. No natural X provenance. |
| remote868-x-parser-control | Same for868 parser10ce4; identical92-instruction result. |
| remote-at-screen-no-button | Initial @ screen probe, PA10LOW, stub poll/transport/delay/display/general service. Actual button-read instructions; no W loop through5,000. |
| remote-at-screen-button | Same, PA10HIGH atd028. Six5930 hits with `W\|\0`; reachesd078 after373 instructions. No exit-word or button-return override. |
| remote-captured-at-entry | Re-execute parser probe after reading actual0x40 from held-no-command-queue's first @ send at12,520,776. Same result. |
| remote-captured-at-no-button | Capture-bound replay of no-button screen control. |
| remote-captured-at-button | Capture-bound replay of button screen control; six W requests. |
| operator-w-held-return | Original915 held/W recipe plus queue/byte-send observation. W matches captured Remote requests; one delivered W at first completion;60M, second start, no X. Zero-distance return. |
| operator-w-while-live | Diagnostic: W delivery at every5fa4 live visit,14M; watch5274 and phase/idle writes. Later repetitions are harness-driven, **not an autonomous loop**. |
| operator-w-single-stop-prefix | Same inputs, end12,603,450 before second5fa4 injection. Exactly one W delivery; stop/return then second acceptance/rate/TC0 ENABLE request. |

All16 final processes returned0 with no guest errors or dropped watched writes.
Four65M no-W runs and the60M supplied-W return replay have only a reset-zero
overlapping write to queue0 atcc82. Watch caps were not reached. Budget stops
are not product-completion claims. Remote screen controls stub general service;
they are not continuously initialized sessions.

AutoPilot assumptions are exactly disclosed in the commands: program/MC4 RX
inputs, fake tick, radio-ID, calibration page, MMIO ready/completion responses
and DWT-delay stub. No forced idle/live/phase/completion/position values.

The Remote button entry is original table `0x24860+45*0x18=0x24c98`: port0,
bit10, actual digitalRead17200 reads0x41008020. Initial screen invocations
without the established0x4000000 MMIO size failed before guest execution with
UC_ERR_WRITE_UNMAPPED; corrected commands are retained. No failed initialization
became a firmware verdict.

The staged W replay delivers **one** of six request payloads. Full-burst timing,
the other five arrivals, duplicates and delayed/nested UI behavior remain open.

## Static reproduction

Public tool: `tools/ghidra/aptrace_ghidra.py`. Headless queries use the existing
environment, for example:

```sh
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot915 0x9090 0x9110
```

| Saved output | Arguments after script name |
|---|---|
| completion-phase-listing.txt | disasm autopilot915 0x9090 0x9110 |
| completion-senders.txt | decompile autopilot915 0x5be8 0x5fac 0x6e68 0x7f84 |
| event-enqueue.txt | decompile autopilot915 0x449c 0x6952 0x4630 |
| alternative-notifications.txt | decompile autopilot915 0x9268 0x8a80 0x4440 0x5dd0 |
| remote-rx-running.txt | decompile mando915 0x10cf4 0xcfc8 0xb4f8 0x583c 0x17200 |
| remote-peripheral-boundaries.txt | decompile mando915 0xb440 0x16850 |
| remote-rx-listing.txt | disasm mando915 0x10d10 0x10e60 |
| stop-return-consumers.txt | decompile autopilot915 0x5958 0x693c 0x6fd8 |
| queue0-xrefs.txt | xrefs autopilot915 0x200025bc |
| queue1-xrefs.txt | xrefs autopilot915 0x200025bd |

Additional public literals/dumps inspected pin/RX/service/IRQ pointers. Earlier
caller and byte-region evidence remains in the Phase1 packet. Decompilation
assists reading; instruction listings and native execution anchor results.

Four copied `*-ghidra-meta.json` files record firmware/engine/script identities.
`firmware-identities.json` preserves Phase1 original hashes, checked against
current bytes. `artifact-hashes.json` covers packet files except itself. No
new symbolic all-path or alias-completeness result is asserted.

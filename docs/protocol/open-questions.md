# Protocol Open Questions (consolidated, current)

This merges `research/autopilot_static_inventory/open-questions.md` (v0.3,
static-analysis questions) with questions raised by APTrace's own
symbolic-execution work. Harness/tooling-level blockers (as opposed to
protocol-content questions) live in
[`docs/project-status.md`](../project-status.md) instead — this file is
about the protocol itself.

## From the static-analysis pass (priority order, per v0.3)

1. **Name event-7's 11 fields** — trace the Remote's stores after each of
   its ten `0xb51c` parses and match RAM locations to UI labels/behavior.
   The 11th (AutoPilot-only) field is a separate question — see next.
2. ~~**Resolve the event-7 11-vs-10 field mismatch**~~ — **RESOLVED
   (execution-confirmed, `tools/unicorn/virtual_link.py bang`)**: the
   Remote neither drops nor corrupts anything within the transaction —
   it simply never attempts field 11. Its parser calls the shared field
   parser exactly 10 times, unconditionally marks itself "done," and
   moves on; field 11 and its trailing comma are left byte-for-byte
   UNCONSUMED in the real RX ring buffer (write pointer stays exactly
   `len(field11)+1` bytes ahead of read, confirmed by direct pointer
   inspection after a real parse). No error, no assert, no crash, no
   version-skew signal either side. Whether a later, unrelated read ever
   treats that leftover as the start of a different message was not
   re-traced (out of this scenario's scope) — see
   [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)'s
   Open items.
3. ~~**Resolve the `I<channel><mode>` numeric semantic**~~ — **RESOLVED
   (execution-confirmed, `tools/unicorn/virtual_link.py i`)**: the
   returned signed value is `AUTOPILOT_LIVE_POSITION[channel]`
   (`0x20002064+channel*4`), read directly by the event-15 builder
   (`0x8ddc`) regardless of mode. The per-channel state machine around
   `0x20001b14`/`0x200029d8`: the RX handler (`0x872e-0x877c`) stores the
   wire mode digit verbatim into `0x200029d8[channel]` (no inversion —
   the inversion happens only on the Remote's send side) and
   unconditionally sets `0x20002524[channel]=5`; the real main-loop poll
   `channel_event_monitor__CUSTOM` (`0x8a80`) is what actually notices
   state 5 and schedules event 15 (the RX handler itself does not); mode
   only gates a side-effect cache write into the per-channel config
   struct, never which value is reported. See
   [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)'s
   Open items for the full trace.
4. **Name the `a0`/`a1`/`a2` states** (event 13) — trace producers of
   `0x2000209d` and `0x20002529`, and the Remote-side state variable.
5. Trace the five backing values in the periodic `MTddddx|` status packet.
6. Trace `T...|` outbound telemetry values back to motion/state globals;
   separate from the inbound non-TR `T` command path (schedules `##`).
7. Resolve the Remote's `PN...` branch — reachable in this build, or dead?
   **Refined (2026-09-08)**: the Remote's own `PN` handling is fully
   implemented, not missing (`0xc440`: on `PN`, if its stored state is 9,
   10, or 11, reset it to 1) — confirmed by reading the full
   disassembly, not by a failed search. Still open: the AutoPilot `S`
   handler's switch (all 5 cases read) never emits `'N'` as a second
   byte in *this* build, so there is still no producer here — but the
   question is now "does any AutoPilot build/config reach it," not
   "does the Remote support it." See
   [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md).
8. **Reconcile Remote-transmitted packets not accepted by the visible
   AutoPilot dispatcher**: `MS|`, `MR|`, `MM|`, `N|`, `KK|`, `E1,...|`, bare
   `W|`. (The short `I9|`/`I1|` forms are now resolved — **execution-
   confirmed, `tools/unicorn/virtual_link.py i9i1`**: `I1|` silently
   aliases `I<channel=0>|`'s real dispatch path and completes normally;
   `I9|` decodes to an out-of-bounds channel index (8) that the real
   monitor's 4-channel scan never visits, so it is a genuine, silent
   firmware-level dead end — removed from this list.) **Note**: since
   [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
   found the AutoPilot dispatcher's real structure is more complex than the
   flat model this question assumed, some of these may turn out to be
   reachable through the previously-unmodeled indexed-lookup mechanism.
   Worth revisiting once that mechanism is understood (see
   [`docs/project-status.md`](../project-status.md)'s current blocker).
9. **Are events 2, 3, 8, 9, 11, 12, 14 truly unreachable**, or reachable via
   a computed-pointer/indirect write the static survey missed? Flagged in
   the original pass as "a good symbolic-execution/reachability target" —
   this is a direct reachability question APTrace's discovery/solver
   pipeline is well-suited to answer, once the current whole-function
   execution blocker is resolved (it requires running more of the
   dispatcher's call graph than has been safely executed so far).

## Raised by APTrace's symbolic-execution work

10. ~~What do `0x5274` and `0x5448` actually do?~~ **Largely resolved
    (2026-09-07) via Ghidra decompilation** — see
    [`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
    for the full read/write breakdown. Summary: at their loop call sites,
    `0x5274` writes `0x200024cc[channel]` and `0x2000309d[channel]`
    unconditionally; `0x5448` writes `0x20000134[channel]`,
    `0x200023d8[channel]`, `0x20002524[channel]` unconditionally plus two
    conditional writes. **None of these overlap the loop's own reads**
    (buffer bytes and `TABLE[channel]` at `0x20000180`), which is now in
    tension with the "memory side effects explain non-termination"
    hypothesis rather than confirming it — see that document's "Tool/evidence
    disagreement" section and [`docs/project-status.md`](../project-status.md)'s
    current blocker.
11. ~~Is the `0x801c` ARM/A32-mode lift a real Macaw/dismantle discovery
    limitation, or dead code on real hardware?~~ **Resolved (2026-09-07),
    in favor of "decode limitation."** A Ghidra cross-check (`ARM:LE:32:Cortex`,
    architecturally incapable of decoding A32 on this target) found `0x801c`
    to be an ordinary, well-formed, 8-times-called Thumb function. See
    [`docs/investigations/trigger-input.md`](../investigations/trigger-input.md)
    and [`docs/tooling/tool-selection.md`](../tooling/tool-selection.md).
    Reporting the Macaw/dismantle decode issue upstream remains open (not a
    protocol question, tracked as a follow-up in `trigger-input.md`).
12. **What is R0's real value when the real firmware calls the dispatcher**
    (`0x8a34 -> 0x8259`)? The trace back through `0x801c` hit the anomaly
    above and couldn't reliably establish it. Understanding this may be
    necessary to correctly seed the whole-function replay.

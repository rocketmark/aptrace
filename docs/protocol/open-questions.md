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
2. **Resolve the event-7 11-vs-10 field mismatch** — does the Remote
   silently drop the 11th field, does it corrupt the next transaction, or
   is there a version-skew explanation? Not yet traced dynamically or
   symbolically. See `event7-schema.md`.
3. **Resolve the `I<channel><mode>` numeric semantic** — trace table
   `0x20002064` producers and the per-channel state machine around
   `0x20001b14` / `0x200029d8`.
4. **Name the `a0`/`a1`/`a2` states** (event 13) — trace producers of
   `0x2000209d` and `0x20002529`, and the Remote-side state variable.
5. Trace the five backing values in the periodic `MTddddx|` status packet.
6. Trace `T...|` outbound telemetry values back to motion/state globals;
   separate from the inbound non-TR `T` command path (schedules `##`).
7. Resolve the Remote's `PN...` branch — reachable in this build, or dead?
8. **Reconcile Remote-transmitted packets not accepted by the visible
   AutoPilot dispatcher**: `MS|`, `MR|`, `MM|`, `N|`, `KK|`, `E1,...|`, bare
   `W|`, and the short `I9|`/`I1|` forms. **Note**: since
   [`docs/investigations/parser-dispatch.md`](../investigations/parser-dispatch.md)
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

10. **What do `0x5274` and `0x5448` actually do?** These per-channel
    "motor state" functions are called from inside the indexed-lookup loop
    near `0x8258`; they are currently believed to have memory side effects
    the harness doesn't model (opaque stubbing), which is the leading
    explanation for the whole-function replay not terminating. See
    [`docs/project-status.md`](../project-status.md) and
    [`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md).
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

# Command Inventory (curated)

**Authoritative source data**: `research/autopilot_static_inventory/commands.csv`
(exhaustive) and `commands.md` (readable subset, high-confidence entries
only). This file is a curated summary pointing at that data — for the full
table with confidence ratings and notes, read the CSV/MD directly.

**Execution-confirmed** (see [`docs/protocol/protocol-overview.md`](protocol-overview.md)):
`&`, `G`, `!`, `S` — the AutoPilot dispatcher's real comparison instructions
require exactly these ASCII values to reach each command's handler.
**Also execution-confirmed, concretely, through the real live RX path**
(a separate, later line of investigation — see each command's own row
below for its specific evidence doc): `MC4`, `LL1`/`LL2`, `D`, and
(for its `mode=0x62` bulk-push form only, both sender and receiver, plus
the downstream real `G` mode-1 consequence) `'+'`.
Everything else below is static-analysis-only.

## High-confidence single/short commands

| Pattern | Direction | Interpretation | Response |
|---|---|---|---|
| `&\|` | Remote -> AutoPilot | Firmware-version query | `V01R39` (event 5) — **execution-confirmed** |
| `S\|` | Remote -> AutoPilot | State/config query | `P<value0>,` or `P<value0>,<value1>,<bool>,` (event 6) |
| `!0\|` / `!1\|` | Remote -> AutoPilot | Bulk state/config query | 11-field numeric CSV (event 7); Remote only parses 10 — see [`event-map.md`](event-map.md) |
| `G<d><d><seq>\|` | Remote -> AutoPilot | Synchronous request, rolling sequence digit; **also arms a state byte (`0x200025e1=2`) a separate manual-move state machine gates on — execution-confirmed, concretely, to reach that state machine's real "commit a move" call once `MC4` has run.** That same state machine reuses `G`'s own `<d><d>` fields as a channel digit and a "type"/mode digit (`0`-`9`, tried exhaustively) selecting a target from a per-channel-per-mode config struct — currently always `0` (mode `0`) or `-1` (modes `1`-`9`) in this firmware image, since its backing config data is blank — see [`mc4-transition.md`](../investigations/mc4-transition.md) and [`target-config-provenance.md`](../investigations/target-config-provenance.md) | `#` (event 17) |
| `B0\|` / `B1\|` / `B2\|` | Remote -> AutoPilot | B-family mode/state command | inline state change |
| `TR0\|` / `TR1\|` | Remote -> AutoPilot | Boolean family (false/true) | inline state change |
| `W0\|` / `W1\|` | Remote -> AutoPilot | W-family subcommand | `W1` -> up to five `#` (event 17), conditional |
| `R0\|` / `R1\|` / `R2\|` | Remote -> AutoPilot | R-family state | `R0`->`@`, `R1`->`@@` (event 4) |
| `MC<0-3><a>,<b>,<c>,<d>,\|` | Remote -> AutoPilot | Motor configuration, one channel — does **not** unlock the motor subsystem (see next row) | — |
| `MC4<a0>,<b0>,<c0>,<d0>,...\|` | Remote -> AutoPilot | Motor configuration, all four channels; **the only command in this firmware image that ends the boot-phase loop and hands control to the loop containing the motor-phase/ramp/monitor subsystem** (clears `0x20000060`) — execution-confirmed, concretely, including the real handoff to `FUN_000093fc`. Of its 4 per-channel fields, only the 4th is consumed by that subsystem (an index into a secondary table); the other 3 feed unrelated boot-time/display functions. See [`mc4-transition.md`](../investigations/mc4-transition.md). **User-guide mapping: UNKNOWN** — no Remote-side sender has been found for `MC<0-3>`/`MC4` yet, despite this being the single most consequential command in the protocol; see [`action-command-map.md`](../ui/action-command-map.md)'s "Quick Setup" entry and its #2-ranked open question | — |
| `I<1-4><0-1>\|` | Remote -> AutoPilot | Per-channel async/query state machine | `<signed-number>,` (event 15) |
| `LL1\|` / `LL2\|` | Remote -> AutoPilot | First/second limit workflow — **execution-confirmed**: `LL1` clears two globals + a validity flag; `LL2` orders them and sets the flag only if they differ. Neither touches live position, target/config, or `0x20001b14`; no GPIO/MMIO dependency; no other firmware code writes either global with a real value — see [`ll-limit-workflow.md`](../investigations/ll-limit-workflow.md). **User-guide mapping: UNKNOWN** on the Remote side (no sender found) — see [`action-command-map.md`](../ui/action-command-map.md)'s limit-setting entry | — |
| `H\|` / `J\|` | Remote -> AutoPilot | Toggle a global flag (opposite directions) | — |
| `0xF0 <payload>` | ? -> AutoPilot | Binary motor/control frame | — |
| `0xE0 <payload>` | ? -> AutoPilot | Binary motor/control frame (2nd variant) | — |
| `+<units><reserved>,<confirm>,<confirm>,<channel>,<mode><count><recordFields...>\|` | Remote -> AutoPilot | Previously undocumented; **now confirmed Remote-generated** (see below). Writes up to 3 per-channel "mode sub-record" entries (a signed delta, a 0-100 percentage, a rate divisor, a duration) into the exact `0x20001b40` per-channel motor-config struct `FUN_00007cc0`'s `G`-command target lookup reads, via `FUN_000046c8`/`FUN_00004910` (selected by the `<units>` byte right after `'+'`); when the mode field is `>50`, also calls `FUN_00004ca8` (computes `target = start + delta`, chained across sub-records) and `FUN_000043f0` (persists the whole struct back into the flash-backed `0x12000` buffer — the write-back counterpart to `FUN_00004b64`'s bulk load). The two "confirm" fields must match or the write/persist tail is skipped. **AutoPilot side: static-analysis-only, disassembly-confirmed** (every literal-pool address resolved directly against the compiled image): the delta field is copied from the wire with no clamp toward live position, so mode `1`'s target after a `'+'` write should equal `live_position_at_write_time + wire_delta` — a real, protocol-reachable way to drive `FUN_00006fd8`'s move distance past its `8`-unit threshold. **Remote side: confirmed Remote-generated, statically and concretely** — `FUN_000049c4` builds this exact frame (byte-for-byte match to the schema above, including the confirm1==confirm2 invariant and the same `+0xc`/`+0x10` delta convention), called from the Auto-Mode configuration screen state machine (`FUN_0000e670`, each call gated behind a real confirmation wait) and from the `'S'`-handler's bulk "push all channels' stored config" path (`FUN_0000c440`, mode `0x62` — the one mode value confirmed to cross the AutoPilot-side `>50` compute+persist threshold). **AutoPilot side: now concretely confirmed end to end for the `mode=0x62` bulk-push call** — a real `FUN_000049c4`-built `'+'` frame, delivered through the real AutoPilot dispatcher (no full boot needed; entering directly at the real dispatcher call site, the same established boundary every other command in this table uses), produces `target=500` for a wire delta of `500`, dirties the persisted buffer, and a subsequent real `G010|` (channel 0, type 1, also from the Remote's real builder) drives `FUN_00006fd8` to `distance=500`, crossing its real `8`-unit threshold (move-committed flag observed `=1`) — see `tools/unicorn/virtual_link.py plus`. The three interactive Auto-Mode screen confirmations (mode `0`/`0x14`) were not concretely exercised this pass and are known, by disassembly, not to cross the persist threshold by themselves. **Probable** user-guide mapping: for the `mode=0x62` bulk-push trigger specifically, a confirmed real `'S'`-driven config-resync event (most plausibly reconnect/status-refresh); for the interactive screens, confirming/saving a programmed Auto Mode move segment (A/B/C/D points, duration/ramp/delay/loop) remains the working hypothesis, unproven — see [`persistent-record-motor-target-mapping.md`](../investigations/persistent-record-motor-target-mapping.md), [`plus-command-remote-provenance.md`](../investigations/plus-command-remote-provenance.md), and [`plus-target-distance-roundtrip.md`](../investigations/plus-target-distance-roundtrip.md). Full workflow placement (which screen, which of the four interactive call sites — not three, see [`auto-mode-plus-callsite-identity.md`](../investigations/auto-mode-plus-callsite-identity.md) — what stacks with what) is in [`action-command-map.md`](../ui/action-command-map.md)'s Auto Mode deep dive | — |
| `D<value>,\|` | Remote -> AutoPilot | Writes a 32-bit numeric field into the persisted config buffer (the same buffer backing the `0x12000` flash region) at logical offset `0x15`, then writes a `0xDE` marker byte at offset `0x19`; a real boot-time reader (`FUN_00004c20`) checks that marker and, if present, reads the value back. If the written value differs from what's already stored, this also sets the buffer's dirty/save-pending flag. **Execution-confirmed, concretely, full round trip**: requires the trailing comma (`D1234,\|` parses cleanly and writes the exact value; a bare `D1234\|` dispatches but the field parser runs past the packet into adjacent memory since its only real terminator is a literal comma; an 8-byte `D12345,\|` failed to dispatch at all, an unexplored framing curiosity). The real save path fires naturally afterward (real GPIO/tick behavior, no fabrication) and, once the driver object's page-size field was correctly modeled from `NVMCTRL.PARAM`, actually mutates flash at `0x12000` — confirmed by a direct memory dump matching the written value/marker byte-for-byte. A genuinely fresh boot from that mutated flash recovers `1234`/`0xDE` through the real load path with zero commands re-sent — see [`dirty-flag-persistence.md`](../investigations/dirty-flag-persistence.md), [`d-command-persistence-roundtrip.md`](../investigations/d-command-persistence-roundtrip.md), and [`nvm-param-and-full-roundtrip.md`](../investigations/nvm-param-and-full-roundtrip.md) | — |

## Lower-confidence / unresolved

- `Y...,`, `+...`, `A...`, `X1`/`X2` — top-level parser branches exist;
  command semantics only partially understood. (`D...` moved up to the
  high-confidence table above this pass.)
- `V<decimal>,\|` — construction confirmed on the Remote side, but no
  matching top-level branch found in the AutoPilot's main text dispatcher.
- `MS\|`, `MR\|`, `MM\|`, `N\|`, `KK\|`, `E1,...\|`, bare `W\|` — the Remote
  actively transmits these, but they don't fit the AutoPilot's visible
  dispatch tree (see [`docs/investigations/parser-dispatch.md`](../investigations/parser-dispatch.md)
  for why that dispatch-tree model itself is now known to be incomplete —
  these may yet turn out to be reachable through paths the static pass
  didn't find). Tracked in [`open-questions.md`](open-questions.md).
- `I9\|` / `I1\|` short forms — used by a separate Remote routine, don't
  cleanly match the three-character `I<channel><mode>` parser.

## See also

- [`bidirectional-protocol.md`](bidirectional-protocol.md) for the full
  request/response transaction graph.
- [`event-map.md`](event-map.md) for the AutoPilot's outbound event
  dispatcher these responses go through.
- [`../ui/user-guide-workflows.md`](../ui/user-guide-workflows.md) and
  [`../ui/action-command-map.md`](../ui/action-command-map.md) for the
  user-visible workflow this flat command list sits inside — which
  screen/action plausibly emits each command, what state must already
  exist for it to be meaningful, and what it establishes for later
  commands. This flat list stays the reference for "what does command X
  do"; that pair of docs answers "what sequence of user actions gets the
  system into the state where X is emitted and means something."

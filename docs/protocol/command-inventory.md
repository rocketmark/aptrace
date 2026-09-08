# Command Inventory (curated)

**Authoritative source data**: `research/autopilot_static_inventory/commands.csv`
(exhaustive) and `commands.md` (readable subset, high-confidence entries
only). This file is a curated summary pointing at that data — for the full
table with confidence ratings and notes, read the CSV/MD directly.

**Execution-confirmed** (see [`docs/protocol/protocol-overview.md`](protocol-overview.md)):
`&`, `G`, `!`, `S` — the AutoPilot dispatcher's real comparison instructions
require exactly these ASCII values to reach each command's handler.
Everything else below is static-analysis-only.

## High-confidence single/short commands

| Pattern | Direction | Interpretation | Response |
|---|---|---|---|
| `&\|` | Remote -> AutoPilot | Firmware-version query | `V01R39` (event 5) — **execution-confirmed** |
| `S\|` | Remote -> AutoPilot | State/config query | `P<value0>,` or `P<value0>,<value1>,<bool>,` (event 6) |
| `!0\|` / `!1\|` | Remote -> AutoPilot | Bulk state/config query | 11-field numeric CSV (event 7); Remote only parses 10 — see [`event-map.md`](event-map.md) |
| `G<d><d><seq>\|` | Remote -> AutoPilot | Synchronous request, rolling sequence digit | `#` (event 17) |
| `B0\|` / `B1\|` / `B2\|` | Remote -> AutoPilot | B-family mode/state command | inline state change |
| `TR0\|` / `TR1\|` | Remote -> AutoPilot | Boolean family (false/true) | inline state change |
| `W0\|` / `W1\|` | Remote -> AutoPilot | W-family subcommand | `W1` -> up to five `#` (event 17), conditional |
| `R0\|` / `R1\|` / `R2\|` | Remote -> AutoPilot | R-family state | `R0`->`@`, `R1`->`@@` (event 4) |
| `MC<0-3><a>,<b>,<c>,<d>,\|` | Remote -> AutoPilot | Motor configuration, one channel | — |
| `MC4<...>\|` | Remote -> AutoPilot | Motor configuration, all four channels | — |
| `I<1-4><0-1>\|` | Remote -> AutoPilot | Per-channel async/query state machine | `<signed-number>,` (event 15) |
| `LL1\|` / `LL2\|` | Remote -> AutoPilot | First/second limit workflow | — |
| `H\|` / `J\|` | Remote -> AutoPilot | Toggle a global flag (opposite directions) | — |
| `0xF0 <payload>` | ? -> AutoPilot | Binary motor/control frame | — |
| `0xE0 <payload>` | ? -> AutoPilot | Binary motor/control frame (2nd variant) | — |

## Lower-confidence / unresolved

- `Y...,`, `+...`, `D...`, `A...`, `X1`/`X2` — top-level parser branches
  exist; command semantics only partially understood.
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

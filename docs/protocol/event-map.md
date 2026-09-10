# AutoPilot Outbound Event Map (curated)

**Authoritative source**: `research/autopilot_static_inventory/event-map.md`,
`pending-events.md`, and `pending-writes.csv`. This file is a curated
summary.

## Mechanism

- Outbound dispatcher: flash `0x9268`.
- Pending-event counters: one byte per event ID, at RAM `0x200025bc + event_id`.
- Something (not yet identified — likely a periodic main-loop poll) reads
  this array and, for each nonzero slot, calls the corresponding builder and
  sends the result via `0x7f84` (single byte) or `0x8c10` (string), then
  presumably clears/decrements the slot.

**Execution-confirmed**: writing `1` to `pending[5]` (event 5, the
firmware-version response) via the real `&` character check in the real
compiled dispatcher, **and** the full consumption side — `0x9268` (the
outbound dispatcher itself) concretely confirmed to consume `pending[5]`
(observed going `1` -> `0`) and hand the real TX hook (`0x8c10`) a pointer
to exactly `"V01R39\0"`, closing the whole AutoPilot milestone at the
concrete evidence tier. See
[`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
and [`docs/project-status.md`](../project-status.md). No other event's
producer has been checked by execution yet.

## Event table (18 slots, 0-17)

| Event | Output | Producer found (static)? | Context |
|---:|---|---|---|
| 0 | `X` | no | endpoint only |
| 1 | `@` | yes | bounds/position condition, count 3 |
| 2 | none | no | — |
| 3 | none | no | — |
| 4 | `@` | yes | `R0` x1 / `R1` x2 |
| 5 | `V01R39` | **yes — execution-confirmed** | `&\|` firmware-version query |
| 6 | `P...` | yes | `S\|` query |
| 7 | 11-field numeric CSV | yes | `!0\|` / `!1\|` |
| 8 | 3-part numeric CSV | no | dormant/unknown |
| 9 | scaled numeric | no | dormant/unknown |
| 10 | `C` | yes | timed monitor |
| 11 | `M1` | no | likely dormant/legacy |
| 12 | `M2` | no | likely dormant/legacy |
| 13 | `a0`/`a1`/`a2` | yes | startup x5 / state-change x1 |
| 14 | `M3` | no | likely dormant/legacy |
| 15 | signed per-channel numeric | yes | dynamic `I` completion |
| 16 | `MS` | yes | connection/state transition x3 |
| 17 | `#` | yes | `G` x1; helper x2; `W1` x5 conditional |

Events 2, 3, 8, 9, 11, 12, 14 have **no direct producer found** by the
static xref survey of the `0x200025bc` base pointer — see
[`open-questions.md`](open-questions.md) for whether that means truly
unreachable, or reachable via a path the static survey missed (a real
reachability question APTrace's discovery/symbolic-execution capability
could answer directly, once the current blocker is resolved — see
[`docs/project-status.md`](../project-status.md)).

## Producer sites (selected, high-confidence)

| Site | Event | Trigger |
|---|---:|---|
| `0x889a` | 5 | `&\|` — **execution-confirmed** |
| `0x87d2` | 6 | `S\|` |
| `0x87ba` | 7 | `!0\|` / `!1\|` |
| `0x83ea` | 17 | `G` request |
| `0x94b2` | 13 | startup, x5 |
| `0x5ea4` | 16 | connection/state transition, x3 |

Full producer table: `research/autopilot_static_inventory/pending-writes.csv`.

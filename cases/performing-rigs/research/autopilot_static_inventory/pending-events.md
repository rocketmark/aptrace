# AutoPilot pending-event producer survey — v0.3

## Event queue structure

The AutoPilot outbound dispatcher is `0x9268`. Pending counters begin at RAM `0x200025bc`; each event ID indexes one byte in that array.

A scan of the 915 MHz AutoPilot image found the exact base pointer literal `0x200025bc` at 13 flash locations. Following every direct load/xref to those literals yields the producer sites in `pending-writes.csv` plus the dispatcher itself. A separate search for direct `base + event_id` literals and obvious `movw/movt` forms did not reveal additional direct schedulers.

This does **not** prove that no computed-pointer write can exist, but it gives high confidence about the normal direct producers in this build.

## Active producer map

| Event | Producer(s) | Count | Output | Context |
|---:|---|---:|---|---|
| 1 | `0x8f9c` | 3 | `@` | bounds/position condition |
| 4 | `0x86ac` | 1 or 2 | `@` | `R0` / `R1` |
| 5 | `0x889a` | 1 | `V01R39` | `&|` firmware-version query |
| 6 | `0x87d2` | 1 | `P...` | `S|` query |
| 7 | `0x87ba` | 1 | numeric CSV | `!0|` / `!1|` query |
| 10 | `0x8b4e` | 1 | `C` | timed state monitor |
| 13 | `0x445a`, `0x94b2` | 1 / 5 | `a0` / `a1` / `a2` | state change / startup |
| 15 | `0x8b70` | 1 | signed numeric + comma | per-channel `I` completion |
| 16 | `0x5ea4` | 3 | `MS` | connection/state transition |
| 17 | `0x4622`, `0x4638`, `0x83ea` | 2 / caller count / 1 | `#` | ack/helper paths and `G` |

Event 17 is also explicitly cleared at `0x81fc`.

## Event 13: `a0` / `a1` / `a2`

Function `0x4440` builds the event-13 payload at RAM `0x20001fcc`:

- byte 0 = `'a'`
- if `u8[0x2000209d] != 0`, byte 1 = `'1'`
- otherwise if `u8[0x20002529] != 0`, byte 1 = `'2'`
- otherwise byte 1 = `'0'`

If `u8[0x20002329] == 0`, the function schedules event 13 once at `0x445a`.

Startup explicitly schedules event 13 five times at `0x94b2`.

The Remote asynchronous dispatcher `0x10cf4` has a lowercase-response path that accepts a second digit in the range `0..2` and stores the state when it changes. Therefore the active payload is structurally confirmed as **`a0`, `a1`, or `a2`**. The human meaning of those three states remains open.

## Dormant / unproduced endpoints in this build

No direct scheduling producer was found for events:

`2, 3, 8, 9, 11, 12, 14`

Events 11, 12, and 14 would emit literal strings `M1`, `M2`, and `M3`. The Remote's active asynchronous `M` branch handles `MS` and `MT`, but does not branch on `M1`, `M2`, or `M3`, and no separate active comparison was found.

**Harness implication:** treat `M1/M2/M3` and events 8/9 as low-priority compatibility/legacy endpoints unless symbolic execution finds a computed scheduling path that this direct-reference survey missed.

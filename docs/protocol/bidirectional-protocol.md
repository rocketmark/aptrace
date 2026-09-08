# Bidirectional Protocol Graph (curated)

**Authoritative source**: `research/autopilot_static_inventory/protocol-bidirectional.md`
and `synchronous-responses.md`. This file is a curated summary; read those
for exact register/RAM addresses and instruction-level detail.

## Overall shape

```
Remote UI / state machine
        |
        v
Remote TX wrapper (flash 0x58a8)
        |
        | RF (LoRa)
        v
AutoPilot parser (flash 0x8258)         <- one command byte confirmed
        |                                  by execution to require
        +--> command/state logic            exact ASCII value; see
        |                                    docs/investigations/parser-dispatch.md
        +--> pending[event] @ RAM 0x200025bc
                      |
                      v
             event dispatcher (flash 0x9268)
                      |
          +-----------+-----------+
          |                       |
          v                       v
   byte TX (0x7f84)        string TX (0x8c10)
          |                       |
          +-----------+-----------+
                      |
                      | RF (LoRa)
                      v
             Remote RX ring buffer
                      |
          +-----------+-------------+
          |                         |
          v                         v
 synchronous request parser     async dispatcher (0x10cf4)
```

## Best-documented transactions (static analysis)

### Firmware-version query (execution-confirmed end to end, both firmwares)

```
Remote (0xba98): send "&|"             [execution-confirmed: real "&|\0" literal, real TX call]
    -> AutoPilot parser (0x8258)
    -> 0x889a schedules event 5           [execution-confirmed]
    -> event 5 sends RAM 0x20003134
    -> payload "V01R39"                    [execution-confirmed: real TX hook, exact bytes]
    -> Remote captures at RAM 0x200002fc  [execution-confirmed: real RX loop, exact bytes]
    -> shown on Remote's firmware-info UI
```

Both the AutoPilot side (parser -> event 5 -> TX hook -> `"V01R39"`) and
the Remote side (TX construction and RX capture) are now
execution-confirmed at the concrete (Unicorn) evidence tier — see
[`docs/harness/protocol-harness-results.md`](../harness/protocol-harness-results.md),
[`docs/investigations/tx-hook-verification.md`](../investigations/tx-hook-verification.md),
and
[`docs/investigations/mando-first-execution.md`](../investigations/mando-first-execution.md).
Not yet done: connecting the two sides into one live virtual-RF-link
harness run (design validated, not yet built — see
`mando-first-execution.md`) and a solver-confirmed (Crucible) proof of
either side's whole transaction — see
[`docs/project-status.md`](../project-status.md).

### `G` acknowledgement

```
Remote (0xb680) builds "G<d><d><seq>|"
    -> 0xb59c sends / retries
    -> AutoPilot G branch                  [byte value execution-confirmed]
    -> 0x83ea schedules event 17
    -> "#"
    -> Remote accepts acknowledgement
```

### `S` state/config query

```
Remote (0xc440) sends "S|"
    -> AutoPilot schedules event 6         [byte value execution-confirmed]
    -> "P<value0>," [or "P<value0>,<value1>,<bool>,"]
    -> Remote P parser
```

### Bulk `!` transaction (known field-count mismatch)

```
Remote (0xc440) sends "!0|" or "!1|"
    -> AutoPilot schedules event 7         [byte value execution-confirmed]
    -> AutoPilot emits 11 numeric fields
    -> Remote's parser only calls its numeric-field parser 10 times
```

This 11-vs-10 mismatch is a genuine discrepancy in the shipped firmware
pair, not a research error — see `event7-schema.md` in the static inventory
for the exact field list. Do not "fix" it by trimming the AutoPilot's output
or extending the Remote's parser in any harness built on this.

### Dynamic per-channel `I` transaction

```
Remote (0xb958) sends "I<channel><mode>|"
    -> AutoPilot seeds per-channel state machine
    -> completion monitor (0x8b5c) detects done
    -> 0x8b70 schedules event 15
    -> "<signed-number>,"
    -> Remote parses/stores value
```

## First harness milestone (recommended in the static inventory)

The firmware-version transaction (`&|` -> `V01R39`) was recommended as the
cleanest first full round-trip test — deterministic, short, no motor state
involved. **This is exactly APTrace's current milestone** (see
[`docs/project-status.md`](../project-status.md)), independently arrived at
by both the static-analysis pass and the harness work.

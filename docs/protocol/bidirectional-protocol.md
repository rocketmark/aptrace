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
        |                                    docs/investigations/protocol-pipeline.md
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
the Remote side (TX construction and RX capture) are execution-confirmed
at the concrete (Unicorn) evidence tier — see
[`docs/investigations/protocol-harness-results.md`](../investigations/protocol-harness-results.md),
[`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md),
and
[`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
— **and now also connected into one live, harness-driven round trip**
(`tools/unicorn/virtual_link.py`, no LoRa/SPI hardware modeled): Remote's
real TX call, a harness-mediated byte transfer, AutoPilot's real parse
and response, a second harness-mediated transfer, Remote's real capture,
asserted end to end. See
[`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md).
Not yet done: a solver-confirmed (Crucible) proof of either side's whole
transaction — see [`docs/project-status.md`](../project-status.md).

### `G` acknowledgement (execution-confirmed end to end, both firmwares, through the virtual link)

```
Remote (0xb680) builds "G<d><d><seq>|"        [execution-confirmed: real bytes, real send call]
    -> 0xb59c sends / retries
    -> AutoPilot G branch                  [execution-confirmed: pending[17] concretely set, not just entry reachability]
    -> 0x83ea-equivalent schedules event 17
    -> "#"                                  [execution-confirmed: real 0x7f84 call, exact byte]
    -> Remote 0xb59c accepts acknowledgement  [execution-confirmed: real retry/ack loop, R4=1]
```

Confirmed via `tools/unicorn/virtual_link.py g` (roadmap M4) — the same
harness-driven virtual link built for `&|` (M3), reusing its
`capture_tx_bytes`/`deliver_and_observe` primitives plus a new
byte-value `capture_tx_byte` (event 17's response is a single byte via
`0x7f84`, not a string via `0x8c10`). See
[`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md)
for the full trace, including two AutoPilot-side helpers stubbed for the
same reasons already documented for the RF drivers (one is architecturally
identical: a driver-object virtual call only valid after real startup).

### `S` state/config query (execution-confirmed end to end, both response forms, through the virtual link)

```
Remote (0xc440) sends "S|"                [execution-confirmed: exact bytes, real send call]
    -> AutoPilot schedules event 6 AND     [execution-confirmed: pending[6] set, value0 computed
       computes value0, in the same pass    in the same handler pass, not two separate steps]
    -> "P<value0>," [or "P<value0>,<value1>,<bool>,"]   [execution-confirmed: both forms, real bytes]
    -> Remote's real parser consumes and stores it       [execution-confirmed, both forms]
```

Confirmed via `tools/unicorn/virtual_link.py s` (roadmap M4), run at two
concrete AutoPilot device-state values to exercise both response forms
for real. Two refinements to the reading above (both found by running
the real code, not by re-reading the decompile more carefully): the
AutoPilot-side "send the extended form" condition and the Remote-side
"parse two extra fields" condition are the *same* variable by
construction, not independently observed and coincidentally aligned; and
the Remote has its own "don't downgrade" guard — a fresh device
receiving the short form `"P1,"` does not update its stored state at
all. See
[`docs/investigations/protocol-pipeline.md`](../investigations/protocol-pipeline.md).

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

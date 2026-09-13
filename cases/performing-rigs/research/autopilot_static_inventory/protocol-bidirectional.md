# Bidirectional protocol graph — v0.3

```text
Remote UI / state machine
        |
        v
Remote TX wrapper 0x58a8
        |
        | virtual RF
        v
AutoPilot parser 0x8258
        |
        +--> command/state logic
        |
        +--> pending[event] @ 0x200025bc
                      |
                      v
             event dispatcher 0x9268
                      |
          +-----------+-----------+
          |                       |
          v                       v
   byte TX 0x7f84          string TX 0x8c10
          |                       |
          +-----------+-----------+
                      |
                      | virtual RF
                      v
             Remote RX ring buffer
                      |
          +-----------+-------------+
          |                         |
          v                         v
 synchronous request parser     async 0x10cf4
```

## Best proven harness transactions

### Firmware-version transaction

```text
Remote 0xba98
    send &|
       -> AutoPilot parser 0x8258
       -> 0x889a schedules event5
       -> event5 sends RAM 0x20003134
       -> exact payload V01R39
       -> Remote captures at 0x200002fc
       -> information UI 0xfa10 / 0xfadc
```

This is probably the cleanest first bidirectional harness test because it is deterministic, short, and does not involve motor state.

### G acknowledgement

```text
Remote 0xb680 builds G<d><d><seq>|
    -> 0xb59c sends / retries
    -> AutoPilot G branch
    -> 0x83ea schedules event17
    -> #
    -> Remote 0xb59c accepts acknowledgement
```

### S state/config transaction

```text
Remote 0xc440 sends S|
    -> AutoPilot schedules event6
    -> P<value0>, [or P<value0>,<value1>,<bool>,]
    -> Remote c440 P parser
```

### Bulk `!` transaction

```text
Remote 0xc440 sends !0| or !1|
    -> AutoPilot schedules event7
    -> AutoPilot emits 11 numeric fields
    -> Remote c440 calls numeric parser only 10 times
```

The harness should preserve this discrepancy exactly.

### Dynamic per-channel I transaction

```text
Remote 0xb958 sends I<channel><mode>|
    -> AutoPilot I parser seeds per-channel state
    -> AutoPilot monitor reaches completion
    -> 0x8b70 schedules event15
    -> <signed-number>,
    -> Remote 0xb958 parses/stores value
```

## First harness milestone recommendation

Use `&| -> V01R39` as the first **full two-firmware round trip**. It exercises:

1. real Remote request logic,
2. Remote TX hook,
3. real AutoPilot parser,
4. pending-event scheduling,
5. real AutoPilot outbound dispatcher,
6. AutoPilot text TX hook,
7. Remote receive buffering,
8. real Remote synchronous response handling,
9. an observable application-state/UI buffer result.

After that, add `G -> #`, `S -> P...`, and `! -> CSV` before attempting motion-related paths.

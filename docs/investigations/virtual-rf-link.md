# Investigation: A Harness-Driven Virtual RF Link (M3 Step 8)

**Question**: [`docs/investigations/mando-first-execution.md`](mando-first-execution.md)
proved all four pieces of the `&|` -> `V01R39` round trip independently,
at the concrete (Unicorn) evidence tier, as separate hand-run scenarios,
and worked out the exact design for connecting them. This slice turns
that design into one harness-driven round trip between both unmodified
firmware images — [`docs/harness/roadmap.md`](../harness/roadmap.md)'s
M3 step 8 — without modeling LoRa/SPI hardware.

**Scope**: wire the existing, already-proven pieces together; reuse
`tools/unicorn/run_concrete.py` and its `--stub-call` mechanism exactly as
already established; no new Unicorn/Crucible/Macaw capability, no
peripheral/radio emulation, no Ghidra work (nothing new to discover — the
static structure was already fully mapped in the prior two investigations).

## Design: hook above the radio driver, transfer exact bytes, resume

Per `mando-first-execution.md`'s "Boundary found": both firmwares gate
their real radio I/O behind a runtime driver object that only becomes
valid after real startup runs, and reaching *through* it concretely would
mean either running full startup or building real SPI/radio peripheral
behavior — both explicitly out of scope. The link therefore hooks
**above** that layer on both ends, exactly where
`research/autopilot_static_inventory/rf-boundaries.md` originally
recommended (before any execution work existed to confirm it):

```
Remote 0xba98                              AutoPilot 0x8258 (dispatcher)
  real code computes "&|"                    real code parses it, sets pending[5]
        |                                           |
        v (capture: stop at the real TX             ^ (deliver: seed the real RX
        |  wrapper's own entry, read its             |  packet buffer, run from the
        |  argument register, dump the                |  real dispatcher call site)
        |  string it points at)                        |
        v                                           |
   [[ harness: exact bytes, no radio ]] ------------+
                                                     |
AutoPilot 0x9268 (event dispatcher)                 v
  real code builds "V01R39"              Remote 0xba98 collection loop
        |                                     real code copies it into
        v (capture, same technique,            its own capture buffer
        |  AutoPilot's 0x8c10)                       ^
        v                                            | (deliver: seed the real RX
   [[ harness: exact bytes, no radio ]] -------------+  ring buffer + its write
                                                         pointer, run with the
                                                         not-yet-modeled radio-
                                                         driver calls stubbed)
```

## Reusable primitives, not a one-off script

Two primitives fall out of doing this for real (both in
[`tools/unicorn/virtual_link.py`](../../tools/unicorn/virtual_link.py)),
not specific to this one transaction:

- **`capture_tx_bytes(firmware, entry, tx_wrapper_entry, seed_mem=...)`**:
  runs the real firmware from `entry` until it reaches `tx_wrapper_entry`
  — a `void wrapper(char *s)`-convention TX call, entered *fresh* (not
  stepped into, so none of the wrapper's own not-yet-modeled body ever
  runs) — and returns exactly the NUL-terminated bytes it is about to
  hand that wrapper. **Two real Unicorn runs, not one**: the first
  discovers what address the firmware itself computed as the argument
  (`R0`) at the wrapper's entry, without assuming it; the second dumps
  memory there. This is what makes it reusable for a transaction whose
  output *isn't* already known in advance (unlike this pass's own `&|`
  demo, where both outputs were already independently proven) — a future
  `G`/`S`/`!` transaction can call the exact same function.

  Both firmwares' real TX wrappers share this exact calling convention
  (confirmed independently, not assumed): AutoPilot's `0x8c10`
  ([`tx-hook-verification.md`](tx-hook-verification.md)) and Remote's
  `0x58a8` ([`mando-first-execution.md`](mando-first-execution.md)) are
  both `void wrapper(char *s)` under AAPCS32. Stopping *at* the wrapper's
  own entry (rather than at the call site inside its caller) works
  identically for both — confirmed this pass for Remote's `0x58a8` too
  (previously only tried at the call site `0xbab0` in
  `mando-first-execution.md`; stopping at `0x58a8` directly gives the
  identical `R0` with one fewer address to track, so this pass adopted
  the AutoPilot-style convention for both).

- **`deliver_and_observe(firmware, entry, seed_mem, observe_addr,
  observe_len, stub_calls=..., stop_at=...)`**: seeds a firmware's real RX
  state (a packet buffer, or a ring buffer plus its read/write pointers)
  with bytes already captured from the other side, runs its real,
  unmodified code, and returns whatever memory range the caller wants to
  observe (a pending-event byte, a response-capture buffer). Reusable for
  any future transaction's RX side the same way.

Both primitives are thin wrappers around `run_concrete.py` invoked as a
subprocess — the *same* CLI command a human would type, not a new
Unicorn/emulation code path. `tools/unicorn/virtual_link.py` adds no new
harness capability; it only orchestrates the existing one.

## The round trip

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py
```

```
=== Leg 1: Remote constructs its real query ===
  Remote's real, unmodified 0xba98 calls 0x58a8 with a pointer to flash 0x1c7ec, bytes = b'&|\x00'
=== Leg 2a: AutoPilot receives it and schedules event 5 ===
  AutoPilot's real, unmodified 0x8258 dispatcher, given the real wire bytes b'&|', sets pending[5] = 0x01
=== Leg 2b: AutoPilot's outbound dispatcher builds its real response ===
  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x8c10 with a pointer to RAM 0x20003134, bytes = b'V01R39\x00'
=== Leg 3: Remote receives it ===
  Remote's real, unmodified 0xba98 collection loop, given the real wire bytes b'V01R39\x00', captures b'V01R39\x00' at 0x200002fc

Round trip PASSED: Remote "&|" -> AutoPilot event 5 -> Remote "V01R39\0"
```

**This closes the acceptance target exactly**: Remote sends `"&|"` ->
harness transfers the exact emitted bytes -> AutoPilot parses it and
produces `"V01R39"` -> harness transfers the exact emitted bytes -> Remote
captures exactly `"V01R39\0"`. Every byte crossing an RF boundary in this
transcript is the *real* value the *real*, unmodified firmware computed
at that step — none of the four payloads (the `&|` query, the wire bytes
AutoPilot's dispatcher receives, the `V01R39` response, the bytes Remote
captures) is hardcoded anywhere in `virtual_link.py`; only the six
already-proven RF-boundary *addresses* are (`REMOTE_TX_ENTRY`,
`REMOTE_TX_WRAPPER`, `AUTOPILOT_RX_ENTRY`/`AUTOPILOT_RX_BUFFER`,
`AUTOPILOT_TX_ENTRY`/`AUTOPILOT_TX_WRAPPER`, `REMOTE_RX_ENTRY`/ring-buffer
addresses), matching exactly the anchors already established in
`mando-first-execution.md` and `dispatcher-loop-concrete-trace.md`/
`tx-hook-verification.md`.

`pending[5]` is likewise threaded through as an **observed** value from
leg 2a into leg 2b's seed, not hardcoded to `1` — a small but real
improvement in rigor over the two separate, hand-run scenarios this
replaces (which each seeded their half independently).

## What the harness still substitutes for real hardware behavior

Documented here for completeness, not new to this pass — all inherited
directly from `mando-first-execution.md`'s "Boundary found" and
`dispatcher-loop-concrete-trace.md`'s own documented simplifications:

- **The AutoPilot RX buffer is seeded directly** rather than simulating
  byte-by-byte LoRa/UART arrival through `FUN_00008960`'s real assembly
  loop. Already justified: that loop's own gating (`0x8266`'s
  `buffer[0]==0xF0` check) is independent of *how* the buffer got filled,
  confirmed in `dispatcher-loop-concrete-trace.md`.
- **The AutoPilot outbound scan table/count/timestamp are seeded, not
  derived**, per `tx-hook-verification.md`'s own documented
  simplification (the table's real initialization code was not traced).
- **Remote's radio poll, TX wrapper body, and SysTick-based delay are
  stubbed** (`--stub-call` on `0xb440`/`0x58a8`/`0x168c0`) rather than
  executed, per `mando-first-execution.md`'s "Boundary found" — both
  firmwares' real SPI/radio driver objects are only valid after real
  startup, which this link's entry points, by design, skip.
- **Remote's drain loop, preamble (`FUN_00005a14`), and post-request
  routine (`FUN_00005a50`) are bypassed by entry-point choice** (entering
  at `0xbaaa`/`0xbaa6`, past them) — not concretely exercised, matching
  `mando-first-execution.md`'s already-documented scope.
- **This is a single-shot, one-transaction link**, not a live loop: each
  leg is a separate `run_concrete.py` process (Unicorn has no persistent-
  session mode — see `docs/tooling/unicorn-backend.md`'s "Known
  limitations"). Running a second transaction means calling the
  primitives again with new addresses, not resuming state from this run.

None of this is new scope creep — it is the same set of simplifications
already documented and justified in the two prior investigations, now
just exercised end-to-end in one script instead of by hand across two.

## Evidence level

**Concrete (level 2)** end to end, per
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md)'s
evidence levels — the same tier as the AutoPilot-only milestone and the
Mando first-execution pass. No genuinely symbolic question arose in this
slice (per the task's own framing, "stay concrete unless a genuinely
symbolic question appears"), so no Crucible/What4/Z3 work was done or
needed.

## Next logical transaction

**Update (2026-09-08)**: `G -> #` is done — see
[`docs/investigations/g-ack-roundtrip.md`](g-ack-roundtrip.md). It
confirmed the two primitives above generalize (with two real additions:
register seeding, and a byte-value `capture_tx_byte` alongside the
pointer-based `capture_tx_bytes`, since event 17's response is a single
byte via `0x7f84`, not a string via `0x8c10`).

Next: **`S -> P...`** — Remote's `0xc440` sends `S|`, AutoPilot schedules
event 6, Remote's `0xc440` parses the `P<value>,...` response. `0xc440`
is a larger function (also handles `!0|`/`!1|`), so expect to spend part
of the slice narrowing down the `S`-specific path — not started, per the
`g-ack-roundtrip.md` task's explicit scope.

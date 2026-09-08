# Investigation: `S -> P...` Through the Virtual RF Link (M4)

**Question**: per
[`docs/harness/roadmap.md`](../harness/roadmap.md)'s M4 (next after
`G -> #`) and
[`research/autopilot_static_inventory/synchronous-responses.md`](../../research/autopilot_static_inventory/synchronous-responses.md)'s
already-detailed static reading of `S|` -> `P...`: what does the real,
running firmware actually do — not just "does the transaction complete,"
but which concrete RAM state produces which response fields, whether the
short or extended form comes out, and how the Remote actually parses and
stores what comes back?

**Scope**: reuse `capture_tx_bytes`/`deliver_and_observe`/register
seeding/`--stub-call` exactly as already established; investigate
Remote's `0xc440` and AutoPilot's `S` handler/event-6 builder only as far
as needed to answer the questions above; no new harness features unless
the firmware genuinely required one (it didn't, this time — see below);
no Crucible/Macaw work; explicitly not continuing into `!`/`I` (`0xc440`
handles `!0|`/`!1|` too, immediately after `S`/`P`, but that's out of
scope for this slice).

## The exact request: `"S|"`

`FUN_0000c440(0)` (`param_1 = 0` in R0) is Remote's combined
`S`-then-`!` synchronous routine. Confirmed by literal-pool read (the
same technique used throughout this project): `DAT_0000c660` resolves to
flash `0x1c58c`, a contiguous string literal `"S|\0"` — captured directly
via `capture_tx_bytes`, stopping at `0x58a8`'s own entry:

```
Remote's real, unmodified 0xc440(0) calls 0x58a8 with a pointer to
flash 0x1c58c, bytes = b'S|\x00'
```

One real wrinkle, same class as `G`'s: `0xc440` calls a wake preamble
(`0x5a14`) **unconditionally** when `param_1 == 0` (unlike `0xb59c`'s
*conditional* preamble for `G`, gated by a flag) — left un-skipped, the
preamble's own call to `0x58a8` gets captured instead of the real `S`
request. Fixed by `--stub-call`-ing `0x5a14` directly (simpler than the
flag-seed trick used for `G`, and arguably the more general form of the
same fix: skip the whole irrelevant preamble function, rather than find
a flag that happens to gate it).

## AutoPilot concretely schedules event 6 — and computes `value0` in the same step

The `S` handler is not a separate, standalone "build the response" step —
it's the *same* code (inside `FUN_000083b2`, the shared ASCII-command
dispatcher) that both **schedules event 6** and **computes and stores
the response's first field**, in one pass:

```c
if (in_r3 == 0x53) {                          // 'S' -- actually the
                                                //  `else` arm of an
                                                //  `if (in_r3 != 0x53)`
                                                //  test; see full decompile
  ...
  switch (*(byte *)0x20002524) {               // device state/mode, 0-4
    case 0: cVar12 = 1; break;                 // (via a shared tail, LAB_00008510)
    case 1: cVar12 = 9, 0x1b, or 7;             // sub-selected by two more flags
    case 2: case 3: cVar12 = 2; break;
    case 4: cVar12 = 0xb, 0xa, or 0x1c;         // sub-selected by two more flags
    default: /* value0 left unset */
  }
  *(byte *)0x200025ad = cVar12;                // value0, for event 6's builder to read later
  ...
  *(byte *)0x200025c2 = 1;                     // pending[6] = 1
}
```

(Literal-pool-resolved addresses, not assumed: `0x20002524`, `0x200025ad`,
and pending-base-plus-6 = `0x200025c2` were all confirmed by reading the
raw flash bytes at the relevant `DAT_*` symbols, the same way every
address in this project's investigations has been.)

Concretely, from cold RAM (`0x20002524 == 0`): **55 instructions,
`pending[6] = 0x01`, `value0 = 0x01`** — no `--stub-call` needed at all
for this path (unlike `G`'s handler, which needed two). This is itself
worth noting: not every ASCII-command handler touches the same
not-yet-modeled driver/config helpers `G`'s did.

## AutoPilot's real response: two forms, both exercised concretely

The outbound dispatcher's case 6 (inlined directly in `0x9268`'s switch,
not a separate builder function — `synchronous-responses.md`'s "`0x930a`"
is this inline block's own address, not a distinct function):

```c
case 6:
  buffer[0] = 'P';
  itoa_and_comma(*(byte*)0x200025ad);                 // value0
  if (*(byte*)0x20002524 == 4) {                       // the SAME mode variable
    itoa_and_comma(*(int*)0x20002530);                 // value1
    itoa_and_comma(*(byte*)0x20003100 != 0);            // bool
  }
  buffer[len] = 0;
```

`itoa_and_comma` (`FUN_00004644`, decompiled and confirmed) converts a
signed integer to decimal ASCII **and appends a trailing comma** — this
is why every field in a `P...` response is comma-terminated, including
the last one (`docs/protocol/`'s existing "P<value0>," notation is
exact, not shorthand).

Concretely, from the two `AUTOPILOT_S_MODE` values this pass ran (not
just the cold-RAM default):

| `AUTOPILOT_S_MODE` | `value0` | Real response (`capture_tx_bytes`, `0x8c10`) |
|---:|---|---|
| `0` (cold RAM) | `0x01` | `b'P1,'` |
| `4` (seeded) | `0x0b` | `b'P11,0,0,'` |

**The response buffer address (`0x20002548`) was not named in the
existing static docs** — found this pass by letting `capture_tx_bytes`
discover it from the real `R0` at the `0x8c10` call, not by assumption.

**A refinement to the static interpretation, not just a confirmation**:
`synchronous-responses.md` documents two *separately observed* facts —
AutoPilot appends extra fields "when `u8[0x20002524] == 4`," and Remote
expects extra fields "if the resulting stored state becomes `10`, `11`,
or `28`." Reading the `S` handler's switch shows these are not two
independently-tuned constants that happen to agree — **they are the same
condition by construction**: case `4` of the switch is the *only* case
that can produce `value0 ∈ {10, 11, 28}` (`0x0a`, `0x0b`, `0x1c`), and it
is guarded by the exact same `0x20002524 == 4` test the builder checks
separately, later. The protocol's short/extended framing and its
apparent "value happens to be in this set" framing are the same design
decision seen from two sides, not two.

## Remote's real parse and store: confirms the static reading, plus a real guard it didn't mention

Disassembling `0xc440`'s parse loop (`0xc4dc`-`0xc55e`, not just
decompiling it — needed exact addresses for concrete entry/stop points
and to resolve which registers the loop's own prologue sets up) pins
down what the decompile already suggested and adds one real behavior:

```
0xc4f8: cmp r3,#'P' ; bne <not-P, keep scanning>
0xc4fc: consume 'P'
0xc508: cmp r3,#'N' ; bne 0xc51e            <- our real responses take this path
0xc51e: bl 0xb51c                            ; parse a signed decimal field -> R0 (value0)
0xc524: cmp r0,#1 ; bne 0xc52e               ; if value0 != 1, always store it
0xc528: cmp [stored_state],#6 ; bls 0xc530   ; if value0 == 1 AND stored_state <= 6: DON'T store it
0xc52e: strb r0,[stored_state]
0xc530: sub [stored_state],#0xa ; cmp #1 ; bls <extended>   ; stored_state in {10,11}?
0xc53a: cmp [stored_state],#0x1c ; beq <extended>            ; or == 28?
        ...(extended: bl 0xb51c x2 for value1, bool)...
```

Confirmed concretely, both forms:

| Response | Remote's stored state (`0x200018e7`) | value1 (`0x20002688`) | bool (`0x20002671`) |
|---|---|---|---|
| `b'P1,'` | `0x00` (**unchanged from cold RAM's `0`**) | — | — |
| `b'P11,0,0,'` | `0x0b` (updated) | `0` | `0x00` |

**The short-form result is the interesting one, and it is not a
harness artifact**: `synchronous-responses.md` describes the parse as
"parses a signed decimal field... if the resulting stored state becomes
10, 11, or 28, [parse two more]" — read plainly, this suggests the parsed
value always becomes the new stored state. Concretely, from a genuinely
cold device, receiving the real `"P1,"` response does **not** update the
stored state at all — `0xc440` has its own guard
(`if (value0 != 1 || stored_state > 6) store it`) that a fresh device
with `stored_state == 0` fails, so the `1` is silently dropped. This is
real firmware behavior, demonstrated with the device's actual cold-start
state, not a value chosen to force an interesting result — see "Cold-
start and driver-state caveats" below for exactly which values are cold-
RAM defaults versus seeded.

A second small, real nuance visible in the disassembly but not chased
further (out of scope — doesn't affect either response form this pass
exercised): `if (stored_state == 7) stored_state = 0x17 (23);` — a direct
remap, unconditional once state reaches 7. Noted, not investigated.

## `PN...`: Remote parses it fully; AutoPilot's producer side still doesn't reach it

`docs/protocol/open-questions.md`-equivalent
(`research/autopilot_static_inventory/open-questions.md` #6) frames this
as unresolved: "no matching producer has yet been found." Reading
`0xc440`'s full disassembly resolves the Remote half of that question
definitively: **the Remote's `PN` branch is fully implemented**, not
missing or stubbed —

```c
if (byte == 'P') {
  consume();
  if (byte == 'N') {
    consume();
    if (stored_state - 9 < 3) {   // stored_state in {9, 10, 11}
      stored_state = 1;
    }
    // else: falls through, no-op
  }
  ...
}
```

This pass did **not** find a producer on the AutoPilot side either —
the `S` handler's switch (above) only ever selects cases `0`-`4`, never
emitting `'N'` as a second byte, confirmed by reading the *entire*
switch, not by a failed search. The refinement is in the framing, not
the conclusion: this is not "the Remote doesn't handle `PN`, so it can't
matter" — the Remote handles it completely; it is specifically *this*
AutoPilot firmware build's `S` handler that never triggers it. A
different AutoPilot build/config could in principle reach it without any
Remote-side change.

## Reproduce it

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/virtual_link.py s
```

```
=== Leg 1: Remote constructs its real S query ===
  Remote's real, unmodified 0xc440(0) calls 0x58a8 with a pointer to flash 0x1c58c, bytes = b'S|\x00'

--- AUTOPILOT_S_MODE = 0 (short response) ---
=== Leg 2a: AutoPilot receives it and schedules event 6 ===
  AutoPilot's real, unmodified 0x8258 dispatcher (mode=0) sets pending[6] = 0x01, value0 = 0x01
=== Leg 2b: AutoPilot's outbound dispatcher builds its real "P..." response ===
  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x8c10 with a pointer to RAM 0x20002548, bytes = b'P1,\x00'
=== Leg 3: Remote's real parser consumes and stores it ===
  Remote's real, unmodified 0xc440 parser, given the real wire bytes b'P1,', stores state=0x00 value1=0 bool=0x00

--- AUTOPILOT_S_MODE = 4 (extended response) ---
=== Leg 2a: AutoPilot receives it and schedules event 6 ===
  AutoPilot's real, unmodified 0x8258 dispatcher (mode=4) sets pending[6] = 0x01, value0 = 0x0b
=== Leg 2b: AutoPilot's outbound dispatcher builds its real "P..." response ===
  AutoPilot's real, unmodified 0x9268 dispatcher calls 0x8c10 with a pointer to RAM 0x20002548, bytes = b'P11,0,0,\x00'
=== Leg 3: Remote's real parser consumes and stores it ===
  Remote's real, unmodified 0xc440 parser, given the real wire bytes b'P11,0,0,', stores state=0x0b value1=0 bool=0x00

Both response forms observed:
  short:    mode=0 -> value0=0x01 -> response=b'P1,' -> Remote stores state=0x00 (...)
  extended: mode=4 -> value0=0x0b -> response=b'P11,0,0,' -> Remote stores state=0x0b, value1=0, bool=0x00
```

## No new harness capability was needed

Unlike `G`, this transaction needed no new primitive and no change to
`run_concrete.py` — only the already-existing `reg_seed`/`stub_calls`
parameters on `capture_tx_bytes`/`deliver_and_observe`/`run_concrete`,
used directly (a couple of call sites use `run_concrete` directly rather
than `deliver_and_observe`, because this transaction needs to observe
*two* unrelated memory addresses from one run — `deliver_and_observe`'s
contract is one address; generalizing it for a single call site here
wasn't judged worth doing yet). One genuine new register-seeding fact
was found empirically, not planned in advance: the extended-response
parse path dereferences `R9` (the value1-store pointer, set once far
earlier in `0xc440` and never reloaded) — omitted on the first attempt,
which crashed cleanly on a null-pointer-shaped write; added once the
crash pinpointed it. The short-response path never touches `R9` at all,
confirmed by *not* needing it there, not assumed.

## Cold-start and driver-state caveats

Documented explicitly, not silently chosen to force a result:

- **`AUTOPILOT_S_MODE` (`0x20002524`) itself is never derived** — this
  pass ran the transaction at two representative concrete values (`0`,
  the cold-RAM default, and `4`, chosen because it's the only value that
  produces the extended form) rather than tracing what real device
  operation sets it to. What that variable actually *means* (which
  device condition maps to which of its 5 values) is not answered here —
  a real next question, not resolved by this slice.
- **The secondary sub-select flags** (`0x2000252e`, `0x2000312c`,
  `0x200030dc` — refining cases `1` and `4` into their exact `cVar12`
  value) are left at their cold-RAM defaults (`0`) throughout; only one
  of each case's sub-branches was exercised.
- **`value1`/`bool`'s real sources** (`0x20002530`, `0x20003100`) are
  also cold-RAM zero in the extended-form run — the response `"P11,0,0,"`
  reflects a genuinely fresh device, not a device with anything
  interesting to report; this pass did not investigate what sets these
  to something else.
- **The Remote's own `param_1 != 0` path (the `!0|`/`!1|` half of
  `0xc440`) was not executed** — Leg 1 stops at the `S`-request send,
  well before `0xc440` would reach that code, per this task's explicit
  "do not continue into `!` or `I` yet."

## Evidence level

**Concrete (level 2)**, both response forms, matching `&|` and `G`. No
genuinely symbolic question arose.

## Next: a deliberate pivot from protocol mapping to hardware provenance

Per the task, the next slice is **not** `!` or `I` — those stay queued
(`!`'s already-known 11-vs-10 field mismatch, `I`'s per-channel state
machine). Instead: **complete the SAMD51 motor-timer hardware mapping**
already started in
[`docs/investigations/samd51-peripheral-mapping.md`](samd51-peripheral-mapping.md).
That investigation fully closed one channel's hardware chain
concretely — TCC1's interrupt handler (`IRQ93`, flash `0x60ec`) toggles
`PB22` — and explicitly flagged finding the other three motor channels'
ISR/pin pairs (TC0, TC1, TC2 — the same four-timer group `FUN_00005570`
and siblings configure at startup) as its own next step, using the exact
same technique (find the IRQ vector via `tools/vector_scan.py`,
decompile the handler, resolve literal-pool GPIO addresses via
`tools/svd/resolve_mmio.py`). That is the best next
behavior-to-hardware target: it is small, self-contained, already
partially scoped by a prior investigation, and directly extends a
technique already proven to work — a "smallest useful slice" in exactly
this project's own established sense. Once all four channels' pins are
named, the natural follow-on (a separate, later slice) is connecting
`I<channel><mode>|`'s already-mapped protocol-level state machine
(`u8[0x20001b14[channel]]`, `u8[0x200029d8[channel]]`,
`i32[0x20002064[channel]]` — see
[`research/autopilot_static_inventory/synchronous-responses.md`](../../research/autopilot_static_inventory/synchronous-responses.md))
to which specific TC peripheral and pin each channel drives, completing
the full `command -> internal state -> timer/MMIO -> ISR -> GPIO -> pin`
chain the project is deliberately pivoting toward.

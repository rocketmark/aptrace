# Investigation: First Concrete Execution of the Remote (`mando`) Firmware

**Question**: with the AutoPilot-only milestone closed at the concrete
(Unicorn) evidence tier, and M3 ("Remote firmware") now unblocked per
[`docs/harness/roadmap.md`](../harness/roadmap.md), what is the smallest
useful concrete foothold in `firmware_mando868.bin`, and what would it take
to connect the two firmwares through a virtual RF link?

**Scope**: get Mando running through the *existing* Ghidra/Unicorn
machinery with no special-casing beyond what the platform genuinely needs;
find and concretely execute a real Remote-side protocol boundary; determine
(don't yet build) the virtual-RF-link design. No Crucible/Macaw work, no
general harness redesign, no peripheral/radio emulation — consistent with
[`docs/tooling/tool-selection.md`](../tooling/tool-selection.md).

## Reusing the existing static research

Before doing any new RE, this pass read the existing Remote-side static
inventory — it turned out to already contain exactly the anchor needed:

- [`research/autopilot_static_inventory/functions-of-interest.md`](../../research/autopilot_static_inventory/functions-of-interest.md)
  names `0xba98` as "**`&|` firmware-version request; captures `V01R39`**"
  at "very high" confidence — the Remote-side mirror of the AutoPilot
  milestone already closed.
- [`research/autopilot_static_inventory/rf-boundaries.md`](../../research/autopilot_static_inventory/rf-boundaries.md)
  had already identified `0x58a8` (Remote TX wrapper) and `0xb440`/`0xb4f8`
  (Remote LoRa receive poll / bytes-available) as the RF boundary
  functions, and recommended hooking *above* them, not modeling the radio.
- [`research/autopilot_static_inventory/protocol-bidirectional.md`](../../research/autopilot_static_inventory/protocol-bidirectional.md)
  already diagrammed the exact `Remote 0xba98 -> send &| -> ... -> Remote
  captures at 0x200002fc` transaction and recommended it as "the first
  full two-firmware round trip."

This pass did not need to discover a new anchor — it needed to confirm
this existing one by real execution, which had not been attempted (no
Ghidra/Unicorn/Macaw/Crucible work had touched `firmware_mando*.bin`
before this pass).

## Ghidra: clean discovery, no special-casing

`tools/ghidra/analyze_firmware.sh` (same script, same flash base `0x4000`,
same vector-table seeding) ran against `firmware_mando868.bin` unchanged:

```
tools/ghidra/analyze_firmware.sh research/firmware/originals/firmware_mando868.bin \
    0x4000 research/runs/ghidra/firmware_mando868.json "0xba98,0x58a8,0xb440,..."
```

563 functions discovered (vs. AutoPilot's 414 — Mando is the larger image).
Every previously-named function of interest resolved cleanly as a real
Ghidra function at its documented address (`0x58a8`, `0xb440`, `0xb59c`,
`0xb680`, `0xba98`, `0xc440`, `0xfa10`, `0xfadc`, `0x10cf4`) — no
mismatches, no re-basing needed. This confirms the "same platform, same
loader assumptions" premise directly rather than by inference: Mando needs
zero platform-specific harness changes.

## Decompiling and disassembling `0xba98`

Decompiling `0xba98` and its direct callees (`APTraceDecompileFunctions.java`,
already-integrated tool) shows:

```c
void FUN_0000ba98(void)  // Remote's "&|" query
{
  while (FUN_0000b4f8() != 0) { FUN_0000583c(); }   // drain stale RX bytes
  FUN_00005a14();                                    // wake/preamble (unrelated)
  uVar2 = DAT_0000bb0c; piVar1 = DAT_0000bb08;
  FUN_000058a8(DAT_0000bb04);                        // <-- send the query
  *piVar1 = FUN_00016840();
  while (FUN_0000b4f8() == 0 && FUN_00016840() - *piVar1 < 300) {
    FUN_0001486c(uVar2);                             // wait up to 300 (ticks) for a reply
  }
  iVar4 = 0; puVar6 = DAT_0000bb10;
  do {                                                // collect exactly 7 bytes
    if (FUN_0000b4f8() == 0) break;
    *puVar6++ = FUN_0000583c(); *puVar6 = 0;
    iVar4++;
    FUN_000168c0(2);
  } while (iVar4 != 7);
  FUN_00005a50();                                     // post-request (unrelated)
}
```

Reading the literal pool directly off the raw firmware bytes (the same
technique used throughout this project — e.g.
[`docs/investigations/tx-hook-verification.md`](tx-hook-verification.md)'s
`FUN_00004328`) resolves every `DAT_*` symbol above to a real address:

| Symbol | Value | What it is |
|---|---|---|
| `DAT_0000bb04` | `0x0001c7ec` | flash address — points at the literal bytes `"&|\0USB-R..."` |
| `DAT_0000bb08` | `0x2000276c` | RAM — last-send timestamp |
| `DAT_0000bb10` | `0x200002fc` | RAM — the response-capture buffer |

**`DAT_0000bb04` resolving to a real, contiguous, null-terminated `"&|\0"`
string literal in flash independently confirms the exact static claim**
(`functions-of-interest.md`'s "`&|` firmware-version request") **before
any execution — and it's even cleaner evidence than the AutoPilot side's
`"V01R39"`, which the compiler spread across individual byte-store
instructions rather than a contiguous literal.** `DAT_0000bb10` resolving
to `0x200002fc` also independently matches `protocol-bidirectional.md`'s
pre-existing claim ("Remote captures at 0x200002fc") — the static research
was accurate.

Disassembling the exact instruction range (`APTraceDisassembleRange.java`,
new small reusable Ghidra script added this pass, alongside the existing
`APTraceDecompileFunctions.java` — needed because decompiled C hides real
instruction addresses, and this investigation needed exact call-site and
loop-entry addresses to choose Unicorn entry points) gives the real
addresses used below: the send call is `0xbab0` (`bl 0x58a8`, with R0
loaded from the literal pool two instructions earlier at `0xbaaa`); the
7-byte collection loop runs `0xbac0`-`0xbafe`.

## Concrete execution: two runs, mirroring the AutoPilot milestone's own two-step structure

### Run A — real TX construction (Remote sends `"&|"`)

Entering at `0xbaaa` (the real `ldr r0,[0xbb04]` instruction — skipping
only the drain loop above it, which depends on the not-yet-modeled radio
driver, see "Boundary found" below) and stopping at the call (`0xbab0`):

```
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py \
    --firmware research/firmware/originals/firmware_mando868.bin \
    --entry 0xbaaa --mmio-base 0x40000000 --mmio-size 0x4000000 \
    --stop-at 0xbab0 --dump-mem 0x1c7ec:8 --max-instructions 100
```

Result: **4 real instructions**, `R0 = 0x0001c7ec` at the call to the real
TX wrapper (`0x58a8`), and the bytes at that address are exactly `"&|\0"`.
**The Remote's real, unmodified code constructs and would transmit exactly
`"&|"`** — the direct mirror of the AutoPilot side's already-proven
`"V01R39"` TX-hook result.

Continuing further (no `--stop-at`) runs into `0x58a8`'s own body and
crashes at `0x11986` (same class of issue as below) — `0x58a8` itself
depends on the same not-yet-modeled radio driver object, exactly as the
AutoPilot's `0x8c10` did in
[`docs/investigations/samd51-peripheral-mapping.md`](samd51-peripheral-mapping.md).
Both firmwares gate real RF I/O behind the same architectural pattern.

### Run B — real RX capture (Remote receives `"V01R39"`)

Entering at `0xbaa6` (after the drain loop, at the preamble call — the
byte-collection loop unconditionally re-invokes the radio poll every
iteration, so there is no address *inside* `0xba98` that avoids it; see
"Boundary found"), with the RX ring buffer pre-seeded with the AutoPilot's
own already-proven real response bytes, and three real-but-irrelevant
calls (the radio poll, the TX wrapper, and a SysTick-based delay) treated
as opaque:

```
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py \
    --firmware research/firmware/originals/firmware_mando868.bin \
    --entry 0xbaa6 --mmio-base 0x40000000 --mmio-size 0x4000000 \
    --stub-call 0x58a8 --stub-call 0xb440 --stub-call 0x168c0 \
    --seed-mem 0x20001773:5630315233390000 \
    --seed-mem 0x200017d7:00 --seed-mem 0x200017d8:07 \
    --stop-at 0xbacc --dump-mem 0x200002fc:8 --max-instructions 5000
```

(`0x20001773`/`0x200017d7`/`0x200017d8` are the RX ring buffer, its read
pointer, and its write pointer — resolved the same literal-pool way from
`FUN_0000b440`/`FUN_0000b4f8`/`FUN_0000583c`, cross-checked for
consistency across all three functions' independent literal-pool copies of
the same three addresses.)

Result: **292 real instructions**, correctly looping through the real
7-byte collection loop, and **`RAM[0x200002fc..+7]` = exactly `"V01R39\0"`**
— matching the AutoPilot side's already-proven exact TX output byte for
byte. **The Remote's real, unmodified byte-consumption logic correctly
copies a real AutoPilot response into its own capture buffer.**

This is the same evidence tier (level 2, concretely executed — see
`tool-selection.md`'s evidence levels) as the AutoPilot milestone, and
the same kind of entry-point choice (skip a not-yet-modeled earlier stage,
let the firmware establish its own state for everything downstream of
that point) already used and documented throughout this project (e.g.
entering at `0x8a34`/`0x9268` rather than the AutoPilot's true reset
vector).

## New harness capability: `run_concrete.py --stub-call`

Three calls in Run B (`0x58a8`, `0xb440`, `0x168c0`) needed to be treated
as opaque — real functions whose *internals* this scenario doesn't depend
on (a radio SPI transaction, a radio poll, a hardware-timer delay), all of
which either touch an uninitialized driver-object pointer (see below) or
spin forever against the zero-behavior MMIO stub. This is the exact same
concept as the already-existing "opaque function-call override" on the
Crucible side (`docs/project-status.md`'s "A real calling-convention bug,
fixed") — extended to Unicorn for the first time. `--stub-call HEXADDR`
(repeatable) installs a code hook that, on reaching that address, sets
`PC := LR` immediately instead of executing the body — it does not
fabricate a return value (these three are all `void`); it does not
change what already-working scenarios do (no flag, no effect). See
[`docs/tooling/unicorn-backend.md`](../tooling/unicorn-backend.md).

Also fixed in this pass (a real gap, not scenario-specific): the ARM
Private Peripheral Bus (`0xE0000000`-`0xE00FFFFF` — SysTick, NVIC, SCB,
etc.) was not mapped at all, so *any* firmware touching SysTick (which
essentially all non-trivial Cortex-M code does, for delays or `millis()`)
faulted. Now mapped unconditionally (same zero-behavior stub as the
board-specific MMIO window) — this is completing the standard Cortex-M
address space, not a scenario-specific fix, and applies to the AutoPilot
firmware too (harmless there — its tested paths hadn't touched this
region yet).

## Boundary found: both firmwares gate real RF I/O behind an unmodeled driver layer

Entering `0xba98` at its true top (`0xba98` itself) — i.e. including the
initial drain loop — faults after 57 instructions at address `0x0000000a`:
a null-pointer-shaped dereference inside `FUN_0000b440` (the real LoRa
receive poll). Tracing it down (`FUN_0000b440` &rarr; `FUN_00011830` &rarr;
`FUN_00011326`/`FUN_000112e8`) shows this is a **real SPI-based radio
register-access driver** — not a simple ring-buffer counter — reading a
config struct (`DAT_0000b4e8` = RAM `0x200038fc`) for SERCOM/GPIO
addresses and chip-select timing, then doing an actual register
read/write transaction. That struct is populated by a constructor-style
function (found at `0x1129c`, literal-pool-confirmed to write SERCOM/pin
constants into it) that runs during Remote's own startup — which this
pass's entry points, by design, skip.

**This is architecturally the same boundary already found and documented
on the AutoPilot side** in
[`docs/investigations/samd51-peripheral-mapping.md`](samd51-peripheral-mapping.md)
(the outbound TX path's driver-object indirection at `0x8c10`) — both
firmwares hide their real radio I/O behind a runtime driver object that
only becomes valid after real startup runs, and reaching it concretely
would mean either running real startup first (then dealing with the
already-documented "a real register-status poll against a zero-behavior
MMIO stub spins forever" limitation) or building actual SPI/radio
peripheral behavior — the "peripheral emulator" work explicitly out of
scope for this slice. `--stub-call` is the disciplined way past this
without doing either.

**This finding directly answers the "how would the virtual RF link work"
question** — see below.

## What this means for the virtual RF link

Both sides' real radio-poll functions are unreachable without either full
startup or peripheral modeling. The virtual link should therefore hook
**above** the radio driver on both ends — exactly where
`rf-boundaries.md` already recommended, now confirmed concretely rather
than by static inference, with exact, tested addresses:

```
Remote FUN_000058a8(char *s)              AutoPilot 0x8c10(char *s) / 0x7f84(byte b)
  argument = the wire bytes to send          argument = the wire bytes to send
        |                                           |
        v                                           v
  [[ harness reads *s until '\0' ]]          [[ harness reads the string/byte ]]
        |                                           |
        v                                           v
  write into AutoPilot RAM 0x2000232a        write into Remote RX ring buffer at
  (the real RX packet buffer -- see          0x20001773, advance write pointer
  dispatcher-loop-concrete-trace.md)         at 0x200017d8 (both confirmed this pass)
        |                                           |
        v                                           v
  enter AutoPilot at 0x8a34 (real           enter/continue Remote at 0xba98's
  dispatcher call, already proven)          collection loop, with --stub-call on
                                             0xb440/0x58a8/0x168c0 (proven this pass)
```

Concretely: (1) capture the Remote's argument to `FUN_000058a8` (Run A's
technique — stop at the call, read the string at R0), (2) seed it into the
AutoPilot's `0x2000232a` buffer and run the AutoPilot side (existing,
already-proven machinery), (3) capture the AutoPilot's argument to
`0x8c10`/`0x7f84` (existing, already-proven technique from
`tx-hook-verification.md`), (4) seed it into the Remote's RX ring buffer
and run the Remote side with the three driver-layer calls stubbed (Run B's
technique, now proven). All four steps use machinery that already exists
and has now been exercised at least once concretely on real firmware —
the remaining work is wiring them into one harness-driven loop instead of
two hand-run Unicorn invocations, not inventing any new technique.

## What's proven vs. what remains inferred

**Proven (level 2, concrete)**:
- Mando loads/discovers cleanly through the existing Ghidra pipeline with
  zero platform-specific changes.
- The Remote's real, unmodified `0xba98` loads R0 from a real `"&|\0"`
  flash literal and calls the real TX wrapper with it.
- The Remote's real, unmodified byte-collection loop, given the
  AutoPilot's already-proven real response bytes in its RX ring buffer,
  copies exactly `"V01R39\0"` into its capture buffer.
- Every RAM address used above (ring buffer, pointers, capture buffer,
  timestamp) is cross-consistent across three independent literal-pool
  reads (`FUN_0000b440`, `FUN_0000b4f8`, `FUN_0000583c`), not asserted
  from one source.

**Still inferred / not concretely proven**:
- The drain loop, preamble (`FUN_00005a14`), and post-request routine
  (`FUN_00005a50`) — read from decompiled structure, not concretely
  executed (they're not needed for either proof above, and the preamble/
  post-request sends look unrelated to the `&|` transaction itself).
- Real SPI/radio timing and register-level behavior — deliberately not
  modeled (see "Boundary found").
- Everything past `0xfa10`/`0xfadc` (the information-screen UI that
  consumes the captured version string) — not touched this pass.
- The `G`/`S`/`!`/dynamic-`I` transactions `protocol-bidirectional.md`
  also diagrams — not attempted this pass; `&|` was chosen because the
  existing research already flagged it as the cleanest first round trip,
  and this pass's results confirm that was the right call (no scan-table-
  style simplification was even needed, unlike the AutoPilot TX-hook
  pass).

## Next logical slice

1. ~~Wire the four-step recipe above into one harness-driven virtual RF
   link~~ — done, same day: `tools/unicorn/virtual_link.py`. See
   [`docs/investigations/virtual-rf-link.md`](virtual-rf-link.md).
2. Repeat the virtual link's technique for `G -> #` (`0xb680`/`0xb59c`) and
   `S -> P...`/`! -> CSV` (`0xc440`) — `protocol-bidirectional.md`'s
   next-recommended transactions after `&|`. Not started.
3. If a real use case ever needs it: run the Remote's own Reset_Handler-
   equivalent first (find it the same way `docs/firmware/firmware-layout.md`
   found the AutoPilot's) so the radio driver object is genuinely
   initialized, narrowing (not eliminating) the boundary found above — not
   attempted here since neither proof needed it.

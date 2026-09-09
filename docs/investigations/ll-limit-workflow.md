# Investigation: The Real `LL1|`/`LL2|` Workflow, and Why It Can't Close the Provisioning Gap

**Question**: [`target-config-provenance.md`](target-config-provenance.md)
named `LL1|`/`LL2|` as the strongest remaining real command for advancing
live position or writing a genuine target, without fabricating data.
This slice: characterize `LL1`/`LL2` fully, exercise them concretely
through the real RX path, and check whether they touch live position
(`0x20002064`), the target/config struct (`0x20001b40`), `0x20001b14`,
rate/timer state, or any real GPIO/limit-switch input.

**Scope**: concrete Unicorn plus disassembly. No fabricated flash/NVM
content, no seeded position/target values. Terminology caution taken
seriously: "limit," "reference," "home," and "calibration" are used only
where evidence supports them; see the dedicated section below.

## Result

**Outcome 3, confirmed both statically and concretely: `LL1`/`LL2` is a
real, complete, but self-contained bookkeeping pair over exactly two
globals plus a validity flag — and this firmware image has no other code,
anywhere, that ever writes those two globals with a real position.**
`LL1` unconditionally clears them; `LL2` compares and reorders them,
setting a validity flag only if they differ. Delivered concretely through
the real RX path (after diagnosing a real, non-timing framing behavior,
below), `LL1` then `LL2` touch **only** their own three globals — no
write to `0x20002064` (live position), the `0x20001b40` config struct,
`0x20001b14`, or any timer/rate register. `LL1`/`LL2` depend on **no
GPIO or external MMIO input at all** — both branches are pure RAM
reads/writes. This does not close the provisioning gap `target-config-
provenance.md` found; it is a second, independent confirmation of the
same kind of gap, on a different pair of globals.

## 1. Exact parser/handler path

`FUN_00008258` (the ASCII dispatcher), top-level character `'L'`
(`0x4c`) branch at `0x877e`-`0x8786` — confirmed by disassembly, the
same tier as every other top-level command (`&`, `G`, `S`, `M`) — tail-
jumps unconditionally to **`FUN_000054e0`**, the shared "L-family"
handler for both `LH<1-4>` and `LL<1-2>`. This reach requires **no
`MC4` unlock**: `FUN_00008258` runs from cold boot exactly as it does
for `&`/`G`/`S`, confirmed by the same evidence tier as
`virtual_link.py`'s already-passing round trips.

`FUN_000054e0`, disassembled in full (not decompiled-and-trusted — the
decompile's variable reuse across the `'H'`/`'L'` branches was
misleading, resolved by disassembly the same way this project always
resolves that ambiguity):

```asm
0x54e0  ldr  r3,[0x5550]        ; r3 = packet base (0x2000232a, the shared RX buffer)
0x54e2  ldrb r2,[r3,#1]         ; r2 = packet[1]
0x54e4  cmp  r2,#0x48 ('H')
0x54e6  bne  0x5510              ; not 'H' -> the 'L' branch
        ; ---- LH1..4 branch (packet[1]=='H') ----
0x54e8  ldrb r3,[r3,#2]         ; r3 = packet[2] ('1'..'4')
        ; selects one of four DISTINCT globals (0x5554/0x5558/0x555c/0x5560)
        ; and clears it to 0, then tail-calls FUN_00004480
0x5510  cmp  r2,#0x4c ('L')
0x5512  bne  0x554e              ; neither 'H' nor 'L' -> return, no-op
0x5514  ldrb r3,[r3,#2]         ; r3 = packet[2]
0x5516  cmp  r3,#0x31 ('1')
0x5518  bne  0x552a
        ; ---- LL1 ----
0x551a  *(0x20003114) = 0        ; posA
0x5522  *(0x20002414) = 0        ; posB
0x5526  *(0x20002458) = 0 (byte) ; valid
0x5528  b 0x54f4 -> FUN_00004480 (tail)
0x552a  cmp r3,#0x32 ('2')
0x552c  bne 0x54f4 -> FUN_00004480 (tail, no-op)
        ; ---- LL2 ----
0x552e  posB_val = *(0x20002414); posA_val = *(0x20003114)
0x5536  cmp posB_val, posA_val
0x5538  bge 0x5548
          ; posB_val < posA_val:
          *(0x20002424) = posB_val   ; minDest = smaller
          *(0x20002414) = posA_val   ; posB slot overwritten with the larger
          *(0x20002458) = 1 (byte)   ; valid = true
          b 0x54f4
0x5548  ble 0x54f4                    ; posB_val == posA_val -> no-op, tail call only
        ; posB_val > posA_val:
          *(0x20002424) = posA_val   ; minDest = smaller (posA_val)
          ; falls into the same "posB slot = larger, valid = 1" code above
```

## 2. State variables and per-channel fields

**Not per-channel at all.** `LL1`/`LL2` operate on exactly three fixed
globals, confirmed by an exhaustive whole-firmware literal-pool scan
(the same method used for `0x20001b14` and `0x20000060`) to have **no
other reference anywhere in the image**:

| Address | Role (confirmed by disassembly) | Other readers/writers found |
|---|---|---|
| `0x20003114` ("posA") | first stored value; cleared by `LL1`; read (never written elsewhere) by `LL2` | none |
| `0x20002414` ("posB") | second stored value; cleared by `LL1`; read and conditionally overwritten (with the larger of the two) by `LL2` | none |
| `0x20002424` ("minDest") | written only by `LL2`, holds the smaller of the two values once they differ | none |
| `0x20002458` ("valid") | cleared by `LL1`; set to `1` by `LL2` only if the two values differ | **also read by `FUN_00008c70`**, a response-builder that reports it back in an outbound frame (a real, but read-only, downstream consumer — not a producer) |

`LH1`-`LH4` (packet\[1\]=='H') are a *separate*, per-command-digit family
clearing one of **four different, unrelated globals**
(`0x20001c60`... no — confirmed by direct resolution: `0x200025b0`,
`0x200030e4`, `0x20002324`, plus `posA` itself for `LH1`) — not a
per-channel array (no `0x120`-stride relationship to each other or to
the motor config struct). Not chased further: out of this slice's scope
(`LL`, not `LH`), and it shares no state with the move path either.

## 3. What `LL1`/`LL2` do — and don't — touch

Checked explicitly, by disassembly and by a live `--watch-mem-write` on
every candidate address across a full concrete `LL1`-then-`LL2` run:

| Candidate | Touched? |
|---|---|
| Live position, `0x20002064[channel]` | **No** — never referenced anywhere in `FUN_000054e0` |
| Target/config struct, `0x20001b40`+ | **No** |
| `0x20001b14[channel]` (the busy gate) | **No** |
| `step_delta` / rate / any TC register | **No** |
| "Limit/reference" state (`posA`/`posB`/`valid`) | **Yes** — the only state this workflow touches |
| Persistent/NVM data | **No** — `posA`/`posB`/`valid` are plain `.bss` RAM (cleared by `Reset_Handler`'s bulk zero, confirmed in range), not part of the `FUN_00004b64`-loaded config blob |

## 4. External GPIO/input dependency

**None.** `FUN_000054e0`'s entire body is RAM reads, RAM writes, and a
tail call to `FUN_00004480` (also pure RAM: clears one flag, records a
timestamp — `docs/investigations/g-command-motor-subsystem-unlock.md`'s
class of "cheap, unrelated-to-control-flow helper"). No MMIO address, no
GPIO port, no ADC, no SERCOM/SPI reference anywhere in this function or
its one callee. This is a firmware-internal bookkeeping pair, not a
hardware-sensing routine — contrary to what "limit" might suggest before
checking.

## 5. What distinguishes `LL1` from `LL2`

`LL1` **unconditionally resets** all three globals to `0`/false — a
real "clear/prepare" operation, no comparison, no completion condition.
`LL2` **conditionally completes**: it compares the two stored values and
only sets `valid=1` (and writes the ordered min/max pair) when they
differ; if they are equal (including the degenerate case where neither
was ever set to anything but `0` by `LL1`), it silently no-ops — a real,
disassembly-confirmed "reject a degenerate pair" guard, not a missing
mechanism.

## Concretely exercised through the real RX path

### A real, non-timing framing behavior found and worked around

The first delivery attempt (`"LL1|LL2|"`, both queued in one injection,
`--fake-tick` period 300 — proven safe for `G`'s 5 bytes) dispatched
`LL1` correctly but **silently dropped `LL2` entirely**, with **zero**
`0x8258` hits at `LL2`'s expected address. This is *not* the same
per-byte-timeout artifact `mc4-transition.md` diagnosed for `MC4` (raising
the tick period from 300 to 2000 did not change the outcome, ruling that
out directly). A full single-step trace of the exact instruction window
found the real cause: right after recognizing `LL1`'s `'|'` terminator
(`0x8a20`), the real receive routine (`FUN_00008960`) checks for any
**immediately available** further bytes and, if present, drains them in
a loop (`0x8a3a`-`0x8a4c`) that inspects each one only for a literal
`'O'` (`0x4f`) byte — a real framing check whose purpose is not
established here (a multi-frame or binary-interop artifact, not
resolved this pass) — **before dispatching the buffered command**. Since
`LL2|`'s bytes were already sitting in the ring when `LL1|`'s terminator
was recognized, this loop silently consumed and discarded all four of
them, and `LL1` alone was dispatched. **Fixed the same way
`mc4-transition.md` sequenced `G` after `MC4`**: a second `--force-mem`
trigger at `0x8a38` (the instruction right after `FUN_00008258`'s call
site returns from dispatching `LL1` — a real one-time point *for this
run*, since nothing dispatches before `LL1` does) injects `LL2|`'s bytes
only once `LL1`'s own ring is empty. This is a structural
availability issue, not a tick-calibration one — raising `--fake-tick`
alone could never have fixed it, and did not.

### Result: both real, no state relevant to a move touched

| Instruction | Address | What |
|---|---|---|
| 1,156,568 | `0x8258` | real dispatch of `LL1` |
| 1,156,608 | `0x551a` | `LL1`'s real clear branch |
| 1,182,342 | `0x8258` | real dispatch of `LL2` (properly sequenced) |
| 1,182,384 | `0x552e` | `LL2`'s real compare branch |

At `LL2`'s own entry (`0x552e`), `--watch-mem` confirms `posA=0`,
`posB=0`, `valid=0`, `minDest=0` — exactly `LL1`'s cleared state,
untouched by anything in between. `LL2`'s own comparison
(`posB_val(0) < posA_val(0)`? no; `<=`? yes) takes the **degenerate
equal-values no-op branch** — concretely confirmed, not just predicted:
no write to `minDest` or `valid` occurs. `--watch-mem-write` across the
entire run on `0x20001b14`, the `0x20001b40`+`0x10` target field, and
`0x20002064` shows **no hits attributable to `LL1`/`LL2`** — every hit
in the log is the already-known boot-time `.bss` clear and
`FUN_00004b64`/`FUN_00004b24` config-load sequence from
`target-config-provenance.md`, all before either `LL` command runs.

## Terminology discipline

- **"Limit"**: the only evidence is `commands.csv`'s own note that
  "remote UI strings around this command describe setting the first
  limit" — a static, textual hint this slice did not re-verify, not a
  firmware-code confirmation of physical meaning. The two globals
  (`posA`/`posB`) are referred to here neutrally as "stored values,"
  not asserted as physical limit-switch positions.
- **"Reference"**: not used to describe `LL1`/`LL2` — nothing in the
  disassembled code establishes a "reference position" semantic beyond
  "two comparable stored numbers."
- **"Home"**: not applicable here — this workflow shares no code, state,
  or address with `FUN_00006968` (the function this project's own
  terminology note, in `post-probe-main-loop.md`, already renamed from
  "homing" to "startup reference/input routine").
- **"Calibration"**: not used — `LL1`/`LL2` never touch the `MC`/`MC4`
  configuration path (`FUN_00007a98`, `0x2000006c`/`0x200000dc`/
  `0x200000f0`/`0x20000138`) or the target/config struct
  (`0x20001b40`).
- The plausible reading — "LL1/LL2 exist to let an operator capture two
  physical extremes, e.g. via a manual jog UI, then have the firmware
  order and validate them" — remains a **reasonable inference from the
  command names and the old static UI-string note**, not something this
  slice's code-level evidence confirms or refutes. What *is* confirmed:
  whatever mechanism is supposed to populate `posA`/`posB` with a real
  captured value is **not** reachable through this firmware's ASCII
  protocol, by any direct-literal-referenced instruction.

## Confirmed vs. inferred vs. unresolved

| Item | Status |
|---|---|
| `LL1`/`LL2` reach `FUN_000054e0` via the top-level `'L'` dispatch branch, reachable pre-`MC4` | **Confirmed** (disassembly + concrete dispatch hits) |
| `LL1` clears `posA`/`posB`/`valid`; `LL2` orders them and sets `valid` only if they differ | **Confirmed** (disassembly, corrected from an initially-misleading decompile, and matched by a concrete run) |
| No GPIO/MMIO dependency anywhere in this workflow | **Confirmed** (full disassembly, no MMIO-range address touched) |
| `LL1`/`LL2` never touch live position, the target/config struct, `0x20001b14`, or rate/timer state | **Confirmed concretely** (`--watch-mem-write` across a full real run) |
| No other code in the firmware writes `posA`/`posB` with a real value | **Confirmed** (exhaustive literal-pool scan — the same method and confidence tier as the `0x20001b14`/`0x20000060` searches) |
| A real, non-timing "swallow extra buffered bytes checking for `'O'`" framing behavior exists in the receive path | **Confirmed concretely**, its *purpose* **not established** — out of this slice's scope |
| Whether `posA`/`posB` are meant to be populated by a physical LCD/button UI path not reachable via the ASCII protocol | **Inferred, not confirmed** — plausible given the old static UI-string note, but no such writer was found by the same exhaustive method that would find one if it existed via a direct literal reference |
| `LH1`-`LH4`'s four distinct target globals and their real role | **Not characterized** — out of scope for this `LL`-focused slice |

## Evidence level

Level 2 (concrete, Unicorn) for the dispatch reachability, the real
framing behavior, and the confirmed no-touch result on every move-path
state variable. Level 1 (static, disassembly-verified, exhaustive
literal-pool scan) for the absence of any other producer of `posA`/
`posB`. No solver/symbolic step used or needed.

## Next step

This closes the `LL1`/`LL2` avenue `target-config-provenance.md` named:
**it does not provide a path to a real nonzero committed move.** The
remaining, precisely-named external dependency is unchanged from that
slice: this firmware image's compiled-in motor-position default
configuration (flash `0x12000`) is blank, and no command reachable
through the real ASCII protocol — `G`, `MC4`, or now `LL1`/`LL2` — can
supply real position/target data the harness has no way to fabricate
without inventing state, per the task's explicit scope. Two independent,
narrower items remain, neither started:

1. **`FUN_00004c20`** (the sibling bulk-config-loader named alongside
   `FUN_00004b64` since `channel-busy-gate-search.md`) — still not
   traced for other fields it might populate.
2. **The `'O'`-byte framing check** (`0x8a3a`-`0x8a4c`) found this slice
   — its real purpose (multi-frame framing? binary-mode interop?) is
   undetermined and could matter to a future slice injecting more than
   one command back-to-back.

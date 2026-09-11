# APTrace — Project Status

**This is the single authoritative source for current project state.** If
anything elsewhere in the repo conflicts with this document, this document
wins — and if you find such a conflict, it's a bug in the docs; fix it
here. This file describes *current truth only*: what's proven, what's
open, what's next. Chronological narrative belongs in git history, not
here — do not append "previous update" logs to this file; when a slice of
work closes, fold its durable finding into the relevant section below (or
into a canonical dossier under `docs/investigations/`) and move on.

## What APTrace can do now

APTrace orchestrates four specialist tools against real, unmodified
AutoPilot/Remote (`mando`) firmware (ATSAMD51J19A, Cortex-M4F) rather than
reimplementing any of them — see [`docs/architecture.md`](architecture.md)
and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md) for when
to reach for which:

| Tool | Role | Status |
|---|---|---|
| Ghidra | static RE, decompile, xrefs, tables, MMIO naming | Integrated — [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md) |
| Unicorn | concrete Thumb-2 execution, state capture | Integrated — [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md) |
| Macaw | independent CFG discovery / ARM/Thumb lifting | In use, proven |
| Crucible + What4 + Z3 | targeted symbolic reachability / input solving | In use, proven |

Demonstrated, reusable capabilities: a persistent per-firmware Ghidra
project (build once, query many times without re-analysis); a reusable
`ConcreteMachine` class with a real ARM-AAPCS direct-function-call helper
(`--call`/`--arg`), structured never-discarded failure snapshots, an
always-on bounded PC trace (`--trace-last`), and explicit state
carry-forward between runs (`RunResult.carry`); harness capabilities for
disclosed hardware/timing assumptions (`--fake-tick`, `--mmio-force-bits`/
`--mmio-clear-bits`, `--force-reg`, `--force-mem`, `--watch-mem-write`,
`--log-mmio`), each scoped and justified individually, never a general
peripheral model; a harness-driven virtual RF link
(`tools/unicorn/virtual_link.py`) connecting both firmwares' real TX/RX
paths with no radio hardware modeled; and `aptrace census`
(`tools/census/`, see [`docs/tooling/census.md`](tooling/census.md)) — a
fully mechanical, no-LLM-in-the-loop static+dynamic evidence database
(functions, basic blocks, CFG edges, RAM/MMIO accesses, vectors, pins,
Unicorn dynamic coverage) built and run against all four known firmware
images, with a deterministic query CLI and closure/warning report, PLUS
a closure-reduction layer (`census reduce`) on top of it: mechanical
reachability from justified roots, indirect-edge resolution (static/
dynamic/finite-candidate-set/unresolved), cross-image library/platform
fingerprinting kept as shared-code EVIDENCE only (never "library truth"
by itself — only a curated match against real, fetched
`ArduinoCore-samd` source counts as confirmed library), per-function
feature records, deterministic component grouping, and a reusable boot
recipe (`tools/census/boot_recipes.py`) that mechanically packages this
project's own cited boot/hardware-bringup assumptions and feeds a real
boot execution's coverage/indirect-call observations back into the
reducer, plus a minimal, narrow interrupt-delivery primitive
(`ConcreteMachine.deliver_interrupt`, real ISR body, real AAPCS nested
call — never a stub, never a full exception simulator). **All four
known firmware images now boot (in Unicorn) all the way to real
main-loop steady state (`init_status=complete`)**: AutoPilot868/915
exactly reproduce `docs/investigations/boot-and-hardware-bringup.md`'s
own milestones; Mando868's previously-open blocker — a RAM-flag wait at
`0x20003b30` with no resolved static caller — was closed by mechanically
tracing and modeling its real DMAC channel-2 transfer-complete interrupt
chain (vector → `FUN_00011d20` → channel-table lookup → `FUN_00011cb8`
→ registered callback), delivered for real via `interrupt_bridges` (see
census.md's "Interrupt delivery"); Mando915 was then sibling-remapped
from the same recipe via the existing exact-fingerprint machinery and
delivers the identical four interrupts at identical instruction counts.
Run against all four images: AutoPilot868's residual narrowed from 414
discovered functions to 102, AutoPilot915 to 123; Mando868 narrowed to
309, Mando915 to 323. Unresolved indirect edges: AutoPilot868/915 87 →
58 (29 newly `DYNAMICALLY_OBSERVED` via boot capture), Mando868/915 146
→ 127 (19 newly `DYNAMICALLY_OBSERVED`). Still no "understood %"
invented; semantic classification of the residual is underway for
AutoPilot868 (Mando868/915 and AutoPilot915 not yet started).

**A fourth census layer now turns that residual set into a prioritized,
component-grouped, evidence-disclosed queue** (`residual_priority.py`,
extended `components.py`, see census.md's "Residual prioritization,
component reduction, and hardware contract"): a fixed, disclosed-reasons
priority score (9 positive + 4 negative mechanical signals — MMIO/pin/
IRQ/NVM/protocol-RAM access, unresolved-indirect involvement, dynamic-
coverage proximity vs. isolated-leaf/confirmed-platform-code) sorts each
residual function into `HIGH`/`MEDIUM`/`LOW`; `HIGH` counts: AutoPilot868
32, AutoPilot915 21, Mando868 40, Mando915 12. Two new component union
rules (shared low-fan-out caller; shared string/constant) were added,
and a real over-collapse bug in the PRIOR unbounded resource-sharing
rules was found and fixed (`RESOURCE_UNION_MAX_OWNERS=8`) — one
mando868 RAM address alone was statically touched by 46 reachable
functions and, left unbounded, collapsed nearly the whole reachable set
into one component. Even fixed, one large "core" component still
dominates mando868/915 — confirmed this pass to be a property of the
CALL-GRAPH union rules alone (not the resource-sharing fix), i.e. a
real, disclosed finding about this firmware's dense interconnection,
not a bug (see census.md's Limitations). A machine-readable, per-image
hardware contract (`hardware_contract.py`, persisted to
`hardware_contract_runs`) was also added — MCU/clock-tree/PORT/ADC/TC-
TCC/SERCOM/EIC/DMAC/USB/WDT/NVMCTRL/IRQ-vector state, raw register
values always alongside whatever decode is actually available, with
peripheral/pin ownership resolved to owning functions/components — plus
a structured, mechanical 868-vs-915 diff (`firmware_diff.py`,
`census diff`) that correctly and specifically isolated mando868/915's
real RF-band difference at the string level (`"868MHz band"` vs.
`"915MHz band"`) with zero hardware-register/MMIO/pin differences
(both images reach the identical post-init MCU configuration).

A real Unicorn correctness bug
(`log_ram=True` corrupting long/RAM-heavy runs via a cross-hook
reentrancy hazard) was found and partially fixed along the way — see
`tools/unicorn/concrete.py`'s `_ranges_excluding` and
`test_concrete.py`'s new regression coverage.

**A fifth census layer mechanically fetches, COMPILES, and matches the
confirmed reference toolchain** (`reference_corpus.py`/
`reference_match.py`, see census.md's "Reference-source
fingerprinting"): Adafruit `ArduinoCore-samd` v1.7.11 (already named by
embedded build-path strings) plus its own mechanically-discovered
dependencies — `arm-none-eabi-gcc` 9-2019q4 (Adafruit's own pinned
toolchain version), CMSIS 5.4.0, CMSIS-Atmel 1.2.2 (resolving a
previously-open item: `startup_samd51.c`/`system_samd51.c`'s exact
upstream source), and a git-submodule header dependency
(`Adafruit_ZeroDMA`, pinned by the core's own `.gitmodules` gitlink) —
all fetched/downloaded at EXACT versions, never guessed. Compiled with
the exact discovered flags (board `adafruit_feather_m4`, the only
Adafruit SAMD board whose macros match this project's own confirmed
part number `ATSAMD51J19A`): 28/28 evidenced source files compiled
clean, 346 reference symbols extracted with real ELF-relocation-based
fingerprints (four tiers: exact bytes, exact instructions, relocation-
normalized, PC-relative-normalized). Two real bugs were found and fixed
along the way: `objdump` prints a Thumb halfword as its NUMERIC value
(not memory byte order) — every reference symbol's bytes were silently
wrong until fixed; and a compiled symbol's ELF size includes trailing
alignment `nop` padding that Ghidra's own firmware-side function-size
convention excludes. `millis()` (already manually confirmed
byte-identical in `boot-and-hardware-bringup.md`) is independently
rediscovered as an exact match after both fixes — the key positive-
control validation. AutoPilot868 residual 102 → 95, AutoPilot915 123 →
116, Mando868 309 → 306, Mando915 323 → 320 (12 functions mechanically
reference-source-confirmed per image, including real named C++ methods
— `SPIClass::endTransaction()`, `SERCOM::SERCOM()`, three SERCOM UART
helpers — beyond the previously-curated 7). Four documented negative
controls (mando868 application-specific functions) correctly show
`NO_MATCH`. One open item, disclosed rather than chased further this
pass: `Reset_Handler`/`SysTick_Handler` do not match this corpus at any
tier despite an earlier manual finding of byte-identity — plausibly an
unselected `boards.txt` menu option (`-DENABLE_CACHE` most likely), not
yet built as an alternate variant.

## Semantic classification of the residual (AutoPilot868)

Of AutoPilot868's 95 residual functions, 37 now carry a HIGH-confidence
coarse semantic classification (`MOTOR_CONTROL`, `MOTOR_STEPPING`,
`PROTOCOL_TX_EVENT`, `PROTOCOL_RX_INJECTION`, `BOOT_STARTUP`,
`PERSISTENCE_NVM`, `RADIO_DRIVER`, `SENSING_ADC`,
`PLATFORM_HEAP_ALLOCATOR`), 5 carry a LOW-confidence hint, and 53 remain
semantically `UNKNOWN` — mechanical priority tier (`HIGH`/`MEDIUM`/`LOW`)
is a separate axis from this confidence and is not itself a semantic
result. Evidence and per-function results live under
`research/generated/autopilot-semantic-pass*.jsonl`; not yet started for
AutoPilot915, Mando868, or Mando915.

## Current milestone: the core protocol pipeline

**Status: CLOSED at the concrete (Unicorn) evidence tier**, both firmwares,
for five transactions: `&|` → `V01R39`, `G` → `#`, `S` → `P...`,
`!0|`/`!1|` → 11-field CSV, and `I<channel><mode>|`/`I9|`/`I1|` → signed
number. Every stage — real dispatcher, real event scheduling, real TX/RX
— has been independently demonstrated against unmodified firmware,
entering at real call sites with the firmware establishing its own
state. See
[`docs/investigations/protocol-pipeline.md`](investigations/protocol-pipeline.md)
for the full evidence chain, the real dispatcher structure, and a real
tooling limitation found and explained along the way (a whole-function
Crucible replay of the dispatcher can't fold a readonly-flash-derived
branch — a harness limitation, not a firmware bug; deliberately left
unfixed since no current use case needs it).

`!`/`I` closed this pass (`tools/unicorn/virtual_link.py`'s `bang`/`i`/
`i9i1` scenarios): the event-7 11-vs-10 field mismatch is resolved
(Remote's parser never attempts field 11; it's left unconsumed in the
real RX ring buffer, silently, on both sides); `I<channel><mode>|`'s
signed response is confirmed to be `AUTOPILOT_LIVE_POSITION[channel]`,
scheduled by the real main-loop poll rather than the RX handler itself;
and `I9|`/`I1|` are confirmed genuinely distinct from `I<channel><mode>|`
and from each other (`I1|` aliases channel 0's real path; `I9|` is a
real, silent, out-of-bounds dead end). A solver-confirmed (level-3) proof
of the *whole* dispatcher chain in one run remains blocked by the
tooling limitation above; individual pieces (e.g. the `&` character
check) already have independent level-3 confirmation.

## Major established system facts

- **Boot sequence, fully concretely reproducible**: `Reset_Handler` →
  clock/peripheral init → SERCOM/DMA driver construction → startup
  reference/input routine ("homing") → a real SPI radio-chip-ID probe
  (fails with no chip attached, taking a real infinite retry loop — not a
  timing gap) → a stable, repeating real main loop. See
  [`docs/investigations/boot-and-hardware-bringup.md`](investigations/boot-and-hardware-bringup.md)
  for the exact SVD-named completion bits modeled, the real Arduino-idiom
  function names (`main`/`setup`/`loop`), and the confirmed pin/peripheral
  map (TC0→PB10, TC1→PA08, TC2→PB12, TC3→PA10, TCC1→PB22).
- **The TX path's real transport (`0x8c10`) is CONFIRMED**: `SERCOM2`
  in SPI Master mode, chip-select `PA15`, zero DMA involvement, driven
  through a real, boot-constructed C++/`Stream`-derived driver object
  (`0x20004160`) whose vtable[1] dispatch was independently reconfirmed
  and whose entire dispatch chain was traced with a real, unstubbed
  Unicorn call from a completed boot snapshot (`CallResult.returned =
  True`). The specific external device on the other end of that SPI
  bus (a LoRa-family transceiver, by register-address pattern) remains
  PROBABLE, not independently hardware-confirmed. See
  [`docs/investigations/boot-and-hardware-bringup.md`](investigations/boot-and-hardware-bringup.md)'s
  "The TX path's real transport, `0x8c10` — CONFIRMED".
- **The motor subsystem is unreachable from a cold boot without `MC4`**:
  the real main loop lives entirely inside the sketch's `setup()` and never
  returns until `MC4` clears one specific unlock byte. `MC<0-3>`/`G`/`I`
  and the AutoPilot's own boot-time `MT` Quick-Setup broadcast are all
  fully characterized, including a genuine, exhaustively-confirmed negative
  result (nothing in this firmware image ever sets one specific per-channel
  busy gate). See
  [`docs/investigations/motor-subsystem-unlock.md`](investigations/motor-subsystem-unlock.md).
- **Motor-target persistence (flash `0x12000`) is closed end to end**:
  command → dirty flag → save → real flash mutation → reboot recovery, all
  concretely demonstrated, including the real page-size register
  dependency that had to be resolved. The real protocol-native producer of
  nonzero target deltas is a previously-undocumented command, `'+'`. See
  [`docs/investigations/motor-config-persistence.md`](investigations/motor-config-persistence.md).
- **`'+'` and Auto Mode, traced end to end**: real Remote-side triggers and
  UI call sites found, with a load-bearing distinction preserved — the
  interactive Auto-Mode confirm screens are *not* the same event as the
  bulk config-push that actually arms a drivable target. A full concrete
  round trip (Remote `'+'` → AutoPilot persist → `G` → real move-commit)
  is demonstrated. See
  [`docs/investigations/auto-mode-and-plus-command.md`](investigations/auto-mode-and-plus-command.md).
- **Manual Mode's live jog is a previously-unknown binary frame family**
  (`0xF0`/`0xE0`), not any ASCII command — continuous, once per UI tick,
  not discrete. `LL1`/`LL2` ("Set Limits") are confirmed pure RAM
  bookkeeping with **no path to a real physical position anywhere in the
  firmware** — a negative result confirmed three independent ways. See
  [`docs/investigations/manual-mode-and-limits.md`](investigations/manual-mode-and-limits.md).
- **The 3.5mm trigger-input bug is fully characterized, on both of its two
  mutually-exclusive boot-time arms**: a digital arm (no debounce, no
  latch — a bouncy insertion can produce multiple accepted config-reloads)
  and a previously-unknown analog arm (boot-time-latched: a *post-boot*
  transient can't reach it, but a trigger chain already connected at
  power-up can influence the one boot-time sample that gets latched for
  the whole session). Neither arm can cause uncommanded motor motion. A
  software mitigation (consecutive-sample debounce) is designed and
  Unicorn-prototyped, but **not deployed to real firmware** — no verified
  flash code cave was found for a real trampoline. See
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).
- **Physical hardware facts** (part numbers, board/bootloader mechanics,
  condensed manual summary): [`docs/hardware/hardware-reference.md`](hardware/hardware-reference.md).

## Current open questions

Full protocol-level list: [`docs/protocol/open-questions.md`](protocol/open-questions.md).
Headline items still unresolved:

- Dormant-event reachability (events 2, 3, 8, 9, 11, 12, 14) — a natural
  Crucible/What4 target, not attempted since the pivot to hardware
  provenance. (The event-7 11-vs-10 field mismatch is resolved — see
  "Current milestone" above.)
- Whether any Remote-transmitted packet exists outside the currently-known
  dispatch tree.
- The physical trigger-port electrical behavior (transient shape, bounce,
  minimum legitimate pulse width, real main-loop period) — needed before
  any trigger-input mitigation candidate can be called *correct* rather
  than merely *possible*. See `trigger-input.md`'s "Open / physical
  unknowns."
- A second, deeper NVM-erase-loop dependency found during hardware
  bring-up, reported but not chased (`boot-and-hardware-bringup.md`).

## Tooling limitations that still matter

- **Readonly flash vs. plain Crucible execution**: a whole-function
  symbolic replay through a literal-pool-derived branch doesn't fold
  correctly (solver assumptions ≠ concrete literals to a non-solver-
  mediated step). Deliberately unfixed; revisit only if a real symbolic
  use case needs a whole-function proof through such a branch — see
  [`docs/investigations/protocol-pipeline.md`](investigations/protocol-pipeline.md).
- **No real, verified flash code cave** has been found for a trigger-input
  mitigation trampoline; the most promising unexplored option is flash
  beyond the current image's end, within the part's real 512KB, not yet
  checked against a real device.
- **`GhidraSVD`** (the proper Ghidra SVD-loading extension) is still not
  installed — the standalone `tools/svd/resolve_mmio.py` resolver remains
  good enough for routine use; install only if that stops being true.

## Next priorities

1. Attempt dormant-event reachability now that whole-function execution
   habits are better understood.
2. Get real physical measurements at the trigger jack/PB05 (see
   `trigger-input.md`) before choosing a debounce threshold or attempting
   a real flash patch.
3. Continue semantic classification of the AutoPilot868 residual, then
   extend to AutoPilot915/Mando868/Mando915.

Fuller, itemized unfinished-work tracking lives in
[`docs/harness/roadmap.md`](harness/roadmap.md) — not duplicated here.

# Performing Rigs Case Status

**This is the authoritative source for the Performing Rigs investigation.**
Framework capability status is separate at
[`docs/status.md`](../../docs/status.md). If another case document conflicts
with this document, this document wins. This file describes *current case truth
only*: what's proven, what's
open, what's next. Chronological narrative belongs in git history, not
here — do not append "previous update" logs to this file; when a slice of
work closes, fold its durable finding into the relevant section below (or
into a canonical dossier under `cases/performing-rigs/docs/investigations/`) and move on.

## Analysis capabilities exercised by this case

APTrace orchestrates four specialist tools against real, unmodified
AutoPilot/Remote (`mando`) firmware (ATSAMD51J19A, Cortex-M4F) rather than
reimplementing any of them — see [`docs/architecture.md`](../../docs/architecture.md)
and [`docs/tooling/tool-selection.md`](../../docs/tooling/tool-selection.md) for when
to reach for which:

| Tool | Role | Status |
|---|---|---|
| Ghidra | static RE, decompile, xrefs, tables, MMIO naming | Integrated — [`docs/tooling/ghidra-backend.md`](../../docs/tooling/ghidra-backend.md) |
| Unicorn | concrete Thumb-2 execution, state capture | Integrated — [`docs/tooling/unicorn-backend.md`](../../docs/tooling/unicorn-backend.md) |
| Macaw | independent CFG discovery / ARM/Thumb lifting | In use, proven |
| Crucible + What4 + Z3 | targeted symbolic reachability / input solving | In use, proven |

**Macaw static-analysis layer** (`aptrace macaw-census`/
`macaw-census-expand`, see
[`docs/tooling/macaw-analysis.md`](../../docs/tooling/macaw-analysis.md) for the full
model): an independent, Cortex-M-safe Macaw census (Thumb-only discovery,
no A32 mis-lifts); a normalization/fixpoint expansion recovering concrete
targets for `classify_failure`/misclassified-`ParsedCall` terminators; an
APTrace-owned semantic control-transfer classification layer that
separates Macaw's `ParsedCall` terminator into its real ISA-level
categories (genuine indirect call, tail call, conditional branch, table
branch, computed jump) instead of treating every one as a function call;
and a deterministic Ghidra-vs-Macaw comparison (`macaw_compare.py`) with
zero genuine normalized-target disagreements found so far.

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
(`cases/performing-rigs/scripts/virtual_link.py`) connecting both firmwares' real TX/RX
paths with no radio hardware modeled; and `aptrace census`
(`tools/census/`, see [`docs/tooling/census.md`](../../docs/tooling/census.md)) — a
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
recipe (`cases/performing-rigs/config/boot_recipes.py`) that mechanically packages this
project's own cited boot/hardware-bringup assumptions and feeds a real
boot execution's coverage/indirect-call observations back into the
reducer, plus a minimal, narrow interrupt-delivery primitive
(`ConcreteMachine.deliver_interrupt`, real ISR body, real AAPCS nested
call — never a stub, never a full exception simulator). **All four
known firmware images now boot (in Unicorn) all the way to real
main-loop steady state (`init_status=complete`)**: AutoPilot868/915
exactly reproduce `cases/performing-rigs/docs/investigations/boot-and-hardware-bringup.md`'s
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

Of AutoPilot868's 95 residual functions, 47 now carry a HIGH-confidence
coarse semantic classification (`MOTOR_CONTROL`, `MOTOR_STEPPING`,
`PROTOCOL_TX_EVENT`, `PROTOCOL_RX_INJECTION`, `BOOT_STARTUP`,
`PERSISTENCE_NVM`, `RADIO_DRIVER`, `SENSING_ADC`, `TRIGGER_INPUT_SENSING`,
`PLATFORM_HEAP_ALLOCATOR`, `PLATFORM_DMAC_LIBRARY`,
`INTERRUPT_HANDLER_EIC`), 1 carries a MEDIUM-confidence hint (`RADIO_DRIVER`),
and 47 remain semantically `UNKNOWN` — mechanical priority tier
(`HIGH`/`MEDIUM`/`LOW`) is a separate axis from this confidence and is
not itself a semantic result. Evidence and per-function results live
under `cases/performing-rigs/research/generated/autopilot-semantic-pass*.jsonl`; not yet started for
AutoPilot915, Mando868, or Mando915.

## Current milestone: the core protocol pipeline

**Status: CLOSED at the concrete (Unicorn) evidence tier**, both firmwares,
for five transactions: `&|` → `V01R39`, `G` → `#`, `S` → `P...`,
`!0|`/`!1|` → 11-field CSV, and `I<channel><mode>|`/`I9|`/`I1|` → signed
number. Every stage — real dispatcher, real event scheduling, real TX/RX
— has been independently demonstrated against unmodified firmware,
entering at real call sites with the firmware establishing its own
state. See
[`cases/performing-rigs/docs/investigations/protocol-pipeline.md`](docs/investigations/protocol-pipeline.md)
for the full evidence chain, the real dispatcher structure, and a real
tooling limitation found and explained along the way (a whole-function
Crucible replay of the dispatcher can't fold a readonly-flash-derived
branch — a harness limitation, not a firmware bug; deliberately left
unfixed since no current use case needs it).

`!`/`I` closed this pass (`cases/performing-rigs/scripts/virtual_link.py`'s `bang`/`i`/
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
  [`cases/performing-rigs/docs/investigations/boot-and-hardware-bringup.md`](docs/investigations/boot-and-hardware-bringup.md)
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
  [`cases/performing-rigs/docs/investigations/boot-and-hardware-bringup.md`](docs/investigations/boot-and-hardware-bringup.md)'s
  "The TX path's real transport, `0x8c10` — CONFIRMED".
- **The motor subsystem is unreachable from a cold boot without `MC4`**:
  the real main loop lives entirely inside the sketch's `setup()` and never
  returns until `MC4` clears one specific unlock byte. `MC<0-3>`/`G`/`I`
  and the AutoPilot's own boot-time `MT` Quick-Setup broadcast are all
  fully characterized, including a genuine, exhaustively-confirmed negative
  result (nothing in this firmware image ever sets one specific per-channel
  busy gate). See
  [`cases/performing-rigs/docs/investigations/motor-subsystem-unlock.md`](docs/investigations/motor-subsystem-unlock.md).
- **Motor-target persistence (flash `0x12000`) is closed end to end**:
  command → dirty flag → save → real flash mutation → reboot recovery, all
  concretely demonstrated, including the real page-size register
  dependency that had to be resolved. The real protocol-native producer of
  nonzero target deltas is a previously-undocumented command, `'+'`. See
  [`cases/performing-rigs/docs/investigations/motor-config-persistence.md`](docs/investigations/motor-config-persistence.md).
- **`'+'` and Auto Mode, traced end to end**: real Remote-side triggers and
  UI call sites found, with a load-bearing distinction preserved — the
  interactive Auto-Mode confirm screens are *not* the same event as the
  bulk config-push that actually arms a drivable target. A full concrete
  round trip (Remote `'+'` → AutoPilot persist → `G` → real move-commit)
  is demonstrated. See
  [`cases/performing-rigs/docs/investigations/auto-mode-and-plus-command.md`](docs/investigations/auto-mode-and-plus-command.md).
- **Manual Mode's live jog is a previously-unknown binary frame family**
  (`0xF0`/`0xE0`), not any ASCII command — continuous, once per UI tick,
  not discrete. `LL1`/`LL2` ("Set Limits") are confirmed pure RAM
  bookkeeping with **no path to a real physical position anywhere in the
  firmware** — a negative result confirmed three independent ways. See
  [`cases/performing-rigs/docs/investigations/manual-mode-and-limits.md`](docs/investigations/manual-mode-and-limits.md).
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
  [`cases/performing-rigs/docs/investigations/trigger-input.md`](docs/investigations/trigger-input.md).
- **The EIC/EXTINT interrupt-callback dispatch mechanism is identified;
  its registration path is not.** Vector-table indices 28-43 correspond
  exactly to the ATSAMD51's `EIC_0_IRQn`…`EIC_15_IRQn`, all 16 sharing one
  physical register-indirect dispatch site; the callback-table/mask-table/
  registered-count RAM layout is statically characterized (addresses,
  stride, layout regularity). An exhaustive static search (whole-firmware
  literal scan plus a MOVW/MOVT disassembly sweep, cross-checked against
  Ghidra's own static references) found no writer/registration routine
  anywhere in the compiled image — application use of this Arduino-SAMD-
  style EIC callback registration remains **unsubstantiated**, not
  disproven. A 2026-10-12 re-check added anchor-relative/negative-offset
  scans, `.bss` placement, and a concrete boot (count `0x200052e4` stays
  0, arrays stay zero, `0xcb92` never hit; USB slot populated as a
  control). Result: **zero statically recoverable callback slots**, and no
  `resolved_indirect` edge at `0xcb92`. See
  [`cases/performing-rigs/docs/investigations/boot-and-hardware-bringup.md`](docs/investigations/boot-and-hardware-bringup.md)'s
  "The EIC/EXTINT interrupt-callback dispatch mechanism".
- **Physical hardware facts** (part numbers, board/bootloader mechanics,
  condensed manual summary): [`cases/performing-rigs/docs/hardware/hardware-reference.md`](docs/hardware/hardware-reference.md).
- **Feather M4 Express feasibility (simulation-only so far — no physical
  Feather exists in this investigation yet)**: the unmodified AutoPilot
  image, run under a Feather-grounded hardware profile derived from
  `AUTOPILOT_RECIPE` (`config/boot_recipes.py`'s `FEATHER_M4_PROFILE`),
  never reaches the main loop within a 4,000,000-instruction bound — it
  stalls inside the real startup-reference routine's own wait loop,
  which never accumulates its required continuous-PA22-high streak once
  AutoPilot's board-specific PA22 drive is removed (mechanically
  confirmed via the firmware's own pin-descriptor table, not assumed).
  Separately, **AutoPilot's STEP0/1/3 and DIR0/1/3 GPIO pins are exactly
  Feather M4's onboard QSPI flash chip's SCK/IO0/IO2/CS/IO1/IO3** — a
  real wiring collision with no header exposure at all, confirmed
  against Adafruit's own vendored board-support source already in this
  repo. See
  [`cases/performing-rigs/docs/investigations/feather-m4-feasibility.md`](docs/investigations/feather-m4-feasibility.md)
  for the full evidence chain and the first-physical-test recommendation.

## Current open questions

Full protocol-level list: [`cases/performing-rigs/docs/protocol/open-questions.md`](docs/protocol/open-questions.md).
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
- Whether `FUN_0000b4b4` (SERCOM-object → index lookup) is ever reached
  with a SERCOM0 argument. In boot and 10 virtual-link scenarios every
  observed call passes a RAM SERCOM object (SERCOM2/5), and the selecting
  RAM words never change after their constructor stores. The one
  unexecuted static path (`c7c0 → b658 → b5bc`) needs a vtable-`0x14900`
  slot 7 (`0xc744`) or slot 8 (`0xc7c0`) dispatch.
  - All 86 register-indirect sites were classified, including the census's
    56 unresolved ones.
  - Only the slot-7 thunk's own `bx r3` (`0xc74c`) can load slot 8.
  - 58 sites are excluded within a stated scope; 27 are unresolved
    (callbacks, stack spills, runtime tables).
  - One-hop caller-argument provenance (static) covers 23 of the 27
    unresolved sites:
    - All 23 targets are incoming arguments. The three `f0b4` "spills" are
      really stack argument 4.
    - 20 sites have one CONCRETE caller value:
      - 19 (in `ec48`/`f190`) get `0xe883` (→ `0xe882`) from `e8a8`
        (`0xeaac`/`0xeae0`);
      - `0x105d2` gets `0x10379` (→ `0x10378`) from the stub `0x10438`.
    - The three `f0b4` sites are FORWARDED: their callers forward their
      own `r3`.
    - `0xc744` is a candidate nowhere. It is excluded within scope at the
      three CLOSED sites (`f396`, `f3b6`, `105d2`).
    - At the 17 `ec48` sites the target set is still OPEN only because
      `ec48`'s address is a flash literal (`0xeafc`, loaded at `0xea54`,
      next used by `cbnz`). At the 3 `f0b4` sites it is OPEN because of
      the forwarding.
    - That `0xea54` use is now a recorded operation result
      (`value_forward_use`, Ghidra p-code, static, complete, BOUNDED): the
      value is only compared and is overwritten on both successors; nothing
      escapes `FUN_0000e8a8`. The 17 sets stay OPEN until a callback-
      provenance version applies a closing rule with its assumptions; see
      [`research/pcode-forward-use-v1.md`](research/pcode-forward-use-v1.md)
      §4.
    - Four runtime-table/walk sites are unchanged.
    - No existing scenario (boot plus 10 virtual-link) enters any of the
      six functions involved.

    See
    [`research/callback-argument-provenance-v1.md`](research/callback-argument-provenance-v1.md).
  - No direct transfer and no analyzed site enters `0xc744`.
  - The three `0x14900` objects bind SERCOM3/4/1 objects, never SERCOM0's.
    If the path ran, `b4b4` would read RAM.

  The path is unestablished, not unreachable. Global negative not
  established. See
  [`research/sercom0-scenario-observation-v2.md`](research/sercom0-scenario-observation-v2.md)
  and
  [`research/indirect-dispatch-resolution-v1.md`](research/indirect-dispatch-resolution-v1.md).
  - The planner-trial claims of a `c5cc → c7c0` call (scratch ledger
    only) are now rejected by call-relation admission
    (`CALL_RELATION_UNSUPPORTED`). Canonical `C9:v1` ("`FUN_0000b4b4` is
    definitively reachable") states reachability with no root or scope and
    is reported as unsupported in that form; its state is unchanged. See
    [`research/call-relation-admission-benchmark.md`](research/call-relation-admission-benchmark.md).

## Tooling limitations that still matter

- **Original AutoPilot on Feather minimum READY conditions (2026-10-19):**
  unresolved beyond historical modeled receive-loop startup. PA22 plus the
  radio-ID stand-in restores the successful AutoPilot execution assumptions,
  but neither READY nor USB responsiveness has been verified. Fresh comparison,
  ten-instruction reset replay and existing regressions all fail with host
  Unicorn 2.1.4 SIGILL in `init_cache_info` during `uc_mem_map`, before target
  execution. No new target blocker is inferred. Six motor-output/QSPI net
  conflicts rule out recommending an intact-Feather trial; earlier advice to
  test whether the flash survives is superseded. See
  [minimum startup / READY report](docs/investigations/feather-minimum-ready.md)
  for separate milestones, partial regression results, the candidate recipe,
  USB assessment and next discrimination experiment.

- **Readonly flash vs. plain Crucible execution**: a whole-function
  symbolic replay through a literal-pool-derived branch doesn't fold
  correctly (solver assumptions ≠ concrete literals to a non-solver-
  mediated step). Deliberately unfixed; revisit only if a real symbolic
  use case needs a whole-function proof through such a branch — see
  [`cases/performing-rigs/docs/investigations/protocol-pipeline.md`](docs/investigations/protocol-pipeline.md).
- **No real, verified flash code cave** has been found for a trigger-input
  mitigation trampoline; the most promising unexplored option is flash
  beyond the current image's end, within the part's real 512KB, not yet
  checked against a real device.
- **USB IRQ dispatch is now resolved statically; the EIC callback and the
  USB endpoint-handler call remain unresolved** (2026-10-12). The census and
  Ghidra seeding read all 16 + 136 vectors (IRQ count derived from the case
  SVD, `config/performing_rigs.py` `NUM_EXTERNAL_IRQ`). USB IRQ80 →
  `FUN_0000cc14`, IRQ81–83 → `b.w 0xcc14` stubs. `FUN_0000cc14` tail-calls
  through RAM `0x200052e8` (`bx r3` at `0xcc1a`). **Static, mechanically
  derived** (`tools/census/fnptr_resolve.py`, STRONG): the slot's only
  Ghidra-attributed store is `str r0,[r3]` at `0xccc6` in `FUN_0000ccc4`,
  whose `r0` is its argument; the single direct call `bl 0xccc4` at `0xbcda`
  in USB init `FUN_0000bc44` sets `r0` from literal `0xbd54` = raw `0xc725`
  → canonical `0xc724`. `0xc724` is `ldr r0,=0x20004ca0; b.w 0xc5cc` (a
  tail-call stub with a constant argument, not a bare branch). Seeding
  `0xc724`/`0xc5cc` (`research/runs/ghidra_seeds/autopilot868.json`)
  recovers `FUN_0000c5cc` (`0xc5cc`–`0xc705`, 30 blocks); seeded at `0xc724`
  alone Ghidra makes one 320-byte function, as Macaw `explore` does (Macaw
  stops at three `cbz` classify failures; its 77 instructions are a strict
  subset of Ghidra's 122). The census graph carries `0xcc1a` → `FUN_0000c724`
  as a `resolved_indirect` edge (not a direct call); 26 USB-stack functions
  moved from NO_KNOWN_PATH to DEFINITELY_REACHABLE on that static edge
  (no dynamic delivery observed). Still open: the endpoint-handler call
  `blx r3` at `0xc6d8` (object/vtable through `0x20004ca4`), the USB
  register base held in RAM `0x20005158` (only writer is unowned code at
  `0xc730`, so most endpoint-register accesses are not attributed), and the
  EIC handler's callback at `0xcb92` (`blx` through RAM array `0x2000525c`,
  no registration writer in the image and count 0 after concrete boot,
  see the EIC bullet above). EIC↔USB common-path analysis from the
  dispatcher/16 vector stubs remains `NO_KNOWN_PATH` (16 EIC / 45 USB
  explored), which is not evidence of disconnection. Using the whole
  census EIC usage set (which adds the radio-path `INTENCLR`/`INTENSET`
  helpers `FUN_0000a000`/`FUN_0000a03c`) reports `KNOWN_COMMON_PATH` at
  `FUN_0000e628`. That path rests on a block Ghidra attributes to
  `FUN_0000a000` (`0x9fc4`), which branches into the middle of
  `FUN_0000a1f4` (`0xb43e`), a heuristic boundary that has not been
  verified. It does not pass through the EIC callback dispatch.
- **`GhidraSVD`** (the proper Ghidra SVD-loading extension) is still not
  installed — the standalone `cases/performing-rigs/config/svd/resolve_mmio.py` resolver remains
  good enough for routine use; install only if that stops being true.

## Next priorities

The project's goal is to recover enough of the hardware and external
behavioral contract to write a clean replacement firmware — we are still
primarily in the hardware-contract phase. **Decision rule**: further
reverse engineering is prioritized only when it can change the hardware
contract, externally observable behavior, rewrite architecture, or a
regression test needed for the replacement firmware — not merely because
an analysis tool (Macaw, Ghidra, census) still has unresolved/residual
items. An unresolved analysis item is tracked (see `harness/roadmap.md`),
not automatically the next thing to chase.

1. Attempt dormant-event reachability now that whole-function execution
   habits are better understood.
2. Get real physical measurements at the trigger jack/PB05 (see
   `trigger-input.md`) before choosing a debounce threshold or attempting
   a real flash patch.
3. Continue semantic classification of the AutoPilot868 residual, then
   extend to AutoPilot915/Mando868/Mando915.

Fuller, itemized unfinished-work tracking lives in
[`cases/performing-rigs/roadmap.md`](roadmap.md) — not duplicated here.

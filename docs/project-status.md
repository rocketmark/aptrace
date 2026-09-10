# APTrace — Project Status

**This is the single authoritative source for current project state.** If
anything elsewhere in the repo conflicts with this document, this document
wins — and if you find such a conflict, it's a bug in the docs; fix it here.
Historical detail lives in linked docs, not here — this file stays short by
design.

Last updated: 2026-09-09 (compact RAM zero-initialization implemented for
Crucible/What4 queries, and measured against the real narrowed PB05 query
diagnosed in the trigger-input investigation's own Part 6): the
~196,615-assert-per-byte RAM zero-initialization that investigation
identified as ~73.5% of a real query's total assertion count is eliminated
— `APTrace.ProtocolHarness.runPacketTransactionTraced` now builds its base
memory `SymbolicMutable` (which asserts nothing about writable segments)
and reasserts "every writable segment starts at zero" itself as one SMT
constant-array store per segment (addresses/sizes read from the `MM.Memory`
itself, not hardcoded), instead of one equality per byte — the same idiom
already used, unchanged, for this module's own stack zeroing. On the exact
narrowed PB05 -> `0x8f98` query: the standalone SMT-LIB2 file drops from
41.3MB/267,385 asserts to **10.8MB/70,775 asserts** (-73.9%/-73.5%), and the
online Z3 check — which previously had to be killed after ~9 minutes with
no answer at all — now **converges in 367.7s**, though to `unknown`, not a
reachability answer (a second query in the same investigation, not
previously measured, still does not converge within an 18-minute budget
even with the smaller encoding). **No prior firmware-behavior conclusion
changes**: no solver witness was produced either before or after, so
nothing here is promoted past what `trigger-input-symbolic-reachability.md`
already established via Ghidra provenance and Unicorn replay. Verified as a
real fix, not just by construction: the SMT-LIB2 output's RAM region is
confirmed to carry zero per-byte assertions and exactly one
`forall`-guarded equality covering the whole region; and a direct
git-stash-based before/after comparison of the existing `aptrace protocol`
whole-function check reproduced byte-identical execution (same step count,
same cycling addresses) with and without this change, confirming it doesn't
alter behavior for concrete execution either — the check's own failure is a
separate, pre-existing, already-documented flash/Crucible gap, not
something this change touches or introduces. Flash encoding is deliberately
untouched. See
[`docs/tooling/compact-ram-initialization.md`](tooling/compact-ram-initialization.md)
and [`docs/harness/execution-model.md`](harness/execution-model.md) (updated).

Previous update (2026-09-09, trigger-input gate-cell provenance closed via
Ghidra + Unicorn; Macaw/Crucible/Z3 attempted, a real classifier
limitation found, the SAT query itself did not converge): the two
previously-unresolved gate cells behind the trigger's second
`digitalRead(PB05)` path are now fully provenance-closed, not synthetic
— gate cell 1 (`0x20001b38` = `0x7b`) is a real side effect of the
already-known `'+'` command's `mode=0x62` bulk-push finalize path (the
same mechanism `bulk-push-trigger-provenance.md` already proved fires on
every Remote boot); gate cell 2 (`0x200000d8` = `9`) is set by a real
all-four-channels-idle check inside the same function, and — a clean new
finding — is unconditionally reset to `0` by the config-reload function
itself once it fires, a genuine self-clearing mechanism, confirmed
concretely (Unicorn) both ways. An attempt to cross-check the bounded
region with Macaw and prove reachability with Crucible/What4/Z3 found a
real, exhaustively-confirmed Macaw limitation (every `CBZ_T1`/`CBNZ_T1`
instruction in this function fails Macaw's branch classifier), worked
around by re-seeding discovery at each branch's own already-known
successor rather than patching Macaw — but the resulting SAT query, in
both a fully-symbolic and a narrowed (gate cells concrete, only PB05
free) form, did not converge within a practical time budget, so no
solver-confirmed claim is made; the reachability answer instead rests on
direct Ghidra provenance tracing plus a concrete Unicorn replay (both
PB05 polarities, and the config-reload's own self-clear), reproduced
from the already-established sound entry point (`0x8e18`, zero
fabricated registers). See
[`docs/investigations/trigger-input-symbolic-reachability.md`](investigations/trigger-input-symbolic-reachability.md)
and [`research/workflows/trigger-input.yaml`](../research/workflows/trigger-input.yaml)
(both updated). No prior conclusion changed.

Previous update (AutoPilot trigger-input runtime path made
concretely reachable; the second `digitalRead(PB05)` path closed): the
prior slice's own named gap — the runtime `"T..."` poll needed fabricated
`r4`-`r11` to reach mid-function — is resolved the simple way: a backward
trace of every branch in the per-channel ramp loop found `r4`-`r11` are
all real, freshly-established state, so **entering at the state
machine's own true function start (`0x8e18`) is itself a sound boundary,
no fabrication needed**. Both real `"T..."` frames (`"T0,1,|"`,
`"T1023,0,|"`) are now reproduced concretely from that entry, on real,
unmodified firmware. The poll's outer enable byte, `0x20003120`,
previously unattributed, is closed: it's set by the real `TR0|`/`TR1|`
ASCII command (`TR1|` arms trigger-status reporting; `TR0|`, the
default, disarms it) — a previously-undocumented AutoPilot-side effect
of an already-known command. With reporting disarmed, the second,
previously-untraced `digitalRead(PB05)` site was also closed: reading
PB05 low, behind four additional idle-state conditions, reaches a real
reload of the persisted motor-target config
(`config_loader__CUSTOM`/`FUN_00004b64`) — not a new move, but a real,
substantive config refresh, concretely confirmed up to the same
lazy-init boundary `target-config-provenance.md` already named (not a
new gap). See
[`docs/investigations/trigger-input-concrete-path.md`](investigations/trigger-input-concrete-path.md)
and [`research/workflows/trigger-input.yaml`](../research/workflows/trigger-input.yaml)
(both updated) for the full evidence and the now much narrower
symbolic-target handoff (whether two remaining gate cells,
`0x20001b38`/`0x200000d8`, are ever naturally driven to the values this
slice used as disclosed test seeds). No prior conclusion changed.

Previous update (AutoPilot trigger-input concrete path closed,
EIC ruled out): tracing a reported bug ("connecting a certain chain to
the 3.5mm trigger input causes exactly one trigger, then normal
operation continues") found the real mechanism is **plain polled
`digitalRead()`, not EIC** — proven, not assumed, by two independent
exhaustive whole-image scans showing the AutoPilot's compiled-in EIC
dispatcher is never armed (its callback table and line count have
exactly one reference anywhere in the image: the dispatcher's own load).
Two physical pins were identified by decoding the real Arduino
pin-descriptor table directly from the firmware image: **PA02**, sampled
exactly once at boot (`FUN_00006968`) to set a mode flag
(`0x20001fc0` — already known from `mt-quick-setup-trigger.md` as the
`MT` frame's 5th field, now explained mechanically for the first time),
and **PB05**, the live signal. Only when PA02 reads low at boot does the
firmware explicitly configure PB05 as a plain digital input (concretely
confirmed via `ConcreteMachine`, both PA02 outcomes); otherwise it runs a
128-sample ADC baseline-averaging routine over the same pin
(`FUN_00005d44`) whose result is **never read by anything else in the
image** — a real, disassembly-confirmed dead end, the same class of
finding as this project's other "computed but never consumed" results.
The one live runtime consumer is a `digitalRead(PB05)`-gated branch
inside the already-known `MC4`-gated motor-phase/ramp state machine
(`phase_ramp_state_machine__CUSTOM`), rate-limited to once per ~500
ticks, sending a **previously undocumented outbound frame,
`"T<0 or 1023>,<1 or 0>,\|"`**, through the AutoPilot's already-proven TX
wrapper (`0x8c10`). This is a level-sampled poll with no debounce and no
history between checks — a real, disassembly-grounded explanation for a
self-correcting one-shot symptom falls straight out of that structure (a
transient level on a floating, no-pull input sampled during exactly one
~500-tick window reads once, then the next independent poll reverts) —
**PROBABLE**, not concretely reproduced end to end, as the explanation
for the specific reported bug. A precise, bounded gap was left for a
Macaw/Crucible/What4/Z3 follow-up: the runtime poll's own register entry
state (`r4`-`r11`) is established earlier in the same function by code
this slice didn't trace backward, and a second, distinct
`digitalRead(PB05)` site (gated behind an untraced four-way condition,
branching to `0x8f98`) was found but not followed. See
[`docs/investigations/trigger-input-concrete-path.md`](investigations/trigger-input-concrete-path.md)
and [`research/workflows/trigger-input.yaml`](../research/workflows/trigger-input.yaml)
for the full evidence chain and the symbolic-target handoff. No prior
conclusion changed.

Previous update (`LL2|`'s Remote sender found, closing the
Set-Limits workflow's last open sender question): `LL2|` is sent from
**the same function that sends `LL1|`** — `FUN_0000de3c`, the shared
Manual-Mode/Set-Limits live-jog engine — found by an exhaustive raw-byte
scan (one literal `"LL2|"` in the whole image) cross-checked by a
whole-image Ghidra xref scan (exactly one reference, at `0xe114`, inside
`FUN_0000de3c`), both independently converging with zero ambiguity. A
genuine surprise fell out alongside it: **`LL1|` is sent twice, not
once** — the already-known entry preamble, and a second resend later in
the same function, both gated on a real, previously-uncharacterized
position-query mechanism this slice also closed: `FUN_0000b834`, the
real sender of `command-inventory.md`'s own long-unattributed `I9|`/`I1|`
short forms, which sends one of them, parses a signed numeric response,
and only on success lets `FUN_0000de3c` (re)send `LL1`/`LL2`. **The
queried position value itself is never forwarded** — confirmed by an
exhaustive xref of its storage slot and by decompiling the shared ASCII
sender (`FUN_000058a8`), which takes only a bare string pointer, no
numeric argument — so no wire path exists from this real position query
to `LL1`/`LL2`'s payload (they have none) or to the AutoPilot's `posA`/
`posB`. This sharpens, rather than reopens, `ll-limit-workflow.md`'s
existing "no producer for `posA`/`posB`" negative result: a third,
independent trace (the Remote's own query mechanism) now confirms the
same conclusion from the opposite direction. Also found and corrected:
`user-guide-workflows.md`'s own hedge that `"SET LIMITS"` might belong to
the trigger/relay settings-screen family (based on string-table
proximity) is **disproven** — `"SET LIMITS"`'s sole code reference
traces cleanly to the Manual-Mode-cluster screen family instead, and
Manual Mode's `"Direction"` row and Set Limits are now shown to be two
rows of the *same* screen (`FUN_0000e314`), not merely two features that
happen to share a jog primitive. Concretely reproduced: all three real
`LL1`/`LL2` send sites, and both arms (`I9|`/`I1|`) of the position-query
sender, entering directly at each real send address with
`ConcreteMachine`/`capture_tx_bytes` — no fabricated packet bytes. See
[`docs/investigations/ll2-set-limits-provenance.md`](investigations/ll2-set-limits-provenance.md).
No AutoPilot-side conclusion changed.

Previous update (Manual Mode wire provenance closed: no prior
slice had identified any wire command for Manual Mode's live jog. This
slice found it is **not** any known ASCII command — it is a previously-
uncharacterized **binary** frame family (`0xF0`/`0xE0`, already listed in
`command-inventory.md` with unconfirmed direction), sent **continuously,
once per UI tick, for as long as the jog wheel is not clicked**, not a
discrete per-gesture command. Traced from two independent directions
that converge exactly: the physical-input side (a real SAMD51 EIC
interrupt callback, `FUN_00007de8`, genuinely registered via
`attachInterrupt`-equivalent `FUN_0001240c`, decoding real quadrature
transitions on pins `0x31`/`0x32` with velocity-sensitive scaling) and
the UI side (the `"Direction"` row of the `"MANUAL MODE"`-titled screen,
leading to a live-jog loop, `FUN_0000de3c`, that sends `"LL1\|"` once on
entry, shows `"Use the joystick to..."`, then calls the real frame
sender `FUN_0000be94` every tick until clicked). The AutoPilot's
`ascii_dispatcher` checks for this binary frame **before any ASCII
command** and routes each per-channel record into `FUN_00005274`/
`FUN_00004d18` — **the same entry point the `I` command already uses**
(`i-command-motor-chain.md`), cross-confirmed via a shared per-channel
array (`0x20000180`). Real, unmodified-firmware frames were captured
concretely, both empty/idle (`MT`-adjacent heartbeat shape) and with one
real per-channel record. Three other, previously-`UNKNOWN`-sender
commands (`N\|`, `B0\|`, `TR0\|`) were closed as a side effect of tracing
the same shared menu widget. **One attribution question stays
PROBABLE, not CONFIRMED**: whether this is Manual Mode's *only*
live-jog entry point, since the same code is concretely tied to the
Set-Limits workflow's own "position with the joystick" step (also
closing half of that workflow's own open `LL1` sender question) — both
readings are consistent with the user guide and not mutually exclusive.
See
[`docs/investigations/manual-mode-wire-provenance.md`](investigations/manual-mode-wire-provenance.md).
No prior conclusion changed.

Previous update (Remote `FUN_0000c440`'s bulk `'+'`/`MC4` push
trigger closed): this function's real control-flow structure (two
request/response rounds sharing one success gate, `cVar24`, computed
purely from whether its own `S|`→`P...` round trip got a clean response)
is now fully mapped by disassembly, cross-checked by an independent
full-image branch decoder. **The primary trigger is the Remote's own
boot sequence** — `Reset_Handler` → `FUN_00016900` → `FUN_0000fdf0`
(a splash-screen routine that also triple-broadcasts `"R0|"`) calls
`FUN_0000c440(0)` unconditionally, exactly once per power-on, immediately
before the Remote's own `"&|"` version query — confirmed exhaustively
unique, with zero indirect dispatch anywhere in the image. **A secondary
trigger** re-arms after a real ~5000-tick radio-silence gap, via the same
inbound-byte dispatcher (`FUN_00010ce4`) the `MT` investigation already
characterized. The bulk-`'+'` loop itself is additionally gated on a
UI-set flag the boot sequence never sets, so a literal cold boot sends
zero `'+'` frames — only `MC4` fires; real `'+'` pushes require the
interactive Auto-Mode UI to have run first in that session. A
structurally distinct sibling (`FUN_0000b6f0`, genuinely periodic,
~every 250 ticks) was found and shown to never send `MC4` — the two
must not be conflated. Concretely reproduced end to end: entering
`FUN_0000c440` directly (its own caller chain now proven unconditional),
given a real `S->P` round trip and disclosed record/flag seeds, produces
the real frames `+1,1,1,0,98,1,0,0,0,500,0,0|` (byte-identical to
`plus-target-distance-roundtrip.md`'s own already-AutoPilot-proven frame)
and `MC40,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,|`. See
[`docs/investigations/bulk-push-trigger-provenance.md`](investigations/bulk-push-trigger-provenance.md).
No prior conclusion changed.

Previous update (`MT<...>|` AutoPilot-side scheduling trigger closed):
the flash `0x7232`-`0x7514` region `mc-command-remote-
provenance.md` left unattributed in the Ghidra cache is now recovered by
disassembly plus an independent full-image branch decoder — one literal
pool, one unrelated sibling routine (tail-jumped from the ASCII command
dispatcher, not part of this chain), and the real connector-probe/`MT`-
builder function, entered by a single, unconditional, exhaustively-
confirmed-unique static path: `sketch_setup()` (called exactly once,
ever, by `main()`) → `BL FUN_00007770` (unconditional, branch-free from
`setup()`'s own entry) → `B.W 0x7334` (unconditional tail-jump). **`MT`
is therefore sent exactly once per physical boot/MCU reset, unconditionally,
after the startup reference/input routine and the radio-ID handshake
complete and before `setup()`'s own `MC4`-wait loop begins — never
periodic, never edge/change-driven, never reconnect-driven; Quick Setup
is boot/setup-only.** The four connector probes were also found to be a
guarded 2-valued (boolean) read per channel, not an arbitrary digit, and
their slot↔probe-object mapping (A→b0, C→b1, B→b2, D→b3) was confirmed
both by disassembly and concretely — real `MT` frames (`MT10101|`,
`MT00001|`) were produced from disclosed connector-GPIO inputs via
`ConcreteMachine`, entering directly at `FUN_00007770`. The 5th field's
source (`0x20001fc0`, written by the startup reference/input routine)
was identified and bounded. Remote-side concrete delivery through
`FUN_00010ce4` was assessed and deferred as a materially larger,
structurally different undertaking (a per-character inbound state
machine, not a whole-packet dispatch) — named as a follow-up, not
silently skipped; the existing static confirmation of its Quick-Setup
effect is unchanged. See
[`docs/investigations/mt-quick-setup-trigger.md`](investigations/mt-quick-setup-trigger.md).
No prior conclusion changed.

Previous update (`MC0`-`MC4` Remote-side provenance closed): a
single Remote function, `FUN_00005a8c`, builds every `MC` frame in the
image, confirmed the sole such builder by four independent full-image
scans, with exactly three call sites. `MC<0-3>` is sent every time the
user clicks out of an edited row on the motor-settings page
(`"CURRENT (mA)"`/`"STEPS/S MAX"`/`"MICRO-STEPPING"`/`"RETURN SPEED"`),
not once per motor; `MC4` is sent when the user clicks `"Continue"` on
the `"Motor <N>: Choose type"` screen once all four motors have a type —
both closed end to end (displayed string -> input gesture -> state ->
sender -> exact wire bytes), concretely reconfirming the AutoPilot's
already-known `setup()`-unlock effect using a **Remote-produced**, not
fabricated, `MC4` frame for the first time. A genuine surprise fell out
alongside this: **Quick Setup is opened by the AutoPilot, not by any
Remote menu action** — a real `MT<...>|` frame, built from live GPIO
motor-connector presence detection, that the Remote's inbound handler
reacts to automatically; no Remote-side Quick-Setup menu entry point
exists. See
[`docs/investigations/mc-command-remote-provenance.md`](investigations/mc-command-remote-provenance.md).
Builds on the prior slice's user-guide workflow/state model
([`docs/ui/user-guide-workflows.md`](ui/user-guide-workflows.md),
[`docs/ui/action-command-map.md`](ui/action-command-map.md)), which
reorganized this project's command-by-command findings around how a
human actually operates the product and surfaced this exact gap (zero
confirmed Remote-side sender for `MC0`-`MC4`) as a top-ranked open
question — now closed. No firmware-behavior conclusion from any prior
slice changed.).

**Before doing firmware-analysis work, read
[`docs/tooling/tool-selection.md`](tooling/tool-selection.md)** (short
version: [`CLAUDE.md`](../CLAUDE.md)) for which of Ghidra/Unicorn/Macaw/
Crucible to reach for.

## Current milestone

**Goal**: one complete AutoPilot-only transaction, verified through
APTrace's own pipeline:

```
wire command "&|"
    -> real receive/parser path (unmodified compiled firmware)
    -> event 5 scheduled
    -> outbound TX hook (0x8c10 / 0x7f84)
    -> observed string == "V01R39"
```

**Status: COMPLETE at the concrete (Unicorn) evidence tier, end to end.**
As of 2026-09-07, every stage of the chain above has been independently,
concretely demonstrated against real, unmodified firmware, entering at
real call sites with the firmware establishing its own state (not
hand-picked to make the answer come out right):

1. `&|` → `pending[5]=1`: entering at the real caller (`0x8a34`) with a
   real `&|` packet, `pending[5]` becomes `1` in 46 instructions. See
   [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
2. `pending[5]=1` → TX hook → `"V01R39"`: the real, unmodified outbound
   dispatcher (`0x9268`) consumes event 5 and calls the real TX hook
   (`0x8c10`) with a pointer to a buffer holding exactly `"V01R39\0"` —
   independently confirmed to be what a real, unconditional startup
   routine (`FUN_00004328`) writes there before the main loop ever runs.
   See [`docs/investigations/tx-hook-verification.md`](investigations/tx-hook-verification.md).

Per [`docs/tooling/tool-selection.md`](tooling/tool-selection.md)'s
evidence levels, this is **level 2** (concretely executed) across the
whole chain. A **level 3** (solver-confirmed, Crucible/What4/Z3) proof of
the *whole* chain in one run remains blocked by a known, deliberately
unfixed tooling gap — see "Tooling gaps," not a firmware blocker. Individual
pieces of the chain (e.g. the `&` character check itself) already have
independent level-3 confirmation.

**Note on the command itself**: `&|` is the wire-level frame the Remote
transmits (`|` is the frame terminator). The dispatcher's first-byte check
requires exactly `0x26` ('&') at flash `0x888c` — solver-confirmed
(level 3) — and the full `&|` frame reaching that check, and the full
onward path to `"V01R39"`, has now also been demonstrated concretely
(level 2, above).

**Remote (`mando`) firmware**: first concrete execution (2026-09-08), then
a full harness-driven virtual RF link (2026-09-08) closing roadmap M3
entirely at the concrete evidence tier. Ghidra's existing pipeline loads/
discovers Mando cleanly with zero platform-specific changes (563
functions; every previously-named Remote function of interest resolves
at its documented address). The complete `&|` -> `V01R39` round trip now
runs as **one harness-driven script** (`tools/unicorn/virtual_link.py`),
not two hand-run scenarios: Remote's real `0xba98` computes `"&|"` and
calls its real TX wrapper; the harness transfers those exact bytes (no
radio modeled) into AutoPilot's real RX buffer; AutoPilot's real
dispatcher schedules event 5 and its real outbound dispatcher builds
`"V01R39"`; the harness transfers those exact bytes into Remote's real RX
ring buffer; Remote's real collection loop captures exactly `"V01R39\0"`.
See [`docs/investigations/mando-first-execution.md`](investigations/mando-first-execution.md)
for the per-firmware proofs and the honest boundary found (both firmwares
gate real RF I/O behind an unmodeled driver layer — reaching past it
needed the `--stub-call` Unicorn capability, not full radio emulation),
and [`docs/investigations/virtual-rf-link.md`](investigations/virtual-rf-link.md)
for the round trip itself and the two reusable primitives
(`capture_tx_bytes`/`deliver_and_observe`) it's built from. A second
transaction, `G -> #` (roadmap M4), closed the same way immediately
afterward (2026-09-08), confirming the primitives generalize — see
[`docs/investigations/g-ack-roundtrip.md`](investigations/g-ack-roundtrip.md).
A third, `S -> P...`, closed the same day (2026-09-08) at *both* its
response forms — see
[`docs/investigations/s-p-roundtrip.md`](investigations/s-p-roundtrip.md)
— after which the project deliberately paused protocol-transaction work
to pivot toward hardware provenance (see "Next steps").

## Proven capabilities & findings

Demonstrated on real, unmodified firmware; safe to build on without
re-proving:

- **Target/platform**: Performing Rigs AutoPilot/Remote firmware on
  Microchip/Atmel **ATSAMD51J19A** (Cortex-M4F, 512KB flash, 192KB SRAM —
  exact part confirmed by physical board inspection, not inferred),
  Arduino/Adafruit SAMD lineage, app image loaded at flash `0x4000`.
  Hashes: [`docs/firmware/firmware-inventory.md`](firmware/firmware-inventory.md).
  Layout/vector table: [`docs/firmware/firmware-layout.md`](firmware/firmware-layout.md).
  Hardware/board-level research:
  [`docs/hardware/autopilot-research-handoff.md`](hardware/autopilot-research-handoff.md).
- **Macaw pipeline**: raw `.bin` loading (no ELF), vector-table parsing,
  Thumb-2 lifting (zero decode failures across ~1500 real instructions),
  and CFG discovery from arbitrary seeded entry points — used to seed the
  protocol dispatcher directly.
- **Crucible execution infrastructure works** at both granularities:
  single-block (`APTrace.SymbolicRunner.checkBranchModel`) and
  whole-function (`APTrace.ProtocolHarness.runPacketTransaction`) — i.e.
  the lift-to-Crucible-to-What4/Z3 machinery runs correctly in general.
  **A whole-function solver-confirmed replay of the full `&`-command
  dispatcher specifically is still blocked by a known, documented, and
  deliberately unfixed tooling gap — see "Tooling gaps," not a claim
  about the firmware.**
- **Solver-confirmed single-block protocol checks** (not hand-derived): a
  register holding the packet's first byte, checked against each command's
  real comparison instruction, reaches the correct handler exactly at that
  command's ASCII value:

  | Command | Solver-confirmed value | Check block |
  |---|---|---|
  | `&` | `0x26` | `0x888c` -> `0x8890` |
  | `G` | `0x47` | `0x83b2` -> `0x83b6` |
  | `!` | `0x21` | `0x87b2` -> `0x87b6` |
  | `S` | `0x53` | `0x87be` -> `0x87c2` |

  See [`docs/harness/protocol-harness-results.md`](harness/protocol-harness-results.md).
- **The real caller into the protocol dispatch region**: `0x8a34 -> 0x8259`
  (Macaw-call-classified `BL`, not a tail-jump). See
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md).
- **A real calling-convention bug, fixed**: the opaque function-call
  override used to clobber *every* register (including AAPCS callee-saved
  R4-R11), corrupting a loop's own counter/table-pointer state and
  producing a hang that looked like firmware complexity. Fixed to only
  substitute the genuinely caller-saved registers (R0-R3, R12). See
  [`docs/harness/execution-model.md`](harness/execution-model.md).
- **A reusable diagnostic**: `APTrace.ProtocolHarness.debugFeature`, a
  Crucible `ExecutionFeature` that logs the visited program location every
  N steps — turns an opaque hang into "stuck cycling through X, Y, Z."
  Reuse it whenever a whole-function run doesn't terminate as expected.
- **Ghidra headless static analysis** integrated
  (`tools/ghidra/analyze_firmware.sh`, Thumb-only `ARM:LE:32:Cortex`,
  vector-table entry seeding): 414 functions discovered on real firmware
  (vs. 204 unseeded), including the dispatcher region. See
  [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md).
- **Unicorn concrete execution** integrated (`tools/unicorn/run_concrete.py`,
  Cortex-M4 model): concretely running from `0x888c` with `r3=0x26`
  reproduces the solver-confirmed `&` -> `0x8890` branch exactly. See
  [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--watch`/`--watch-mem`** added to the Unicorn backend: records full
  register/memory state at multiple addresses across one run without
  halting (unlike `--stop-at`) — needed for a per-iteration loop trace. See
  [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--watch-mem-write`** added to the Unicorn backend: a true memory
  watchpoint (fires on any write landing in an address range, regardless
  of which instruction performs it) rather than `--watch`'s code-address
  trigger — for exactly the case where a static xref search finds no
  writer and the question is whether a computed/indirect store reaches a
  RAM address at all. First used in
  [`docs/investigations/channel-busy-gate-search.md`](investigations/channel-busy-gate-search.md).
  See [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--fake-tick` added to the Unicorn backend**: a narrow,
  instruction-count-paced increment of a *firmware-maintained tick
  variable* (identified first, not assumed) — deliberately not a
  SysTick/timer peripheral model. Used to get a real concrete run past
  `FUN_00006968`'s homing-timeout wait; results obtained this way are
  documented as "firmware behavior observed after time was advanced by
  the harness," not "real hardware timing modeled." See
  [`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md)
  and [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--mmio-force-bits`/`--mmio-clear-bits`/`--map-page` added to the
  Unicorn backend**: explicit, address-scoped hooks that force a named
  MMIO register's bits set or clear on every read (never on a write,
  never on a timer), for a real, SVD-identified completion/self-clearing
  bit the zero-behavior model otherwise leaves permanently wrong —
  plus a minimal facility to map one extra fixed page (e.g. the SAMD51
  NVM calibration row) outside flash/RAM/MMIO. Not a peripheral model —
  each address is named and justified individually. Used to run
  `Reset_Handler`'s real clock-init chain and a real SERCOM/DMA driver
  constructor to completion for the first time. See
  [`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md)
  and [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **`--force-reg` added to the Unicorn backend**: fabricates one
  register's value at one exact instruction — deliberately a different,
  stricter-disclosure mechanism than `--mmio-force-bits`/
  `--mmio-clear-bits` (which model documented MCU-internal silicon
  behavior; this stands in for something genuinely external, like an
  attached device's response, that the harness has no way to know).
  Scoped to a single program point (the instruction after one specific
  call site returns), not a callee's every invocation. First and only
  use so far: one SPI chip-ID read result, disclosed as harness-supplied
  external-device state every time it's mentioned. See
  [`docs/investigations/post-probe-main-loop.md`](investigations/post-probe-main-loop.md)
  and [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md).
- **The real `&|` -> `pending[5]=1` transaction, concretely demonstrated**:
  entering at the real caller (`0x8a34`), letting the firmware establish
  its own entry state (not manually seeded), with a real `&|` packet in the
  buffer — `pending[5]` becomes `1` in 46 instructions. See
  [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
- **`tools/doctor.sh`** verifies Ghidra, Unicorn, and Macaw/Crucible/What4/Z3
  are all usable, including functional smoke tests.
- **`APTrace.ProtocolHarness.RichTraceConfig`/`runPacketTransactionTraced`**:
  a reusable, fine-grained (every-step, not sampled) execution trace for a
  bounded address range within a whole-function run, using the existing
  `Data.Macaw.Symbolic.Regs.simStateRegs` API to recover live register
  state. What found the readonly-flash root cause — see "Tooling gaps."
  See [`docs/investigations/whole-function-trace-divergence.md`](investigations/whole-function-trace-divergence.md).
- **The real `pending[5]=1` -> TX hook -> `"V01R39"` transaction, concretely
  demonstrated**: the real, unmodified outbound dispatcher (`0x9268`)
  consumes event 5 (`pending[5]` observed going `1` -> `0`) and calls the
  real TX hook (`0x8c10`) with a pointer to a buffer independently
  confirmed to hold exactly `"V01R39\0"` — written there unconditionally
  by a real startup routine (`FUN_00004328`), not seeded to force the
  answer. Combined with the `&|` -> `pending[5]=1` result above, this
  closes the full AutoPilot milestone at the concrete evidence tier. See
  [`docs/investigations/tx-hook-verification.md`](investigations/tx-hook-verification.md).
- **Real ATSAMD51J19A peripheral/register naming for raw MMIO addresses**:
  [`tools/svd/resolve_mmio.py`](../tools/svd/resolve_mmio.py), backed by
  the real vendor SVD file, plus `run_concrete.py --log-mmio` to capture
  what a concrete run actually touches. Used to confirm the full
  `Reset_Handler` startup peripheral-init chain (clock tree, analog block,
  WDT, PORT, TC0-TC3, TCC1, USB), and one fully-resolved pin-level fact:
  **PB22 is toggled from a real timer interrupt handler (IRQ93/TCC1)** —
  a named GPIO tied to already-understood firmware behavior, matching the
  hardware doc's "4 motor-output channels." Also produced an honest
  negative result: the outbound TX path (`0x9268`→`0x8c10`) touches no
  MMIO directly — its real transport peripheral is gated behind a runtime
  driver-object pointer, not a literal address, and naming it is the next
  slice, not done here. See
  [`docs/investigations/samd51-peripheral-mapping.md`](investigations/samd51-peripheral-mapping.md).
- **First concrete Mando (Remote) execution**: Ghidra discovery clean with
  no platform-specific changes; both halves of the `&|` -> `V01R39`
  round trip confirmed from the Remote's own side via Unicorn (real TX
  construction and real RX capture, in two separate runs mirroring the
  AutoPilot milestone's own two-step structure). Required a new
  `run_concrete.py --stub-call` capability (the Unicorn-side equivalent of
  Crucible's existing opaque function-call override) to get past a real,
  not-yet-modeled radio/SPI driver dependency — the same class of boundary
  already found on the AutoPilot's TX path. See
  [`docs/investigations/mando-first-execution.md`](investigations/mando-first-execution.md).
- **A full, harness-driven virtual RF link, both firmwares, one round
  trip**: `tools/unicorn/virtual_link.py` runs the complete `&|` ->
  `V01R39` transaction end to end — Remote's real TX call, a harness-
  mediated byte transfer (no radio modeled), AutoPilot's real dispatch
  and response, a second harness-mediated transfer, Remote's real
  capture — asserting the exact bytes at every step. Built from two
  reusable primitives (`capture_tx_bytes`, `deliver_and_observe`) that
  don't hardcode transaction content, only the already-proven RF-boundary
  addresses, so the same script structure applies to future transactions
  (`G -> #`, `S -> P...`). This closes roadmap M3. See
  [`docs/investigations/virtual-rf-link.md`](investigations/virtual-rf-link.md).
- **`G -> #` through the same virtual link (roadmap M4)**: confirms the
  M3 primitives genuinely generalize — `tools/unicorn/virtual_link.py g`
  runs Remote's real `G<d><d><seq>|` request (register-seeded call
  arguments, not just RAM), AutoPilot's real handler concretely
  scheduling event 17 (not just solver-confirmed *reachability* — a real
  first for this project), AutoPilot's real single-byte TX wrapper
  (`0x7f84`, a new `capture_tx_byte` primitive alongside the
  pointer-based `capture_tx_bytes`), and Remote's real retry/ack loop
  (`0xb59c`) accepting the real `"#"` byte (`R4` becomes `1`, its own
  genuine `int` return value). Needed two new `--stub-call` targets on
  the AutoPilot side for real-but-irrelevant helpers (one hits the same
  "driver object needs real startup" boundary already known from RF; one
  spins on what's plausibly persistent motor-config data, not yet
  investigated further). See
  [`docs/investigations/g-ack-roundtrip.md`](investigations/g-ack-roundtrip.md).
- **`S -> P...` through the same virtual link (roadmap M4), both response
  forms**: `tools/unicorn/virtual_link.py s` runs Remote's real `"S|"`
  query, AutoPilot's real handler concretely scheduling event 6 *and*
  computing the response's first field in the same pass (from a
  literal-pool-confirmed device-state variable, `0x20002524`), and
  Remote's real parser consuming and storing the result — at **both** the
  short (`"P1,"`) and extended (`"P11,0,0,"`) response forms, exercised
  concretely by seeding two different real device-state values rather
  than asserting one and trusting the decompile for the other. No new
  harness capability needed (first time since M3 that a transaction
  didn't need one). Found, by running it rather than by reading the
  decompile: a real "don't downgrade" guard in the Remote's parser (a
  fresh device receiving `"P1,"` does **not** update its stored state at
  all), and that the AutoPilot- and Remote-side conditions for the
  extended form (`docs/protocol/`'s existing description already named
  both) are the *same* variable by construction, not independently
  aligned. See
  [`docs/investigations/s-p-roundtrip.md`](investigations/s-p-roundtrip.md).
- **Motor-timer survey completed (roadmap M6)**: TC0/TC1/TC2/TC3 are
  IRQ107-110 (`0x607c`/`0x6098`/`0x60b4`/`0x60d0`), each clearing its own
  MC0+OVF interrupt flags then reaching a shared, table-indexed
  GPIO-pulse helper (`FUN_00005898`/`FUN_0000d388`) — a real, confirmed
  mechanism, structurally different from the already-proven TCC1 -> PB22
  case (inline toggle, no shared helper), and concretely exercised on all
  four channels via `run_concrete.py --log-mmio`. The rate-control
  mechanism fell out naturally: `FUN_00005c00`/`FUN_00006260` write/read
  each TC's `CC0` (period) with correct SYNCBUSY/RETRIGGER sequencing.
  **Honestly limited, not forced, at the time**: the real per-channel pin
  assignment depended on a RAM index byte per channel that pass found no
  static producer for — cold-RAM concrete execution gave the same pin
  (PA23) for all four channels, an artifact of uninitialized state, not a
  hardware fact, and was documented as exactly that rather than reported
  as a result. A genuine protocol-to-hardware link was found in passing:
  the event-15/`I`-command result value
  (`i32[0x20002064[channel]]`) is the *same* address as this mechanism's
  own step-position counter. See
  [`docs/investigations/motor-timer-survey.md`](investigations/motor-timer-survey.md).
- **Pin-index provenance resolved (roadmap M6)**: the per-channel
  pin-index bytes above (`0x20000164`-`0x20000167`) are not written by any
  application instruction — they are `.data`-segment initializers,
  compiled into flash and copied into RAM by `Reset_Handler`'s own
  startup copy loop (`0xcc24`-`0xcc70`), before any peripheral init runs.
  Read directly from the unmodified firmware image: **TC0 -> PB10, TC1 ->
  PA08, TC2 -> PB12, TC3 -> PA10** — a static (level-1), compiled-image
  fact, not a concrete-execution artifact, cross-validated against the
  already-proven PB22/TCC1 fact (table index 40 independently decodes to
  PB22 under the same group/pin scheme). Also ruled out, with evidence,
  as *not* the source: NVM/EEPROM-persisted config (real NVM flash-write
  helpers exist in this firmware but none reads config into this array)
  and board/runtime detection (nothing runs before the `.data` copy). See
  [`docs/investigations/pin-index-provenance.md`](investigations/pin-index-provenance.md).
- **`I<channel><mode>|` traced into the motor/timer chain, meet-in-the-
  middle (roadmap M6)**: the command handler's own `0x20001b14[channel]`
  gate conditionally calls `FUN_00005274`->`FUN_00004d18`, which writes
  `step_delta[channel]`'s direction sign — concretely validated with
  Unicorn (both branches of the gate exercised, matching the
  disassembly exactly). Independently, `FUN_00006338` (ramp/velocity
  logic) only forwards a rate update to the already-proven
  `FUN_00005ee8`->`FUN_00005c00`->`FUN_00005898` chain when that same
  gate is nonzero — the two directions of the meet-in-the-middle search
  converge on the identical byte. Also corrected the record: the
  handler's "`=5`" write is to `0x20002524[channel]`, not
  `0x20001b14[channel]` as an older static-inventory pass had it. See
  [`docs/investigations/i-command-motor-chain.md`](investigations/i-command-motor-chain.md).
- **`0x20001b14[channel]`'s producer searched exhaustively — a genuine
  negative result (roadmap M6)**: a dedicated follow-up
  ([`docs/investigations/channel-busy-gate-search.md`](investigations/channel-busy-gate-search.md))
  checked all 12 direct-reference functions, 7 one-hop candidates
  (including the two originally suspected, `FUN_00006fd8` and
  `FUN_00008e18`), the complete one-time-init boot chain, and every
  literal-referenced global packed around the byte (ruling out a
  computed-offset alias) — no setter found by any static method. Also
  confirmed the byte is `.bss` (cold value `0`, not a fixed nonzero
  startup constant, unlike the pin-index bytes) and resolved a
  decompiler artifact by disassembly along the way. Added a genuine
  Unicorn memory watchpoint (`--watch-mem-write`, new in
  `tools/unicorn/run_concrete.py`) and used it for a partial concrete
  confirmation.
- **A concrete follow-up ran past the homing timeout, then hit a
  different real dependency (roadmap M6)**: the elapsed-time source was
  diagnosed precisely (a firmware-maintained tick RAM variable, not a
  SysTick register) and resolved with a new, narrow `--fake-tick`
  capability, plus one disclosed real-GPIO-input boundary condition
  (`PORT.GROUP0.IN` bit 22 read high) and one disclosed stub (a
  `DWT->CYCCNT`-based pulse-width delay, unrelated to control flow). The
  run escaped `FUN_00006968`'s homing-timeout loop at almost exactly the
  predicted tick count, with `--watch-mem-write 0x20001b14:4` live
  throughout — then crashed on a null-pointer dereference into an
  uninitialized DMA/SERCOM-shaped peripheral driver object, touched from
  more than one call site. Root-caused, not just described: a separate
  true-`Reset_Handler` run confirms this object would have been
  constructed by `FUN_0000cdd8`'s own clock/peripheral bring-up chain,
  which is blocked by the already-documented `SYNCBUSY`-style stall in
  "Tooling gaps" below — this is a downstream symptom of that same known
  gap, not an independent new one. No write to `0x20001b14` beyond the
  already-known `.bss` clear was observed. See
  [`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md).
- **The `FUN_0000cdd8` stall resolved; the null-driver-object crash
  avoided for real (roadmap M6)**: identified all 4 of `FUN_0000cdd8`'s
  16 status polls that don't already pass under zero-behavior MMIO
  (each a real, SVD-named ready/lock bit — see "Tooling gaps"), modeled
  them with a new, explicit `--mmio-force-bits`/`--mmio-clear-bits`
  mechanism, and reran from the true `Reset_Handler`. The run now
  completes clock init, constructs the real SERCOM/DMA driver object
  (two SERCOM instances, `SERCOM5` then `SERCOM2`, each needing its own
  SWRST-clear and DRE-ready treatment) without the previous crash, and
  reaches and exits `FUN_00006968`'s real homing timeout — the primary
  acceptance target for this slice. Still no write to `0x20001b14`
  observed; reaching a directly observable main-loop state needs more
  simulated tick-time than expected, a new characterization gap (not a
  hardware-modeling one) named precisely rather than patched around. See
  [`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md).
- **The "excessive tick cost" explained: a real radio-chip-ID probe
  fails, not a timing gap (roadmap M6)**: tracing `FUN_00009464`'s real
  post-homing call graph (not assuming `FUN_00007770`/`FUN_00005d44`
  were the whole story — they turn out to be unreached) found
  `FUN_0000610c` runs *second*, right after homing: a real device
  bring-up (`FUN_00009d88`) that resets a peripheral, performs a real
  SPI transaction through the already-confirmed SERCOM/DMA driver, and
  requires register `0x42` to read back `0x12` — concretely confirmed
  (`--watch 0x9dd4`) to instead read `0` under this harness, since no
  real chip answers. On failure the firmware takes its own real,
  intentional **infinite** retry loop (print + `delay(1000ms)`,
  forever) — fully explaining the large, ever-climbing tick counts
  `reset-handler-clock-init.md` found, which are that same loop's
  per-iteration countdown, not a stuck one-time boot delay. Register
  `0x42`=`0x12` matches the well-known SX127x LoRa "RegVersion" check —
  a strong pattern match, not independently verified against this
  board's actual silicon — plausibly the same unmodeled transport
  peripheral already on record in `samd51-peripheral-mapping.md`/
  `virtual-rf-link.md`. Correctly **not faked**: a real external-device
  response is a different evidence class from the MCU's own
  self-completing status bits modeled in the prior slice. No new
  tooling needed. See
  [`docs/investigations/post-homing-radio-probe.md`](investigations/post-homing-radio-probe.md).
- **A real concrete run now reaches the real main loop, past the
  radio-ID boundary (roadmap M6)**: confirmed no software bypass exists
  for the radio-ID probe (both call sites and the probe body checked).
  Introduced the narrowest possible disclosed assumption — a new,
  explicit `run_concrete.py --force-reg ADDR:REG:HEX` flag, used exactly
  once (`--force-reg 0x9dd4:r0:0x12`, the single instruction right after
  the SPI read returns) — deliberately a different, stricter-disclosure
  mechanism than `--mmio-force-bits` (that models documented MCU
  silicon; this fabricates one external value at one program point,
  disclosed every time as harness-supplied, not observed). With it, a
  real run goes `Reset_Handler` -> real clock/peripheral init -> the
  real startup reference/input routine (the neutral term for what was
  called "homing") -> the disclosed radio-ID assumption -> real
  post-probe init -> the **real main loop, confirmed stable and
  repeating** (`FUN_00008960` hit five times, ~400,000 instructions
  total, confirming the earlier tick-cost puzzle really was entirely the
  now-resolved infinite retry loop). `0x20001b14` remains unwritten
  across genuine steady-state idle execution — confirmed concretely,
  not inferred. A second, deeper dependency (a real bulk NVM erase loop
  that doesn't visibly advance over millions of instructions, likely
  gated on a zero-valued config field rather than a documented status
  bit) was found and precisely reported, not chased, since it doesn't
  block the above. The real RX injection point for a follow-on "inject
  I/M" slice was identified concretely (a 100-byte RAM ring buffer at
  `0x2000245c`) but not used. See
  [`docs/investigations/post-probe-main-loop.md`](investigations/post-probe-main-loop.md).
- **A real `G<d><d><seq>|` command delivered end to end through the real
  RX ring, real parser, and real dispatcher (roadmap M6) — and the
  reason `0x20001b14` still doesn't move**: a new, disclosed
  `run_concrete.py --force-mem TRIGGER:MEMADDR:HEXBYTES` flag (the
  memory-range counterpart to `--force-reg`) injected a real `"G000|"`
  packet into the live RX ring right after boot reaches the main loop.
  Delivery first required diagnosing and fixing a genuine harness-timing
  artifact: the real per-byte "is data available" check re-runs a real
  SX127x-style radio IRQ-flags poll on *every* byte, costing far more
  real instructions than the existing `--fake-tick` period accounted
  for, which spuriously tripped the firmware's own real inter-byte
  assembly timeout and prevented the terminator from ever being
  recognized — fixed by raising the tick period (20 -> 300), not by
  adding a new model. Once fixed, the real dispatcher ran to completion
  and this slice found `G`'s handler also writes a previously
  undocumented `0x200025e1 = 2` arm byte a second function
  (`FUN_00007e2c`) gates on — but `0x20001b14` still didn't move.
  Tracing why found the real reason: `FUN_00007e2c` (and
  `FUN_00008e18`/`FUN_00006338`/`FUN_00008a80` — everything this project
  has ever described as "runs every main-loop iteration") is **not
  reachable from a cold boot at all**, because it lives inside
  `FUN_000093fc`, which is only called after `FUN_00009464` returns — and
  `FUN_00009464` contains its own internal loop (the *real*,
  currently-permanent main loop, confirmed concretely to never exit in
  any run this slice performed) with exactly one real exit, gated on a
  byte (`0x20000060`) this slice traced, via an exhaustive whole-firmware
  literal-pool scan, to exactly one writer: **`MC4<...>|`** (motor
  configuration, all four channels — never the per-channel `MC<0-3>`
  form). Concretely confirming the `MC4` unlock hit a second, distinct
  per-byte timing dependency (not yet characterized) and was not chased
  further, per the task's explicit anti-fuzzing scope. See
  [`docs/investigations/g-command-motor-subsystem-unlock.md`](investigations/g-command-motor-subsystem-unlock.md).
- **`MC4` concretely confirmed as the real cold-boot-to-motor-subsystem
  transition; `FUN_00006fd8` (real "commit a move") fires for the first
  time in this project (roadmap M6)**: static characterization first —
  `MC4`'s handler (`FUN_00008258` at `0x86f0`, calling `FUN_00007a98` x4)
  writes four per-channel fields, of which only the 4th is genuinely
  consumed by the locked subsystem (`FUN_00007e2c`/`FUN_00008e18`, via
  exhaustive literal-pool xref), then writes `0x20000060=0` — the sole
  unlock, confirmed by a from-scratch exhaustive scan. Delivering a real
  36-byte `MC4` frame hit a second, now precisely diagnosed, per-byte
  timing dependency: `FUN_00008960`'s inter-byte timeout is measured
  *cumulatively from packet start*, not per byte, so a longer frame needs
  a proportionally larger `--fake-tick` period (300 -> 2000, sized from a
  direct ~5,696-instruction-per-byte measurement, not guessed). With that
  fix, `MC4` alone concretely unlocks `FUN_000093fc` (confirmed: `0x8714`
  -> `FUN_00009464` returns -> `FUN_000093fc`/`FUN_00007e2c`/`FUN_00008e18`
  all reached repeatedly). Sending `G` and `MC4` in the same buffer found
  a real "flush stale bytes while busy" firmware behavior that silently
  drops the second command — fixed by sequencing a second `--force-mem`
  injection at `FUN_00009464`'s own one-time return instruction. With
  `MC4` then `G` properly sequenced, `G`'s `0x200025e1=2` arm — confirmed
  independent of `MC4` by both xref and control flow — lets
  `FUN_00007e2c` reach **`FUN_00006fd8`, the real motor move-commit
  function, for the first time ever observed in this project**
  (register-captured: `channel=0, distance=0, rate=0x121fa`). Still no
  write to `0x20001b14`: with `distance=0`, `FUN_00006fd8`'s own code
  takes its documented "8 units or fewer, no real move" branch — a
  concrete, register-level explanation, not an open question. See
  [`docs/investigations/mc4-transition.md`](investigations/mc4-transition.md).
- **Traced the motor target/position config to a real, blank compiled-in
  default-configuration blob — a genuine external-data boundary, not a
  missing mechanism (roadmap M6)**: `FUN_00004b64` bulk-loads the
  `0x20001b40` per-channel struct from a lazily-initialized RAM buffer
  (`FUN_00009724`), itself sourced from a plain flash-address read (no
  driver/peripheral indirection — confirmed by register capture,
  `src=0x00012000`) — and that exact flash address is, in this firmware
  image, **entirely `0x00`** (confirmed by reading the raw `.bin` file
  directly, the strongest possible evidence tier). The loader's own real
  fallback (fully disassembled, including a genuine ARM void-return
  subtlety the decompiled pseudo-C got wrong) then fills the struct with
  `0xFF`; a separate, one-shot, `.data`-driven resync
  (`FUN_00004b24`) immediately overwrites each channel's mode-0 target
  with that channel's own live position (`0x20002064[channel]`, cold-
  zero) — a real "no move commanded yet" default. Exhaustively trying
  every `G` "type" digit (`0`-`9`) after a real `MC4` gives exactly two
  concrete, register-captured outcomes — `distance=0` (mode 0) or
  `distance=-1` (modes 1-9) — neither of which crosses `FUN_00006fd8`'s
  `8`-unit real-move threshold. This is the same evidence class as the
  unanswered radio-ID chip in `post-homing-radio-probe.md`: a real
  external-data/provisioning gap, not something this harness can close
  without fabricating motor-position data. See
  [`docs/investigations/target-config-provenance.md`](investigations/target-config-provenance.md).
- **`LL1`/`LL2` characterized fully and exercised concretely — a second,
  independent confirmation of the same provisioning gap (roadmap M6)**:
  `LL1`/`LL2` reach a shared "L-family" handler (`FUN_000054e0`,
  disassembly-corrected after an initially misleading decompile) via the
  top-level `'L'` dispatch branch, reachable pre-`MC4`. `LL1`
  unconditionally clears two fixed globals plus a validity flag; `LL2`
  compares and reorders them, setting the validity flag only if they
  differ. Neither touches live position (`0x20002064`), the target/
  config struct (`0x20001b40`), `0x20001b14`, or any timer/rate state —
  confirmed both by disassembly and by a real `--watch-mem-write` run.
  **No GPIO or MMIO dependency at all** — pure RAM bookkeeping. An
  exhaustive literal-pool scan (the same method used for `0x20001b14`/
  `0x20000060`) found **no other code anywhere in the firmware writes
  either of `LL`'s two globals with a real value** — a second genuine
  negative result. Delivering `LL1` then `LL2` concretely hit a real,
  non-timing framing behavior (the receive routine drains and discards
  any bytes immediately available right after a `'|'` terminator, unless
  one is literal `'O'`) — fixed by sequencing the second command's
  injection after the first's dispatch returns, the same technique
  `mc4-transition.md` used for `G` after `MC4`. Concretely confirmed:
  with only `LL1`'s cleared (zero) state feeding it, `LL2` takes its own
  documented "values are equal, no-op" branch. See
  [`docs/investigations/ll-limit-workflow.md`](investigations/ll-limit-workflow.md).
- **Bounded standard-library/toolchain provenance classification pass
  (roadmap M6)**: fetched the exact evidenced toolchain source
  (Adafruit `ArduinoCore-samd` git tag `1.7.11`, named directly by
  embedded build-path strings in `docs/firmware/firmware-layout.md`) and
  structurally matched it against functions this project keeps
  re-deriving. Confirmed: `Reset_Handler`, the shared default-handler
  stub, `SysTick_Handler`, `millis()`, and — a new finding —
  **`FUN_0000cd90` is `main()`, `FUN_00009464` is the AutoPilot sketch's
  real `setup()` (with its own internal, permanent loop that only
  returns once `MC4` clears `0x20000060`), and `FUN_000093fc` is the
  sketch's real `loop()`** — the exact Arduino-idiom names for what
  `g-command-motor-subsystem-unlock.md`/`mc4-transition.md` already
  characterized behaviorally. Also classified (at LIKELY-STANDARD or
  LIKELY-THIRD-PARTY tiers, honestly, where a byte-for-byte match wasn't
  practical): SERCOM SPI reset, SPI transceive, the `digitalWrite`-shaped
  GPIO pulse helper, `memcpy`/`memset`, a `libgcc`-shaped 64-bit
  arithmetic cluster, an SX127x-register-map-matched radio driver
  cluster, and a vtable-call-shaped LCD status function. Recorded in a
  new, reusable CSV
  ([`research/provenance/function_classification.csv`](../research/provenance/function_classification.csv))
  and applied back into the Ghidra pipeline as a small, optional,
  tested post-script
  (`tools/ghidra/scripts/APTraceApplyProvenance.java`, 42 functions
  renamed concretely against the real firmware image). **Sharpened the
  `0x12000` question**: every decision-making function in the read chain
  is confirmed `CUSTOM_APPLICATION` built on a standard `memcpy` — and,
  while checking for other references to the same flash address, found
  a **real, previously unexamined write path**
  (`FUN_0000449c`->`FUN_000097a4`->NVM erase/write, reached from a
  channel-0 move-completion handler) that this project hadn't
  encountered before. Not exercised concretely, and the "dirty" flag
  that gates the save was not traced to its setter — a precise pointer
  for the next persistence slice. See
  [`docs/investigations/standard-library-provenance.md`](investigations/standard-library-provenance.md).
- **The `0x1002` dirty flag traced to its exact address, sole setter,
  and a real protocol-reachable writer — `0x12000` is confirmed
  firmware-owned persistent storage, not external provisioning (roadmap
  M6)**: the dirty byte is `0x20004147` (`0x20003145` buffer base +
  `0x1002`) — found only by a full-image disassembly scan for the
  16-bit immediate `#0x1002` in a `movw` instruction, since the offset
  exceeds Thumb-2's encodable immediate range and never appears in the
  flash literal pool (an ordinary xref search would have missed it
  entirely). **`FUN_0000977c`, a single shared "write one config byte,
  only if it actually changed" accessor, is the sole setter** — real
  change-detection (`cmp`+`itttt ne`), not a channel- or event-specific
  trigger. A previously undocumented ASCII command, **`D<value>|`**,
  writes through this exact accessor (a 32-bit value at logical offset
  `0x15`, then a `0xDE` marker at `0x19`, read back at boot by
  `FUN_00004c20`) — a real, protocol-native way to dirty the buffer,
  not delivered concretely this pass. `FUN_000097a4` (the save-if-dirty
  path `FUN_0000449c` calls) never clears the flag after saving; only
  `FUN_000097f4` does, and it has **no confirmed caller anywhere in the
  image** (checked via both the calls graph and a full-image
  branch-target scan) — left as a genuine open question, not guessed.
  The save trigger's channel-0 association is confirmed to come from a
  real, already-documented TC0-ISR asymmetry (`channel-busy-gate-
  search.md`), not a new per-channel design; the dirty flag and buffer
  themselves are global across all four channels. See
  [`docs/investigations/dirty-flag-persistence.md`](investigations/dirty-flag-persistence.md).
- **A real `D<value>,|` command delivered concretely through the live RX
  path, tracing dirty -> save -> real NVM erase call, using only the
  already-disclosed PA22 assumption (roadmap M6)**: found, concretely,
  that `D` needs a trailing comma before `|` to parse cleanly (a bare
  `D<value>|` dispatches but its field parser runs past the packet into
  adjacent memory, since its only real terminator is a literal comma —
  a real protocol fact, not a harness artifact). With `D1234,|`, the
  real value (`1234`) and marker (`0xDE`) land exactly where
  `dirty-flag-persistence.md` predicted. Running the boot further (no
  new commands, no seeding) found the real save path
  (`FUN_00005dd0`->`FUN_0000449c`->`FUN_000097a4`) fires **naturally**:
  `FUN_0000d3dc(1)` (a real `digitalRead()`-shaped call) reads `PA22`
  (`PORT.GROUP0.IN` bit 22) — **the exact same GPIO signal this project
  has disclosed and carried forward since `systick-tick-injection.md`**,
  not a new assumption. The resulting real erase call
  (`FUN_000098f0(obj=0x20004148, dest=0x00012000, len=0x1001)`) uses the
  identical destination and length the `0x12000` read path consumes —
  concretely confirming, by register capture, that the write path
  targets the same flash region. It then stalls forever: the driver
  object's own page-size field (`0x20004148+0xc`) reads `0`, the same
  class of gap `post-probe-main-loop.md` already found and didn't chase,
  now reconfirmed with real arguments in this exact context. No flash
  byte at `0x12000` was actually written this pass, so the reboot/
  recovery half of the round trip wasn't reached. Also found, in the
  process: `FUN_00004c20`'s own "clamp an out-of-range setting to a
  default" boot logic dirties the buffer on every cold boot with blank
  config — a real, previously-unenumerated producer, added to the dirty-
  flag producer list. See
  [`docs/investigations/d-command-persistence-roundtrip.md`](investigations/d-command-persistence-roundtrip.md).
- **The zero-page-size stall resolved — a real hardware register, not a
  missed firmware step; the full `D` round trip now completes, byte-for-
  byte (roadmap M6)**: the driver object's `+0xc` field is computed fresh
  before every save by `FUN_0000981c` — previously mis-filed as opaque
  "NVM plumbing" — which reads `NVMCTRL.PARAM` (`0x41004008`, confirmed
  via this project's own vendored SVD), extracts `PSZ` via the exact same
  mask/shift the SVD's own field layout implies, and looks up the real
  byte-size through a flash-resident table at `0x14000` that — read
  directly from the firmware image — matches the SVD's `PSZ` enumeration
  exactly (`[8,16,32,64,128,256,512,1024]`). The harness's zero-behavior
  MMIO model returns `0` for this real, read-only register, so the field
  computed to `0`. **Resolved as Option B**: modeled the one real,
  documented value this exact, physically-confirmed part (ATSAMD51J19A,
  512KB flash) guarantees — `PSZ=6` (512-byte pages) with `NVMP=0x400`
  (1024 pages, a direct consequence of the already-confirmed flash size)
  — via `--mmio-force-bits 0x41004008:0x00060400`, the same established
  mechanism as every other MCU-completion-bit fix in this project, no new
  tooling. A second stall, on `NVMCTRL.INTFLAG.DONE`, was the *same*
  already-known bit `post-probe-main-loop.md` modeled for a different NVM
  call — simply missing from this specific recipe. With both in place,
  the real erase (`FUN_000098f0`->`FUN_000098d8`) and real write
  (`FUN_0000984c`) both execute, and dumping flash `0x12000` directly from
  Unicorn's own memory confirms the exact bytes `D1234,|`'s value (`1234`)
  and marker (`0xDE`) landed, byte-for-byte matching the RAM buffer at
  save time. A disclosed harness step (patching a copy of the firmware
  image with those real, Unicorn-produced bytes, standing in for a power
  cycle Unicorn cannot otherwise model) then let a genuinely fresh boot —
  **zero commands injected** — reach `FUN_00004c20`'s real load path and
  recover `r0=0x000004d2=1234` exactly. **This closes the `0x12000`
  persistence investigation's core round trip**: real command -> real
  dirty -> real save -> real flash mutation -> real reboot recovery, all
  concretely demonstrated. See
  [`docs/investigations/nvm-param-and-full-roundtrip.md`](investigations/nvm-param-and-full-roundtrip.md).
- **The persistent-record <-> motor-target mapping closed, and the real,
  protocol-reachable producer `target-config-provenance.md` asked for is
  found: a previously undocumented `'+'` command (roadmap M6)**:
  `FUN_00004b64`'s already-known bulk load (persisted logical offsets
  `500`-`1651` -> the whole 4-channel `0x20001b40` struct) has a real
  write-back counterpart, **`FUN_000043f0`**, found by pulling every
  caller of the shared config-write accessor from the Ghidra call graph
  rather than searching for one specific offset. Its only caller is a
  real ASCII command, **`'+'`**, reached via a tail-jumped region
  (`0x806c`) `FUN_00008258`'s decompile silently follows — the same
  class of correction this project has made before. Full disassembly,
  with every address resolved directly against the compiled image (not
  guessed from decompiler naming), shows `'+'`'s mode`>50` branch calls
  **`FUN_00004ca8`** (chains `target = start + delta` across a channel's
  mode sub-records — the multi-record generalization of `FUN_00004b24`'s
  already-known single-record version) and **`FUN_000046c8`/
  `FUN_00004910`** (two unit-family variants that copy a **wire-supplied,
  unclamped signed delta** straight from the packet into the exact
  struct field `FUN_00007cc0`'s `G`-command target lookup reads for mode
  `1`), then `FUN_000043f0` persists the result. Arithmetically, this
  means a real `'+'` write followed by a real `G<channel>1<seq>|` should
  compute `distance = wire_delta` — a complete, disassembly-grounded
  answer to why `FUN_00006fd8` is designed to receive a real distance
  `> 8`. **Concrete confirmation was attempted and is incomplete**: two
  real, fixable gaps were found along the way (the disclosed `PA22` GPIO
  seed conflicting with `FUN_00005dd0`'s own already-documented
  hold-triggers-a-real-intentional-halt path once a run continues far
  enough into the main loop; a `SERCOM` `SYNCBUSY`/`INTFLAG` bit-breadth
  gap for a real, `CONFIRMED_ADAFRUIT_CORE` `SPIClass` construction not
  previously exercised), both fixed, but even so, reaching `'+'`'s own
  dispatch from a fresh boot now costs far more instructions than any
  previous single-command injection in this project — real, finite
  (not looping) `SERCOM` device-probe activity this session's boot
  recipe doesn't yet budget for, precisely named but not yet
  characterized or resolved. See
  [`docs/investigations/persistent-record-motor-target-mapping.md`](investigations/persistent-record-motor-target-mapping.md).
- **`'+'` traced backward through the Remote firmware — confirmed
  Remote-generated, with a real UI caller and a probable user-guide
  mapping (roadmap M6)**: a full-image disassembly scan for the literal
  `'+'` (0x2b) byte, checked against every caller of the shared TX
  wrapper and its numeric-field encoder, found exactly one real sender:
  **`FUN_000049c4`**, which builds the identical wire frame this
  project's AutoPilot-side analysis reconstructed field for field
  (confirm1/confirm2/channel/mode/records), including the
  `confirm1 == confirm2` invariant and the same `+0xc`/`+0x10`
  delta-computation convention as the AutoPilot side — strong,
  independent cross-confirmation, not merely internal consistency.
  **Confirmed UI caller**: the Auto-Mode configuration screen state
  machine (`FUN_0000e670`), three call sites each gated behind a real
  user confirmation wait (`FUN_0000cd70`); a fourth context, a bulk
  "push all channels' stored config" path inside the already-known
  `'S'` handler (`FUN_0000c440`), fires on reconnect/status-refresh
  rather than interactive UI. Correlating the Remote's own embedded
  strings (`"TEST A-B"`/`"TEST B-C"`/`"TEST C-D"`, `"DURATION"`,
  `"to rec C"`/`"to rec D"`, `"NO MOVEMENT"`) against the user manual's
  Auto Mode section (A/B/C/D points, duration/ramp/delay/loop segment
  parameters, persisted after power-off) gives a **probable** — not
  byte-exact-proven — mapping: `'+'` is sent when the user confirms/
  saves a programmed Auto Mode move segment. Ruled out: `'+'` is not
  host/service/internal-only — a real Remote sender exists. See
  [`docs/investigations/plus-command-remote-provenance.md`](investigations/plus-command-remote-provenance.md).
- **A full, concrete, end-to-end `'+'` -> motor-target -> `G` mode-1 ->
  `FUN_00006fd8` distance round trip, closed with a new reusable
  regression fixture (roadmap M6)**: `tools/unicorn/virtual_link.py
  plus` demonstrates, entirely with real, unmodified firmware code: the
  Remote's real `'+'` builder (`FUN_000049c4`, reproducing the `'S'`-
  handler's real bulk config-push call exactly — `confirm1=confirm2=1`,
  `param_4=0`, `mode=0x62`, the one mode value confirmed to cross
  AutoPilot's compute+persist threshold) produces `"+1,1,1,0,98,1,0,0,0,
  500,0,0|"`; AutoPilot's real handler computes and persists
  `target=500`; the Remote's real `G`-request builder (`0xb680`)
  produces `"G010|"` (channel 0, type 1); AutoPilot's real state machine
  (`FUN_00007e2c`, entered twice — once per real internal state
  transition) resolves that same `target=500` and calls
  `FUN_00006fd8(channel=0, distance=500, ...)`; `FUN_00006fd8`'s own
  real `>8` threshold check fires (move-committed flag observed = `1`),
  not the documented `<=8` no-op `mc4-transition.md` found with
  `distance=0`. **`500` is the same number throughout** — the Remote's
  own computed value, never hand-patched into AutoPilot's motor-target
  RAM. Two disclosed, narrowly-scoped harness boundaries make this
  possible without a full boot (avoiding the unresolved `SERCOM`/radio
  stall `persistent-record-motor-target-mapping.md` hit): a
  representative "already-recorded A->B segment" seed on the Remote's
  own local mirror struct, and directly seeding `FUN_00007e2c`'s own arm
  byte to the exact value (`2`) a real `G` dispatch is independently
  confirmed (by disassembly) to set — bypassing the real MC4-unlocked
  main loop this state machine is normally driven from, without
  fabricating the distance value itself, which is computed entirely
  from the real `'+'`-written struct state. This specific scenario's
  own trigger is confirmed to be the `'S'`-handler's bulk resync path,
  not the interactive Auto-Mode segment-confirm screens (which use mode
  values that don't cross the persist threshold) — the manual/UI label
  for *that* interactive action remains **PROBABLE**, unchanged from
  the prior slice. The phase-machine/timer/ISR/GPIO continuation for
  this distance value was not re-verified this pass — it relies on the
  already independently concretely-proven mechanism from
  `motor-timer-survey.md`/`i-command-motor-chain.md`. See
  [`docs/investigations/plus-target-distance-roundtrip.md`](investigations/plus-target-distance-roundtrip.md).
- **Toolchain cleanup: a persistent Ghidra project cache, a reusable
  Unicorn library, and a proper direct-function-call helper (not a
  firmware-behavior finding)**: `tools/ghidra/aptrace_ghidra.py` builds
  a per-firmware Ghidra project once (cache-identity-checked against
  firmware SHA-256/load base/language/Ghidra version/analysis version,
  never silently reused if stale) and answers later `decompile`/`disasm`
  queries by reopening it (`-process -noanalysis`, skipping re-analysis)
  or, for `callers`/`xrefs`/`containing`/`symbol`, from a cached export
  with no Ghidra invocation at all. `tools/unicorn/concrete.py` extracts
  `run_concrete.py`'s Unicorn setup/hook/snapshot logic into a reusable
  `ConcreteMachine` class; `virtual_link.py` now builds one machine per
  firmware and reuses it across every scenario leg (all four scenarios
  together run in ~0.1s, down from several seconds of subprocess-spawn
  overhead) instead of a fresh subprocess per call. New capabilities:
  `ConcreteMachine.call` (a real ARM-AAPCS direct-function-call helper —
  correct stack-argument placement, a real trampoline return address,
  a genuine clean-return signal, replacing hand-picked SP/LR values and
  inferring success from where a fabricated return crashed);
  `dump_reg_pointee` (dereference a register in the same run that
  reaches it, eliminating a real two-run pattern `capture_tx_bytes` used
  to need); structured failure snapshots (a failed run is never
  discarded — the full `RunResult`, including a bounded always-on
  `recent_pcs` ring buffer, is available without a second manual rerun);
  and `RunResult.carry` (explicit, visibly-tagged state transfer between
  runs, replacing manual hex round-tripping). Also fixed a real CLI
  ambiguity this same cleanup effort surfaced: `--reg`/`--arg`/length
  values now parse as `int(value, 0)` (`28` decimal, `0x28` hex) instead
  of always-hex — the direct fix for the exact bug that produced a false
  investigative path in `plus-target-distance-roundtrip.md` (`--reg
  r0=28` meant as decimal, silently read as hex `0x28`=40). **No
  firmware-behavior conclusion changed** — `tools/doctor.sh` and
  `virtual_link.py all`/`plus` both still pass, byte-identical results;
  two new regression scripts
  (`tools/unicorn/test_concrete.py`, `tools/ghidra/test_aptrace_ghidra.py`)
  cover the new mechanics. See
  [`docs/investigations/toolchain-cleanup.md`](investigations/toolchain-cleanup.md).
- **Toolchain cleanup hardening pass (not a firmware-behavior finding)**:
  the reuse the cleanup above introduced (one `ConcreteMachine`/one
  persistent Ghidra project reused across many calls) was checked against
  the exact isolation guarantee it replaced (a fresh subprocess/fresh
  Ghidra import per call) and two real gaps were found and fixed, plus two
  smaller ambiguities. **(1)** `fresh=True` now restores *every* mapped
  mutable region between runs — RAM, flash, the MMIO window, and the PPB —
  not just RAM/registers, via page-granularity dirty tracking (not a
  blind re-zero); this also required explicitly marking every direct
  harness-side memory write (`seed_mem`, `--fake-tick`, `--force-mem`,
  `--mmio-force-bits`/`--mmio-clear-bits`) as dirty, since Unicorn's
  write hook only ever fires for the CPU's own executed stores. **(2)**
  `ConcreteMachine.call()`'s return trampoline moved to a dedicated
  harness-only page entirely outside real device RAM (it had been carved
  out of the top of real RAM, which silently lowered an ordinary
  `run()`'s default SP below the real SAMD51 RAM top and left harness
  bytes inside what should be pristine real RAM). **(3)** the Ghidra
  cache's identity now hashes the actual content of every build-time
  script and provenance TSV, so an ordinary edit to one of them
  invalidates the cache automatically rather than depending on a human
  remembering to bump `ANALYSIS_VERSION`. **(4)** `RunResult.success` (an
  ambiguous "no Unicorn exception" flag that could make an
  instruction-limit result look like a properly reached stop) was split
  into explicit `error_free`/`completed` properties. Also: `virtual_link
  .py`'s failure paths now attach the full structured snapshot to the
  exception they raise, and a new regression test runs all four
  `virtual_link.py` scenarios in two different orders against the same
  reused machine cache to confirm scenario order doesn't change results —
  exactly the class of bug a fresh-subprocess-per-call model could never
  have had. **No firmware-behavior conclusion changed** — `tools/doctor
  .sh`, `virtual_link.py all`/`plus`, `test_concrete.py`, and
  `test_aptrace_ghidra.py` all still pass, byte-identical results. See
  [`docs/investigations/toolchain-cleanup.md`](investigations/toolchain-cleanup.md)'s
  "Hardening pass" section for the full detail, including two real
  Unicorn/ARMv7-M gotchas found while fixing this (implicit Execute-Never
  on Device-type memory; `UC_HOOK_MEM_WRITE` not firing for direct
  `mem_write()` API calls).
- **A user-guide-driven workflow/state model, layered on top of the
  existing flat command inventory (not a new firmware-behavior slice)**:
  [`docs/ui/user-guide-workflows.md`](ui/user-guide-workflows.md)
  reconstructs the major user-visible workflows (power-on, Quick Setup,
  Manual Mode, Auto Mode's record/test/execute cycle, limit-setting,
  persistence, RF/settings, firmware update) from
  [`docs/hardware/autopilot-research-handoff.md`](hardware/autopilot-research-handoff.md)'s
  existing user-manual summary, cross-referenced against the Remote
  firmware's own 211 embedded UI strings — with the two source types kept
  explicitly separate (`[user manual]` vs. `[firmware string]` tags), since
  a string existing in the image does not by itself prove which workflow
  step displays it. [`docs/ui/action-command-map.md`](ui/action-command-map.md)
  overlays every command this project has characterized (`&`, `G`, `S`,
  `!`, `I`, `D`, `'+'`, `MC0`-`MC4`, `LL1`/`LL2`) onto that skeleton, with
  an explicit CONFIRMED/HIGH/PROBABLE/UNKNOWN scale kept separate from the
  firmware-evidence-level scale already in use elsewhere — a command being
  concretely CONFIRMED does not make its user-guide label CONFIRMED. The
  single most important correction this pass makes explicit (from
  evidence this project already had, just never stated this plainly
  before): **the interactive Auto-Mode `'+'` confirm screens
  (`FUN_0000e670`, modes `0`/`0x14`) and the mechanism that actually arms
  a drivable motor target are not the same event** — only the separate
  `'S'`-handler bulk config-push call (mode `0x62`) crosses AutoPilot's
  `>50` compute+persist threshold; a naive "user confirms a segment ->
  it becomes drivable" reading of the existing investigation docs would
  be wrong. Also surfaced, for the first time, as a genuine gap rather
  than an unasked question: `MC4`/`MC<0-3>`/`LL1`/`LL2` have **zero**
  confirmed Remote-side sender or UI-input evidence, despite `MC4` being
  the sole instruction anywhere in the image that ends the boot-phase
  loop — every prior command-by-command investigation characterized these
  from the AutoPilot side only, and framing the work as "one command at a
  time" never surfaced that the Remote-side half was still completely
  open. `docs/protocol/command-inventory.md` now links back to both new
  documents. A bounded follow-up disassembly-plus-concrete-execution pass
  into `FUN_0000e670`'s own `'+'` call sites found there are **four**, not
  three (screen 5 has two mutually-exclusive sites, identical arguments,
  collapsed into one by an earlier decompile-only reading) and closed the
  full evidence chain — displayed string -> input gesture -> state
  transition -> exact `'+'` wire bytes — for the two screen-5 sites for
  the first time in this project: the point-recording dialog shows
  exactly `"Click"` / `"to rec A"`-`"to rec D"` (segment-dependent) /
  `"Long-click to end"`, and a short jog-wheel click (not a long one) is
  the exact, disassembly-confirmed gesture that writes the recorded
  point. The other two sites (screens 9/10) are confirmed to render
  `"RUNNING"` after the send but their pre-send highlighted-row label
  remains PROBABLE, one row-arithmetic extrapolation short of proof — see
  [`docs/ui/action-command-map.md`](ui/action-command-map.md)'s Part 3
  for the full chain and exactly what's still missing. No firmware-
  behavior conclusion from any prior slice was revisited or changed by
  this pass — it is a reorganization and gap analysis of already-
  established evidence, plus this one bounded new disassembly pass.
- **`MC0`-`MC4` Remote-side provenance closed — a single sender, two
  distinct real UI actions, and a genuine surprise about how Quick Setup
  even starts**: a single Remote function, `FUN_00005a8c`, builds every
  `"MC"` frame in the image — confirmed the sole such builder by four
  independent full-image scans (not just a literal-string search, since
  `"MC"` is never stored as a contiguous literal), with exactly three
  call sites confirmed two independent ways (the Ghidra call graph and a
  from-scratch decode of every `BL`/`BLX` in the image). **`MC<0-3>`** is
  sent from the Remote's motor-settings numeric-row editor
  (`FUN_00010698`) every time the user clicks out of an edited
  `"CURRENT (mA)"`/`"STEPS/S MAX"`/`"MICRO-STEPPING"`/`"RETURN SPEED"`
  row — not once per motor, and not tied to finishing a motor's setup.
  **`MC4`** has two real call sites: the already-known `'S'`-handler bulk
  push, and a newly-found one (`FUN_00010258`) fired when the user clicks
  the Remote's one and only `"Continue"` string, on the
  `"Motor <N>: Choose type"` screen, once all four motors have an
  assigned type. Both `MC<0-3>` and this `MC4` site close the full
  evidence chain — displayed string -> input gesture -> state -> sender
  -> exact wire bytes — confirmed both statically and concretely,
  including reconfirming the AutoPilot's already-known `setup()`-unlock
  effect using a **Remote-produced**, not AutoPilot-side-fabricated,
  `MC4` frame for the first time in this project. Also found: `MC` frames
  are sent three times each with **no acknowledgement wait** — mechanically
  different from `'+'`'s request/ack pattern, and worth remembering for
  any future harness work. The genuine surprise: **Quick Setup is opened
  by the AutoPilot, not by any Remote menu action** — the Remote's own
  Quick-Setup-in-progress flag has exactly one writer, and it's the
  Remote's *inbound* radio-command handler, reacting to a real,
  disassembly-confirmed AutoPilot-built `MT<b0><b1><b2><b3><x>|` frame
  encoding four live GPIO motor-connector presence probes. No Remote-side
  menu entry point into Quick Setup exists. The AutoPilot-side function
  that decides when to send `MT` was not identified this slice — a
  precisely-named remaining gap, not guessed at. See
  [`docs/investigations/mc-command-remote-provenance.md`](investigations/mc-command-remote-provenance.md).

## Corrected assumptions

- **The `I` handler's "`=5`" write targets `0x20002524[channel]`, not
  `0x20001b14[channel]`.** `research/autopilot_static_inventory/synchronous-responses.md`'s
  original static-inventory pass conflated two distinct, adjacent-in-role
  per-channel byte arrays. Disassembly of the real handler
  (`0x872e`-`0x877c`) shows `0x20001b14[channel]` is only ever *read*
  there (as a gate on calling `FUN_00005274`); the literal `5` is stored
  to `0x20002524[channel]`, a separate flag also written by
  `FUN_00006fd8` (`=1`, on committing a real move) and an unnamed
  periodic poller (`=2`). See
  [`docs/investigations/i-command-motor-chain.md`](investigations/i-command-motor-chain.md).
- **The `0x827e`-`0x82c4` loop is not on the ASCII-command path at all —
  it's gated on `buffer[0]==0xF0`.** Two earlier passes (Ghidra-based
  decompilation, then a first symbolic-execution pass) both examined this
  loop under the assumption that it runs first for *every* packet,
  including `&`. Concrete execution found the dispatcher's actual first
  decision, at `0x8258`-`0x8266`, is `cmp buffer[0],#0xF0; bne <skip the
  loop>` — the loop is v0.1's own "binary motor/control frame" path
  (`0xF0`/`0xE0`), and ASCII commands branch straight past it into the
  character-comparison chain instead. **The loop is never entered for the
  `&` command the current milestone is about.** This supersedes the
  "flat parser chain" correction below it and the memory-side-effect
  blocker hypothesis that followed from it. See
  [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md)
  and [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **The "flat parser chain" model of `0x8258` is not fully trusted** (background,
  now refined by the point above). The original static pass modeled the
  dispatcher as a simple if/else-if scan over the packet's leading byte;
  the real shape is a `buffer[0]` gate into either the binary-frame loop or
  the ASCII chain. See
  [`docs/investigations/parser-dispatch.md`](investigations/parser-dispatch.md).
- **Macaw vs. Ghidra disagreement at `0x801c`, resolved.** Macaw lifted this
  address (on the path that sets up the dispatcher's R0 argument) as
  ARM/A32-mode code — architecturally impossible on Cortex-M4F. Ghidra's
  Thumb-only Cortex-M language (incapable of decoding A32 at all) instead
  decoded it as an ordinary, well-formed, 8-times-called Thumb function.
  **Conclusion: the A32 lift was a Macaw/dismantle decode limitation, not
  dead code.** R0's exact value at the dispatcher call site was
  subsequently pinned down directly via Unicorn: **R0 = 0**, traced to
  `*(byte*)0x20001fd4` at the real call site, a byte never written before
  that point from cold RAM. See
  [`docs/tooling/tool-selection.md`](tooling/tool-selection.md#tool-disagreements-investigate-dont-default),
  [`docs/investigations/trigger-input.md`](investigations/trigger-input.md),
  and [`docs/investigations/dispatcher-loop-concrete-trace.md`](investigations/dispatcher-loop-concrete-trace.md).
- **`FUN_000093fc` (and the motor-phase/ramp/monitor code it calls) is not
  reachable from a cold boot at all, without a prior `MC4` command.**
  `i-command-motor-chain.md`, `channel-busy-gate-search.md`, and
  `post-probe-main-loop.md` all describe `FUN_00006338`/`FUN_00007e2c`/
  `FUN_00008e18`/`FUN_00008a80` as running "every main-loop iteration" —
  an accurate reading of `FUN_000093fc`'s static structure, but this was
  never concretely confirmed as *reachable* until this slice tried and
  found the real, currently-running main loop is actually
  `FUN_00009464`'s own internal loop, which calls only
  `FUN_00008960`/`FUN_00005dd0` and does not return under any condition
  exercised so far. Those docs are not rewritten retroactively (their own
  static findings still stand); this is the corrected, concretely-checked
  reachability picture. See
  [`docs/investigations/g-command-motor-subsystem-unlock.md`](investigations/g-command-motor-subsystem-unlock.md).

## Tooling gaps

**Resolved: `FUN_0000cdd8`'s clock/peripheral-init chain now runs to
completion under Unicorn.** Previously stalled indefinitely (confirmed
in
[`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md)
at `pc=0xcde8`), root-caused and fixed in
[`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md):
of 16 status-register polls in the function, exactly 4 don't already
pass under the zero-behavior MMIO model (`OSC32KCTRL.STATUS.XOSC32KRDY`,
`OSCCTRL.STATUS.DFLLRDY`, `OSCCTRL.DPLL0/DPLL1.DPLLSTATUS.{LOCK,CLKRDY}`
— all real, SVD-identified, predictably-completing bits on hardware
already confirmed to boot), now satisfied via a new, explicit
`run_concrete.py --mmio-force-bits`/`--mmio-clear-bits` mechanism (never
a general peripheral model — each address is named and justified
individually). A real, unmodified concrete run now goes
`Reset_Handler` -> `FUN_0000cdd8` (complete) -> the real SERCOM/DMA
driver constructor (also completes, resolving the downstream
null-pointer crash `systick-tick-injection.md` found) -> real homing,
confirmed via `--watch` hits at the same exit point found from the
routed-around entry point. **Not fully resolved**: continuing past
homing to a directly observable main-loop state (`FUN_00008960`) needs
far more simulated tick-time than initially expected — a newly
identified characterization gap (not a missing-MMIO-behavior one), see
that doc's "next step."

**Not a firmware blocker — a known, documented, and deliberately unfixed
harness limitation.** A whole-function Crucible replay of the `&`-command
dispatcher gets stuck in the `0x827e` loop, taking the wrong branch at
`0x8266` despite `buffer[0]` being concretely `0x26`. This was fully
investigated and explained (not left as an open mystery):

- The `0x8266` branch itself, Macaw's lift of it, and `mkFunCFG`'s entry/
  branch-CFG wiring are all confirmed correct — isolating the exact block
  in Crucible (existing single-block machinery, extended with a small
  `bqMemoryBytes` addition to seed the buffer content) reproduces the
  correct, deterministic result for both `buffer[0]=0x26` and the `0xF0`
  control case. See
  [`docs/investigations/gate-block-crucible-isolation.md`](investigations/gate-block-crucible-isolation.md).
- **Root cause**: the dispatcher's buffer pointer is loaded from a literal
  pool in flash, and flash is `readonly` — `populateSegmentChunk` always
  populates readonly memory via solver assumptions, never as folded array
  literals, regardless of `ConcreteMutable`/`SymbolicMutable`. That's fine
  for a solver query, but plain Crucible execution has no solver in the
  loop for an ordinary `Br`, so the branch condition never folds to a
  concrete `Pred` and Crucible picks the wrong side. See
  [`docs/investigations/whole-function-trace-divergence.md`](investigations/whole-function-trace-divergence.md)
  and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md#known-limitation-readonly-flash-and-plain-crucible-execution).

**Deliberately not fixed in this pass, and not planned unless needed**: no
general fix (baking all of flash into literals, redesigning
`populateSegmentChunk`) — that's a real execution-model change with no
current symbolic use case requiring it, now that the milestone below is
closed at the concrete evidence tier. Revisit only if a future
Crucible/What4/Z3 use case genuinely needs a whole-function proof through
a literal-pool-derived branch; the narrow fix (baking the *specific*
literal-pool words that target reads, the same store pattern already
proven for the packet buffer) would be the smallest starting point.

## Next steps

**Note**: a tooling-only detour (2026-09-08, ahead of a Galois meeting)
happened between the milestone above and this section — two clean repros
(Macaw's A32-on-Cortex-M mode selection, readonly-flash/plain-Crucible
divergence), an experimental `aptrace debug` (`crucible-debug`/
`crucible-macaw-debug`), an optional GREASE experiment, and a small MMIO-
diagnostics addition. See
[`docs/tooling/galois-premeeting.md`](tooling/galois-premeeting.md). It did
not touch the milestone/roadmap; roadmap M3 (the virtual RF link) closed
separately and immediately afterward, also on 2026-09-08.

1. **Deliberate pivot: behavior-to-hardware provenance (in progress).**
   `&|`, `G -> #`, and `S -> P...` are all done — a deliberate stop before
   `!`/`I`, pivoting toward `command/state -> internal variable/function
   -> timer/MMIO -> ISR/GPIO -> MCU pin -> physical hardware behavior`.
   The motor-timer survey (TC0-TC3's ISR/GPIO mechanism, matched against
   the already-proven TCC1 -> PB22 case) is now done — see
   [`docs/investigations/motor-timer-survey.md`](investigations/motor-timer-survey.md).
   The per-channel pin-index gap that survey left open is now also
   closed: TC0->PB10, TC1->PA08, TC2->PB12, TC3->PA10, a `.data`-segment
   startup-initialization fact, not application-written — see
   [`docs/investigations/pin-index-provenance.md`](investigations/pin-index-provenance.md).
   `I<channel><mode>|`'s state machine is now traced forward and meets
   the timer chain from (12)/(13) in the middle: the handler's own
   `0x20001b14[channel]!=0` gate conditionally calls `FUN_00005274` ->
   `FUN_00004d18`, which writes `step_delta[channel]`'s *sign* (a
   confirmed, concretely-validated edge — also corrected the record:
   the handler's `=5` write is `0x20002524[channel]`, not
   `0x20001b14[channel]` as previously catalogued); separately,
   `FUN_00006338`'s ramp logic only propagates a rate update to the
   real `FUN_00005c00`/`FUN_00005898` chain when that same
   `0x20001b14[channel]` gate is nonzero. See
   [`docs/investigations/i-command-motor-chain.md`](investigations/i-command-motor-chain.md).
   **One link remains**: what sets `0x20001b14[channel]` nonzero in the
   first place — exhaustively searched (12 direct-reference functions, 7
   one-hop candidates, the full boot chain, a neighbor-offset sweep) and
   not found by any static method; a concrete watchpoint (new
   `run_concrete.py --watch-mem-write`) confirmed one branch writes
   nothing. See
   [`docs/investigations/channel-busy-gate-search.md`](investigations/channel-busy-gate-search.md).
   Two concrete follow-ups: first
   ([`docs/investigations/systick-tick-injection.md`](investigations/systick-tick-injection.md))
   resolved the homing-timeout tick gap with a new `--fake-tick`
   capability and got past it with the watchpoint live, but hit an
   uninitialized DMA/SERCOM-shaped peripheral object, root-caused to the
   `FUN_0000cdd8` clock-init stall; second
   ([`docs/investigations/reset-handler-clock-init.md`](investigations/reset-handler-clock-init.md))
   resolved *that* stall too (4 real, SVD-named completion bits, a new
   `--mmio-force-bits`/`--mmio-clear-bits` mechanism) and reran from the
   true `Reset_Handler` — clock init now completes, the driver object
   constructs without crashing, and real homing runs and exits, all
   confirmed. A third follow-up
   ([`docs/investigations/post-homing-radio-probe.md`](investigations/post-homing-radio-probe.md))
   traced *why*: `FUN_0000610c`, reached second after homing (before
   either `FUN_00007770` or `FUN_00005d44`), performs a real SPI
   device-ID probe (register `0x42` expected `0x12`, matching the
   well-known SX127x LoRa `RegVersion` check) through the already-real
   SERCOM/DMA driver — concretely confirmed to read `0`, not `0x12`,
   with no chip attached, so the firmware takes its own real,
   **infinite** retry loop. Not a timing gap; not faked (a different,
   external-device evidence class from the MCU-internal bits already
   modeled) — correctly identified and left as an open, real hardware
   boundary. A fourth follow-up
   ([`docs/investigations/post-probe-main-loop.md`](investigations/post-probe-main-loop.md))
   confirmed no software bypass exists, then introduced the narrowest
   possible disclosed assumption (a new `--force-reg` mechanism,
   fabricating exactly one register value at one instruction) to get
   past it. The real main loop is now reached and confirmed stable
   (`FUN_00008960`, 5 iterations, ~400,000 instructions total from
   `Reset_Handler`) — resolving the earlier "excessive tick cost" as
   entirely attributable to the now-bypassed infinite retry loop.
   `0x20001b14` remains unwritten through genuine idle main-loop
   execution, concretely confirmed. **The real RX injection point is
   now identified** (a 100-byte RAM ring buffer at `0x2000245c`,
   index `0x200024c0`) for a follow-on slice that injects a real `I`/`M`
   command — not attempted this pass. A second, deeper dependency (a
   real bulk NVM erase loop that doesn't advance over millions of
   instructions, likely gated on a zero-valued config field rather than
   a status bit) was found and reported precisely; it does not block
   the above and was not chased further.
   A fifth follow-up
   ([`docs/investigations/g-command-motor-subsystem-unlock.md`](investigations/g-command-motor-subsystem-unlock.md))
   delivered a real `G000|` through the real RX ring for the first time
   (a new `--force-mem` mechanism, plus a `--fake-tick` recalibration
   after diagnosing a real per-byte radio-poll-vs-inter-byte-timeout
   collision), confirmed `G`'s handler arms a previously undocumented
   `0x200025e1=2` byte, and — the real answer to why `0x20001b14` never
   moves — found that `FUN_00007e2c`/`FUN_00008e18`/`FUN_00006338`/
   `FUN_00008a80` (the whole motor-phase/ramp/monitor subsystem) are not
   reachable from a cold boot at all: the real, currently-running main
   loop lives entirely inside `FUN_00009464` and never returns, so
   `FUN_000093fc` (which calls all four) is never called. The one real
   unlock — clearing `0x20000060` — traces to exactly one command,
   `MC4<...>|` (never per-channel `MC<0-3>`), found by the same
   exhaustive literal-pool-scan method already used for `0x20001b14`
   itself. A concrete `MC4` delivery attempt hit a second, distinct
   per-byte timing dependency and was not chased further this pass.
   A sixth follow-up
   ([`docs/investigations/mc4-transition.md`](investigations/mc4-transition.md))
   characterized `MC4` fully (frame schema, per-channel field storage —
   only the 4th field feeds the locked subsystem — and the exact
   `0x20000060=0` unlock instruction), diagnosed the second timing
   dependency precisely (a *cumulative*, not per-byte, inter-byte
   timeout — fixed by sizing `--fake-tick`'s period from a direct
   per-byte-cost measurement), and delivered `MC4` alone concretely:
   `FUN_000093fc` reached for real, with `FUN_00007e2c`/`FUN_00008e18`
   now running every iteration. Sequencing a real `G` after `MC4` (a
   second `--force-mem` at `FUN_00009464`'s own one-time return
   instruction, after finding same-buffer back-to-back delivery gets the
   second command silently flushed by a real firmware behavior) reached
   **`FUN_00006fd8`, the real move-commit function, for the first time in
   this project** — still no `0x20001b14` write, explained concretely by
   a register-captured `distance=0` taking `FUN_00006fd8`'s own
   documented no-op branch. `0x200025e1` (`G`'s arm) and `0x20000060`
   (`MC4`'s unlock) are confirmed independent by both xref and control
   flow — no function touches both.
   A seventh follow-up
   ([`docs/investigations/target-config-provenance.md`](investigations/target-config-provenance.md))
   traced `distance=0`'s producer: `FUN_00006fd8`'s config struct
   (`0x20001b40`, confirmed base — a same-session decompiler-vs-
   disassembly correction after `FUN_00007e2c`'s tail-jump initially
   mis-attributed it) is bulk-loaded from a lazily-initialized buffer
   sourced from a plain flash-address read (`0x00012000`, register-
   captured, no driver indirection) — and that exact flash address is,
   in this firmware image, entirely `0x00` (confirmed by reading the raw
   `.bin`). The real loader fallback fills the struct with `0xFF`; a
   one-shot, `.data`-driven resync then overwrites each channel's mode-0
   target with its own live position (cold-zero). Exhaustively trying
   every `G` "type" digit (`0`-`9`) gives only `distance=0` or `-1`,
   never `>8` in magnitude — a real, external-data provisioning boundary
   (the same evidence class as the unmodeled radio-ID chip), not a
   missing mechanism.
   An eighth follow-up
   ([`docs/investigations/ll-limit-workflow.md`](investigations/ll-limit-workflow.md))
   characterized `LL1`/`LL2` fully (shared `FUN_000054e0` handler,
   reachable pre-`MC4`; `LL1` clears two globals + a validity flag,
   `LL2` orders and validates them) and confirmed, both statically
   (exhaustive literal-pool scan) and concretely (`--watch-mem-write`
   across a real `LL1`-then-`LL2` run, sequenced past a real
   `'O'`-byte framing drain this slice also found), that neither
   command touches live position, the target/config struct,
   `0x20001b14`, or any GPIO/MMIO — and that nothing else in the
   firmware ever writes `LL`'s two globals with a real value either.
   A second, independent confirmation of the same provisioning gap, not
   a new mechanism.
   A ninth follow-up
   ([`docs/investigations/standard-library-provenance.md`](investigations/standard-library-provenance.md))
   was a deliberate, bounded classification pass rather than continued
   provisioning work: fetched Adafruit `ArduinoCore-samd@1.7.11` (the
   exact evidenced toolchain) and structurally matched it against the
   infrastructure functions this project keeps re-deriving, confirming
   `Reset_Handler`/`main()`/`millis()`/`SysTick_Handler` and newly naming
   `FUN_00009464`/`FUN_000093fc` as the sketch's real `setup()`/`loop()`.
   Recorded in a reusable CSV plus an optional, tested Ghidra
   post-script. While checking for other references to the `0x12000`
   flash address, found a real, previously unexamined **write path**
   (`FUN_0000449c`->`FUN_000097a4`->NVM erase/write, from a channel-0
   move-completion handler) — not exercised concretely, and its "dirty"
   flag's own setter not traced; the precise next persistence target.
   A tenth follow-up
   ([`docs/investigations/dirty-flag-persistence.md`](investigations/dirty-flag-persistence.md))
   found that setter: the dirty byte (`0x20004147`) is set by a single
   shared, change-detecting "write one config byte" accessor
   (`FUN_0000977c`), found only via a full-image scan for the `movw
   #0x1002` immediate (the offset exceeds Thumb-2's immediate-encoding
   range and never appears in the flash literal pool, so an ordinary
   xref search would have missed it). A previously undocumented ASCII
   command, `D<value>|`, writes through this exact accessor — a real,
   protocol-reachable way to dirty the persisted-config buffer, not
   delivered concretely this pass. The save-if-dirty path never clears
   the flag after saving; the one function that does (`FUN_000097f4`)
   has no confirmed caller anywhere in the image. `0x12000` is now
   confirmed real, firmware-owned, round-trip persistent storage — not
   external provisioning, per the task's own explicit caution. Next:
   deliver a real `D` command concretely and watch the dirty flag: see
   that doc's own "Next step."
   An eleventh follow-up
   ([`docs/investigations/d-command-persistence-roundtrip.md`](investigations/d-command-persistence-roundtrip.md))
   did exactly that: delivered `D1234,|` concretely, confirmed the real
   buffer/marker writes, and — running the boot further with no new
   fabrication — found the real save path fires naturally via the
   already-disclosed PA22 signal, reaching a real NVM erase call with
   arguments matching the `0x12000` read path exactly, before stalling
   at an already-known (now reconfirmed) zero-page-size gap. No flash
   byte was actually written; the reboot/recovery half of the round trip
   awaits resolving that gap. Next: determine whether the page-size
   field should come from a real SAMD51 register or an untraced
   driver-construction step — see that doc's own "Next step."
2. **Exercise `!`/`I` through the virtual link** (roadmap M4, deferred
   per (1)): `!0|`/`!1|` (`0xc440`, event 7 — already has a known
   11-vs-10 field mismatch to preserve, not normalize away) and
   `I<channel><mode>|` (`0xb958`/`0xb834`, dynamic per-channel state) —
   same two primitives, not started.
3. `G`/`S`'s handler-side event-scheduling writes are now concretely
   verified; `!` still only has solver-confirmed entry *reachability* —
   a smaller, parallel task, not a prerequisite for (1) or (2).
4. If a real symbolic use case for the readonly-flash gap above ever
   arises, apply the narrow fix described in "Tooling gaps" — not before.
5. Name the TX path's real transport peripheral by tracing what
   populates the driver-object pointer `0x8c10` dispatches through;
   install `GhidraSVD` only if the standalone resolver stops being
   convenient enough for routine use. **Possibly related**: the radio-ID
   probe object `post-homing-radio-probe.md` found (`0x20004160`) is a
   real, constructed SERCOM/DMA driver object of the same general shape
   — worth checking whether it's the *same* object `0x8c10` dispatches
   through, not assumed to be.

The `0x827e` loop's own internal structure and its callees `0x5274`/`0x5448`
([`docs/investigations/dispatcher-loop-callees.md`](investigations/dispatcher-loop-callees.md))
remain correctly documented and are relevant to future `0xF0`/`0xE0`
binary-frame work. Fuller backlogs (protocol open questions, remaining
tooling gaps like the still-not-installed `GhidraSVD` extension) are
tracked in [`docs/protocol/open-questions.md`](protocol/open-questions.md)
and [`docs/tooling/tool-selection.md`](tooling/tool-selection.md), not
duplicated here.

## Tool architecture

APTrace orchestrates specialist tools rather than reimplementing them:

| Tool | Role | Status |
|---|---|---|
| Ghidra | static RE / decompiler / xrefs / tables / MMIO naming | Integrated — [`docs/tooling/ghidra-backend.md`](tooling/ghidra-backend.md) |
| Unicorn | concrete Thumb execution / state snapshots | Integrated — [`docs/tooling/unicorn-backend.md`](tooling/unicorn-backend.md) |
| Macaw | independent CFG discovery / machine-code lifting | In use, proven |
| Crucible + What4 + Z3 | targeted symbolic reachability / input solving | In use, proven |
| APTrace | orchestration, evidence model, scenarios, traces, UI | This repo |

See [`docs/tooling/tool-selection.md`](tooling/tool-selection.md) for when
to use which, and [`docs/architecture.md`](architecture.md) for rationale.

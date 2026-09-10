# Investigation: AutoPilot Trigger-Input Software Mitigation — Design and Binary Patchability

**Question**: given the trigger-input firmware path already closed by
[`trigger-input-concrete-path.md`](trigger-input-concrete-path.md) and
solver-confirmed by
[`trigger-input-symbolic-crosscheck.md`](trigger-input-symbolic-crosscheck.md),
what software mitigations are technically possible at the real, narrowest
patch point, are they implementable as a Thumb/Thumb-2 patch (in-place or
via a trampoline), and can APTrace/Unicorn exercise them concretely before
any physical hardware is touched?

**Explicitly not this slice's question**: the real electrical behavior of
the physical trigger-port connection chain remains **UNKNOWN**. Nothing
below claims a mitigation is *correct* for the hardware fault — only that
it is *possible*, *minimal*, and *testable*. No distributable patched
firmware image is produced or flashed; every patch below lives only in a
Unicorn-emulated copy of the image.

**Scope**: static disassembly (direct byte reads, cross-checked against
Ghidra/Macaw's already-published block structure) for the patch site;
Unicorn (`tools/unicorn/concrete.py`'s `ConcreteMachine`) for concrete
prototype execution, per this project's own tool-selection hierarchy
(Ghidra → Unicorn → Crucible) — no new Crucible/What4/Z3 work was needed,
since every question here is "what does this patched code do," not "what
input satisfies this," and the underlying gate was already solver-confirmed
by the crosscheck slice.

## Confidence scale

**CONFIRMED** (disassembly and/or concrete Unicorn execution of the real,
unmodified firmware) / **PROTOTYPE** (concrete Unicorn execution of an
in-memory candidate *patch*, never the real firmware) / **INFERENCE**
(reasoning about likely usefulness against a possible electrical
transient) / **UNKNOWN** (the real physical trigger-port waveform, or
anything that depends on it). Every claim below is labeled.

---

## Part 1 — The exact patchable region, byte-exact

`trigger-input-symbolic-crosscheck.md` Part 1 already established the
seven-guard gate's block structure via Ghidra/Macaw. This slice re-derived
it directly from the firmware bytes (`research/firmware/originals/firmware_autopilot868.bin`,
file offset = flash address − `0x4000`) to get exact instruction encodings
for patchability — **CONFIRMED**, and it matches the prior slice's block
table exactly, instruction-for-instruction:

| Address | Bytes | Instruction | Size |
|---|---|---|---|
| `0x9202` | `2b 78` | `ldrb r3,[r5,#0]` | 2 |
| `0x9204` | `ab b9` | `cbnz r3,0x9232` | 2 |
| `0x9206` | `6b 78` | `ldrb r3,[r5,#1]` | 2 |
| `0x9208` | `9b b9` | `cbnz r3,0x9232` | 2 |
| `0x920a` | `ab 78` | `ldrb r3,[r5,#2]` | 2 |
| `0x920c` | `8b b9` | `cbnz r3,0x9232` | 2 |
| `0x920e` | `eb 78` | `ldrb r3,[r5,#3]` | 2 |
| `0x9210` | `7b b9` | `cbnz r3,0x9232` | 2 |
| `0x9212` | `13 4b` | `ldr r3,[pc,#0x4c]` → `0x9260` (`0x20001b38`'s address) | 2 |
| `0x9214` | `1b 68` | `ldr r3,[r3,#0]` | 2 |
| `0x9216` | `7b 2b` | `cmp r3,#0x7b` | 2 |
| `0x9218` | `0b d1` | `bne 0x9232` | 2 |
| `0x921a` | `12 4b` | `ldr r3,[pc,#0x48]` → `0x9264` (`0x200000d8`'s address) | 2 |
| `0x921c` | `1b 78` | `ldrb r3,[r3,#0]` | 2 |
| `0x921e` | `09 2b` | `cmp r3,#9` | 2 |
| `0x9220` | `07 d1` | `bne 0x9232` | 2 |
| `0x9222` | `33 78` | `ldrb r3,[r6,#0]` | 2 |
| `0x9224` | `2b b9` | `cbnz r3,0x9232` | 2 |
| `0x9226` | `39 20` | `movs r0,#0x39` | 2 |
| `0x9228` | `04 f0 d8 f8` | `bl 0xd3dc` (`digitalRead`) | 4 |
| **`0x922c`** | `00 28` | **`cmp r0,#0`** | 2 |
| **`0x922e`** | `3f f4 b3 ae` | **`beq.w 0x8f98`** | 4 |
| `0x9232` | `03 b0` | `add sp,#0xc` | 2 |
| `0x9234` | `bd e8 f0 8f` | `pop.w {r4-r11,pc}` | 4 |

`0x9202`→`0x9231` is **exactly 48 bytes**, zero slack: every byte is
accounted for by a real instruction (4+4+4+4+8+8+4+2+4+2+4 = 48). Right
after it, `0x9232`-`0x9237` is the function's real, shared "no-op" epilogue
(reached by every failed guard above, and by `digitalRead` returning
non-zero). This byte-exact reconstruction is new evidence, not a repeat of
the prior slice's Ghidra/Macaw-only view — it is what patchability analysis
needs and the disassembly view alone doesn't give.

Immediately following the epilogue (`0x9238`-`0x9245`) is more real code
(a `bl` into another helper, a counter increment, a backward branch — part
of the analog/T-status arm's own tail, not this gate), then a single
2-byte `nop` alignment pad (`0x9246`), then this function's **literal
pool** (`0x9248`-`0x9267`, 8 words). Five of the eight are RAM addresses
already named in this project's own docs — `0x20002410`
(`rate_limit_last_check`), `0x20002548` (`tx_buffer_base`), `0x200025ac`
(`tx_buffer_index`), and the two gate-cell addresses `0x20001b38`/
`0x200000d8` (matching the crosscheck slice's own values exactly, at the
same literal-pool offsets `0x9260`/`0x9264` that slice's own `ldr
r3,[pc,#...]` computations resolved to). The other three words
(`0x200000a8`, `0x200000c0`, `0x0001111e`) are **not** previously
characterized by this project and were not chased further this slice —
named here, not silently omitted, since they occupy space this patchability
analysis needs to account for. Immediately after the pool, `0x9268` is
the **next function's own entry** (`push {r4-r7,lr}`). **CONFIRMED**:
there is no free byte anywhere between this gate and the start of the next
function — the region is fully packed, standard for a size-optimized
`arm-none-eabi-gcc` build.

### The first irreversible action

`0x8f98` (the `beq.w` target) is:

```
0x8f98  ldr r3,[0x9148]      ; = 0x200025bc
0x8f9a  movs r2,#3
0x8f9c  strb r2,[r3,#1]      ; *(0x200025bc+1) = 3 -- a real RAM write
0x8fa0  pop.w {r4-r11,lr}
0x8fa4  b.w 0x00006e4c       ; tail-jump into config_reload_motion_profile_compute
```

**CONFIRMED** (byte-exact, matching `trigger-input-concrete-path.md` Part
9 exactly): the *first* RAM mutation on the accept path is the `strb` at
`0x8f9c`, immediately followed by an unconditional tail-jump into the real
config-reload chain (`config_loader__CUSTOM` → `config_reload_motion_profile_compute`,
288 real memory writes and a real PB30/PB31 GPIO pulse per
`trigger-input-motion-causality.md` — already proven **not** to arm motor
motion, but a real, consequential firmware event nonetheless).

**This answers the "narrowest safe patch point" question directly**: the
input can still be rejected, with zero side effects, anywhere up to and
including the branch at `0x922e`. Once `0x8f98` executes, the trigger
action has started. The chain is:

```
physical/input observation      digitalRead(0x39) result in R0, at 0x922c
    -> accepted trigger          the beq.w at 0x922e actually taken
    -> internal state mutation   the strb at 0x8f9c (0x8f98's own first instruction)
    -> downstream action         config_loader__CUSTOM's 288 writes + GPIO pulse (0x8fa4 onward)
```

The narrowest patch point is **the branch instruction at `0x922e`** (or
equivalently, the decision it encodes), not `0x9226`/`0x9228` (before the
real `digitalRead` call). Patching *before* the call would mean either
skipping the real hardware read entirely (a bigger, less honest change —
the mitigation should still observe the real pin) or duplicating it；
patching *at* the branch changes only what the firmware *does* with an
already-real reading, which is the smaller, more defensible edit.

---

## Part 2 — Intended trigger semantics

| Question | Answer | Basis |
|---|---|---|
| Level- or edge-sensitive? | **Level-sensitive.** Every poll re-evaluates `digitalRead(0x39)` independently; nothing stores the previous reading. | **CONFIRMED** (disassembly, this slice + `trigger-input-concrete-path.md` Part 5) |
| Active-low or active-high at the `digitalRead()` boundary? | **This gate (the second `digitalRead`, `0x9226`/`0x8f98` path): active-LOW** — `R0==0` (PB05 electrically LOW) is required to reach `0x8f98`. (The *other* poll, the `TR1\|`-armed T-status broadcast at `0x91ca`, treats PB05 HIGH as "active" in its own wire-frame convention — a different consumer of the same physical pin, not the same "trigger" this patch touches.) | **CONFIRMED** (`trigger-input-symbolic-crosscheck.md` Query C: `0x8f98` reached iff `R0=0`, UNSAT otherwise) |
| Can a held trigger generate more than one event? | **Yes.** No latch, no "already fired" flag. Every poll where all seven guards hold and PB05 reads LOW re-executes `0x8f98` and re-triggers the config reload. | **CONFIRMED** (disassembly: nothing on the accept path sets a bit any guard checks) |
| What prevents repeat firing? | **Nothing, in this gate.** (The four idle-state guards — `0x20002524[0..3]==0`, gate cells `0x7b`/`9` — are unrelated to PB05 debounce; they gate on system idleness, not on trigger history.) | **CONFIRMED** |
| What re-arms it? | **N/A — it is never disarmed.** Every poll is independent. | **CONFIRMED** |
| Triggering immediately after startup/setup? | This whole function (`phase_ramp_state_machine__CUSTOM`) is unreachable until `MC4` unlocks it (`mc4-transition.md`) — which itself requires the user to complete motor-type setup, not merely power on the device. So "immediately after boot" in the strict physical-power-on sense never reaches this gate at all; the earliest real call is after `MC4`, whenever that happens in a given session. | **CONFIRMED** (inherited from `mc4-transition.md`/`g-command-motor-subsystem-unlock.md`) |
| Does legitimate use depend on very short pulses? | **UNKNOWN** — no minimum valid pulse width is established by firmware or user-guide evidence. The poll cadence itself (how often this exact gate is evaluated in real time) is architecturally "every real main-loop iteration, no throttle" (`FUN_000093fc` calls `phase_ramp_state_machine__CUSTOM` every iteration, confirmed in `g-command-motor-subsystem-unlock.md`) but the main loop's own real-world period was never measured by any prior slice. | **CONFIRMED** (no throttle exists) / **UNKNOWN** (real-time period) |

**User-guide claim, kept separately labeled** — `[USER GUIDE]`, section
12 (`docs/ui/user-guide-workflows.md` line 438): connecting the trigger
cable *before* power-up establishes a noise baseline (less sensitive,
less false-triggering); connecting it *after* power-up is more sensitive,
more prone to false triggering. This is **not** about the gate this
document patches specifically (that gate only exists on the PA02-LOW boot
arm, where PB05 is *always* configured as a bare no-pull digital input —
`trigger-input-concrete-path.md` Part 3) — it describes the *other*
firmware branch (PA02-HIGH, the 128-sample ADC baseline path,
`FUN_00005d44`), which this project already found is a dead end (its
result is never read by anything — Part 4 of the same doc). **The
user-guide behavior and the firmware's actual implementation are
therefore in tension**: the manual describes a working baseline/threshold
feature; the firmware's own baseline computation is disassembly-confirmed
never consumed. This tension is inherited, not introduced by this slice —
recorded here because it bears on Candidate A below.

---

## Part 3 — Mitigation families evaluated

### A. Startup arming / initial-state qualification

**Concept**: don't accept the first LOW reading until PB05 has first been
observed HIGH for some qualification window after this code starts
running.

- **Where an armed bit could live**: the same confirmed-dead RAM this
  slice's prototype reuses (`0x20001fc4` or a neighboring byte — Part 4 of
  `trigger-input-concrete-path.md`).
- **When it could safely become armed**: only after `MC4` has unlocked
  `phase_ramp_state_machine__CUSTOM` — this is **not** "at physical
  boot"; per Part 2 above, the earliest real call to this gate is
  whenever the user finishes motor setup in that session, which could be
  seconds or much longer after power-on.
- **Does existing state already provide this?** No — nothing currently
  distinguishes "this is the first call since MC4" from any later call.
- **Would it alter behavior for a device booted with an intentionally
  active trigger?** **Yes, and this is the candidate's real weakness.**
  The user guide's own section 12 describes a supported workflow where the
  trigger is connected *before* power-up specifically so it's active/ready
  from the start; a one-time "must see it clear first" arming gate is in
  direct tension with that documented intent for this gate's PB05-LOW
  convention (though, per Part 2, this specific dead-end-ADC-baseline
  distinction means the two may not even be the same code path — an
  unresolved ambiguity this slice does not chase further).
- **Ranking**: **weak alone**. It only ever protects the *one* window
  right after MC4-unlock; a connection event happening later in the same
  session (plausible — nothing stops plugging in a trigger cable mid-use)
  gets no protection at all once the arm bit is set. Retained only as a
  possible *supplementary* layer under Candidate B, not a standalone
  answer.

### B. Consecutive-sample debounce / qualification

**Concept**: require PB05 LOW for *N* consecutive polls of this exact gate
before accepting.

- **Actual poll cadence**: **CONFIRMED architecturally** — every real
  main-loop iteration, no artificial throttle (unlike the *other*,
  `TR1\|`-armed T-status poll, which *is* rate-limited to ~500 ticks; that
  throttle does **not** apply to this gate). **UNKNOWN** in real
  milliseconds — the main loop's own period was never measured.
- **Available tick source**: `millis()`'s backing store (`0x200052ec`) is
  real and already used elsewhere in this function, but using it here
  would require reading it every poll and is unnecessary if the poll rate
  itself is already fast and untethered from real time — a plain
  poll-counter is cheaper and makes no claim about real-world timing at
  all (see Part 6's regression matrix, which deliberately uses poll counts
  as an experiment parameter, not milliseconds, per this slice's
  instructions).
- **Repeated `digitalRead` calls**: already how the firmware itself
  works — no change needed to the call, only to what happens with each
  result.
- **Minimum extra state/code**: one RAM byte (counter) + ~34 bytes of
  Thumb-2 (Part 5).
- **Danger of rejecting a real short pulse**: real, and undetermined —
  since the minimum legitimate pulse width is **UNKNOWN**, any concrete
  *N* is an **INFERENCE**, not a proven-correct threshold. This is exactly
  why Part 8 asks for physical measurement before picking one.
- **Ranking**: **strongest candidate**. General (protects boot-time *and*
  mid-session connection events, unlike A/E), doesn't require a real-time
  clock, and — as prototyped in Part 6 — preserves the CONFIRMED
  repeat-refire-while-held behavior exactly (once qualified, every
  subsequent LOW poll still accepts, matching today's firmware), so it
  changes nothing about legitimate held-trigger use; it only delays
  *onset* acceptance by *N* polls.

### C. Edge qualification (accept only inactive→active transition)

**Concept**: remember the previous poll's level; accept only on a
HIGH→LOW transition.

- **Does this match current semantics?** **No — it changes them.** Today
  every LOW poll re-fires (Part 2); an edge-only gate would fire exactly
  once per HIGH→LOW transition and then go silent until a HIGH is
  observed again, i.e. it removes the CONFIRMED repeat-refire behavior.
  That is a real, unforced change to behavior the task's own gathering of
  evidence does not show is needed or unwanted — a genuine risk to
  "without changing unrelated trigger behavior."
- **Connection-transient case vs. legitimate later trigger**: a bouncing
  connector can produce *multiple* inactive→active edges in a short
  window, each one separately accepted by a bare edge check — **worse**
  than today for a noisy connection, not better, unless paired with a
  per-edge debounce anyway (at which point it reduces to Candidate B plus
  an unnecessary behavior change).
- **Ranking**: **rejected as a standalone candidate.** Its only genuine
  value (distinguishing a transient's *trailing* edge from a sustained
  level) is already provided by B without the side effect of changing
  repeat-fire semantics.

### D. Active-state dwell + release/re-arm state machine

**Concept**: `WAIT_INACTIVE → ARMED → CANDIDATE_ACTIVE → ACCEPTED →
WAIT_RELEASE`.

- This is strictly more capable than B (it also suppresses refire while
  held, requiring release before a second acceptance) but strictly more
  state (an explicit state byte, not just a counter) and more code — a
  larger cave, more registers to manage.
- **Is the added complexity justified by the actual trigger behavior?**
  **No, on current evidence.** Nothing in the firmware's own design or the
  reported bug requires suppressing refire-while-held; the reported
  symptom is specifically about a *spurious* trigger from a connection
  event, which B already addresses without touching the refire behavior.
  Per the task's own instruction ("only retain this candidate if the
  complexity is justified"), D is **not** retained as the primary
  candidate, but is named here as the natural next step if a maintainer
  separately decides refire-while-held is itself undesirable.

### E. Simple fixed startup delay (ignore PB05 for T ticks after boot)

- **Does it address a connection made later, during runtime?** **No.**
  This is the task's own predicted weakness, and the firmware confirms
  it: since the gate isn't even reachable until `MC4` unlocks it (Part
  2), "after boot" doesn't even align with when this code starts running,
  and — more importantly — nothing stops the trigger cable being
  connected at any later point in the session, which a fixed one-time
  delay does nothing to protect.
- **Ranking**: **rejected**. Strictly weaker than A (which at least ties
  the window to when the code first runs) and A itself is already ranked
  weak.

### F. One-shot suppression of the first trigger after boot/setup

- **Proving unsafety from the workflow, not assuming it**: the user
  guide's own section 12 describes a supported configuration where the
  trigger cable is connected *before* power-up specifically to be
  active/ready immediately. A one-shot suppression would unconditionally
  drop that first, potentially fully legitimate, trigger — this is not a
  hypothetical edge case, it is the documented primary use of "connect
  before power-up." Unlike A/B, F also adds no observation of *inactivity
  first* — it just blindly discards one event regardless of whether it
  looks like a transient or a clean level, so it cannot even claim to
  target the reported bug specifically.
- **Ranking**: **rejected**, confirmed unsafe from workflow evidence, as
  the task predicted.

---

## Part 4 — Ranking summary

| Candidate | Fault shapes rejected | Legitimate behavior at risk | New state | Timing dependency | Complexity | Reversible | Unicorn-testable | Needs physical data first? |
|---|---|---|---|---|---|---|---|---|
| **B. Consecutive-sample debounce** | Any transient shorter than *N* polls, at boot or mid-session | None identified — repeat-refire-while-held preserved exactly | 1 byte (counter) | Poll-count only, no real-time claim | Low (~34 bytes) | Yes (revert the one branch) | **Yes — prototyped, Part 6** | Yes, to choose *N* |
| A. Startup arming | A transient in the one window right after MC4-unlock only | Tension with "trigger pre-connected before power-up" workflow (Part 2) | 1 bit | None | Low | Yes | Yes (not prototyped this slice) | Yes, and even then only partial coverage |
| D. Full dwell/re-arm state machine | Same as B, plus suppresses legitimate refire-while-held | Removes CONFIRMED repeat-refire behavior — unforced change | 1+ bytes (state + counter) | Poll-count | Medium | Yes | Yes (not prototyped — complexity not justified this slice) | Yes |
| C. Edge qualification | Nothing beyond B; can be *worse* on a bouncy line | Removes CONFIRMED repeat-refire behavior — unforced change | 1 bit | None | Low | Yes | N/A — rejected | N/A |
| E. Fixed startup delay | Nothing reliably — misses any later-session connection | None new, but doesn't fix the reported class of fault | 1 word (a timer) | Real-time (unestablished) | Low | Yes | N/A — rejected | N/A |
| F. One-shot suppression | Nothing reliably — blind, not conditioned on transient shape | Drops a legitimate pre-connected boot-time trigger (user-guide-documented workflow) | 1 bit | None | Low | Yes | N/A — rejected | N/A |

**Recommendation for what to prototype**: **B**, optionally layered with
**A** as defense-in-depth once physical data justifies it — never C, E, or
F as designed.

---

## Part 5 — Binary patchability

### The patch site

Replace **only** the 4-byte `beq.w 0x8f98` at `0x922e` with a same-size
`b.w <cave>`. This is the smallest possible in-place edit: 4 bytes for 4
bytes, no growth, no shift of anything after it (so every other branch
target, literal-pool PC-relative offset, and function boundary in the
image is undisturbed).

```
before: 0x922e  3f f4 b3 ae   beq.w 0x8f98
after:  0x922e  <b.w CAVE>    (4 bytes, in place)
```

`cmp r0,#0` at `0x922c` is left completely untouched — the real
`digitalRead(0x39)` call at `0x9228` still executes exactly as before;
only what happens with its result changes.

### Registers/flags that must be preserved

**CONFIRMED by direct disassembly** (not assumed): at both possible
landing points —

- **`0x9232`** (reject): `add sp,#0xc; pop.w {r4-r11,pc}` — restores
  `r4`-`r11` from the stack; **`r2` and `r3` are not in that list**, so
  whatever a mitigation leaves in them is irrelevant.
- **`0x8f98`** (accept): `ldr r3,[0x9148]; movs r2,#3; ...` — **both `r2`
  and `r3` are overwritten by the target's own first two instructions**,
  before anything else reads them.

So **`r2` and `r3` are the only registers a cave may freely clobber**,
and they are exactly the ones this slice's prototype cave uses. `r0` is
still needed (the real `digitalRead` result) and must be read, not
clobbered before use. No stack push/pop is needed in the cave — SP is
untouched by the whole seven-guard chain and must stay that way (the real
epilogue's own `add sp,#0xc` assumes SP is wherever the function's own
entry left it).

### RAM state

One new byte is needed for Candidate B's counter. Reusing
`0x20001fc4` (part of the RAM `trigger-input-concrete-path.md` Part 4
proved is unconditionally zeroed by `FUN_00005d44` at boot — on **both**
PA02 outcomes, since that clear happens before the PA02-HIGH/LOW branch
inside `FUN_00005d44` — and never read by anything else in the image, via
exhaustive xref) rather than inventing new RAM, per this project's own
preference. Because this gate is only ever reachable on the `*0x20001fc0
== 2` (PA02-LOW) boot arm anyway (Part 2/3 of `trigger-input-concrete-path.md`
— PB05 is only wired as a plain digital input on that arm), the byte is
guaranteed zero and unread by anything else on exactly the arm this
mitigation needs it on, even though its own zeroing is unconditional
across both arms.

### Is a trampoline required, or can this be entirely in-place?

**A trampoline is required for every candidate that adds any logic beyond
changing the branch's target** (Part 1: zero slack in the 48-byte gate,
and the literal pool + next function begin immediately after with no
padding beyond one required 2-byte alignment `nop`). The absolute
smallest addition — one `ldrb`+`cbz` pair to test a single armed-bit
(Candidate A) — is still 4+ bytes more than the existing footprint, which
cannot be inserted without shifting every subsequent instruction, literal
pool offset, and function boundary in the image. That is not an in-place
patch; it is closer to a relink. **Every viable candidate here needs a
trampoline out to a code cave.**

### Candidate cave locations checked, and why each was rejected

Per instruction, "no Ghidra xref" was **not** treated as proof of
"unused." Every zero-byte run ≥8 bytes anywhere in the image was found
and inspected directly (not just noted):

| Candidate location | Size | What it actually is |
|---|---|---|
| Flash `0x1113f`-`~0x14000` (~12KB) | 11,969 bytes | **Not free.** Contains flash `0x12000`, the already-documented, real, flash-backed persisted motor-target config blob (`target-config-provenance.md`: "every one of the 4097 bytes at flash `0x12000`... confirmed... all-zero in this firmware image" — a currently-blank, but live and read/written, NVM region). Overwriting any of it would corrupt persisted configuration storage on a real unit. |
| Flash `0x401a` | 18 bytes | Inside the vector table region (`0x4000`-`0x40e0`, 56 entries × 4 bytes) — a reserved/unused **vector table slot**, not code space; not something to repurpose as executable memory. |
| Flash `0x48d8`, `0x4ab8`, `0x7238` | 12-13 bytes each | **Not free.** All three are the *same* recurring pattern, confirmed by direct byte inspection at all three sites: a function's `pop.w{...}` epilogue, a `nop.w` (`f3af 8000`) 4-byte-alignment pad, then that function's own **literal pool** (a run of `0x00000000` constants — plausibly pooled `0.0f`/`int 0` literals — followed immediately by real float/RAM-pointer constants). These are compiler-emitted data, not slack. |
| End of image (last 64 bytes) | 64 bytes, all `0x00` | Simple end-of-file padding within the 70,768-byte `.bin`; not large enough for any candidate cave (34 bytes) plus alignment, and its role relative to the flashing tool's own expectations was not checked further (out of scope). |

**Honest negative result**: this pass found **no verified, adequately-sized,
genuinely-unused flash region** for a real, flashable trampoline. This
does not mean none exists — the most promising unexplored option (not
verified this slice) is flash beyond the current image's end (`0x15470`)
up to wherever the real 512KB flash actually ends (`ATSAMD51J19A`,
`firmware-layout.md`) — roughly 442KB of address space this `.bin` simply
doesn't cover. Whether that space is genuinely blank/erased on a real,
physically-provisioned unit, or reserved by the bootloader/BOSSA flashing
convention for something else, is **UNKNOWN** and would need either a
real device flash dump or vendor/BOSSA documentation review — explicitly
named as a follow-up, not chased here (this slice also produces no
distributable image, so a real cave address was not needed to finish it).

### This slice's prototype cave (harness-only, not a real flash address)

Because no verified real cave was found, and because this slice does not
produce a distributable image anyway, the concrete Unicorn prototype
(Part 6) places its cave at a **harness-only scratch page** (`0x00020000`,
mapped via `ConcreteMachine`'s existing `extra_maps`/`run_concrete.py`'s
`--map-page`) that does not correspond to any location in the real
70,768-byte image. This is explicitly **not** a claim about where a real
trampoline would live — only a demonstration that the *logic* is
correct and Unicorn can exercise it end to end.

**Trampoline size**: 34 bytes (Thumb-2, no literal pool — uses
`movw`/`movt` for the counter's 32-bit RAM address instead of a
PC-relative literal, avoiding alignment/literal-pool placement concerns
entirely):

```
CAVE+0x00  movw r3, #0x1fc4        ; r3 = 0x20001fc4 (the counter)
CAVE+0x04  movt r3, #0x2000
CAVE+0x08  cmp  r0, #0             ; redone here -- self-contained, doesn't
                                    ; rely on flags surviving the b.w that got us here
CAVE+0x0a  bne  reset
CAVE+0x0c  ldrb r2, [r3]
CAVE+0x0e  adds r2, r2, #1
CAVE+0x10  strb r2, [r3]
CAVE+0x12  cmp  r2, #N              ; N = experiment parameter, not a real-time value
CAVE+0x14  blo  reject
CAVE+0x16  b.w  0x8f98              ; ACCEPT
reset:
CAVE+0x1a  movs r2, #0
CAVE+0x1c  strb r2, [r3]
reject:
CAVE+0x1e  b.w  0x9232              ; REJECT
```

**Return point**: none needed — both exits are direct branches to the
real firmware's own existing accept/reject addresses (`0x8f98`/`0x9232`),
not back into the cave or a synthetic trampoline-return page.

**Branch range**: the outer patch (`0x922e` → cave) and the cave's own
`b.w 0x8f98`/`b.w 0x9232` are all plain Thumb-2 `B.W` (±16MB range) —
comfortably sufficient for any real cave location in a 512KB part. No
literal-pool hazard exists in this design (deliberately avoided via
`movw`/`movt`).

**Encoding verification** (not just hand-derivation): every instruction
above was hand-encoded from the ARMv7-M Architecture Reference Manual's
bit layouts, then verified two independent ways — (1) a **capstone**
disassembly round-trip of the exact byte sequence (below), and (2)
empirical Unicorn execution (Part 6) landing on the intended PC in every
one of the bookend and regression-matrix runs:

```
0x20000:  movw r3, #0x1fc4
0x20004:  movt r3, #0x2000
0x20008:  cmp  r0, #0
0x2000a:  bne  #0x2001a
0x2000c:  ldrb r2, [r3]
0x2000e:  adds r2, r2, #1
0x20010:  strb r2, [r3]
0x20012:  cmp  r2, #4
0x20014:  blo  #0x2001e
0x20016:  b.w  #0x8f98
0x2001a:  movs r2, #0
0x2001c:  strb r2, [r3]
0x2001e:  b.w  #0x9232
```

### Integrity/flashing implications

**UNKNOWN / no evidence found.** No prior AutoPilot investigation
(including multiple full `Reset_Handler`-to-main-loop traces:
`reset-handler-clock-init.md`, `post-homing-radio-probe.md`,
`post-probe-main-loop.md`) has surfaced any application-level checksum,
CRC, or signature check over the app image. Flashing is via `bossac`
(`Autopilot_firm/update_firmware.bat`: `bossac -i -d ... --offset=0x4000
-w -v ... -R`) — the `-v` flag is bossac's own **write-then-read-back
verify**, a flashing-tool-level check that the bytes it wrote match what
it sent, not a firmware- or bootloader-level integrity check of the
running image. No size field, magic, or footer was found in the last 64
bytes of the image (all zero — ordinary end-of-file padding). This is
stated as an absence of evidence in what's already been traced, not
certainty; per instruction, this slice does **not** reverse-engineer the
16KB bootloader (`0x0`-`0x3fff`, not present in these `.bin` files) to
confirm it further, since nothing found here indicates that's necessary.

---

## Part 6 — Unicorn prototype (Candidate B)

**New file**: [`tools/unicorn/trigger_mitigation_prototype.py`](../../tools/unicorn/trigger_mitigation_prototype.py).
Patches only an in-memory `ConcreteMachine` copy of the image — the real
`.bin` on disk is never modified. Reuses the existing, unmodified
`ConcreteMachine`/`extra_maps` API (`concrete.py`) with **zero changes**
to any existing harness file — no new "general binary patch framework"
was built, per instruction; this is one purpose-built script for this
one gate.

### A real bug this prototype's own first attempt hit (worth recording)

The first version of this script wrote the patch bytes and the PB05
MMIO level directly via `machine.uc.mem_write(...)` **before** calling
`ConcreteMachine.run(fresh=True)`. Every bookend and regression result
came back wrong (e.g. a hard-coded "always reject" patch still produced
`ACCEPT`). Root cause, confirmed by reading `concrete.py`: `run(fresh=True)`
calls `reset()` first, which restores every *dirty* page — including
ones dirtied by a direct `mem_write` *before* `run()` was ever called —
back to the machine's pristine, pre-patch snapshot. The fix: deliver
every patch and every input level through `run()`'s own `seed_mem`
parameter, which is applied **after** `reset()` inside the same call.
This is recorded here because it is a real, generalizable lesson for
*any* future Unicorn-based patch prototype in this project, not specific
to this gate — analogous to `CLAUDE.md`'s existing "harness rules" about
trusting Unicorn as ground truth only once the harness itself is
understood.

### Sanity bookends (before trusting the debounce cave)

| Patch | Input | Result | Meaning |
|---|---|---|---|
| `b.w 0x8f98` (always accept) | PB05 HIGH | `ACCEPT(0x8f98)` | The branch *target*, not PB05, now controls the outcome — the in-place redirect works |
| `b.w 0x9232` (always reject) | PB05 LOW | `reject(0x9232)` | A real LOW no longer automatically reaches `0x8f98` once the branch is redirected |

Both **PROTOTYPE**-confirmed via real Unicorn execution.

### Regression matrix (N=4 polls; poll count, not milliseconds — Part 2's UNKNOWN real-time cadence)

All nine required scenarios, entering at the gate's own real block start
(`0x9202`) with the same disclosed background state
`trigger-input-symbolic-crosscheck.md`/`trigger-input-concrete-path.md`
already established (idle channels, gate cells `0x7b`/`9`, `TR0\|`
disarmed), only PB05's electrical level varied per poll:

| # | Scenario | PB05 sequence | Result |
|---|---|---|---|
| 1 | inactive throughout | HIGH×6 | Never accepts |
| 2 | active throughout | LOW×6 | Accepts at poll 3 (4th consecutive LOW) |
| 3 | short transient during startup, then inactive | LOW, HIGH×5 | **Never accepts — nuisance transient correctly rejected** |
| 4 | short transient after runtime established | HIGH,HIGH,LOW,HIGH,HIGH,HIGH | Never accepts |
| 5 | longer transient after runtime (3 polls, < N) | HIGH,HIGH,LOW×3,HIGH,HIGH | Never accepts (shorter than threshold) |
| 6 | clean intentional trigger after startup (5 polls, ≥ N) | HIGH,HIGH,LOW×5 | Accepts at poll 5 (4th consecutive LOW), continues accepting |
| 7 | valid trigger after an earlier rejected transient | HIGH,LOW,HIGH,LOW×5 | Earlier 1-poll blip rejected; later sustained LOW accepts normally at poll 6 |
| 8 | held-active behavior | LOW×8 | Accepts at poll 3, **continues accepting every subsequent poll** (repeat-refire preserved, matching CONFIRMED original semantics) |
| 9 | release and second legitimate trigger | LOW×4, HIGH×2, LOW×4 | First trigger accepts at poll 3; release resets counter; second trigger accepts at poll 9 |

**The most important regression — nuisance transient → no accepted
trigger, followed by an intentional valid trigger → accepted normally —
is scenario 7, and it passes.** All results are **PROTOTYPE**-tier
(behavior of an in-memory candidate patch, real Unicorn execution, not a
claim about the real hardware fault).

Run it yourself: `tools/unicorn/.venv/bin/python3 tools/unicorn/trigger_mitigation_prototype.py --threshold 4`
(`--threshold` is a free experiment parameter, not a claimed real-world
value, per instruction).

---

## Part 7 — Historical/version comparison

Not performed. Per instruction, 868 vs. 915 firmware differ only in radio
config (`firmware-layout.md`), and no prior slice's evidence suggests the
trigger code itself differs between them — a comparison was not cheap or
newly motivated by this slice's findings, so it was skipped rather than
turned into its own investigation.

---

## Part 8 — Physical measurements still required

These are measurements needed to **choose** between candidates (Part 4),
not assumptions this document makes about the hardware fault:

**At the jack (before the MCU):**
- Idle level with nothing connected, and with the "certain chain" attached but the AutoPilot unpowered.
- Polarity and direction of the transient at the instant of physical connection (rising, falling, or both).
- Transient duration (µs/ms) and whether it bounces (multiple transitions vs. one clean edge).
- Whether the line floats (high impedance) when disconnected, consistent with the CONFIRMED no-pull, bare digital-input configuration (`trigger-input-concrete-path.md` Part 3).

**At PB05 (MCU-side):**
- Whether the MCU-side waveform matches the jack-side waveform, or differs (e.g. attenuated, filtered, or distorted by whatever "certain chain" is being connected) — this is the single most decision-relevant measurement, since it tells us whether the fault is *external* to the MCU (jack/cable/connector) or something in between.
- Whether the transient happens only at power-on/connection establishment, or can also occur from a connection made during ordinary runtime (directly resolves which of Candidates A/B/E apply at all — Part 3's central discriminator).

**Correlated with firmware behavior:**
- The real main-loop period (ms per iteration of `FUN_000093fc`) — needed to translate any chosen poll-count threshold (*N* in this document's prototype) into a real debounce time, and to check that *N* polls doesn't exceed the shortest legitimate intentional trigger pulse (itself still **UNKNOWN**).
- Whether a deliberately-triggered event (a real, intended use of the 3.5mm input) produces a measurably different waveform shape (duration, bounce count, edge count) than the reported spurious connection-time event — this is the actual test of whether *any* software debounce can distinguish the two, independent of which candidate is chosen.

---

## Evidence-level summary

| Claim | Level |
|---|---|
| Gate byte layout, patch site, register/flag preservation, epilogue behavior | **CONFIRMED** (direct byte-exact disassembly, this slice) |
| Trigger semantics (level-sampled, no debounce, no latch, main-loop-rate polling) | **CONFIRMED** (disassembly, inherited from `trigger-input-concrete-path.md`) |
| Candidate B's debounce logic behaves as designed across the 9-scenario matrix | **PROTOTYPE** (real Unicorn execution of a hand-encoded, capstone-verified patch, harness-only cave) |
| Candidate B (or any candidate) is *useful* against the real reported fault | **INFERENCE** — plausible, not proven; depends on real transient shape (Part 8) |
| No app-level checksum/signature exists | **UNKNOWN**, stated as absence-of-evidence-found, not certainty |
| No sufficiently large, verified-safe real flash code cave was found in this pass | **CONFIRMED** as a negative result of this pass's own search (3 distinct candidate classes checked and rejected with reasons); does not prove none exists |
| The real electrical behavior of the trigger-port connection chain | **UNKNOWN** — untouched by this slice, as instructed |

---

## Summary

**Strongest mitigation candidate**: **B, consecutive-sample debounce** —
require PB05 LOW for *N* consecutive polls of the already-real,
already-solver-confirmed second-gate `digitalRead` before accepting.
General (works for a boot-time *or* mid-session connection event, unlike
A/E), requires no real-time clock, and — uniquely among the candidates
evaluated — preserves the firmware's own CONFIRMED repeat-refire-while-held
behavior exactly, changing nothing about legitimate trigger use while
delaying spurious onset acceptance.

**Patchability result**: the narrowest safe rejection point is the
4-byte `beq.w 0x8f98` at `0x922e`, replaceable in place (same size, zero
growth, no shift of anything else in the image) with a `b.w` to a
trampoline. **Every** candidate requiring more than a bare branch-target
change needs that trampoline — the 48-byte gate and its immediately
following literal pool have zero slack. Three classes of apparently-free
flash were checked and all three turned out to be real, meaningful
content (the persisted NVM config blob, reserved vector-table slots,
per-function literal pools) — a genuine negative result, not an
assumption. No verified-safe real flash cave was found this slice; the
most promising unexplored option is flash beyond the current 70,768-byte
image's end, within the part's real 512KB, not chased here.

**What the Unicorn prototype demonstrated**: a real, hand-encoded,
capstone-verified 34-byte Thumb-2 trampoline, executed concretely (not
merely modeled) against the exact, already-solver-confirmed gate, passes
all 9 required regression scenarios — critically, scenario 7 (a rejected
nuisance transient followed by a later intentional trigger accepted
normally). The prototype's own first version had a real bug (patches
applied before `run(fresh=True)` were silently reverted by `reset()`) —
found and fixed by reading the harness's own semantics, not by inspection
alone; recorded as a reusable lesson for future Unicorn-patch work in this
project.

**Legitimate behavior at risk**: none identified for Candidate B
specifically. Candidates C and D were rejected precisely because they
*would* change the CONFIRMED repeat-refire-while-held behavior without
evidence that change is wanted. Candidate F was confirmed unsafe against
the user guide's own documented "trigger connected before power-up"
workflow.

**What remains unknowable without physical capture**: the real transient
shape at the jack and at PB05 (polarity, duration, bounce, floating
behavior, boot-only vs. runtime-insertion), the real main-loop period (to
translate a poll-count threshold into real time), and the minimum
legitimate trigger pulse width — all named concretely in Part 8, all
required before any specific value of *N* (or any candidate at all) can
be called correct rather than merely possible.

**Files changed**:
- Added `docs/investigations/trigger-input-mitigation-patchability.md` (this document).
- Added `tools/unicorn/trigger_mitigation_prototype.py` (reusable, purpose-built Unicorn prototype and regression matrix for this one gate).
- Added `capstone==5.0.9` to `tools/unicorn/requirements.txt` as an optional, verification-only dependency (the prototype degrades gracefully without it, per its own `try`/`except ImportError`).
- `docs/project-status.md` and `research/workflows/trigger-input.yaml` were reviewed and intentionally left unchanged — this slice's findings are about *mitigation design*, not a new firmware-behavior conclusion, and don't warrant an update to either per this task's own instruction ("only if warranted").

**Regressions run**: `tools/unicorn/test_concrete.py` (8/8 pass, unmodified — confirms this slice's new script didn't misuse `ConcreteMachine`'s existing API). No existing harness file was modified, so no other regression suite was at risk.

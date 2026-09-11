# Remote UI → Command Connection Tree

**Purpose**: an explicit graph of Remote UI states and transitions,
showing for every known user action (and every known inbound
AutoPilot-driven transition) the chain: UI node → input/event →
Remote-local state change → wire command (if any) → next UI node.
**This is a documentation/reconciliation task — no new reverse
engineering was performed.** Built entirely from
`docs/ui/user-guide-workflows.md`, `docs/ui/action-command-map.md`,
`docs/replacement/manual-to-firmware-traceability.md`/`.json`,
`docs/replacement/four-firmware-contract.md`/`.json`,
`docs/hardware/hardware-reference.md`, `docs/protocol/*`,
`docs/investigations/*`.

**Machine-readable companion (authoritative)**: [`research/generated/remote-ui-command-tree.json`](../../research/generated/remote-ui-command-tree.json) — 21 nodes, 50 edges (CLEAR split into two edges by a later closure pass — see "Unresolved UI → command edges," below).

## Compact tree

```
REMOTE.ROOT
├── INFO                              (& | -> V01R39; RF-band string; Signal/IRSens/Trigger [UNKNOWN])
├── QUICK_SETUP                       (entered ONLY via inbound MT...|, never a Remote menu path)
│   └── MOTOR_SETTINGS                (CURRENT / STEPS-S-MAX / MICRO-STEPPING / RETURN SPEED -> MC<0-3>)
│       └── (Continue, all 4 types set) -> MC4 -> back to ROOT
├── MANUAL MODE
│   ├── Direction -> LL1|x3 preamble
│   │   └── LIVE jog: rotate -> F0/E0  |  click -> stop (no frame)
│   ├── (double-click) -> CHANNEL_SELECT -> back to MANUAL
│   ├── (direction-invert config, local)
│   └── Set Limits -> LL1|x3
│       ├── Phase 1 jog -> click -> I9|/I1| -> (success) LL1|x3
│       ├── Phase 2 jog -> click -> I9|/I1| -> (success) LL2|x3
│       └── Outcome ("No limits set" traced; success/failure branch [UNKNOWN])
├── AUTO MODE
│   ├── Record A/B/C/D -> interactive '+' (mode 0x00) -- does NOT arm a target
│   │   └── long-click -> end dialog (local only)
│   ├── Segment params (Duration/Speed/Ramp/Delay/Loop) -> interactive '+' (mode 0x14)
│   ├── Test A-B/B-C/C-D            -> interactive '+' (mode 0x14) [PROBABLE, not confirmed]
│   ├── Test M1-M4 (whole-motor)    [UNKNOWN wire command]
│   ├── Clear A-B (segment)         -- no wire command; local record write observed
│   ├── Clear ALL / Clear M1-M4     -- no wire command (same reasoning, path not independently traced)
│   └── GO / Move to A-D -> G<channel><type=1><seq>|  (real move-commit if |distance|>8)
├── EXTERNAL_INPUT (inbound: RJ45 controller connected) [UNKNOWN detection mechanism]
└── SETTINGS
    ├── Trigger reporting toggle -> TR0| / TR1|
    └── BRIGHTNESS / RF CHANNEL / IR-SENSOR / TRACTION CTRL  [UNKNOWN wire commands]

(background, not tied to a screen)
├── Remote boot -> '+' mode 0x62 (per channel w/ data) then MC4     [proven re-arm path]
├── ~5000-tick comm-gap reconnect -> same re-arm                    [proven re-arm path]
├── periodic UI-pump push (~250 ticks) -> '+' mode 0x62 only (no MC4)
├── S|/!0|/!1| sync (UI trigger unconfirmed) -> P.../11-field CSV (Remote consumes only 10 fields)
└── AutoPilot -> T<>,<>,| telemetry (when armed) -> Remote redraw only
```

## Per-node transition tables

Full detail (condition, exact wire form, AutoPilot effect, confidence,
evidence) is in the JSON companion. Below: node → outgoing edges,
compact.

### REMOTE.ROOT
| Input | Type | Wire | Status |
|---|---|---|---|
| open Info | USER_ACTION | — | REMOTE_LOCAL_ONLY |
| navigate to Manual Mode | USER_ACTION | — | REMOTE_LOCAL_ONLY |
| navigate to Auto Mode | USER_ACTION | — | REMOTE_LOCAL_ONLY |
| navigate to Settings | USER_ACTION | — | REMOTE_LOCAL_ONLY |
| revisit motor settings | USER_ACTION | — | PARTIAL_PATH_PROVEN |
| inbound `MT...|` | INBOUND_AUTOPILOT | `MT` | FULL_PATH_PROVEN |
| external controller connected | INBOUND_AUTOPILOT | `UNKNOWN` | NO_FIRMWARE_EVIDENCE |
| Remote boot (background) | REMOTE_LOCAL | `+`/`MC4` | FULL_PATH_PROVEN |
| ~5000-tick comm-gap (background) | REMOTE_LOCAL | `+`/`MC4` | FULL_PATH_PROVEN |
| periodic UI-pump push (background) | REMOTE_LOCAL | `+` | FULL_PATH_PROVEN |
| S/! sync (background) | REMOTE_LOCAL | `S`/`!` | FULL_PATH_PROVEN |
| inbound T-status (background) | INBOUND_AUTOPILOT | `T` | FULL_PATH_PROVEN |

### QUICK_SETUP / MOTOR_SETTINGS
| Input | Type | Wire | Status |
|---|---|---|---|
| select motor type | USER_ACTION | — | REMOTE_LOCAL_ONLY |
| open per-motor settings | USER_ACTION | — | REMOTE_LOCAL_ONLY |
| click Continue (all 4 types set) | USER_ACTION | `MC4` | FULL_PATH_PROVEN |
| edit CURRENT, click out | USER_ACTION | `MC<0-3>` | AUTOPILOT_LOCAL_ONLY (display-only effect) |
| edit STEPS/S MAX, click out | USER_ACTION | `MC<0-3>` | FULL_PATH_PROVEN (real step-period effect) |
| edit MICRO-STEPPING, click out | USER_ACTION | `MC<0-3>` | AUTOPILOT_LOCAL_ONLY (display-only effect) |
| edit RETURN SPEED, click out | USER_ACTION | `MC<0-3>` | FULL_PATH_PROVEN (table-index mechanism; table blank) |
| press BACK | USER_ACTION | — | REMOTE_LOCAL_ONLY |

### MANUAL MODE / DIRECTION / SET_LIMITS
| Input | Type | Wire | Status |
|---|---|---|---|
| select Direction row | USER_ACTION | `LL1` | FULL_PATH_PROVEN |
| rotate jog wheel (LIVE) | USER_ACTION | `F0`/`E0` | FULL_PATH_PROVEN |
| click to stop (LIVE) | USER_ACTION | — (no frame) | FULL_PATH_PROVEN |
| double-click → channel select | USER_ACTION | — | PARTIAL_PATH_PROVEN |
| configure direction invert | USER_ACTION | — | PARTIAL_PATH_PROVEN |
| select Set Limits row | USER_ACTION | `LL1` | FULL_PATH_PROVEN |
| jog to 1st position, click | USER_ACTION | `I9`/`I1` → `LL1` | FULL_PATH_PROVEN |
| jog to 2nd position, click | USER_ACTION | `I9`/`I1` → `LL2` | FULL_PATH_PROVEN |
| press knob to exit | USER_ACTION | — | PARTIAL_PATH_PROVEN |

### AUTO MODE
| Input | Type | Wire | Status |
|---|---|---|---|
| select REC A-D, short click | USER_ACTION | `+` (mode 0x00) | FULL_PATH_PROVEN |
| long click (end dialog) | USER_ACTION | — | REMOTE_LOCAL_ONLY |
| edit segment parameter | USER_ACTION | `+` (mode 0x14) | PARTIAL_PATH_PROVEN |
| select TEST A-B/B-C/C-D | USER_ACTION | `+` (mode 0x14, PROBABLE) | REUSES_KNOWN_PATH |
| select TEST M1-M4 | USER_ACTION | none (display-label state only) | REMOTE_LOCAL_PROVEN |
| select CLEAR A-B (segment) | USER_ACTION | none (local record write observed) | REMOTE_LOCAL_PROVEN |
| select CLEAR ALL / CLEAR M1-M4 | USER_ACTION | none (same reasoning) | REMOTE_LOCAL_PROVEN |
| select GO/Move to A-D | USER_ACTION | `G` | PARTIAL_PATH_PROVEN |
| Loop=YES reaches endpoint | REMOTE_LOCAL | — | PARTIAL_PATH_PROVEN |
| click to switch movements | USER_ACTION | — | REMOTE_LOCAL_ONLY |

### SETTINGS
| Input | Type | Wire | Status |
|---|---|---|---|
| toggle trigger reporting | USER_ACTION | `TR0`/`TR1` | FULL_PATH_PROVEN |
| adjust BRIGHTNESS/RF CHANNEL/IR-SENSOR/TRACTION CTRL | USER_ACTION | `UNKNOWN` | NO_FIRMWARE_EVIDENCE |

## Unresolved UI → command edges

A bounded closure pass (using only pre-existing evidence plus one
disassembly check each) resolved 4 of the 7 core Auto Mode edges this
section previously listed as unresolved:

- **`AUTO.TEST`** (TEST A-B/B-C/C-D) — upgraded to `REUSES_KNOWN_PATH`:
  existing row-arithmetic evidence in `action-command-map.md` Part 3
  points to call site C (screen 10, interactive `'+'`, mode `0x14`) as
  the likely producer — **PROBABLE, not confirmed**; this pass's bounded
  check of the shared row-renderer did not independently confirm it.
- **`AUTO.CLEAR` A-B (segment)** — upgraded to `REMOTE_LOCAL_PROVEN`:
  the already-documented "exactly four `'+'` call sites" fact rules out
  the interactive-`'+'` path (sites A/B require an *empty* record, the
  opposite precondition of clearing existing data); this pass's bounded
  disassembly of `FUN_0000e670`'s already-flagged sole local-record
  WRITE (`0xf47a`) found a real local write in the adjacent code region.
- **`AUTO.CLEAR` ALL / M1-M4** — upgraded to `REMOTE_LOCAL_PROVEN` by the
  same "no wire command exists in the inventory" argument, though this
  pass did not separately trace its own specific code path.

A later pass (**Final TEST Path Closure**) closed the remaining two Auto
Mode TEST edges:

- **`AUTO.TEST`** — direct disassembly of `FUN_0000e670` @`0xf5c0`-`0xf620`
  found `cmp r6,#0xa; bne 0xf664` gating the mode-`0x14` `'+'` call at
  `0xf60c` — this independently *proves* (not merely extrapolates) that
  reaching screen/menu-index 10 provably reaches the known interactive-`'+'`
  path. The same check disassembled call site D (`0xf68c`, gated on
  `cmp r6,#0x9`, screen 9) and confirmed it is a *separate* row consistent
  with the pre-existing screens-6-9 = SPEED/RAMP/DELAY/LOOP mapping (screen
  9 = LOOP), ruling it out as a second TEST call site. The **sole**
  remaining gap is the screen-10 → on-screen-label identity itself (is
  screen 10 really where "TEST A-B" is displayed, vs. "TEST B-C"/"TEST
  C-D"?) — the `'TEST A-B'` string was confirmed (via xref) to live inside
  the shared row-renderer `FUN_00005474`'s label table, but tracing which
  row-index argument selects it for `r6==10` specifically would require
  following `FUN_0000e670`'s generic menu-index dispatch beyond one
  intervening helper — out of this pass's bounded scope. Per explicit
  instruction not to broaden the investigation merely to force
  confirmation, **`AUTO.TEST` stays `REUSES_KNOWN_PATH`/`PROBABLE_UNCONFIRMED`**,
  now with a directly-proven wire-mechanics gate rather than a purely
  arithmetic one.
- **`AUTO.TEST_MOTOR`** (TEST M1-M4) — resolved to `REMOTE_LOCAL_PROVEN`:
  the "TEST M1"-"TEST M4" strings are referenced only from `FUN_00005190`,
  which a full decompile shows is a straight-line `switch` on the current
  channel selector (`0x2000180c`, the same already-known channel byte used
  by `'+'`/`G`) that writes only local label-pointer/display fields — it
  contains **zero calls**, so no wire command of any kind is emitted by
  it. Its two call sites (`FUN_0000e670` @`0xe762` and the 5-caller shared
  display dispatcher `FUN_0000f8c8` @`0xf9b2`) are both generic periodic
  display-refresh blocks, not a distinct "user pressed TEST M1-M4"
  handler — consistent with "TEST M1-M4" being per-channel label text
  rather than four separately actionable commands.

**2 edges remain unresolved** (`wire_command = "UNKNOWN"` /
`NO_FIRMWARE_EVIDENCE`, no command form guessed):

1. `EXTERNAL_INPUT` — external RJ45 controller detection
2. `SETTINGS` — adjust BRIGHTNESS/RF CHANNEL/IR-SENSOR MODE/TRACTION CTRL

See [`manual-to-firmware-traceability.md`](../replacement/manual-to-firmware-traceability.md)
(`MAN-AUTO-005`, `MAN-AUTO-006`) for the full per-edge record.

Additionally, `AUTO.GO`'s wire command (`G`) is known, but which exact
UI string/call-site triggers it (vs. a possible `I<channel><mode>|`
alternative) is **not** traced — recorded as `PARTIAL_PATH_PROVEN`, not
unresolved, since the wire form itself is proven.

## Important current truths reflected in this graph

- Quick Setup is entered **only** from inbound `MT...|`; no Remote menu
  path exists.
- `MC0..3` sent on leaving an edited numeric row; `MC4` sent on
  `Continue` once all four types are set; both fire-and-forget (3x, no
  ack).
- `LL1`/`LL2` are fire-and-forget (3x, no ack).
- Live jog emits `F0`/`E0`, sharing channel + sign/23-bit-magnitude
  layout; `E0` selected when the relevant Remote state equals `3`.
- Interactive `+` updates segment/program information but does **not**
  arm/commit the AutoPilot move; bulk mode-`0x62` is the proven
  re-arm/target-arming path, triggered on Remote boot and the
  ~5000-tick communication-gap reconnect.
- `!` parses only 10 of the AutoPilot's 11 returned fields.
- `I9` follows the real invalid-channel/dead-end path and eventually
  times out.

No node or command was invented beyond what these sources already
establish.

## Out of scope for this graph

`docs/ui/user-guide-workflows.md#13` (firmware update via NOXON
Firmware Uploader over USB-C) is a bootloader/tooling flow, not a
Remote on-screen menu state navigable via the jog wheel — it is not
represented as a node here. It is already covered as
`HARDWARE_PHYSICAL` in
[`research/generated/manual-to-firmware-traceability.json`](../../research/generated/manual-to-firmware-traceability.json)
(`MAN-UPDATE-001`).

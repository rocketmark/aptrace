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

**Machine-readable companion (authoritative)**: [`research/generated/remote-ui-command-tree.json`](../../research/generated/remote-ui-command-tree.json) — 21 nodes, 49 edges.

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
│   ├── Test A-B/B-C/C-D            [UNKNOWN wire command]
│   ├── Test M1-M4 (whole-motor)    [UNKNOWN wire command]
│   ├── Clear A-B/ALL/M1-M4         [UNKNOWN wire command]
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
| select TEST A-B/B-C/C-D | USER_ACTION | `UNKNOWN` | NO_FIRMWARE_EVIDENCE |
| select TEST M1-M4 | USER_ACTION | `UNKNOWN` | NO_FIRMWARE_EVIDENCE |
| select CLEAR ... | USER_ACTION | `UNKNOWN` | NO_FIRMWARE_EVIDENCE |
| select GO/Move to A-D | USER_ACTION | `G` | PARTIAL_PATH_PROVEN |
| Loop=YES reaches endpoint | REMOTE_LOCAL | — | PARTIAL_PATH_PROVEN |
| click to switch movements | USER_ACTION | — | REMOTE_LOCAL_ONLY |

### SETTINGS
| Input | Type | Wire | Status |
|---|---|---|---|
| toggle trigger reporting | USER_ACTION | `TR0`/`TR1` | FULL_PATH_PROVEN |
| adjust BRIGHTNESS/RF CHANNEL/IR-SENSOR/TRACTION CTRL | USER_ACTION | `UNKNOWN` | NO_FIRMWARE_EVIDENCE |

## Unresolved UI → command edges

Six edges carry `wire_command = "UNKNOWN"` — no command form is guessed:

1. `AUTO.TEST` — select TEST A-B/B-C/C-D
2. `AUTO.TEST_MOTOR` — select TEST M1-M4
3. `AUTO.CLEAR` — select CLEAR A-B/ALL/M1-M4
4. `EXTERNAL_INPUT` — external RJ45 controller detection
5. `SETTINGS` — adjust BRIGHTNESS/RF CHANNEL/IR-SENSOR MODE/TRACTION CTRL

(Five distinct UI actions; `AUTO.TEST`/`AUTO.TEST_MOTOR`/`AUTO.CLEAR`
count as three of the six edges above — see the JSON for the exact
one-edge-per-action accounting.)

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

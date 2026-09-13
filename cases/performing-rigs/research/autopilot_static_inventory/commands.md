# Command inventory — v0.3

This is a readable subset of `commands.csv`, focused on the commands with the strongest current evidence. The CSV remains the full inventory.

| ID | Pattern | AutoPilot parser / downstream | Current interpretation | Response | Confidence |
|---|---|---|---|---|---|
| `G` | `G<digit><digit><seq>\|` | 0x83b2 -> 0xb258 / state changes | Synchronous request with rolling sequence digit; human meaning of first two digits unresolved | `#` | high grammar / medium semantic |
| `W1` | `W1\|` | 0x85d8/0x85ea -> 0x4630 -> 0x6e4c under state checks | W-family subcommand 1 | `# up to five times` | high |
| `R0` | `R0\|` | 0x866c/0x86b0 -> inline state changes | R-family state 0 | `@ (single byte)` | high |
| `R1` | `R1\|` | 0x866c/0x8678 -> inline state changes | R-family state 1 | `@ twice` | high |
| `S` | `S\|` | 0x87be -> selects status code based on global state | Synchronous state/config query | `P<value0>, or P<value0>,<value1>,<bool>,` | high |
| `!` | `!0\| and !1\|` | 0x87b2 -> sets a flag | Bulk state/config query selector | `11 comma-terminated numeric fields` | high transport / medium semantic |
| `&` | `&\|` | 0x888c -> event5 -> RAM 0x20003134 initialized by 0x4328 | AutoPilot firmware-version query | `V01R39` | very high |
| `I_DYNAMIC` | `I<1..4><0-or-1>\|` | 0x872e -> per-channel state 0x20001b14 / mode 0x200029d8 -> completion monitor 0x8b5c -> event15 | Per-channel asynchronous/query state-machine command | `<signed-number>,` | high structure / medium semantic |
| `LL1` | `LL1\|` | 0x877e -> 0x54e0/0x5510 -> limit state reset/capture logic | First-limit workflow command | `—` | high |
| `LL2` | `LL2\|` | 0x877e -> 0x54e0/0x552a -> compares/reorders stored limit positions; sets valid flag | Second-limit workflow command | `—` | high |
| `MC0_3` | `MC<0-3><a>,<b>,<c>,<d>,\|` | 0x86e4 -> 0x7a98 | Motor configuration for one channel | `—` | high |
| `MC4` | `MC4<a0>,<b0>,<c0>,<d0>,...<a3>,<b3>,<c3>,<d3>,\|` | 0x86e4 -> 0x7a98 x4 | Motor configuration for all four channels | `—` | high |

## Important unresolved protocol mismatches

- The Remote transmits several packets (`MS|`, `MR|`, `MM|`, `N|`, `KK|`, `E1...|`, bare `W|`) that do not fit the visible main AutoPilot text dispatch. These remain explicit targets rather than guessed semantics.
- `I9|` / `I1|` are short query forms used by a separate Remote routine and do not cleanly fit the three-character dynamic `I<channel><mode>|` parser.
- Event-7 output has an exact 11-fields-emitted / 10-fields-parsed mismatch; see `event7-schema.md`.
- `M1` / `M2` / `M3` outbound endpoints exist in the AutoPilot dispatcher but have no direct producer and no active Remote parser in this build.

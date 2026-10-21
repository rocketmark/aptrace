# Persistent state and factory-default downgrade

2026-10-19. **Partial investigation; production recommendation NO-GO.**
Gate D changes **BLOCKED → PARTIAL**. A/B/C remain PARTIAL; E/F remain BLOCKED.

Product-meaning qualification (2026-10-21): the [D investigation](d-serial-number-and-compatibility.md)
identifies the tested value as the Remote's reported SN display identity,
without a demonstrated control dependency. This does not change the storage/
startup observations or release grades below. Stable nonzero identity and
external provisioning compatibility remain optional product decisions.

The original firmware has meaningful, command-controlled persistent local
state. The product belief that it has no persistent user configuration is too
strong: `D1234,|` changes a saved value that original firmware recovers after
modeled reset. However, **retaining that value is not required for the tested
factory-default startup**. Both original frequency variants reach their actual
application loop from the untouched packaged blob after an ordinary-format
`MC4` exchange. A per-device Noxon settings export, migration tool, or verbatim
settings restoration is therefore not a mandatory prerequisite under the
request's requirement that a downgrade may reset local settings.

This is not proof that no device-specific state exists. Factory calibration
and silicon identity are separate from application settings; the firmware reads
them. No physical power cycle, USB enumeration, movement, erase, flashing tool
or board operation was performed. Original firmware files were unchanged.

## Scope and confidence

**CONFIRMED** below means an observed structural relationship or concrete result
within its explicitly stated scope; it is not an APTrace VERIFIED claim or a
hardware qualification. **INFERRED** identifies interpretation/conditional
physical consequences. **UNKNOWN** preserves an evidence boundary.

Evidence: [generated artifacts](../../research/generated/persistent-state-2026-10-19/),
[observations and bounded checks](../../research/generated/persistent-state-2026-10-19/observations.json),
[execution manifest](../../research/generated/persistent-state-2026-10-19/execution-manifest.json).
Input identities are the original AutoPilot868 SHA-256
`6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`
and AutoPilot915 SHA-256
`0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920`.

## Identified storage inventory

| Medium/region | Read/write/validation and consumers | Classification and replacement consequence |
|---|---|---|
| Internal application flash `[0x12000,0x13001)` | 4096 payload bytes plus provisioning byte at `0x13000`. `0x990e` copies into the lazy staging buffer through `0x9724`; a zero provisioning byte causes `0xFF` fill of the 4096 staged payload bytes. `0x9768` reads staged offsets. `0x977c` changes differing bytes and sets dirty. `0x97a4` sets the provisioning byte and calls erase `0x98f0` and program `0x984c` when dirty. | **CONFIRMED** mechanisms and fresh modeled writes. Packaged bytes are all zero in both variants. This is mutable application state, not just immutable constants. Under the intentional-default-reset requirement it is reconstructible for tested startup, not mandatory unit-specific backup data. |
| Config payload fields | `D`: big-endian u32 at `+0x15..+0x18`, marker `0xDE` at `+0x19`, consumed by boot reader `0x4c20` and response builder `0x8c70`. `+0x1a` is clamped to 20 for values outside 20..25 and is changed by `A` before radio reinitialization. `+0x33` selects 1/2 via `X`; boot defaults to 1 if invalid. Offset 400 receives `0x7B` in a command branch. Digital-input housekeeping uses offset `0x14`. | **CONFIRMED** access relationships; complete product meanings/units of all fields **UNKNOWN**. User/command control is real; no evidence identifies these as per-die calibration or immutable identity. One successful reset/save path does not validate every possible blob. |
| Motor state within payload | Offsets 300/301 and 500..1651 stage flags and the four `0x120`-byte target/position structures. Loader `0x4b64`, resync `0x4b24`, writeback `0x43f0`; compute/`+` paths also write back. Boot sanitizes fields, initializes/resynchronizes targets and can call writeback itself. | **CONFIRMED** local writable state; **INFERRED** operational/history-dependent settings rather than manufacturing data. No movement was requested here. Whether any particular lost target creates unacceptable real-product behavior is **UNKNOWN**, so physical non-motion/default acceptance remains required. |
| Application NVM erase/padding | Geometry constructor `0x981c` reads NVMCTRL.PARAM; modeled `0x00060400` gives 512-byte pages and an 8192-byte erase stride. Logical save is 4097 bytes; observed flat-memory programming made 1025 four-byte stores (4100 bytes). The modeled affected erase block is `[0x12000,0x14000)`. | **CONFIRMED** program stores/arguments in Unicorn; real erase physics, alignment and block preservation **UNKNOWN**. Bytes outside the logical payload are not established as free space. Do not equate a successful flat-memory store with a hardware NVM program/erase. |
| RAM staging `[0x20003145,0x20004148)` | Loaded flag at base, payload at base+1, provision marker at base+`0x1001`, dirty at base+`0x1002`. Runtime channel arrays from `MC4` are separate. | **CONFIRMED** volatile staging and flags. Dirty is already set by default boot; dirty=1 after a command alone does not show the command persisted. RAM is not a persistent medium. |
| Factory calibration around `0x00800080` / `0x00800084` | `0xcdd8` reads factory words and derives peripheral calibration register values; `0xd5d8` reads the latter word and supplies fallback trim values for all-ones fields. | **CONFIRMED static** reads; individual silicon values and their physical importance **UNKNOWN** locally, manufacturing-specific character **INFERRED**. Packaged application cannot reconstruct actual factory words. Preserve these regions/invariants; no factory rewrite or cloning is proposed. |
| Silicon identity words `0x008061fc`, `0x00806010`, `0x00806014`, `0x00806018` | `0xc3d0` reads four words and formats a string on the descriptor/string path. Pointer literals and native references are saved. | **CONFIRMED static** reads/formatting; **INFERRED** USB serial derived from silicon identity. No USB host request or individual value was observed here. Identity is outside the application blob and must remain invariant; no separate user-settings reconstruction is indicated. |
| NVM user/fuse row; bootloader; unowned internal flash | Application's resolved NVM sites are saved in `nvm-census.txt`. Exact user-row address query returns no resolved data reference, which is not an all-path absence proof. Vendor host analysis separately identifies conditional user-row/protection option paths. Bootloader bytes and unknown upper-flash ownership are not available. | **UNKNOWN** live protection/row contents and hidden ownership. Keep qualified device/backups and invariants for B/C/E/F. These are not automatically disposable just because local settings may reset. |
| External flash/EEPROM/other media | QSPI census returns no resolved access for the original app. No external persistent-medium transaction or application pairing store was identified in the examined paths/case evidence. RF/display/motor peripheral traffic is not itself an EEPROM operation. | **UNKNOWN** global absence. Resolved MMIO census cannot exclude computed accesses or peripheral-internal nonvolatile state. Feather's attached QSPI chip is a separate board fact, not an AutoPilot application settings store. |

This is an inventory of **identified** mechanisms, not an exhaustive proof over
all instructions/peripherals. A simple provisioning byte/field checks are not
a complete schema, CRC, versioning or authenticated device binding. Unexamined
payload bytes are not presumed irrelevant; intentional reset accepts their
loss only to the extent of the tested default-startup result and stated product
requirement. Original factory/boot/recovery invariants remain mandatory.

## Fresh execution results

| Experiment | Original-firmware observation | Meaning/limits |
|---|---|---|
| Direct boot-reader calls on packaged 868 and 915 | `0x4c20` returns cleanly; runtime `0x200029d4=0`, payload fallback `0xFF`, dirty=1 after clamp. | **CONFIRMED modeled** fallback. These unit calls seed only the driver's source/length fields and do not stand in for full startup. |
| Synthetic valid saved value, 868 | With provisioning=1 and the D marker/value seeded in simulated data flash, reader returns 1234; dirty=0 for these valid fields. | Positive control for validation/consumer. Synthetic data is disclosed, not an observed device backup. |
| Full packaged-default reset → MC4 → loop, both variants | Both stop at `0x93fc`, instruction 11880918, setup flag=0, no native error; no movement commit. Four `0x7a98` handler entries. No config-setter call after the first MC handler, no flash writes in either observed run; blob stays all zero. | **CONFIRMED modeled** normal configured application entry without preexisting unit config. No claim of physical READY, USB command response, RF transport or full product functionality. |
| Configured MC4 → D → save, 868 | `0x4370` writes 1234; save at instruction 17946055, erase call 17962468 (`r1=0x12000,r2=0x1001`), program 17962488 (`r1=0x12000,r3=0x1001`); stop after program at `0x97e6`, instruction 17983185. Flash contains `00 00 04 d2 de` at `+0x15` and provisioning=1. 1025 stores, none dropped. | **CONFIRMED modeled** command-derived data actually stored through original program instructions. PA22/tick/ready/geometry assumptions are disclosed in the manifest. |
| Fresh reader and full reset with those exact saved bytes | A new process carries only prior flash data with supported `--seed-mem`; original file is unchanged. With no D command, reader returns 1234 and full reset plus MC4 reaches `0x93fc` at 11864912 with runtime 1234. | **CONFIRMED logical** persistence/readback across fresh machine/startup. Carry manifests bind the exact 4097 bytes. Real power-cycle retention and reset circuitry remain **INFERRED/UNKNOWN**, not hardware-tested. |
| Replacing saved data with canonical packaged defaults | Separate fresh original-file runs recover zero/defaults and still reach the loop. | **CONFIRMED modeled** intentional state reset. It is not restoration of previous settings, completed moves, physical position or unit-specific factory data. |

`MC4` writes runtime channel arrays and clears the setup gate; the tested handler
path does not call the persistence accessor or program flash. This does **not**
mean no later event can save other state: startup itself dirties/synchronizes
the blob, and save triggers remain present. Also, the tested values in MC4 are
sufficient examples, not minimum settings or safe physical motor parameters.

The two variants have identical native disassembly in the examined save/helper
range `0x97a4..0x9920` and MC handler range `0x7a98..0x7b66`; their untouched
blobs and default-reader/startup outcomes match. **No difference was found in
these persistence mechanisms.** A new D-write/reset round trip was performed
only for 868; exhaustive 868/915 behavior equivalence is not established.

## What restoring the package supplies

The vendor flasher's inspected SAMD51 paths write raw bytes starting at `0x4000`,
implicitly erase during programming even without `-e`, and do not merge the
Noxon blob. For 70768 bytes, file interval is `[0x4000,0x15470)`, rounded page
write end `0x15600`, modeled erase envelope `[0x4000,0x16000)`.
See [vendor evidence](vendor-bossac-behavior.md). This resets the application
blob; it does not prove preservation of bootloader/fuses/calibration/unknown
neighboring bytes on actual hardware.

**Application-level answer:** the packaged image plus normal external
configuration reconstructs tested default operation; no prior unit-specific
blob was necessary. **Whole-device answer:** the package alone is not a proven
complete downgrade/recovery image. It supplies neither the missing bootloader
nor factory rows/identity or proof of safe original-version/region selection.
A blind restore of an old blob over apfw2 is unnecessary for intentional reset
and could overwrite replacement code; do not require or implement it.

## Gate reassessment and smallest remaining experiments

The clarified product requirement permits intentional reset of Noxon local
settings. This narrows D's acceptance oracle from byte-identical historical
settings to documented default reconstruction plus normal reconfiguration;
it does not relax recovery, protection or factory-data requirements. A later
request for exact historical settings/targets would require a separate backup
and compatibility contract.

| Gate | Previous → new | Support | Remaining uncertainty / smallest next experiment |
|---|---|---|---|
| A: bootloader identity/independent entry | PARTIAL → PARTIAL | Existing application touch evidence only. | Obtain unit bootloader identity/capabilities and demonstrate independent entry under a separately authorized plan. |
| B: addressing/protection | PARTIAL → PARTIAL | Pinned host driver paths plus this app save/read inventory. | Read actual geometry/protection/bank state, then measure erase/program/sentinel scope on a representative non-production target. |
| C: original restoration | PARTIAL → PARTIAL | Both packaged apps reconstruct tested defaults; 868 saved-value readback also works. | Actual unit version/region, bootloader and original non-motion behavior remain unqualified. Restore the correct package on a recovery-qualified engineering unit and compare code/default behavior across reset. Prior local settings equality is not required for intentional reset. |
| D: persistent state | BLOCKED → PARTIAL | Explicit product requirement plus both default startups and 868 write/read/reset evidence remove a mandatory settings-preservation/translation blocker. | Need actual apfw2 release/map/erase manifest and a controlled default-state downgrade acceptance across reset/power cycle. Preserve factory/identity/protection and unowned-range invariants. No dedicated Noxon settings export is required. |
| E: independent recovery | BLOCKED → BLOCKED | No new physical access/recovery evidence. | Establish safe SWD/alternative access and a demonstrated application-independent recovery procedure. |
| F: end-to-end reversibility | BLOCKED → BLOCKED | Software prerequisites improved, no physical round trip or interruption recovery. | After A–E prerequisites, perform the representative apfw2→canonical Noxon round trip, reset/reconfigure/default checks, and interrupted-application recovery with invariants intact. |

Overall **NO-GO**, not CONDITIONAL GO: unresolved independent recovery,
protection and representative physical validation remain sufficient blockers.
The remaining D work is a bounded flash/default-acceptance contract, not a
speculative requirement for a Noxon configuration migration system.

## APTrace workflow, corrections and capability boundaries

The normal 10-step research controller selected documentary discovery,
NVMCTRL census, native disassembly and Macaw/Crucible effects. Its scratch-ledger
run stopped at its step budget with structural proposals; `open: []` does not
answer this release question. Symbolic effects were bounded (3000 steps;
counts lower bounds), not a power-loss or all-path persistence proof. Follow-up
operations used the public persistent Ghidra CLI, read-only census queries and
the verified direct Unicorn CLI. Ghidra 12.1.3 and saved project identities are
recorded. No custom instruction analyzer, new harness, framework fix, modified
image, replacement firmware or hardware operation was introduced.

Fresh native evidence corrects older prose in [motor-config-persistence.md](motor-config-persistence.md):
`0x97f4` invokes the geometry constructor `0x981c` then clears loaded/dirty flags;
it is not a second unconditional flash-program routine. `0x97a4` directly uses
the driver object, without a fresh constructor call in that function. Also,
`0x4b64` can call `0x43f0` during startup resync, so `+` is not its only caller.
Historical generated evidence is retained; current interpretation is corrected.

Three preliminary runs demonstrate bounds rather than absence: one hit the
setter watch cap, one saved boot defaults before D delivery, and D-only setup
runs did not reach save within their budgets. The configured MC4/D run resolves
the save question without pretending those earlier runs succeeded. Native
snapshots retain their actual stop reasons.

| Gap | Impact and observed evidence | Next work / priority |
|---|---|---|
| NVM and reset/power-loss model | Unicorn stores to flat mapped flash and MMIO completion is forced; single-shot CLI does not retain physical NVM automatically. Exact byte carry tests the consumer across fresh startup, not erase atomicity, retention or brownout. | Qualified physical readback/reset/power-cycle/interruption observations; high. Develop hardware-faithful NVM/reset modeling only if a future bounded software question requires it. |
| Exhaustive persistence/indirect-access coverage | Resolved census and tested paths cannot exclude computed accesses, hidden peripheral NVM or every unused field; no relevant resolved QSPI access is not global absence. | Existing APTrace can follow additional scoped references/transactions if new evidence identifies them; broad absence/coverage requires a separate capability/evidence plan; medium. |
| Product/factory/bootloader data | No actual device values or physical acceptance trace. Firmware reads identity/calibration independently of settings. | Preserve qualified acquisition/recovery safeguards, obtain actual apfw2 artifacts and run the revised handoff; high. |

See the updated [physical handoff](vendor-bossac-hardware-handoff.md) and
[six-gate assessment](reversible-firmware-update.md). No additional software
replay can close the remaining physical/replacement-artifact gates by itself.

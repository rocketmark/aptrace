# Reversible Noxon → apfw2 → Noxon replacement: release assessment

2026-10-19. Repository revision inspected:
`123a3425cfef5a5803057cde3723c3a50dd274b0`.

## Decision

**NO-GO for the first replacement on a production AutoPilot.** We possess
hash-identified original application images and evidence of an application-side
1200-baud reset mechanism. We do not possess a verified device bootloader
backup, a demonstrated application-independent entry/recovery path, measured
flash protection, a version-pinned erase/write contract, a device-specific
persistent-state backup, or a completed physical upgrade/downgrade/recovery test.

Application replacement, preservation of the bootloader, preservation of user
state and independent recovery are four separate requirements. Neither a
successful application replay nor the vendor updater's “Upgrade completed”
message establishes them. The software evidence supports planning a controlled
validation campaign, not authorizing a production flash.

No hardware was contacted, reset, erased, programmed or interrogated. No original
firmware, apfw2 implementation, bootloader, permission rules or APTrace backend
was modified. The newly executed reset tests are **simulated instruction slices**,
not physical reset operations.

## Evidence register and provenance

| ID | Evidence | What it establishes / limit |
|---|---|---|
| E1 | [Vendor updater](../../research/firmware/vendor-package/update_firmware.bat), [image inventory](../firmware/firmware-inventory.md), fresh `inventory.json` | Original package bytes, user-selected product/region, VID filter, 1200-baud command and requested `0x4000` application write; no actual device transcript |
| E2 | Fresh `touch-and-nvm-static.txt`, `reset-disasm.txt`, `touch-arm.json`, `touch-dtr-held.json`, `reset-request-positive.json`, `reset-request-disabled.json` | Original application control predicate, countdown and magic/AIRCR stores under explicit harness input; no bootloader execution |
| E3 | [Persistence dossier](motor-config-persistence.md), fresh `application-default-nvm.json`, application NVM census | Known writable configuration inside the image, lazy-load fallback, save behavior; prior persistence results are simulation evidence, not a per-device backup |
| E4 | [Local ATSAMD51 SVD](../../config/svd/ATSAMD51J19A.svd), NVMCTRL STATUS and command definitions | Silicon register semantics including BOOTPROT, BPDIS, region locks, USER/AUX erase and chip-erase lock; no live values |
| E5 | [Hardware reference](../hardware/hardware-reference.md), [pin map](../hardware/firmware-pin-function-map.md), [bench checklist](../replacement/replacement-firmware-bench-checklist.md) | Reported MCU marking ATSAMD51J19A-AU and board features; no verified SWD/reset recovery routing or recovery transcript |
| E6 | [Replacement hardware contract](../replacement/replacement-firmware-hardware-contract.md), [runtime diagnosis](unicorn-runtime-failure.md) | Existing reset-request scope and supported direct simulation path; does not supply a bootloader image |

Fresh artifacts are under
[`research/generated/reversible-update-2026-10-19/`](../../research/generated/reversible-update-2026-10-19/).
`execution-manifest.json` records reproduction commands and outputs.

Fresh hashes confirm vendor and working AutoPilot copies match:

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| AutoPilot868 application | 70768 | `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3` |
| AutoPilot915 application | 70768 | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| Vendor `bossac.exe` | 226816 | `eaebd0b6ef980e464b1a6a5a50eee91f9d6202f51dae7d9f78779d18593121a9` |
| Vendor batch file | 1672 | `41005f6a4a2165928538fd33cdf43e1eb23a402caebafc0589dc474cd0667d6b` |

These identify local artifacts, not the firmware or bootloader installed on a
particular production unit. The correct region, board revision and installed
application version must be tied to that unit before selecting an image.

## Bootloader identity, entry and vendor procedure

**Bounded compatibility evidence, not stock identity:** the package selects
serial devices whose WMIC text contains `VID_239A`, sets a port to 1200 baud,
waits five seconds, searches again, then invokes:

```text
bossac -i -d --port=%com% -U -i --offset=0x4000 -w -v %FILENAME% -R
```

This documents the vendor's intended BOSSA-compatible application-update
workflow. It is not a measured VID/PID/serial descriptor, monitor-version
response, UF2 mass-storage observation or proof of a stock Adafruit bootloader.
The embedded Adafruit Arduino core build paths identify **application tooling**,
not the bootloader build. No bootloader bytes are in the four application files.
`[0,0x4000)` is the inferred reserved pre-application interval, not a measured
bootloader length, protection setting or erase boundary.

Historical `research/generated/manual-traceability-gap-list.json` describes a
standard, vendor-unmodified bootloader as fully characterized. No bootloader
capture or physical recovery transcript supporting that stronger assertion
was located. It is not accepted as release evidence here; current hardware,
layout and gap-audit documentation has been qualified accordingly. Historical
generated evidence was not rewritten.

The Windows executable is present and hashed; file identification reports
PE32 Intel 80386. No version-matched BOSSA source/research or bootloader binary
was located in the available case. The referenced cached Arduino source tree
and a separately expected `/Users/mstalzer/github/apfw2` directory are not
available in this workspace. No apfw2 release binary, linker map or flash
manifest was found. Absence from these searched locations is a dependency gap,
not a claim that those artifacts do not exist elsewhere.

APTrace's current public Ghidra registry targets the Cortex-M applications;
an approved analysis path for this Windows host executable was not identified.
It was not executed, reverse engineered with an independent tool, or assigned
a guessed BOSSA version. The meanings and address scope of this particular
build's erase/write/verify/reset operations remain to be established. In
particular, **no `-e` in the batch file does not prove no erase occurs**, and
an offset on a write does not bound every possible erase or protection command.

The batch file is not a release validator: it does not check `bossac` exit
status before printing success; after rediscovery it checks the earlier
`comport` variable rather than the newly selected `com`; and a VID-only search
can select the wrong attached product. Its own warning to connect only one
Noxon product is material. The script does not back up flash, fuses or user data.

Fresh original-application evidence strengthens the **software entry** account:

- At `0xb7a8`, a request-shaped input with bytes `21 22`, stored baud 1200
  (`0x4b0` at `0x200001a0`) and control bit 0 cleared calls `0xd4c0(250)`.
  The corresponding control bit set calls `0xd4cc`, cancelling with `-1`.
- `touch-arm.json`: 31 instructions, clean function return, countdown
  `0x20000224=250`. Negative control `touch-dtr-held.json`: 32 instructions,
  clean return, countdown remains `0xffffffff`. These model the DTR-release
  portion of the touch-reset mechanism, not a complete USB host session.
- `reset-request-positive.json`: with countdown seeded to 1, 20 original
  instructions decrement it to zero, disable interrupts, store
  `0xf01669ef` at `0x2002fffc`, and write AIRCR `0x05fa0004`; stop is `0xd508`.
  Disabled-countdown control reaches `0xd50c` in five instructions without
  magic or AIRCR writes. Static xrefs connect setters to `0xb7a8` and the
  countdown reads/writes to the SysTick-attributed code.

These observations are application-side stores only. The simulator does not
perform the hardware reset, preserve/validate actual SRAM reset retention,
execute a bootloader consumer of the magic or demonstrate re-enumeration.
The vendor's final `-R` is a reset request to its tool; it is not independent
evidence that the vendor host program implements this application AIRCR block.

**Application-independent entry is unproven.** A working application USB stack
and countdown handler are required for this software mechanism. A dead USB
stack, disabled SysTick or bad application cannot be assumed to honor it.
Double-tap reset, reset-pad holds, erased-vector entry, a boot strap, ROM USB
recovery and the power button acting as MCU reset are all unverified on this
AutoPilot. None is included as an available recovery method.

If apfw2 is to retain the software touch workflow, its verified build must
provide compatible control-request handling and timing, safe pre-reset motor
containment, the correct reset/magic convention and USB re-enumeration on this
actual bootloader. Preserving such a convenience does not replace independent
recovery. No replacement implementation is proposed here.

## Flash and persistent-state preservation

All intervals below are half-open; padding/erase intervals must be measured for
the actual flasher and target, not inferred from a file length.

| Region | Evidence and preservation requirement |
|---|---|
| Internal flash `[0,0x4000)` | Expected pre-application/bootloader reservation. No bytes, actual length or protection readback available. Back up and hash before writes; do not replace with a Feather bootloader. |
| Application file `[0x4000,0x15470)` | 70768-byte raw application; offset and vectors support placement. A raw file is not a full-chip image or UF2 package. |
| Noxon persistent blob `[0x12000,0x13001)` | 4097 bytes, **inside that application file**. Fresh original-image Unicorn dump confirms all zeros for AutoPilot868. Actual device settings can differ; vendor defaults are not their backup. |
| Modeled NVM erase block `[0x12000,0x14000)` | Existing constructor derivation yields 8192-byte stride for the stated 512-KB geometry. Save/erase can affect padding beyond the logical blob. Actual flash geometry, granularity and preservation require readback/target validation. |
| Internal flash `[0x15470,0x80000)` | Beyond the vendor application's end but within reported MCU capacity; contents and ownership unknown. Not a proven empty code cave or free persistent partition. |
| NVM user/fuse, calibration/AUX areas | Outside the ordinary application-image contract. Preserve live protection, calibration and device-specific information; factory-row reads include `0x00800080` in existing startup evidence. A zero-filled simulator placeholder is not calibration data. |

The persistence dossier and fresh `0x9724`/`0x981c` decompilation establish
lazy loading, blank-data fallback, geometry-dependent save behavior and
RAM staging at `0x20003145`. RAM loaded/dirty flags are not a substitute for
the flash blob. Known stored fields include the `D` setting at logical
offsets `0x15..0x18` and marker `0x19`, boot-clamped settings, and per-channel
motor/target structures at logical offsets `500..1651`. The marker/fallback
means erased, all-zero and valid saved state need not behave identically.
Unknown fields must be preserved, not translated by guesswork.

**Consequence:** restoring a bit-exact vendor application can reset persistent
state, even if its flash command preserves every byte outside the image.
Conversely, restoring an old config blob over apfw2 could overwrite its code
unless its linker layout explicitly reserves this interval and erase blocks.
Keep Noxon state as an immutable, board-specific backup plus a separate apfw2
state store or explicit, tested versioned translation. No layout or translator
is available for assessment here. Do not merge apfw2-era settings into the
original blob without a schema and compatibility test.

The SVD describes BOOTPROT and BPDIS, lock/unlock commands, security-bit setting,
chip-erase lock/unlock and USER/AUX erase. These capabilities are **not actual
device settings**. Do not change fuses, bank selection, security or boot
protection to make a flash operation succeed. If readout is protected, stop:
an unlock that requires destructive erase is not a backup or safe recovery.
Factory identity/calibration captures are records for the same board, not
permission to program factory/OTP values or clone them to another unit.

## Six release gates

| Gate | Status | Principal gap |
|---|---|---|
| A — Bootloader identity and independent entry | **PARTIAL** | Compatible vendor intent and application touch handler; no measured bootloader identity/capabilities or application-independent entry |
| B — Addressing and protection | **PARTIAL** | Application offset established; actual protection, erase/write rounding and exact BOSSA build behavior unknown |
| C — Original restoration | **PARTIAL** | Correctly hashed application candidates available; no per-device full backup, installed-version match or restore demonstration |
| D — Persistent state | **BLOCKED** | Known config is overwritten by application replacement; live backup and apfw2 coexistence/restore contract absent |
| E — Independent recovery | **BLOCKED** | SWD/reset board access, security state and restore procedure unverified; no application-independent recovery transcript |
| F — End-to-end reversibility | **BLOCKED** | No physical round trip, interrupted-update recovery or assessed apfw2 release artifact |

**A — Evidence E1/E2/E5.** Smallest software task: obtain a hash-identified
bootloader image or vendor capability/version documentation, and relate its
monitor responses to the exact host tool. Smallest physical task: first obtain
safe read-only descriptors/version/identity in the existing authorized state;
then, in a separately authorized bench phase, demonstrate the documented
hardware entry route without relying on application USB. No reset is performed
now. Incorrect assumption: a failed application can permanently remove the
only update path. A familiar VID or a stock Feather test cannot close A.

**B — Evidence E1/E3/E4.** Smallest software task: identify the shipped BOSSA
build and inspect its matching implementation/options, including erase scope,
offset semantics, verification coverage, lock/fuse operations and reset behavior.
Inspect the actual apfw2 linker/flash manifest. Smallest physical task: record
raw flash/protection/security/geometry values read-only, then validate write
and erase bounds on an expendable equivalent target while hashing sentinel
regions. Incorrect assumption: bootloader or neighboring configuration is erased
despite a correct write offset; recovery may then require unavailable SWD.

**C — Evidence E1/E3.** Smallest software task: retain both region variants,
their hashes, the raw-image/offset contract and a proposed per-region readback
manifest. Smallest physical task: identify the live product/revision/region,
read and independently hash its original flash/bootloader/state, and retain
two copies before testing restoration on a representative engineering unit.
Incorrect assumption: wrong product/region/version boots badly, or a vendor
application file is mistaken for a complete device-restoration image.

**D — Evidence E3/E4.** Smallest software task: compare candidate apfw2 map,
erase algorithm and data schema with the Noxon blob and surrounding blocks.
Smallest physical task: capture two consistent flash and configuration reads,
including unknown regions and relevant readable user/factory rows, with board
identity and security metadata. Establish an offline rollback restore image
and explicit protected regions. Incorrect assumption: user settings, limits,
positions, identity/calibration or boot protection are lost; apparently
successful downgraded code may use unsafe or wrong settings.

**E — Evidence E5 and missing bootloader capture.** The silicon's SWD capability
and PA30/PA31 pin identity are not proof of an accessible board connector,
correct voltage or permitted read access. Smallest physical tasks: unpowered
continuity/route verification for SWDIO, SWCLK, MCU reset, ground and target
reference; then separately authorized read-only attachment with a compatible
debugger, target-voltage verification and security-state capture. Demonstrate
connect-under-reset/recovery on an engineering unit. Do not infer MCU reset
from a driver reset signal or power button. Incorrect assumption: the debugger
cannot connect when application USB fails; an attempted unlock destroys data.

**F — Evidence: no qualifying physical sequence or apfw2 release manifest.**
Smallest next task is an approved validation plan and a representative
non-production unit with A–E closed, not a production flash. Perform and
record the sequence below, including a deliberately unavailable application
and interrupted-update trials. Incorrect assumption: successful normal upgrade
is confused with recoverability after a broken vector, partial erase or power
failure. No simulator can mark this gate PASS.

## Risk-ranked unresolved failure modes

| Priority | Failure mode | Required containment |
|---|---|---|
| Critical | No independent entry after replacing app USB/startup | Verified hardware entry or demonstrated SWD recovery before replacement |
| Critical | Client erase/unlock damages bootloader, fuses or protected rows | Exact tool contract, measured protection, bounded writes and validated recovery backup |
| Critical | Reset/programming transition energizes motors or generates steps | Motor/power-stage isolation and measured safe reset/bootloader/application levels on the real revision |
| High | Config blob inside image destroyed or restored over apfw2 code | Immutable pre-upgrade snapshot, explicit linker/erase partition and tested rollback |
| High | Incomplete original backup or unknown upper-flash ownership | Full readable flash and relevant nonvolatile-region inventory, no assumption of blank tail |
| High | Wrong unit or region selected by VID-only updater | Board-bound manifest and explicit target identity; one target attached |
| High | Interrupted flash loses both app and entry mechanism | Fault-injection recovery on representative non-production hardware |
| Medium | Script prints success after failed verify, re-enumeration selects stale port | Independent exit/status checks, reconnect identity and full readback comparison |

## Proposed controlled validation sequence — not executed or authorized now

1. **Offline preparation:** obtain exact bootloader/BOSSA provenance, apfw2
   binary hash, linked address map and writer manifest. Define application,
   bootloader, state and fuse regions separately, along with permitted erase
   blocks. Prepare board-bound backup/readback comparison rules. Do not use an
   unreviewed vendor batch file as the acceptance controller.
2. **Feather rehearsal:** on a separately authorized Feather, using its own
   verified bootloader and GPIO-safe Feather-specific apfw2 build, test host
   version pinning, offsets, error reporting, backup/verify automation, USB
   re-enumeration, missing-application recovery and interruption handling.
   Do not run the original AutoPilot image on an intact Feather: its six QSPI
   conflicts remain unresolved. Feather results do not establish AutoPilot
   bootloader identity, protection, SWD access, motor containment, data layout
   or safe erase scope.
3. **Non-destructive AutoPilot evidence phase:** separately authorize physical
   inspection and interrogation. Motors/mechanics and power-stage energy must
   be contained under the bench checklist. Verify supply/reference requirements;
   do not assume USB supplies all board logic. Bind descriptors, device ID,
   firmware version, board/region and debugger identity to the unit. Read twice
   and hash accessible full internal flash, bootloader, known/unknown persistent
   regions and relevant user/calibration/protection/security information.
   Opening a 1200-baud port or resetting is not part of a read-only query phase.
4. **Recovery qualification on engineering hardware:** verify the physical entry
   mechanism and SWD recovery under conditions where application code does not
   supply USB or cannot start. Confirm no erase/unlock is required merely to
   obtain the saved data. Rehearse exact backup restore with the matched
   bootloader; stop if protection/locking differs from the expected contract.
5. **Controlled upgrade on that non-production target:** with A–E satisfied and
   an approved interruption/rollback plan, write only approved ranges. Verify
   actual readback plus invariant bootloader/fuse/state hashes. Check apfw2
   startup, safe outputs, identity, required update entry and non-motion
   functionality. Do not energize motors as part of this test.
6. **Controlled downgrade:** re-enter via the qualified route, restore the
   correct original application **and the same board's preserved Noxon state**
   with erase-block-aware ordering. Verify all intended bytes and protected
   invariants before booting. Do not overlay an old blob on replacement code
   or invent a full-chip image by concatenation and padding.
7. **Original-operation verification:** cold start and warm restart under
   controlled bench authorization; compare recorded original behavior,
   application version, non-motion queries and persisted settings with the
   pre-upgrade baseline. Ensure subsequent boot does not silently rewrite or
   reject restored data. An updater verify flag alone is insufficient.
8. **Interruption/failure qualification:** on sacrificial engineering hardware,
   interrupt representative erase/write/verify/reset stages and exercise a
   missing/nonfunctional application. Demonstrate recovery through the
   independent path and recheck all invariants and state after restoration.
   Do not deliberately interrupt bootloader/fuse writes: they are excluded
   from the application update contract. Record failure limits explicitly.

All six gates must pass before production-board replacement; gate F is closed
on representative non-production hardware first. A–E closure and an approved
F test plan authorize consideration of an engineering trial, not production.

Minimum authorization evidence: unit-bound full recoverable backups; readable
and verified protection/security state; demonstrated app-independent entry;
working debugger/access and a tested restore recipe; pinned host and both
firmware artifacts; reviewed flash/data partition; measured safe board state;
and a successful representative round trip and interrupted-update recovery.

Independent recovery equipment must include a SAMD51-compatible SWD debugger
with the correct voltage reference, verified physical connection to SWDIO/
SWCLK/reset/ground, a safe controlled supply, matched offline recovery images,
and operators with the tested procedure. A USB cable alone or an assumed
double-reset gesture is not independent recovery. If SWD cannot be used,
an alternative must itself be demonstrated independent of application code;
otherwise the production NO-GO remains.

Downgrade is reasonably **verified** only when readback matches the board-bound
original restore manifest, bootloader/protection/calibration invariants hold,
Noxon persisted state and required non-motion behavior match the baseline
across restart, and the independent recovery route still works. If restoring
the canonical vendor file plus user state, expect the whole-file hash to differ
from the canonical defaults in the state interval: compare code and intended
state separately, or compare to the actual pre-upgrade device snapshot. The
exact vendor file hash is neither necessary for retained user state nor alone
sufficient for a verified downgrade.

## APTrace execution and capability gaps

The normal research workflow was invoked. An initial seed `FUN_0000d4dc`
failed because that subrange is attributed to the SysTick function rather
than indexed under that name. This was corrected by retrying unseeded; the
run produced five evidence records and stopped at its five-step budget with
NVMCTRL structural results. Artifact:
[`reversible-update-2026-10-19.json`](../../research/runs/agent/reversible-update-2026-10-19.json).
Proposed/session structural claims do not constitute physical gate passes.
Read-only Ghidra xrefs, disassembly/decompilation, the NVM census query and
five direct CLI simulations supplied the bounded evidence above. No updater,
serial port, physical debugger, environment installation or network service
was invoked. The local reference-source path lookup failed; no source was
downloaded as a substitute.
All five saved-evidence checks passed (`bounded-evidence-checks.json`); these
validate the bounded simulations and default blob observation, not the six
physical release gates.

| Gap | Impact / observed evidence | Likely cause and needed capability | Priority |
|---|---|---|---|
| Missing target bootloader/live state | Cannot establish identity, protection or independent entry | Missing device/vendor evidence; authorized capture and hardware validation | High |
| Missing pinned BOSSA implementation evidence / public host-PE workflow | Cannot prove erase/protection/verify behavior from `bossac.exe` hash | Obtain matching source/version evidence; supported host-binary inspection would require APTrace development | High |
| Reset/peripheral simulation boundary | Memory stores observed, no actual reset/re-enumeration or power-failure model | Existing concrete engine does not establish real bootloader/hardware outcomes | High for physical gates |
| Missing apfw2 release/map/data contract | Cannot assess overlap or touch-reset compatibility | Supply existing release artifacts for read-only analysis; not implementation work | High |
| Controller seed attribution and bounded synthesis | Failed seed and structural-only retry cannot answer six gates alone | Use indexed functions and objective-bounded relations; improve coordination if needed | Medium |

Existing APTrace can continue static reset/NVM analysis and inspect a supplied
target bootloader or release layout. New physical evidence is essential for
A–F closure; no source-code change to APTrace can substitute for it. A separate
development task would be needed for unsupported host-tool analysis or richer
failure simulation. The stopping objective is met by the defensible **NO-GO**
and the gate-specific evidence/validation requirements above, not by a
speculative flashing command.

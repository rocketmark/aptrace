# Vendor bossac.exe: Gate B investigation

2026-10-19; inspected revision `4507828c27f6c0312816a47dde3f0872a664bd98`.
Decision: **NO-GO remains.** Gate A/B/C remain PARTIAL; D/E/F remain BLOCKED.
Result: **partial, blocked at host-binary analysis**. The exact executable is
identified, but its addressing/erase/protection implementation was not recovered.
The requested stopping objective of establishing exactly what it does is not
achieved by the available APTrace interfaces. This limitation is a finding,
not evidence that its behavior is safe or that it matches another BOSSA build.

This report supplements [the reversible-update assessment](reversible-firmware-update.md).
The [consolidated hardware/recovery handoff](vendor-bossac-hardware-handoff.md)
collects remaining acquisition and validation work into one packet. No hardware,
serial port, debugger, reset, erase, flash, Noxon/apfw2 binary or production
update tool was operated or changed.

## Artifact identity and source provenance

Fresh metadata and hashes are in
[`inventory.json`](../../research/generated/vendor-bossac-2026-10-19/inventory.json).

| Artifact | Fresh observation |
|---|---|
| `research/firmware/vendor-package/bossac.exe` | 226816 bytes; SHA-256 `eaebd0b6ef980e464b1a6a5a50eee91f9d6202f51dae7d9f78779d18593121a9` |
| Architecture | `file` identifies PE32 console executable, Intel 80386, Windows, stripped to external PDB. This is file metadata, not analyzed control flow. |
| Version | **UNKNOWN**; no accepted version extraction, executable run or matching build provenance |
| Upstream relationship | **UNKNOWN beyond name/interface intent**; no version-matched source, byte/semantic comparison or reproducible source build was found |
| `update_firmware.bat` | 1672 bytes; SHA-256 `41005f6a4a2165928538fd33cdf43e1eb23a402caebafc0589dc474cd0667d6b` |
| AutoPilot868 image | 70768 bytes; SHA-256 `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3` |
| AutoPilot915 image | 70768 bytes; SHA-256 `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |

The two vendor applications still match their working copies. Provenance is
membership in the preserved local vendor package, not an independently
authenticated release signature, known upstream commit or target-device dump.
No modern/Homebrew BOSSA was substituted. A version string, if later recovered,
would still require matching code/build evidence to rule out vendor changes.

## APTrace execution and the demonstrated capability boundary

The normal controller was invoked with this host-executable objective and
ledger recording. It produced one documentary search, no claims, and stopped
after duplicate discovery queries: [controller artifact](../../research/runs/agent/vendor-bossac-2026-10-19.json).
It did not analyze PE code. The absence of an OPEN item in its final projection
does not close this investigation's outstanding question.

The public-interface probe and supporting source/metadata observations are
preserved in [interface-evidence.json](../../research/generated/vendor-bossac-2026-10-19/interface-evidence.json):

```text
python3 tools/ghidra/aptrace_ghidra.py status bossac
exit 1: error: unknown firmware key 'bossac'.
Known: autopilot868, autopilot915, mando868, mando915
```

Repository inspection establishes a broader limitation than a missing registry
entry: `tools/ghidra/aptrace_ghidra.py` fixes `PROCESSOR` to
`ARM:LE:32:Cortex`, uses `BinaryLoader` and seeds Cortex-M vectors.
Its CLI exposes no per-target PE loader/x86 language option. Adding only an
entry named `bossac` would not make this a correct PE import. The concrete
backend constructs ARM Thumb/M-class Unicorn machines; target loading and
Macaw policy likewise concern raw Cortex-M images. Source matching depends
on analyzed target evidence that is missing for this executable.

Ghidra's underlying PE capability is distinct from an exposed APTrace workflow.
No direct `analyzeHeadless` import, independent PE disassembler, Windows/Wine
execution, custom parser or source-matching script was used to replace that
missing workflow. No framework development or dependency installation was
undertaken. Local searches found the vendor EXE but no applicable versioned
BOSSA source/research. The expected separate apfw2 directory remains absent.

## What the script establishes, and what it does not

The numbered source is saved in
[`vendor-script-numbered.txt`](../../research/generated/vendor-bossac-2026-10-19/vendor-script-numbered.txt).
The script selects a raw product/region image, locates serial-port text by
`VID_239A`, attempts `mode <port>:1200`, waits five seconds, searches again,
then requests:

```text
bossac -i -d --port=%com% -U -i --offset=0x4000 -w -v %FILENAME% -R
```

It checks neither `bossac` exit status nor a readback manifest before printing
“Upgrade completed.” The second presence test uses the earlier `comport`
variable rather than newly discovered `com`. Product/region selection is user
input, not a cryptographically or device-bound identity check. Multiple devices
matching the VID can defeat its selection assumption. These are source-level
script findings; no Windows execution transcript was obtained.

| Question | Mechanically established now | Remaining implementation evidence |
|---|---|---|
| Address calculation / offset | Script passes literal `--offset=0x4000` | Parsing, offset units, flash-base selection, range checks, page rounding and actual protocol addresses |
| Erase | No explicit `-e` token in that invocation | Whether write implicitly erases, erase scope, alignment, conditional device branches and chip/bank erase behavior |
| Write extent | Selected AutoPilot file has 70768 bytes | Whether all bytes, padding, partial pages, skipped areas or read-modify-write are used |
| Verification | Script requests `-v` | Entire-range versus partial verification, padding treatment, mismatch handling and exit status |
| Application-only restriction | Intended destination begins at `0x4000` | Enforced lower/upper bounds, protection/fuse changes and bypass/error paths |
| Bootloader protection | Nothing measured | Client software checks versus actual BOOTPROT/BPDIS/locks/security state |
| Reset / entry | Script attempts touch before upload and requests `-R` after it | Exact host actions, monitor commands, failure ordering and actual device entry/reset |
| Failure / interruption | Script can print success without checking client status | Client retries, partial writes, rollback/atomicity, verify failure and protocol disconnect handling |
| Vendor modifications | Binary identity is pinned | Matched upstream commit/build and code comparison, including device-specific branches |

None of the unknown implementation cells can be filled with behavior from
modern BOSSA or from Noxon's **application** NVM functions. Those Cortex-M
functions describe application persistence, not this Windows flasher or the
target bootloader. No source addresses in this report are attributed to the EXE.

For the vendor procedure to work, the actual bootloader must support whatever
monitor protocol, addressing and flash operations this exact client uses on
this device. That compatibility requirement does not prove how the bootloader
implements erase, protects its own region, exposes readback or recovers from
an incomplete application. Host-side code recovery alone would not establish
the live protection settings or physical interruption behavior.

## Addressing, configuration and calibration risk

From file length and the script's requested placement, the **intended raw
application interval** is `[0x4000,0x15470)`. The existing application evidence
places Noxon writable configuration at `[0x12000,0x13001)`: all 4097 bytes
are inside that intended interval, at file offsets `[0xe000,0xf001)`.
The [prior persistence investigation](motor-config-persistence.md) and
[saved original-image dump](../../research/generated/reversible-update-2026-10-19/application-default-nvm.json)
establish an all-zero default blob for AutoPilot868, not a unit's user settings.

**Conditional consequence, not an EXE finding:** if this executable writes the
whole selected raw file at the requested offset without a preservation step,
it replaces the config with packaged bytes. Erase may destroy even more at
physical block granularity. No backup/migration/preservation step is visible
in the batch file; such a step inside the EXE or bootloader is **unknown**.
There is no before/after physical config capture proving preservation,
reinitialization or silent loss during a vendor update. Therefore vendor
configuration preservation must not be assumed, and actual vendor loss must
not be reported as already demonstrated.

Calibration/user/fuse areas are outside the ordinary application-file contract.
The prior report's application calibration reads and simulator placeholder do
not show whether this client ever changes such areas. MCU protection can
modify outcomes independently of requested offsets. Keep raw full-flash,
configuration and readable device-specific nonvolatile snapshots separate;
do not unlock, mass-erase, rewrite factory data or call an unavailable backup
“recoverable.” Bank selection, protection and actual erase granularity need
target evidence. No additional firmware simulation would prove these EXE or
physical-device behaviors.

## apfw2 comparison and proposed LID evidence requirements

No current apfw2 flash tool, linker map, release binary or flashing-contract
document was located. The local TMC5160 apfw2 guidance is a peripheral contract,
not a flash contract. Consequently no implemented apfw2/vendor compatibility
difference is verified. The following are proposed LID inputs, not claims that
apfw2 currently violates them, approved implementation changes or permission
to edit it:

| ID / concern | Evidence-backed requirement to resolve |
|---|---|
| FLASH-01 — identity | Pin the exact client and firmware hashes, image format, board/revision/region and expected bootloader capability evidence. Avoid name/VID-only selection. |
| FLASH-02 — addresses | Derive actual linked load/vector address and permitted half-open intervals from the candidate manifest; check offset/base application exactly once and reject out-of-range writes. Noxon's requested `0x4000` is a compatibility input, not a universal constant for every image format. |
| FLASH-03 — erase | Identify every affected erase block, including partial-page padding and any read-modify-write behavior; prove preservation outside approved intervals. Ban implicit unreviewed chip erase or protection/security changes. |
| FLASH-04 — state | Explicitly reserve/preserve or version/restore the Noxon blob and neighboring affected blocks. A larger replacement image cannot blindly share this range. Preserve the original unit's state independently of apfw2 state. |
| FLASH-05 — verification | Define full intended-image readback comparison, intended state comparison, invariant bootloader/fuse/calibration checks and mismatch handling. `-v` or exit zero alone is not the downgrade oracle. |
| FLASH-06 — reset | Separate application touch entry from app-independent recovery, specify actual reset/re-enumeration behavior and measured safe board levels. Do not infer the EXE's reset from an application's AIRCR implementation. |
| FLASH-07 — failures | Stop on nonzero/error/verify mismatch, retain logs and partial-write state, avoid unconditional success, identify the re-enumerated target, and qualify interruptions on non-production hardware. |
| FLASH-08 — reversibility | Bind backups and restore recipes to the same unit; compare original code and original state separately where the canonical image contains defaults. Demonstrate independent recovery before production replacement. |

## Updated release-gate assessment

No gate is promoted. New evidence is the repeated identity check, script audit,
explicit interface rejection and exposed-loader inspection; **not executable
control-flow recovery or a physical flash test**.

| Gate | Status | New evidence / remaining failure risk | Smallest next experiment and class |
|---|---|---|---|
| A | PARTIAL | Same EXE/script hashes; no version, target bootloader bytes or independent entry. App-only touch can disappear with a broken image. | Software: recover exact client/monitor contract. Then AutoPilot: collect bootloader identity and qualify independent entry; reset demonstration is a separately controlled physical test, not a read-only query. |
| B | PARTIAL | Fixed ARM/raw interface blocks PE analysis. Offset intent confirmed; actual erase/write/verify/protection paths remain unknown, risking bootloader or adjacent-state loss. | Software: supported PE/x86 import and bounded parser/flash-driver analysis or exact source/build match. Then read-only protection/geometry capture, followed by controlled erase/write sentinel tests on an engineering unit. |
| C | PARTIAL | Vendor/working application hashes match; no live installed-version or full-device backup. Correct raw placement does not restore unknown state/bootloader. | Read-only AutoPilot acquisition: two consistent unit-bound flash/state/bootloader reads and version/region record; controlled restoration afterward. |
| D | BLOCKED | Intended whole-file interval includes config. Neither EXE preservation/migration nor apfw2 partition is established. Silent data loss remains plausible. | Software: recover preservation paths and inspect actual apfw2 manifest. Read-only board acquisition: full original state; controlled before/after update and restore on engineering hardware. |
| E | BLOCKED | No new SWD/reset-access or security evidence; a locked or inaccessible target can defeat all recovery. | Electrical/physical inspection plus qualified read-only debug attachment; subsequently demonstrate app-independent recovery on engineering hardware. Do not unlock/erase to obtain the first backup. |
| F | BLOCKED | No client behavior proof or physical cycle/interruption recovery; a nominal command is not reversibility. | Software plan and release-artifact review first; controlled non-production upgrade, downgrade and interruption recovery only after prerequisites. |

Gate B cannot reach PASS solely by analyzing the host EXE: actual bootloader
semantics, geometry, protection and physical writes must corroborate it. Gates
A–F must meet their full requirements on representative evidence before a
production replacement. The handoff specifies one consolidated acquisition
bundle so missing evidence is not discovered piecemeal during flashing.

## Capability gaps and next APTrace work

| Gap | Impact / observed evidence | Needed capability or evidence | Priority |
|---|---|---|---|
| PE/x86 target import and query workflow | Public target rejected; hardcoded ARM language, raw loader and vector seeding make simple registration insufficient | Expose executable-format/language-aware import with preserved sections/imports/relocations, identity, reproducible disassembly/xrefs and bounded query outputs; separate APTrace development task | High |
| Host execution/protocol observation | ARM Unicorn does not model Windows process/serial APIs; no EXE runtime/error transcript | Supported isolated host/protocol analysis if static evidence is insufficient; do not execute the update procedure against hardware for discovery | High if needed |
| Source provenance/matching | No accepted version/upstream/build match | Supply pinned source/build provenance and compare vendor code, including device branches; a version string alone is insufficient | High |
| Missing apfw2 artifact | No actual flashing-contract comparison possible | Supply existing release/map/client/LID artifacts for read-only analysis | High |
| Target physical evidence | No bootloader/protection/backups/recovery qualification | Complete the consolidated handoff under future controlled bench work | High |
| Controller closure | One search, no claims, duplicate-discovery stop | Retain the blocked objective and route host-target capabilities explicitly when available | Medium |

The minimal next **software** step is closing the PE/source evidence gap,
not another Cortex-M replay or a speculative BOSSA command. The minimal next
**hardware** step is unit-bound backup and read-only identity/protection/access
acquisition using qualified procedures, not a write. No evidence currently
justifies increasing confidence that the original bootloader survives an
apfw2 upgrade, that user data is preserved, or that interruption is recoverable.
Production **NO-GO is unchanged**.

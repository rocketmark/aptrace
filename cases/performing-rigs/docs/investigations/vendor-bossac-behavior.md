# Vendor bossac.exe: Gate B investigation

2026-10-19. **Result: host PE/x86 analysis gap closed; flashing assessment
PARTIAL. Production NO-GO remains.** Gates A/B/C remain PARTIAL; E/F BLOCKED. The subsequent
[persistence reassessment](persistent-state-release-assessment.md) advances D
to PARTIAL under an intentional-default-reset requirement.
APTrace now imports the original Windows executable natively and recovers its
command parsing, offset forwarding, flash drivers, erase/write/verify and reset
paths. The examined code is consistent with upstream BOSSA 1.9; an exact
upstream build identity or absence of vendor changes is not established.
No Windows process, serial port or physical device was operated. Original
firmware, EXE, script, historical evidence and apfw2 were not changed.

This replaces the former capability-blocked conclusion, not its historical
artifacts. The [old interface/controller evidence](../../research/generated/vendor-bossac-2026-10-19/interface-evidence.json)
remains intact. See [release assessment](reversible-firmware-update.md) and
[physical evidence handoff](vendor-bossac-hardware-handoff.md).

## Identity, provenance and evidence level

New evidence is in [vendor-bossac-pe-2026-10-19](../../research/generated/vendor-bossac-pe-2026-10-19/).
Every executable query records arguments, input SHA-256, native loader policy,
Ghidra/script/provider/export identity, output bounds and result hash.

| Input / observation | Result |
|---|---|
| Preserved vendor `bossac.exe` | 226816 bytes; SHA-256 `eaebd0b6ef980e464b1a6a5a50eee91f9d6202f51dae7d9f78779d18593121a9` |
| Ghidra native import | 12.1.3; Portable Executable (PE); `x86:LE:32:default`; compiler `windows`; image base `0x00400000` |
| Initial structural inventory | 553 functions, 626 strings, 137 external symbols/imports, 3017 direct calls, 11513 instruction-origin data references |
| Embedded banner | `BOSSA) Version 1.9`, copyright 2011–2018 ShumaTech at `0x004330d8` |
| Vendor batch file | SHA-256 `41005f6a4a2165928538fd33cdf43e1eb23a402caebafc0589dc474cd0667d6b` |
| AutoPilot868 / 915 | 70768 bytes each; SHA-256 respectively `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3` / `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |

Evidence is **static Ghidra observation plus analyst interpretation**, not an
admitted/VERIFIED semantic claim, executed Windows behavior or a physical
flash transcript. Native instructions/data anchor the findings below;
decompiled C is a cross-check with explicit heuristic warnings. Missing or
truncated attribution is never treated as absence of behavior. In particular,
the large device function's instruction listing is bounded; it is not an
exhaustive instruction census. Native function queries identify their body
ranges, decompiler completion and independent output truncation flags.

## Recovered behavior and address anchors

The actual vendor command is:

```text
bossac -i -d --port=%com% -U -i --offset=0x4000 -w -v %FILENAME% -R
```

| Behavior | Evidence and interpretation |
|---|---|
| Option flags and argument destinations | [options-table.json](../../research/generated/vendor-bossac-pe-2026-10-19/options-table.json), native mapped bytes at `0x0042d080`, 32-byte records. `e`→`0x00438044`, `w`→`...45`, `v`→`...47`, `o` flag→`...48` and numeric argument→`0x0043805c`. `U`→`0x00438054` with optional numeric argument→`0x00438078`; lowercase `u` is a separate unlock option. |
| Numeric offset parsing | [parser-function.json](../../research/generated/vendor-bossac-pe-2026-10-19/parser-function.json), `0x0040e570`, constructs getopt options and stores `strtol(argument,NULL,0)` in the option's destination. Thus `0x4000` is parsed as hexadecimal, not a decimal string or file header. This parser does not add a bootloader offset. |
| Defaults / transport | [config-constructor.json](../../research/generated/vendor-bossac-pe-2026-10-19/config-constructor.json), `0x0040e100`, initializes operation flags/offset to zero, USB argument to one. `-U` selects USB-port handling; it is not unlock. [main-function.json](../../research/generated/vendor-bossac-pe-2026-10-19/main-function.json), `0x0042ae60`, selects the port, connects, identifies the device and then runs requested operations. |
| Operation order | Main checks `0x00438044` before `0x00407470` (erase), `...45` before `0x004074c0` (write), `...47` before `0x004079d0` (verify). All receive the numeric value at `0x0043805c`. It writes options and finally resets if requested. [main-cfg.json](../../research/generated/vendor-bossac-pe-2026-10-19/main-cfg.json) retains native edges, including incomplete computed transfers. |
| Offset/write calculation | [write-function.json](../../research/generated/vendor-bossac-pe-2026-10-19/write-function.json), `0x004074c0`: rejects non-page-aligned offset or offset ≥ total size; opens raw file, rounds file length to pages. Buffered path writes at `offset + bytesSoFar`; page path at `offset/pageSize + pageNumber`. No ELF/HEX relocation, partition map, bootloader preservation copy or config save is present in these inspected loops. |
| Size guard limitation | Write/verify compare file page count against total device page count, not against remaining pages after the offset. This is not a demonstrated complete host-side `offset+length` guard. Driver/monitor bounds still matter; do not use this client as a general interval validator. |
| Explicit `-e` | [erase-function.json](../../research/generated/vendor-bossac-pe-2026-10-19/erase-function.json), `0x00407470`, dispatches `eraseAll(offset)` and disables automatic erase. The vendor batch omits this option; omission does not disable write-time erase. |
| Device branch | [device-function.json](../../research/generated/vendor-bossac-pe-2026-10-19/device-function.json), `0x004089a0`: reads CPU/device identity, including DID at `0x41002018`, then branches among devices. ATSAMD51x19 calls constructor `0x004035a0` with `0x400` pages, size `0x200`, SRAM arguments `0x20004000`/`0x20008000`. This is a conditional target path, not observation that the live AutoPilot reports that DID. |
| Virtual driver linkage | [d5-constructor.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-constructor.json) sets vtable `0x00436ae8`, auto-erase field at object `+0x88` to one. [d5-vtable.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-vtable.json) records native bytes: slots `+0x20`→`0x004038c0` eraseAll, `+0x60`→`0x00403970` writePage, `+0x68`→`0x00403910` writeBuffer, `+0x5c`→`0x00403ac0` writeOptions. These pointer-derived entries were explicitly passed to Ghidra's native transient function discovery. |
| Implicit erase during writes | [d5-writepage.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-writepage.json), `0x00403970`, checks auto-erase and `page & 0xf == 0`, then calls `0x00403800` for 16 pages. [d5-writebuffer.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-writebuffer.json), `0x00403910`, checks auto-erase and `(dst/pageSize)&0xf == 0`, then erases the requested chunk before calling the base buffer writer. Instructions include the guards, conditional edges and direct erase calls, not merely an erase-related string. |
| Erase geometry / protocol | [d5-erase.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-erase.json), `0x00403800`: erase unit = page size × 16, start must align, end rounded up; writes NVM address `0x41004014` and command 1 through `0x00403740`. With the SAMD51x19 arguments this is `0x2000` bytes. [d5-command.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-command.json) waits ready and checks command errors. |
| Extended erase | [d5-eraseall.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-eraseall.json), `0x004038c0`, uses extended SAM-BA chip erase if advertised, otherwise erases `totalSize-offset`. [samba-chiperase.json](../../research/generated/vendor-bossac-pe-2026-10-19/samba-chiperase.json), `0x00402900`, formats `X%08X#` with the offset. A monitor's acceptance/implementation is independent evidence. This explicit erase path is not requested by the vendor batch. |
| Buffered programming | [flash-writebuffer.json](../../research/generated/vendor-bossac-pe-2026-10-19/flash-writebuffer.json), `0x00402df0`, adds device base to relative destination and calls `0x00402a00`; [samba-writebuffer.json](../../research/generated/vendor-bossac-pe-2026-10-19/samba-writebuffer.json) emits the `Y` buffer/destination protocol and checks responses. Buffer capability changes the path; static evidence cannot tell which the installed bootloader advertises. |
| Last page | Buffered write pads the final short buffer with zeros and rounds its programmed size to page size. The page-at-a-time path passes the short byte count to loadBuffer, then writes a full page; the untouched tail is not established here as zero or preserved flash. Neither path verifies erase-block padding outside the input length. |
| Verify | [verify-function.json](../../research/generated/vendor-bossac-pe-2026-10-19/verify-function.json), `0x004079d0`: validates offset, compares at offset-derived page addresses. Uses cumulative checksum when advertised, with readback/byte comparison on checksum mismatch; otherwise page readback/byte comparison. It checks the file's bytes, not bootloader/config preservation or all padded/erased bytes. CRC agreement is not unconditional full byte readback. |
| Failure/reset | Main returns 2 for verify failure before normal reset; success returns zero. [reset.json](../../research/generated/vendor-bossac-pe-2026-10-19/reset.json), `0x0040d1f0`, device class `0x11` uses write of `0x05fa0004` to `0xe000ed0c`. This is a host request, not proof of re-enumeration, recovery or safe board outputs. No full Windows I/O/error-path execution was performed. |
| Protection/options | [d5-options.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-options.json) can erase/write user row `0x00804000` for dirty changed BOD/BOR/lock options and issue security command for a dirty security request. Main gates those setters on separate flags absent in the vendor command; default dirty bits are cleared. This is conditional static evidence, not an all-path proof that fuses cannot change. [d5-security-read.json](../../research/generated/vendor-bossac-pe-2026-10-19/d5-security-read.json) simply returns zero: printed security false is not a live security/protection measurement. |

**No hard lower bound of `0x4000` is enforced by the inspected write/verify
checks.** The configured offset steers this invocation above the bootloader;
it does not constitute hardware protection. Other options/inputs can request
other offsets. Actual BOOTPROT, bank selection, unlock/security state, monitor
semantics and physical erase outcomes remain unknown.

## Original image and state consequence

For the 70768-byte raw images, the requested file interval is
`[0x4000,0x15470)`. On the recovered SAMD51 geometry it spans 139 pages,
ending at `0x15600` after page rounding. With default write-time erase and
successful operations, the affected erase-block envelope is
`[0x4000,0x16000)` for both inspected programming paths. This envelope is an
arithmetic consequence of the recovered host driver and stated device/
capability assumptions, not a measured device modification.

Noxon configuration `[0x12000,0x13001)` is wholly inside the input file; its
block `[0x12000,0x14000)` is inside that erase envelope. The normal raw-file
write loops supply packaged bytes there. Existing evidence records all-zero
packaged defaults for AutoPilot868, not the unit's settings. There is no config
backup/merge in these loops or the batch. **Successful programming by this path
would replace those settings with image bytes; omission of `-e` does not
preserve them.** Whether an actual unit has already lost settings during an
update has not been measured. Bytes after the image/page through `0x16000`
are also not protected by file-only verification.

## Relationship to upstream BOSSA

Pinned primary source: [ShumaTech BOSSA tag 1.9](https://github.com/shumatech/BOSSA/tree/b176eeef918fc810045c832348590595120187b4),
commit `b176eeef918fc810045c832348590595120187b4`.
Read-only source copies, original licenses, retrieval URLs and SHA-256 values
are in [upstream/provenance.json](../../research/generated/vendor-bossac-pe-2026-10-19/upstream/provenance.json).
They are comparison inputs, not an independent execution/lifting engine.

| Upstream source | Matching inspected binary structures |
|---|---|
| `bossac.cpp`, `CmdOpts.cpp` | Version/help, 18 option records, optional `-U`, numeric base-zero parsing, main operation order/offset arguments, verify-failure exit and reset placement |
| `Flasher.cpp` | Offset/page checks, buffered versus page writes, padding, checksum/readback verification, explicit erase disabling auto-erase |
| `Device.cpp`, `D5xNvmFlash.cpp` | SAMD51 geometries, constructor/vtable, default auto-erase, 16-page erase algorithm, write-time erase guards, NVM register/command paths, option dirty checks |
| `Flash.cpp`, `Samba.cpp` | Relative destination plus base, extended `X`/`Y` monitor operations and response handling |

This supports a **BOSSA 1.9-family implementation consistent with the pinned
upstream paths**, stronger than banner/name similarity. It is not a whole-program
semantic equivalence result or byte-identical reproducible build. The upstream
release listing has no 1.9 binary asset to hash-match; no vendor compiler/build
manifest was found. Unexamined paths and vendor patches remain possible.
Do not label the EXE “verified unmodified upstream BOSSA.”

## Execution, reproducibility and regression results

Use [reproduce.sh](../../research/generated/vendor-bossac-pe-2026-10-19/reproduce.sh)
from the repository root. It defaults to fresh temporary cache/output, imports
through APTrace, then runs the saved bounded native queries and ordinary
`aptrace-agent research` routing. The fixture and original-EXE acceptance tests
never execute Windows code. The [execution record](../../research/generated/vendor-bossac-pe-2026-10-19/execution.json)
and saved logs state commands, outcomes and encountered failures.

The normal host research journal chooses objective-related strings and follows
references within a 12-query budget. It records pending queries and stops with
`budget_exhausted`, not an assertion that the objective is solved; its claim
list is empty. Specific subsequent native queries ground the table above.
The former duplicate documentary-discovery stop no longer substitutes for
executable analysis. Native transient entry discovery closes missing vtable
function attribution without hand-decoding instructions or persisting guessed
boundaries into the project.

Development exposed and corrected mixed stack/memory-address parsing in xrefs.
An invalid explicit entry produced no native JSON; it is an error, not empty
successful evidence. Overlapping access to one Ghidra project produced a native
lock failure: queries on the same project must be serialized; acceptance tests
use isolated project copies. One broad-suite native fixture failed without the
explicit Java configuration and passed on recheck with it. No assertions were
weakened and no Unicorn/backend/security workaround was introduced.

## Remaining gaps and next work

| Gap / confidence boundary | Impact, observed basis and next work | Priority |
|---|---|---|
| Host semantic admission and exhaustive flow | Static journal has no admitted claims; computed virtual/control transfers and heuristic boundaries remain. Scoped native entry/data/CFG queries work, but complete symbolic Windows/serial execution and typed host claim/replay are not implemented. Develop only if the next bounded question needs them; never reuse ARM claim rules unchecked. | Medium |
| Exact build provenance | Banner and inspected semantics match 1.9 sources; no byte/build equivalence. Obtain vendor source/compiler/link flags or authenticated exact binary release for a stronger identity result. | Medium |
| Live monitor/device/protection | Host DID branches, `X`/`Y`/page algorithms are requests. Obtain unit DID/geometry, monitor bytes/capabilities, raw protection/fuse/bank state and duplicated backups. Then qualify actual erase footprint, below-offset invariants and recovery under a separately authorized bench plan. | High |
| State / calibration / rollback | Host loops overwrite the embedded config and can affect neighboring block bytes. Under the clarified default-reset contract, no dedicated local-settings migration/backup is mandatory. Validate default reconstruction and factory/identity/boot invariants; retain full recovery safeguards. | High |
| Missing apfw2 artifacts | No release binary/map/client/flash-state contract is available here. FLASH-01..08 remain requirements: pin identities, interval validation, erase envelope, state preservation, verification oracle, reset/recovery, failure handling and unit-bound reversible restore. No apfw2 change is implied. | High |

Gate B's **software-analysis prerequisite is now satisfied for these inspected
paths**. Gate B itself remains PARTIAL: physical bootloader protection, actual
erase behavior and recovery still lack independent evidence. A/C remain PARTIAL; D is now PARTIAL under the
[subsequent persistence reassessment](persistent-state-release-assessment.md),
and E/F remain BLOCKED. The next hardware step is qualified read-only
identity/protection acquisition and unit-bound backups in the consolidated
handoff, not running the vendor batch. Production **NO-GO is unchanged**.

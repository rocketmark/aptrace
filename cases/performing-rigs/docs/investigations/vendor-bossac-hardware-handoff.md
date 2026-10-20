# Consolidated AutoPilot backup, recovery and flashing-validation handoff

Companion to [the vendor utility investigation](vendor-bossac-behavior.md) and
[the six-gate assessment](reversible-firmware-update.md). Plan only: no device
operations were performed. Production remains **NO-GO**. This is one initial
acquisition packet for Nathan/technician planning, not authorization to run the
vendor batch file or send unreviewed monitor commands.

Current state contract: [the persistence reassessment](persistent-state-release-assessment.md)
advances D to PARTIAL. Local settings do persist, but the required downgrade
may intentionally reconstruct packaged defaults. A dedicated Noxon settings
export/migration or exact settings restore is not mandatory. Full recoverable
backups and factory/identity/protection invariants remain separate safeguards.

## Software preflight — complete without an AutoPilot

The pinned EXE/script/images now have supported native PE analysis: its banner
is BOSSA 1.9 and relevant inspected paths match upstream 1.9 sources, without
exact-build proof. Retain that evidence and obtain the unit’s monitor capability
branch and exact-build provenance if available. SAMD51 writes implicitly erase
16-page blocks; successful raw programming replaces the embedded Noxon blob. Obtain the actual apfw2 release binary,
linker map, format, client version/command, flash/erase manifest and persistence
contract. Resolve FLASH-01..08 in the companion report; FLASH-04 now permits
intentional local-settings reset and requires factory/identity invariants, not
a mandatory settings migration/export mechanism. Review host commands
for side effects before calling any query “read-only.” An unknown `-i`, help
flag or port-open sequence is not approved merely because another BOSSA
version uses it for information.

Prepare a board-bound manifest with these result fields and actual values
(leave unavailable fields explicitly UNKNOWN, with reason):

- Unit identifier, product, board revision, MCU marking, radio region,
  installed application version and baseline non-motion behavior.
- Client/probe/driver versions and hashes, operating system, USB device
  path/VID/PID/serial and interface descriptors, bootloader version/capabilities.
- Power arrangements, logic reference voltage, containment/isolation setup,
  connection photos and verified SWD/reset pin-to-pad map.
- Every captured memory range: start, length, address space, read method,
  access width where relevant, two read hashes, acquisition state/time,
  and whether application/NVM state was quiescent.
- Raw geometry/protection/security register values with their decoded meaning,
  bootloader/flash/state/factory-row captures, exceptions and unreadable ranges.
- Independent entry/recovery method and required tools; exact tested limits.

## One AutoPilot acquisition session: electrical checks and read-only evidence

| Item | Specific observations / queries to collect | Artifact and gate coverage |
|---|---|---|
| Board identity | Photos of unit label, MCU/package, board revision, relevant connectors and accessible pads; identify AutoPilot versus Remote and 868/915 variant | `identity/` photos and `unit.json`; A/C/E |
| Safe electrical access | With power off, map PA30/SWD clock and PA31/SWD data from the actual package to accessible pads, MCU reset, ground and target reference. Distinguish MCU reset from driver-reset and power-button nets. Record continuity results and probe access limits. Determine a valid logic power source and motor/power-stage containment before powered attachment | `electrical/` annotated pin map, measurements and equipment; E/F |
| Existing USB state | Capture descriptors, interfaces, serial identity and baseline enumeration in the current working state; note every connection/power event. No 1200-baud touch or reset is part of a read-only query | `usb/` raw descriptors and timestamped logs; A/C |
| Debug/security availability | Use a qualified non-programming/non-unlocking attachment procedure. Record debugger identity, target voltage, connection mode and all access restrictions. Do not let tool defaults auto-erase, recover, reset or write fuses | `debug/` logs; B/C/E |
| Silicon/geometry/protection | When safe readable access is established, collect DSU.DID `0x41002018` (32-bit), DSU.STATUSB `0x41002002` (8-bit), NVMCTRL.PARAM `0x41004008` (32-bit), STATUS `0x41004012` (16-bit), RUNLOCK `0x41004018` (32-bit). Preserve raw bytes and applicable SVD/datasheet decoding, including PROT, BOOTPROT, BPDIS and bank selection. Obtain chip-erase-lock state by the applicable documented mechanism if readable; do not infer it from ordinary read access | `registers/` raw/decoded records; A/B/E |
| Full internal flash | If readable, acquire the reported 512-KB range `[0,0x80000)` twice with a qualified method. Include `[0,0x4000)`, the app, config, neighboring erase blocks and unknown upper flash. Do not assume unused space is blank | `backup/flash-read1.bin`, `flash-read2.bin`, range/hash manifest; A/B/C/D/E |
| Original Noxon state | Index `[0x12000,0x13001)` and surrounding `[0x12000,0x14000)` in the full recovery capture. Record the intentional settings-reset expectation and required default/non-motion acceptance. No separate settings export or exact previous-setting restoration is required; optional archival data must not be confused with mandatory factory provisioning. Resolve inconsistent reads | Region index in full recovery capture, default-acceptance logs; C/D |
| User/calibration/device-specific NVM | Acquire only readable, documented user/fuse/calibration areas for the actual part, with explicit range manifest. Existing app evidence includes reads around `0x00800080`; it is not a complete factory-memory inventory. Record security/protection/boot configuration separately. Factory/OTP captures are same-board records, not permission to rewrite or clone them | `backup/nonvolatile/` raw data, hashes and restrictions; B/C/D/E |
| Bootloader identity/capabilities | Capture the readable bootloader bytes and any documented non-writing monitor identity/capability response. If entering the monitor requires a reset, defer that portion to the next phase; do not silently treat the whole acquisition as reset-free | `bootloader/` bytes, hashes, decoded/source-match report and monitor log; A/B/E |

Addresses/widths above are **local SVD metadata**, resolved in the investigation,
not observed hardware values or a command sequence. Check applicability to
the actual device/revision before reading. Do not sweep peripheral registers
to “dump everything”; some registers have side effects. User-row addresses and
access rules must come from the applicable device documentation, not a guessed
generic SAMD address.

If protection, missing pads or inconsistent reads prevent acquisition, record
the failure and stop. Do not chip-erase/unlock, rewrite BOOTPROT or substitute
vendor defaults for inaccessible original data. Keep two independently
verified offline backup copies tied to this unit. A USB-port image read that
omits the bootloader or device rows is not a full recoverable backup.

## Separate controlled entry/recovery session — resets may be involved

Use a representative engineering unit with motor energy contained and the
backup acquisition complete. Record the documented physical entry sequence,
its reset/power timing and resulting USB identity; do not assume double-tap
reset or the power button implements it. Demonstrate entry independent of
application USB, and debugger recovery when the application does not start.
Capture SWD connect-under-reset behavior, security/lock consequences and all
changes caused by reset. Do not count a working application's 1200-baud
handler as the independent method.

Minimum independent equipment: compatible SAMD51 SWD debugger, verified pad
access and fixtures, correct target-voltage reference, controlled valid supply,
documented safe board configuration, exact offline backups and the qualified
restore procedure. If a different app-independent recovery route is proposed,
demonstrate its full capability and limits before treating SWD as optional.

## Controlled write validation — non-production hardware first

Proceed only when client semantics, layout/state contract, readable backups,
protection and independent recovery have been qualified. Freeze the exact
host/firmware/board manifest. Capture:

1. Pre-write complete hashes and sentinel contents outside every permitted
   erase/write range, including bootloader and protected device information.
2. The host's actual erase/write/verify/reset protocol sequence, requested and
   actual address ranges, alignment, padding, tool status and failures. Resolve
   differences between host intent and bootloader implementation.
3. Readback of every intended byte, padding policy and factory/identity/boot
   invariants. Confirm intentional packaged-default replacement of Noxon local
   state and expected reconfiguration; exact previous-settings preservation is
   not the acceptance criterion. Record actual reset/power-cycle behavior.
4. apfw2 startup/non-motion verification, then downgrade to the correct
   canonical Noxon package with default local state. Check factory/identity/boot
   invariants, perform normal external reconfiguration, and validate documented
   default behavior across reset and power cycle. Do not require a settings
   migration/restore tool for this contract.
5. Representative interrupted erase/write/verify/reset and unusable-application
   tests on sacrificial hardware. Demonstrate independent recovery and repeat
   backup/state/invariant checks. Bootloader/fuse writes are excluded from an
   application update; do not deliberately corrupt them as an initial test.

Store raw logs, commands, hashes, readbacks, differences, timings and outcomes
in `validation/`, with an explicit PASS/FAIL/NOT_TESTED per requirement. Verify
failure handling itself; do not accept the vendor batch file's success banner.
No production write follows an unexplained byte, protection or device mismatch.

## Feather-first work and limits of transfer

Feather can rehearse host log capture, error propagation, its own safe
application-format/offset path, readback comparisons, its own independent
recovery and interrupted application updates, using a reviewed GPIO-safe
Feather build. It cannot establish AutoPilot bootloader identity/capabilities,
actual protection, erase scope, SWD-pad access, calibration ownership, motor
containment or Noxon state semantics. Do not install a Feather bootloader on
AutoPilot or run original Noxon firmware on an intact Feather while the six
onboard QSPI conflicts remain unresolved.

## Evidence package and release decision

Return one directory with `unit.json`, acquisition/validation manifests,
`identity/`, `electrical/`, `usb/`, `debug/`, `registers/`, `backup/`,
`bootloader/`, `validation/` and a SHA-256 manifest. Distinguish absent,
unreadable and untested data. Have the engineering reviewer reconcile this
single packet against gates A–F before requesting any follow-up measurements.

The first production replacement remains NO-GO until all six gates meet
their full requirements, including representative end-to-end/interruption
validation. A/B/C/D PARTIAL and E/F BLOCKED are not waived by obtaining a
matching version string or by a successful Feather update.

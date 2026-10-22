# Trigger-to-request campaign — 2026-10-21

[Report and matrix](../../../docs/investigations/trigger-misfire-failure-modes.md#targeted-request-campaign-an-overlooked-motion-initiation-path).

**Principal correction:** original trigger reload can initiate pulse generation
through channel-state1/profile-mode1 → main-loop profile service0x6338 →
rate start0x5f8c → timer enable0x5810 → live flag1 at0x5fa4. Neither the separate
phase arm nor a0x6fd8 distance-command call is necessary. This establishes
software motion initiation, not motor movement, physical readiness or timing.

## Reproduction and provenance

`commands.json` contains26 exact direct native commands and observed exit0
statuses. Run the commands individually from repository root, using the existing
venv/direct CLI context. Do not use a subprocess comparison wrapper or alter
security policy. Preserve this packet separately before rerunning, since commands
overwrite their own output files. No firmware, backend, harness implementation,
apfw2 or hardware change is involved.

The Remote builder's prior record state is disclosed: delta500, ramp field50,
timing source10000 and time-mode flag1. Original builder0x49c4 emits
`+2,1,1,0,98,1,0,50,1000,500,0,0|`. All `profile-*` AutoPilot runs consume these
bytes through the native RX ring after full reset, then MC4. No AP motor record,
arm, reference, channel state, filter or timer-start seed is used. Remote UI
record creation, paired RF delivery and physical program safety are not proved.

Common full-startup assumptions are inherited from Pass2: plain MMIO with
explicit completion/read-clear bits, fake tick every4000 instructions, PA22
startup handshake, modeled radio ID return0x12, PA02 selection, existing DWT
peripheral-delay stub0xcd34 and PC-timed RX delivery. ADC.RESULT values are counts,
not measured voltages. The waveform treatments change external ADC input only.
No physical revision is assigned to any hypothetical pulse pattern.

## Files and interpretation

- Named JSON snapshots are native execution results. Positive request witnesses
  stop at0x5fa6 after the original timer-enable and live-byte write; negatives
  and continuations stop at their instruction limit. All commands also retain
  stop-at0x6fd8; none reaches it. Exit0 is not product READY.
- `events-and-outcomes.json` extracts acceptance/start events and endpoint state.
  In the first six phase-arm probes, rate/timer/profile counts are **null**, since
  those addresses were not watched. Null is not a negative rate-start witness.
- `observations.json`:191/191 scoped checks, including byte-identical independent
  profile-held replay, no log drops/cap exhaustion, input controls, request
  counts, phase-arm0 and TC0 ENABLE. One initial check wrongly expected the
  hook-free Remote call to use AP's hooked execution mode; its correction and
  reason are retained. No firmware result or failing execution was suppressed.
- Native `.txt` queries resolve the main-loop branch, profile service, rate start,
  timer enable, W dispatch and Remote builders. `remote-auto.txt` is an initially
  clipped large UI query; omitted material is not used as evidence. `reload.txt`
  retains a semantic query failure (no function at6e4c); native reload-entry
  instructions from the prior packet resolve that tail path instead.
- `static-commands.json` records queries, including argument/address errors and
  selected pointer/string/xref observations. No new importer, decoder or solver
  was substituted for APTrace.
- `manifest.json` binds source/tool/report hashes to repository revision;
  `artifact-hashes.json` binds packet artifacts (excluding itself).

## Scope of controls

The initial `rate-*` controls preserve the previous delta-only zero-timing record;
its starts clamp to period20 and must not be described as a qualified trajectory.
The principal `profile-*` cases use the Remote-built nonzero timing/ramp record:
held, startup-active, low-side, X2 and filter-tail inputs start; inactive,
one-acquisition pulse and opposite-phase excursions do not. Repeated
sample-aligned excursions accumulate to one start; they are not a calibrated
contact-bounce generator or equal-energy counterpart to opposite-phase pulses.

Held and released continuations have one start through14M instructions. The
held22M extension also has one start and ends channel/profile1, live1, idle0,
phase-arm0; it has not completed/re-armed. No forced busy/idle clear, autonomous
IRQ schedule or counted movement is provided. The next transition is original
profile completion and restoration of event eligibility, with actual stage
thresholds checked before assigning a cause to the missing completion.

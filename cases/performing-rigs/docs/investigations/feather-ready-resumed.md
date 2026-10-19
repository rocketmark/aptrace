# Original AutoPilot / Feather: resumed minimum-READY investigation

2026-10-19, repository `d9440f5fc7eb8dcf412b4f50080cb8463b9ed4c1`.
Continues [the initial investigation](feather-minimum-ready.md) using the
[validated direct execution path](unicorn-runtime-failure.md).

## Result and meaning of READY

**Configured, command-responsive application operation is reproducible in
simulation without a motor-controller peripheral model.** The original
AutoPilot868 image completes setup after receiving a real-format `MC4`
configuration packet, repeatedly executes its actual Arduino `loop()`,
parses a subsequently supplied `&|` request and sends its firmware-built
`V01R39` response through the original outbound dispatcher and TX wrapper.
The two fresh positive replays are byte-identical.

This is substantially stronger than the old receive-loop criterion. It is
the firmware-grounded behavioral readiness established here: **configured
operation and servicing a read-only request**. No separately named vendor
READY flag, display state or acceptance predicate has been identified; if
“genuine READY” requires such a product-specific indication, that remaining
claim is **unverified**, not silently equated with the behavior above.
No physical minimum-hardware recipe or USB responsiveness is proven.

The concrete additional barriers discovered after the earlier five-hit boot
criterion are (1) PA22's later save/housekeeping behavior and (2) the `MC4`
protocol gate. No further CPU execution stall appeared in the configured
positive replay. The remaining evidence boundary for a hardware-faithful READY
claim is peripheral-valid radio delivery/readback and a grounded product READY
oracle: the current success still forces the ID comparison and injects RX
bytes into RAM. A known-good READY trace plus the same transactions delivered
through a supported radio model is the next experiment for that stronger claim.

Only AutoPilot868 was dynamically investigated in this continuation. AutoPilot915
was rehashed but was not replayed; the earlier sibling results are not promoted
to new operational-readiness evidence.

## Evidence and distinct milestones

All new runs and static outputs are in
[`research/generated/feather-ready-resumed-2026-10-19/`](../../research/generated/feather-ready-resumed-2026-10-19/).
[`replay-manifest.json`](../../research/generated/feather-ready-resumed-2026-10-19/replay-manifest.json)
contains each complete, directly invoked CLI command and its exit status.
[`observations.json`](../../research/generated/feather-ready-resumed-2026-10-19/observations.json)
indexes counts, final memory, response observations and snapshot SHA-256 values.

| Milestone | Original-firmware observation | Evidence |
|---|---|---|
| Processor startup / initialization | Reset `0xcc24` reaches setup `0x9464` | Four-way matrix, all runs from pristine machines |
| Startup input accepted | `0x69d8` reached after PA22-high wait | `pa22.json`, `both.json`; absent in `neither.json` and `id.json` |
| Radio identification accepted | Firmware resumes beyond `0x9dd4` with disclosed `r0=0x12` assumption | `both.json`; PA22 alone reaches probe but not post-init loop |
| Startup receive loop | `0x8960` repeats while setup flag remains 1 | Released-input runs; distinct from Arduino `loop()` |
| Configured application entry | Dispatcher store at `0x8718` clears `0x20000060`; setup returns at `0x94e4`; execution reaches `0x93fc` | `config-handoff.json`, stop at `0x93fc`, instruction 11880918 |
| Configured command responsiveness | 1305 entries at `0x93fc`, 684 at outbound dispatcher `0x9268`; subsequent `&|` produces `V01R39` at TX entry | `config-identity-operational.json` and identical repeat |
| Product-specific READY indication | No independently grounded predicate identified | Open semantic/evidence requirement |
| USB command response | No USB host enumeration/endpoint transaction delivered | Not demonstrated |

The positive operational runs stop at the **2000-watch-hit cap**, instruction
17960240, with `error=null`, `completed=false`. This is a bounded observation,
not an unlimited stability proof or a clean application exit. The reply is
observed at instruction 12095830: `0x8c10`, `r0=0x20003134`, bytes
`56 30 31 52 33 39 00` (`V01R39\0`). Further loop entries establish that
execution continues after that call; observation does not prove RF emission.
No motion command was supplied. A stop guard at known move-commit entry
`0x6fd8` was not hit. Motor-related initialization and monitoring code still
executes in simulation; this is not a claim that firmware never toggles pins.

## Necessary conditions versus sufficient modeled conditions

The common baseline is the existing profile's clock/SERCOM completion
assumptions, instruction-paced tick, DWT delay stub and calibration placeholder.
Only the listed boundary conditions differ in this table. Each matrix run
has a 1200000-instruction budget and no native execution error.

| PA22 / ID conditions | Observed outcome |
|---|---|
| Neither | Startup wait; no radio probe or receive entry |
| ID stand-in only | Same wait; ID stand-in never fires |
| PA22 high only | Startup exit, radio comparison reached once, then firmware's failure/delay path |
| Both, PA22 held high | 11 receive calls and two periodic TX calls, then zero-progress NVM erase loop |
| Both, PA22 released after startup exit | 190 receive calls and 38 periodic TX calls; identical fresh repeat |
| Released input, extended budget | 602 receive calls, 120 periodic TX calls by 3000000 instructions; no NVM erase entry |
| Released input plus `MC4` | Original setup flag clears and setup returns |
| Configured state plus `&|` | Original event dispatcher services version response; repeated operational loop |

PA22-high observations for >1799 ticks are needed to leave the tested wait;
this is a firmware elapsed-tick condition, not an instruction-count duration
or a physical timing measurement. Holding PA22 high forever is **not** a
minimal steady-operation recipe. The tested release occurs at `0x69d8`,
using `--force-mem 69d8:41008020:00000000`. This is an environmental input
transition, not a forced application flag or skipped firmware branch. Other
release times and input waveforms were not minimized.

The radio comparison requires the expected version response `0x12` on this
startup path. Forcing the returned CPU register is a sufficient simulation
stand-in, not proof that a real radio, SPI signaling, interrupt delivery,
frequency configuration or a one-byte responder is sufficient hardware.

The tested `MC4` packet is an existing Remote-produced format:
`MC420,2400,1,25,20,2400,1,25,20,2400,1,25,20,2400,1,25,|` (56 bytes).
It is configuration, not a movement request. All configuration flags are
written by the original dispatcher; the harness never clears the setup flag.
These particular field values are a sufficient example, **not proven minimum
or necessary values**, nor a validated no-motors configuration for a board.

## Additional blocker: PA22 hold and NVM geometry

The initial apparent “transport” stall was localized to **NVM housekeeping**,
not radio transport. `held-zero-geometry.json` captures `r0=0x20004148`,
`r1=0x12000`, remaining size `r4=0x1001`, and the object at `0x20004148`
containing zero at `+0xc`. Static `transport-wait-disasm.txt` shows the loop
at `0x98f4` subtracts that same `obj+0xc`; with zero, it never advances.
`save-wait-static.txt` and `housekeeping-disasm.txt` connect the path to PA22.
No synthetic transport success or new driver model was introduced.

The existing persistence dossier already derives `NVMCTRL.PARAM=0x60400`
from the target geometry. Supplying it in `held-nvm-geometry.json` removes
the zero-stride loop but produces **15 save/erase entries** in the same
budget. It does not solve the behavioral problem of a permanently held
input. Releasing PA22 avoids this save path in the tested runs.

`NVMCTRL.DONE` forcing is unnecessary for these released-input cases:
`release-no-nvm-done.json` reproduces 190 receive / 38 TX entries without it;
`operational-no-nvm-done.json` also reproduces the configured loop counts and
version response without it. No NVM geometry override is applied to the
released-input or configured positive runs. This does not establish that NVM
completion and geometry are unnecessary for later persistent writes.

## Additional gate: a receive loop can parse without replying

`preconfig-pending.json` injects `&|` at the startup-loop boundary. The real
RX path reaches `0x8a34` and dispatcher `0x8258` once, then leaves
`pending[5]` (`0x200025c1`) equal to 1. Across 621 receive calls, it never
reaches `0x9268` or returns a version response. Setup flag remains 1.

`identity-disasm.txt` confirms the `&` arm sets the pending bit; the existing
protocol dossier identifies `0x9268` as its consumer. The configured positive
run delivers `MC4` first, then `&|` at setup's return. The dispatcher clears
the setup flag itself, the outbound dispatcher executes, pending events drain
to zero, and `V01R39` reaches TX. Thus reaching a parser or counting receive
calls is an insufficient readiness check. A compatible configuration exchange
is an additional external protocol condition on this tested path, even when
no physical motor board is reproduced.

One initial identity experiment reversed the ring indices and consequently
did not dispatch. It is preserved as `released-identity.json`, not interpreted
as a firmware blocker. Existing documentation and `ring-static.txt` identify
read index `0x200024c0` and write index `0x200024c4`; corrected runs use them.

## Reproducible startup / configured-operation recipe

Use the literal direct commands in `replay-manifest.json`, rather than a
wrapper, shell redirect or modified backend. The smallest **tested sufficient
additions to the Feather behavioral profile** for configured response are:

1. Keep the profile's four clock-ready masks, SERCOM5/SERCOM2 SWRST-clear
   and DRE assumptions, calibration placeholder at `0x800080`, and DWT-delay
   stub `0xcd34`. No motor peripheral model or motor-device return override.
2. Provide PA22 high through the startup wait, then low at `0x69d8`.
3. Supply the existing radio-ID stand-in, `r0=0x12` at `0x9dd4`.
4. Supply the recorded `MC4` bytes through the real RX ring at `0x94b8`:
   buffer `0x2000245c`, read index zero, write index 56. Do not set application
   state flags directly. The input packet is a disclosed external stimulus.
5. For the read-only readiness check, supply `&|` at setup return `0x94e4`,
   resetting read index to zero and write index to two. Observe the actual
   `0x9268` → `0x8c10` version response and continuing `0x93fc` entries.
6. Use fake-tick period 4000 for the 56-byte transaction in the tested
   positive run. Period 20 suffices for empty startup polling but cannot be
   assumed sufficient for cumulative packet timeouts. Period 4000 is a tested
   timing assumption, **not a measured physical timing or minimum period**.

`NVMCTRL.DONE` forcing and a geometry override can be omitted for this exact
recipe, as directly replayed. Other common baseline assumptions were not
exhaustively ablated. This is not a proof of a globally minimal harness or
minimum physical peripheral inventory. A no-motors-specific configuration
packet and physically absent-device electrical readbacks remain unvalidated.

## USB and physical feasibility

The injected bytes enter a RAM ring after boot, not USB endpoints. The reply
uses the initialized mode-1 TX path, previously traced to SERCOM2/radio. No
host reset, enumeration, endpoint configuration, USB interrupt delivery or
end-to-end USB reply was exercised. **USB readiness remains unknown.**

`MT11112|` is firmware-produced but **not evidence that four motors exist**.
The inspected presence helpers extract bits 29/30 from virtual device reads;
zero-behavior MMIO lets this path report presence. Actual absent-device
responses on a Feather have not been modeled or measured. The trailing `2`
is the startup branch/result field, not a READY indicator. The new traces also
show periodic MT calls; earlier prose describing MT as strictly once per boot
is not an accurate description of this tested startup-loop execution.

**Do not run the unmodified image on an intact Feather.** Its PB10/PB11,
PA08/PA09 and PA10/PA11 outputs collide with onboard QSPI SCK/CS/IO0–IO3.
No simulator result establishes acceptable contention, flash integrity or
safe levels. No hardware isolation was performed or validated. PA22's tested
high-to-low stimulus cannot be replaced by a permanent 3V3 strap; any future
physical input stimulus needs direction/voltage verification in addition to
resolving all QSPI conflicts. Radio routing/accessibility and valid responses
also require new physical evidence. No physical bring-up is recommended now.

## Execution, regression evidence and capability gaps

The normal research controller was invoked with seed `FUN_00009464`, six
steps and ledger recording. Artifact:
[`feather-ready-resumed-2026-10-19.json`](../../research/runs/agent/feather-ready-resumed-2026-10-19.json),
ledger run `R-20261019T204429-d5ea1f`. It produced eight evidence records but
spent its budget on structural PORT work and did not establish READY. Session
`PROVEN` labels are not promoted to this report's dynamic conclusions. The
subsequent investigations used documented APTrace Ghidra queries and the
existing direct Unicorn CLI; no independent firmware interpreter was written.

The replay commands and expected observations above constitute regression
vectors. Fresh startup repeats have identical snapshot SHA-256
`261c2ea9868ba18075a1462260356003745dc7b7896ea04fd697247509b524ed`;
fresh configured-response repeats have identical SHA-256
`e8c3bfd4a344108e8d980151832d6593c77ef40c896873318914c40c0a7b90c5`.
Negative controls, input-release ablation, NVM ablation, pending-query control
and bounded configuration handoff are preserved separately. These are direct
CLI replay regressions, **not newly integrated framework scenario tests**.
All 12 mechanical checks of the saved replays passed; results and their scope
are recorded in `regression-checks.json` beside the snapshots. These check
observations and reproducibility, not a vendor READY oracle.
No backend, existing tests, profiles, security rules or firmware image changed.

| Gap / uncertainty | Impact and evidence | Needed next work | Priority |
|---|---|---|---|
| Peripheral fidelity | ID is CPU-forced; RX is RAM-injected; absent motors appear present | Existing static/dynamic tools can bound required transactions; a validated radio/absent-device model requires additional capability/evidence | High for physical sufficiency |
| Product READY oracle | Configured operation and reply are observed, but no independent product READY predicate | Known-good trace or authoritative observable criterion; compare without fabricating ready flags | High for stronger READY claim |
| USB host scenario | No endpoint path exercised | Supported host/endpoint stimulus and command-response replay | High for USB claim |
| Controller relevance | Eight evidence records, six steps, no readiness experiment selected | Use objective-bounded relations; improve experiment selection if still insufficient | Medium |
| Global minimality / physical validation | Only selected assumptions ablated; no actual board measurement | Further existing-CLI ablations and new routing/readback/isolation evidence | High before physical execution |

Stop here: configured command-responsive operation is reproducible under
explicit simulation assumptions; a stronger vendor-specific or hardware-valid
READY assertion remains at the evidence boundary above. No speculative extra
motor hardware, USB success, safe physical recipe or unconditional minimum
hardware claim is inferred.

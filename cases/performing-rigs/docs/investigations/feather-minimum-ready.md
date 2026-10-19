# Original AutoPilot on Feather M4: minimum startup and READY investigation

Date: 2026-10-19. Result: **partial; stopped at a concrete execution blocker,
not a demonstrated firmware READY blocker.** No board was flashed, firmware
changed, replacement firmware built, or physical motor operated. APTrace
implementation, profiles and framework tests were preserved.

## Answer and stopping boundary

The existing evidence establishes a sufficient **modeled receive-loop startup
recipe**, not the minimum physical hardware needed for READY. Within the
existing harness, PA22 high plus the disclosed radio-ID stand-in restores the
AutoPilot recipe's assumptions to the Feather profile. Historical runs of that
recipe reach repeated `0x8960` receive calls for both original images. Neither
that criterion nor `init_status=complete` verifies an application READY state,
a transmitted READY indication, USB enumeration, or USB command response.

Fresh replay cannot currently establish more: Unicorn 2.1.4 crashes with
SIGILL in host `init_cache_info`, called by `machine_initialize` →
`uc_init_engine` → `uc_mem_map`. A ten-instruction reset invocation fails
before creating its snapshot, as do the existing comparison and regression
suite. This is a host/backend initialization failure, **not** a faulting
original-firmware instruction. The precise reason that host instruction is
unavailable is unresolved; sandbox/host compatibility is a hypothesis, not a
confirmed cause. No additional peripheral is justified by this failure.

Stop condition: restore a working supported Unicorn execution environment,
then run the bounded discrimination experiment below. It would be misleading
to assert either that READY is impossible or that PA22 plus radio ID is the
actual minimum sufficient READY hardware.

## Evidence and milestones

Fresh static artifacts are under
[`research/generated/feather-ready-2026-10-19/`](../../research/generated/feather-ready-2026-10-19/).
Historical execution artifacts remain under
[`research/generated/feather-m4/`](../../research/generated/feather-m4/).
Fresh inspection confirmed original image SHA-256 values:

| Image | SHA-256 |
|---|---|
| AutoPilot868 | `6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3` |
| AutoPilot915 | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |

| Milestone | Observable evidence | Status |
|---|---|---|
| Processor startup | Reset entry `0xcc24`, data/BSS initialization, CPACR sequence; subsequent setup watch hit | Existing boot dossier and historical runs; no fresh execution |
| Hardware initialization | Clock/peripheral accesses, USB register accesses, setup entry `0x9464` | Reached under both historical profiles; accesses do not prove electrically correct peripheral operation |
| PA22 startup exit | `0x69d8` | Historical AutoPilot runs hit once; bare Feather runs do not hit in 4,000,000 instructions |
| Radio-ID dependency | `0x9dd4`, comparison against `0x12` | Historical PA22-only experiment reaches probe and fails; full recipe forces comparison input |
| Application receive loop | Repeated `0x8960` from setup's internal loop | Historical full recipe: six hits by instruction 403199 for each image; Feather: zero hits in 4,000,000 instructions |
| Normal READY | A firmware-produced, semantically identified state/output and continued progress | **Not established** |
| USB command responsiveness | Enumeration, configured endpoint transfer, command dispatch and corresponding reply | **Not established** |

Addresses above are AutoPilot868 reference addresses; sibling code addresses
must be resolved through the existing fingerprint remapper, not assumed.
The inspected historical comparison happened to record the same milestone
addresses for both images, with no remap gaps.

Fresh Ghidra output `startup-decompile.txt` shows `setup()` calls, in order,
`0x6968`, `0x610c`, `0x6190`, `0x4c20`, `0x4328`, `0x5d44`, and `0x7770`,
then enters its own loop. `ready-loop-disasm.txt` confirms at machine level:
after `0x7770` returns, `0x94b8` reads millis; `0x94c8` compares elapsed
time with 700, `0x94d0` calls `0x8c10` when elapsed >700, `0x94da` calls
`0x8960`, and `0x94de` calls housekeeping. Five receive calls do not require
that the elapsed-time transmit branch has executed. Arduino `loop()` at
`0x93fc` is a different milestone: setup only returns when its loop flag clears.

The literal at `0x94f0` points to RAM `0x20002548`, the periodic transmit
argument. Fresh `ready-output-decompile.txt` shows `0x7770` builds a buffer
starting `MT`, four detection-result digits, an additional digit, `|`, and
NUL; it also performs GPIO pulse loops and device reads. Thus neither its
entry nor a repeated receive call proves a READY message or accepted motor
configuration. `ready-buffer-writers.txt` lists four static writers and no
logged dynamic writes. Ghidra's inferred function ownership is imperfect
(the writer at `0x74b0` is attributed to `0x7770`), and the decompile of
`0x8c10` includes warnings; these are static leads, not dynamic verification.

## Minimum startup recipe: established scope and candidate

For **modeled receive-loop startup**, use the existing `AUTOPILOT_RECIPE`
resolved for the selected image. Equivalently, Feather's derived profile
with both of its dropped boundary assumptions restored has that behavioral
configuration. This is an assumption recipe, **not a peripheral emulator or
an approved physical wiring recipe**:

1. Load the unchanged image at `0x4000`, enter its reset handler; RAM
   `0x20000000` size `0x30000`, MMIO `0x40000000` size `0x4000000`.
2. Supply clock-ready bits at `0x4000140c:1`, `0x40001010:100`,
   `0x40001040:3`, `0x40001054:3` (masks hexadecimal).
3. Supply SERCOM5/SERCOM2 DRE at `0x43000418:4` and `0x41012018:4`,
   clear SWRST bit 0 on reads at `0x43000400` and `0x41012000`, and supply
   NVMCTRL DONE at `0x41004010:1`.
4. Advance tick RAM `0x200052ec` every 20 instructions; stub only the
   DWT delay helper `0xcd34`; map the zero-filled calibration placeholder
   at `0x800080` size `0x40`.
5. Supply PA22 high: seed `0x41008020` with `00004000` (little endian).
6. Supply radio identification: force `r0=0x12` at `0x9dd4` only.

PA22 must remain observed high for an elapsed interval >1799 ticks in the
polling path; a low read restarts the interval. The earlier initial high
read can also invoke `0x6952`, so a permanently high seed includes that
behavior. It does not establish that a hard jumper is necessary, or that
1800 instruction steps equal 1800 physical milliseconds.

The radio stand-in changes a CPU register after the transaction, not the
radio peripheral. Static `0x610c` shows a failed probe enters an endless
print/delay loop; it does **not** retry the probe in that loop. Successful
comparison proceeds to additional radio configuration. Passing identification
does not demonstrate working SPI, radio interrupts, RX/TX, or a physically
substitutable one-byte responder.

| Assumption combination | Necessary/sufficient evidence within existing model |
|---|---|
| Feather baseline | PA22 blocks progress in historical bounded runs |
| PA22 only | Historically exits startup wait, then radio failure; insufficient for receive loop |
| Radio only | Not executed here; code ordering predicts PA22 remains a blocker; prediction only |
| PA22 + ID, common baseline retained | Equivalent execution assumptions to historical successful AutoPilot recipe; sufficient for modeled receive-loop criterion, not verified READY |
| Remove common assumptions individually | Not tested; no claim that every one is necessary or minimal |

Real MCU clock completion, SysTick, DWT, calibration and SERCOM behavior
would replace the corresponding harness substitutions. The investigation
has not established an electrically valid bare-Feather realization of all
those conditions. No motor hardware is needed to obtain the historical
modeled receive-loop result; the simulator's missing motor behavior is not
proof that all real readbacks are irrelevant to READY.

## Regression execution and next discrimination experiment

Existing regression tests were requested through the documented interpreter:

```sh
tools/unicorn/.venv/bin/python3 -u cases/performing-rigs/test/test_feather_m4_profile.py
tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/feather_m4_compare.py --out-dir cases/performing-rigs/research/generated/feather-ready-2026-10-19/baseline
```

The profile derivation and pin-table assertions passed. The suite crashed
with exit 132 while constructing its first AutoPilot868 execution machine;
neither the execution regressions nor AutoPilot915 ran to completion.
`regression.log` preserves the partial output. The comparison likewise
exited 132 at its first AutoPilot868 run and produced no baseline snapshots.
Do not interpret an empty baseline directory as a passing comparison.

The reduced reproducer also exited 132 and produced no JSON:

```sh
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py --firmware cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin --entry cc24 --max-instructions 10 --out /tmp/aptrace-startup-check.json
```

`unicorn-host-crash.ips` preserves the corresponding host crash report.
No new executable regression was invented to bypass the broken backend.
New READY regressions remain **unimplemented**, since their observation
contract is not yet established. Required acceptance cases after recovery:

1. Replay the existing tests and comparison first; match image hashes and
   record complete assumptions, errors, watch overflow and instruction budget.
2. Run the four PA22/ID combinations with a shared fixed baseline. Observe
   `0x69d8`, `0x9dd4`, `0x94b8`, `0x94d0`, `0x8960`, and `0x93fc` separately.
   Keep enough watch capacity that receive-loop visits cannot stop execution
   before the >700-tick branch. Repeat each positive result from pristine RAM.
3. Capture `0x20002548` and TX arguments at `0x8c10`; watch firmware writes
   to that buffer and the motor detection flags identified from `0x7770`.
   Establish what output/state actually means READY; do not seed that state.
   If no such meaning can be grounded, obtain a vendor/known-good READY trace.
4. Remove common assumptions one at a time, then test combinations where
   dependencies interact; use real completion/interrupt behavior where an
   existing supported model exists. Preserve any unresolved assumption.
   A register-forced success is not a validated hardware response.
5. Only after this observable contract exists, encode the positive READY
   replay and the negative boundary cases as case regression scenarios.

For the positive candidate, the generic documented `run_concrete.py` can
express every listed recipe assumption, watches and memory dumps. No new
analysis engine is needed for that immediate experiment. Sibling remapping
and historical recipe handling already exist in `boot_recipes.py`.

## Separate USB-readiness assessment

USB peripheral initialization is historically observed before the PA22 wait;
this does not establish enumeration or an available application command port.
The case's existing status resolves IRQ80–83 statically through `0xcc14`,
RAM dispatch slot `0x200052e8`, thunk `0xc724`, and `0xc5cc`. Endpoint-handler
dispatch at `0xc6d8` remains unresolved in that evidence. No USB interrupt
delivery, host reset/setup transactions, configuration, bulk endpoint RX/TX,
or command-response trace was demonstrated here.

`observation_scenarios.json` offers boot and virtual-link scenarios, not an
end-to-end USB-host scenario. Virtual-link legs enter mid-firmware with seeded
state and stubbed helpers; their parser replies are not evidence of USB
responsiveness after reset. The existing boot dossier records mode selector
`0x2000006a=1` and RX RAM-ring selection after a successful modeled probe;
neither fact means that the ring has a verified USB producer.

USB acceptance must independently show host enumeration, endpoint
configuration, a documented non-motion request traversing the real RX path,
the expected dispatcher execution and reply through the real endpoint path.
USB cable connectivity on PA24/PA25 does not remove the earlier startup or
QSPI hazards. USB READY remains unknown even if application READY is later
demonstrated.

## Electrical safety and physical feasibility

**Do not execute the original image on an intact, powered Feather as a
physical trial.** This supersedes the earlier feasibility dossier's suggestion
to jumper PA22 and test whether the QSPI flash survives.

| AutoPilot output | Feather onboard QSPI connection |
|---|---|
| PB10 / STEP0 | SCK |
| PB11 / DIR0 | CS |
| PA08 / STEP1 | IO0 |
| PA09 / DIR1 | IO1 |
| PA10 / STEP3 | IO2 |
| PA11 / DIR3 | IO3 |

These collisions are locally sourced from the firmware pin map and the
pinned Adafruit variant, not measured on a physical unit. The earlier dossier
places the initialization before the PA22 blocker; this session did not
replay and timestamp the first conflicting write. Fresh static startup output
also contains GPIO pulse loops: a design without external motors still
executes motor-related pin activity. A stopped motor, absent motor board,
PA22 held low, or waiting at the radio check does not isolate onboard flash.

Clocking/selection can expose flash outputs against MCU-driven data lines
and can send unintended flash transactions. Actual contention current,
flash mode, chip-select waveform, corruption likelihood and damage bounds
are **unknown**. No evidence here supports safe brief contention. External
QSPI content corruption must not be conflated with corruption of MCU internal
bootloader flash; recovery details were not established by this investigation.

PA22 is a header input candidate for a current-limited/pull-up stimulus after
power, voltage and pin-direction validation; prefer a bounded resistor-based
stimulus over an unqualified hard strap. Its safety does not authorize
running the rest of the firmware. The radio solution needs independently
verified pin routing and accessible pads: PA15 is absent from the Feather
variant table, while PA16/PA17 are exposed. Table absence alone does not prove
that a pad is electrically unrouted or safe to attach.

Physical feasibility is therefore **conditional on hardware modification and
new electrical evidence**, outside this execution task: electrically isolate
the onboard QSPI device from all six conflicting MCU nets, validate the exact
board schematic/continuity and safe levels, and establish radio connectivity
and required responses. Merely disconnecting flash power is not demonstrated
safe because I/O can back-power an unpowered device. Holding CS high could
conflict with the original MCU DIR output and is not a safe substitute for
isolation. No isolation procedure, radio emulator or physical wiring is
validated here. An unmodified, intact Feather is not recommended.

## APTrace execution and capability gaps

Repository revision inspected: `7d8c44dd6711430c5ffed3fe985cd27322138712`.
The normal controller was used before bounded manual backend operations:

| Controller artifact in `research/runs/agent/` | Result |
|---|---|
| `feather-ready-2026-10-19.json` | One documentary search; duplicate discovery after correction; no claims |
| `feather-ready-startup-2026-10-19.json` | Seeded `0x9464`, eight steps, ten evidence records; budget exhausted after structural PORT work; no READY closure |
| `feather-usb-2026-10-19.json` | One documentary search; duplicate discovery after correction; no USB closure |

Runs and evidence were recorded through `--ledger`. Session `PROVEN` buckets
in the seeded run are structural census facts, not a verification of READY;
the proposed ledger claims were not silently promoted to runtime results.
Ghidra failed initially because LaunchSupport could not save Java selection
under the restricted user settings directory. Supported environment settings
`JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home` and
`JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home` after creating that
temporary directory allowed the normal APTrace decompile/disasm commands to
complete. No toolchain files were modified.

| Gap / category | Impact and observed evidence | Likely cause / needed capability | Priority |
|---|---|---|---|
| Host Unicorn execution failure (environment dependency) | Baseline, reduced reset and regression all exit 132 without a snapshot; host crash attached | Host initialization compatibility unresolved; restore supported backend and add a diagnostic that distinguishes host crash from target fault | High |
| Controller selection/termination limitation | Two searches terminate after duplicate queries; seeded run expends budget on PORT rather than READY experiment | Observed orchestration behavior; retain unresolved objective milestones and select bounded startup discriminators | High |
| No READY observation contract (missing firmware evidence) | Existing recipe counts receive calls; fresh static code has periodic output and detection flags whose READY meaning is not verified | Need firmware-produced state/output capture and semantic grounding, preferably a known-good external reference | High |
| Peripheral-model fidelity | ID forced in CPU register; zero-behavior MMIO, fake tick, delay stub, calibration placeholder | Existing harness assumptions limit physical conclusions; validated completion/transport models are needed for hardware sufficiency | High |
| No USB-host end-to-end scenario | Boot accesses and static IRQ edges cannot establish configured endpoints or response | Missing supported host transaction/endpoint model and regression path | High for USB assessment |
| No electrical validation | Pin collisions known, currents/modes/isolation not measured | New board schematic/continuity/waveform evidence, not a software inference | High before any physical execution |

## Recommended next work

Existing APTrace operations: restore the backend, reproduce comparison and
regressions, then run the READY discrimination experiment and bounded
assumption-ablation matrix above. This is the immediate next experiment;
do not add a speculative motor peripheral to overcome a host crash.

APTrace development, separately authorized: host-crash diagnostics, objective
milestone-aware investigation termination, validated peripheral responses and
USB-host scenarios. Do not silently replace those missing capabilities with
standalone analysis scripts.

New evidence: a grounded definition/trace of normal READY and the actual
Feather board's schematic, flash component state and isolation measurements.
Until then the minimum READY recipe and safe physical realization remain
unresolved. This report records a reproducible execution blocker rather than
claiming the requested READY result has been achieved.

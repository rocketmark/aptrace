# A: radio channel, reinitialization and Remote compatibility

2026-10-20; inspected repository `e08e7cc4dc86ad808f669fe99cb0836cab5e7540`.
**Result: the bounded software configuration/coordination contract is established;
RF operation, natural reconnection and A-specific checkpoint timing remain unverified.**

A is the RF CHANNEL selection: normal values20–25 correspond to displayed
channels1–6. Both devices request `band_base + (A−19)*300000` Hz. The bases
are864000000 for the868 build and915000000 for the915 build. Changing A
reinitializes the radio, rather than just editing a display or device address.
The Remote stages its local selection, sends `A<number>,|` five times on its
existing configuration, then reinitializes locally. This is a one-way retune
sequence, not a demonstrated acknowledged channel migration.

This closes the bounded A package in the [configuration plan](configuration-behavior-investigation-plan.md).
No D investigation, apfw2/framework modification, original-image change, RF
transmission or physical operation was performed. No claims were promoted or
ledger entries changed. Release gates remain A/B/C/D PARTIAL, E/F BLOCKED,
production NO-GO.

## Evidence and confidence

“Observed” denotes the specific original-code run under its disclosed fixture.
“Static” denotes native instructions/references; decompilation aids interpretation.
Neither is a new admitted/VERIFIED claim or hardware confirmation. Interpretive
names/units and missing joins are qualified below.

| ID | Evidence |
|---|---|
| N1 | [New packet](../../research/generated/a-radio-semantics-2026-10-20/), [commands/statuses](../../research/generated/a-radio-semantics-2026-10-20/concrete-commands.json), [observations](../../research/generated/a-radio-semantics-2026-10-20/observations.json), [provenance/static operations](../../research/generated/a-radio-semantics-2026-10-20/manifest.json). Native ranges,52 direct CLI probes including explicitly excluded diagnostics. |
| R1 | [Configuration assessment](configuration-behavior-investigation-plan.md), [persistence assessment](persistent-state-release-assessment.md), [motor persistence](motor-config-persistence.md): AutoPilot logical offset0x1a, shared staging/dirty/checkpoint mechanism, boot/default behavior. |
| R2 | [Protocol pipeline](protocol-pipeline.md), [auto-mode/plus](auto-mode-and-plus-command.md), [motor/reference investigation](motor-state-ownership-and-reference.md): virtual TX/RX boundaries, session handshake/reconnect and their qualified gates. Packet injection is not RF transport. |
| R3 | [AutoPilot variant audit](../replacement/autopilot-868-vs-915-audit.md) establishes the sole four-byte application-image difference. [Remote audit](../replacement/mando-868-vs-915-audit.md) previously left frequency configuration unresolved; N1 resolves its setup override. |

The manifest pins SHA-256 identities for all four original images and native
project/tool identities. Detailed868 discovery precedes the915 comparisons.
No full915 application equivalence beyond the cited ranges is asserted.

## Requested settings and units

Startup qualification (2026-10-21): [bring-up Pass1](autopilot-bring-up-pass1.md)
observes initial0x610c/0x9b20 before0x4c20 loads stored A. A full-reset
provisioned-A25 fixture requests864300000Hz from compiled A20, then loads25
into runtime RAM, without a second bring-up before first loop. The command
mapping below remains supported; startup application of the retained channel
and subsequent reconnect repair require a separate bounded follow-up.
That [Pass2 follow-up](autopilot-bring-up-pass2.md) now shows no further radio
request during extended setup or4985 configured loop entries; runtime25 can
remain requested at864300000Hz. Explicit A25 input requests865800000Hz. The
examined Remote silence/reconnect exchange does not demonstrate channel scan or
cross-channel recovery. Applied settings and actual peer communication remain
unverified; RAM-injected input is not proof that mismatched peers communicate.

| A wire/stored value | Normal Remote channel |868 pair request, Hz |915 pair request, Hz |
|---|---:|---:|---:|
|20|1|864300000|915300000|
|21|2|864600000|915600000|
|22|3|864900000|915900000|
|23|4|865200000|916200000|
|24|5|865500000|916500000|
|25|6|865800000|916800000|

These are requested center frequencies, not measured carriers. The old audit's
864/915MHz “center frequency” constants are **bases**, not the normal channel1
centers. The step is300kHz; neither A20 nor UI channel1 means868MHz exactly.
This is not established as pairing identity, addressing, encryption or link quality.

AutoPilot `0x610c` loads the selector byte at `0x20000069`, the base u32 at
`0x20000000` and constant300000. Native `0x611a..0x6120` passes the calculated
Hz value to `0x9d88`. The eight clean A-command runs cover every valid value
and invalid19/26, beginning with prior runtime23. The Remote's `0x7ba4` uses
the same arithmetic with selector `0x20000159`. Its `0x4560` helper maps
20→1 and25→6, both replayed. Both ends' endpoint requests are replayed for915.

The frequency setter `0x9b20` stores the requested Hz in radio-object `+0x28`
and computes `floor(Hz * 2^19 / 32000000)`, then requests three register bytes
at0x06/0x07/0x08 (SPI write addresses0x86/0x87/0x88). Native division constant
32000000 and the code's encoding ground the nominal frequency units. Direct
setter runs observe864300000→`D8 13 33`,865800000→`D8 73 33`. Quantization,
oscillator accuracy and successful register programming are different questions.

After the ID probe accepts0x12, initialization requests the following settings
independently of A. Remote/native counterparts match this call sequence.
Before that read, the probe configures the bus/CS path and, when the configured
reset pin is not−1, requests reset LOW, delay10ms, HIGH, delay10ms. This is
full radio bringup with an optional reset pulse, not simply a frequency-register
update. The native probe supplies these requests; the replay stubs their
peripheral effects.

| Request | Native evidence / confidence |
|---|---|
| LoRa sleep then standby | Probe calls `0x9b18` / `0x9b10`, requesting operation-mode values0x80/0x81. Register0x01 interpretation follows conventional SX127x LoRa semantics. |
| Frequency from table above | Probe calls `0x9b20`; units/encoding and endpoint writes established above. |
| FIFO TX/RX base0, LNA low bits set, AGC request | Probe writes0x0e/0x0f=0, read-modify-writes0x0c OR3, writes0x26=4. Raw requests established; not observed readback. |
| Spreading factor7 | `0x9bb0(object,7)`; writes the0x1e upper nibble and detection-register settings. Dimensionless SF interpretation follows conventional register semantics. |
| Bandwidth250000Hz | `0x9c14(object,250000)` selects index8 for0x1d upper nibble. Getter table at0x14020 explicitly maps index8 to250000. |
| Coding-rate parameter5, conventionally4/5 | `0x9cac(object,5)` writes `(5−4)<<1` to0x1d coding bits. The4/5 naming is register-convention interpretation, not an on-air measurement. |
| Power parameter17, output selector1 | `0x9d2a(object,0x11,1)` occurs in probe and again in wrapper; requests PA-related values0x4d=0x84,0x0b=0x2b,0x09=0x8f. Conventionally PA_BOOST nominal+17dBm; no calibrated/electrical power claim. |
| Payload CRC enable | `0x9cdc` ORs bit2 into0x1e; Remote wrapper performs the corresponding read-modify-write inline. |

The raw arguments, writes and arithmetic are firmware evidence. Chip-register
names and nominal dBm/CR terminology are engineering interpretation of that
driver pattern; no external source or physical radio was consulted. A does
not select different SF/BW/CR/power in the examined path. A complete packet-mode
contract, including sync word, header mode, preamble and reset defaults, is
**not** established by this initialization subset; untouched registers must not
be assumed to have known values merely because the chip-ID stand-in succeeds.

## Remote coordination and lifetime

`remote-menu.txt` and `menu-pointers.txt` tie the literal RF CHANNEL at0x1c9c6
to settings row7. Native `remote-edit-bounds.txt` permits edits strictly above19
and at most `20 + *0x2000019c`. Both actual reset-data witnesses initialize that
limit byte to5, giving20–25. This is independent of a motor channel selector.

| Event | Demonstrated/static transition | Limits |
|---|---|---|
| Remote confirms selection | `0xd218` case7 calls local store wrapper `0x6f7c(0x2d,A)` before building/sending the command. Wrapper stores a u32 in four byte planes at indices0x2d,+0x400,+0x800,+0xc00 through the dirty setter. | Native-stage replay produces low byte25 at0x2000350f and dirty1 at0x200038e3. This is staging, not a flash checkpoint or durability proof. |
| Remote emits command | `0xd42a..0xd460` builds `A20,|` / `A25,|`; five TX-wrapper calls at0x58a8, each followed by delay50ms, then calls0x7ba4. | Replayed from original handler entry with selected row/value and a clicked-button stand-in. TX/delay are opaque; byte sequence, five iterations and call order observed, not actual timing/delivery. |
| AutoPilot receives A | Dispatcher0x8258 parses a number, changes runtime byte only for20–25, stages retained/new value at logical0x1a, then calls0x610c unconditionally. | `a-command-*-clean` reaches the original probe with expected frequency and dirty1 from differing staged data. No RF/USB delivery is claimed. |
| Valid unchanged A | Same-value23 with staged23 keeps dirty0 but still enters bringup. | Reinitialization is not conditional on a changed byte. |
| Invalid command19/26 | Prior runtime23 retained and staged, then same reinitialization path executes. | This is not “invalid command has no effect.” Strict invalid-request rejection is an apfw2 design choice. |
| AutoPilot reinit success | Under declared peripheral stand-ins, probe/setup return; frequency shadow updated, transport selector0x20000018 cleared. | Nonzero0x20000018 chooses the Serial-object path in recovered I/O wrappers; clearing it is not a link-connected flag or proof of RX. A seeded phase-arm2 survives: no automatic motion disarm is established by A. |
| AutoPilot ID failure | Version stand-in0 leads to helper0x5d24, then0x612e's error loop displaying LORA ERROR and delaying1000ms repeatedly. Runtime/staged A already changed; normal post-success selector clear not reached. | Replay stops at error-loop entry. Helper has timer/config side effects, not a validated safe motor stop. No initialization retry, rollback or normal return exists in that bounded native failure branch. |
| Remote ID failure | `0x7ba4` calls0x7b9c and enters a tight nonreturning loop on probe failure. | Static branch, not a newly replayed full Remote failure scenario. No recovery promise follows. |
| Shared app checkpoint/reset | A setters dirty staging. Later shared save checkpoints can write the blob; boot readers consume stored values. | Existing persistence evidence supplies mechanism. No new A-specific save→full-reset round trip or exact automatic-save schedule was demonstrated. Before checkpoint, reset can recover the previous durable value. |

Native A entry also clears the RX-assembly byte0x20002329 and initializes
the numeric-parser cursor before parsing the value. The examined path does
not establish a whole application-session reset, a heartbeat refresh or peer
reconnection. Its FIFO-base requests and transport-selector clear should not
be treated as those stronger milestones.

The native UI witnesses' output bytes exactly match the AutoPilot clean-input
fixtures. This closes the software producer/parser relationship without
inventing RF delivery. The observed order is **stage Remote → transmit five
times → retune Remote**; AutoPilot retunes on the first received A. If that
first packet arrives and retune succeeds, later repeats may be on the old
frequency and unheard by AutoPilot. If none arrives, Remote can move alone.
Those are consequences of the recovered sequence, not measured packet-loss
results. No application acknowledgment or post-retune peer confirmation occurs
in this handler; full RF/session success and interruption recovery remain open.

R2's S/P configuration exchange and silence/reconnect paths are not channel
negotiation proof. The examined init callers are startup, settings confirmation
and the host command described below. No automatic scan/rollback was established.
Do not conclude that a5-second silence necessarily restores a mismatched pair.

## Startup, invalid values and the915 difference

| State | AutoPilot | Remote |
|---|---|---|
| Stored A source | Logical0x1a, staged byte0x20003160, flash byte0x1201a. | Local store wrapper index0x2d reconstructed across four byte planes. |
| Normal reload |20–25 retained. | With actual limit5,20–25 retained. |
| Invalid values | Fresh readers19/26→20; native default branch also stages corrected20. | Bounded loader reads18/26→20, **19→19**. Native0x7492 rejects values<=18, differing from the UI lower bound20.915 range instructions are the same. |
| Effect of retained19 | AutoPilot rejects it on normal boot. | Radio arithmetic uses base+0. The display helper separately returns3 for values<20, replayed for19; display is not evidence of the actual radio channel. |
| Runtime/durability | Command has immediate radio side effects before a checkpoint. | Local selection is staged before transmissions; no atomic durable agreement between devices is established. |

The stored19 discrepancy is a concrete software compatibility hazard under
that corrupt/nonstandard state: Remote and AutoPilot can initialize to different
frequencies. It is not evidence that production units normally contain19 or
that it caused a reported failure. apfw2 should validate coherently rather than
copy this off-by-one behavior or rely on displayed channel alone.

AutoPilot915's only image change is the data-source base value at0x14c40
(R3). For the Remote, both reset routines copy **864000000** from0x25248 into
RAM0x20000000.915 setup then explicitly overwrites it with915000000 at
`0xffc0..0xffc4`, from literal0x100dc, before the first radio bringup.
Native setup ranges and a three-instruction replay demonstrate the overwrite;
the two reset-data runs demonstrate the common initial value and limit5.
Reading only the common data constant would therefore give the wrong915 result.
This supersedes R3's unresolved Remote frequency-configuration conclusion.

`mando{868,915}-a{20,25}-bringup-request` and the AutoPilot915 endpoints agree
with the table, using disclosed initialized bases. These are composed setup/
bringup witnesses, not two whole paired-device startups. The Remote915 init
sequence/native call arguments match868 with relocated callees; no new full
packet-protocol equivalence is claimed. The same displayed channel/A packet
does **not** align different-band devices. A carries no band field here.

## Separate host retune path, not automatic recovery

Remote `0xc10c` contains a host/bridge path: after its own entry handshake,
completed host buffers beginning `$` go to `0x7c10`. That helper checks positions
1/2 for SC and sets `A = byte[3]−0x1d`, then reinitializes locally. Thus
`$SC1|` corresponds arithmetically to A20. It does not use the same validation,
local-store wrapper or five-packet A broadcast as the UI path.

This is static recovery/service-interface evidence, not a validated recovery
recipe: entry handshake, transport availability, invalid bytes and end-to-end
host access were not exercised. It is neither an over-RF peer request nor
demonstrated autonomous scanning. Reproducing an unvalidated service command
or its permissive input handling is not an apfw2 requirement.

## APTrace execution and capability gaps

Used APTrace's documented persistent Ghidra queries and direct Unicorn CLI,
with static-first discovery and targeted differentials. The missing mando915
cache was built using the existing public build operation; no tool/dependency
or security change was needed. No symbolic solver was necessary for this
bounded arithmetic, call-order and range question.

Bringup-success probes stub GPIO/bus/delay operations and return0x12 for every
radio-register read; this deliberately incoherent readback is sufficient to
observe requested calls and frequency writes, **not final modem register state**.
In particular, later read-modify-writes with that constant can overwrite earlier
modeled fields. Do not combine their write values into a claimed final physical
configuration. Endpoint frequency-setter runs avoid that readback issue. Remote
UI probes stub TX, delays and button reads; the native-stage control executes
the real local setter. Fresh boot-reader and loader-slice probes are labeled
accordingly. No successful communication, physical RF, timing or safe active
motion transition is established.

| Gap/failure | Evidence, impact and next work |
|---|---|
| Write-watch instrumentation changes execution | The initial **A25** `a-command-25-request` probe skips native0x97a0/0x977c and enters0x97a4, yielding no staged change despite runtime25. The single-variable `a25-control-{no-write-watch,write-watch}` pair reproduces this by adding only a write watch on0x20000069: stage25/dirty1 becomes stage0/dirty0. A20 controls do not show the discrepancy. Clean replays reach the real setter; the initial watched matrix remains diagnostic. The [2026-10-21 tooling investigation](write-watch-instrumentation.md) isolates a native Thumb/memory-hook interaction, including with a no-op callback, and adds automatic instruction-boundary execution. Repaired A20/A25 agree across watch and dirty-tracking controls. This corrects observability; the historical failing packet is preserved. |
| Incomplete MMIO map in first failure probe | `a20-radio-id-failure` faults at0x41018044 outside default mapping. Repeating with the documented0x4000000 MMIO span reaches the intended error-loop entry. Invocation/fixture correction, not a firmware failure. Both snapshots retained. |
| No faithful radio/RF model | GPIO/SPI stand-ins and direct packet boundaries cannot show final hardware state, peer reception or loss/recovery. Existing documented model limit. Validated register/peripheral or transport modeling would require separate capability work; physical link evidence is a distinct dependency. High for hardware compatibility certification, not needed for the table of software requests. |
| Missing packet defaults and natural recovery join | Selected init calls do not establish all untouched/default packet registers or a complete reconnection after retune/loss. Existing tools can trace the remaining bounded TX/RX/default paths and inject selected loss/duplicate sequences; actual RF reliability needs new evidence. High before claiming drop-in Remote compatibility. |
| A checkpoint/atomic agreement not established | Native staging and fresh reads plus R1's shared save mechanism do not prove exactly when both A settings become durable or recover coherently after interruption. Existing tools can run selected checkpoint/reset/carry controls; no new framework is needed. Medium if persistent Remote compatibility is required. |

## apfw2 implications and recommended next work

For an unchanged Noxon Remote, retaining ASCII command parsing alone is
insufficient. apfw2 needs a compatible physical/modem transport or a validated
bridge, matching band/channel requests, the established framing and the
remaining packet-default contract. A generic868/915 radio configuration or
LoRaWAN transport is not established as a substitute.

| Retained compatibility requirement | Simplification / replacement choice |
|---|---|
| Map displayed channels1–6 / wire A20–25 to the correct band-specific Hz; match the modem requests above and resolve remaining packet defaults. | Use typed band/channel values and one validated mapping. No Noxon addresses, raw data layout or runtime base-overwrite idiom is required. |
| Accept the Remote's actual `A<number>,|` and tolerate its five sends and timing/order. Both peers must move to matching settings. | Make repeated same-channel requests idempotent where possible; do not repeatedly reset hardware merely to mimic an unchanged A. Preserve necessary wire behavior, not the implementation churn. |
| Handle the one-way transition and absence of an acknowledgment in the unchanged Remote UI sequence. | Track desired, requested/applied, persisted and peer-confirmed/unknown settings separately. Enhanced acknowledged negotiation requires a changed peer/bridge; it cannot be assumed from the legacy handler. |
| Validate startup/default/range behavior coherently and define recovery for interrupted/missed changes. | Reject invalid inputs without side effects; do not carry forward stored19/display3 mismatch, invalid-command reinit or an unbounded LORA ERROR loop. Do not claim automatic scan/fallback without specifying and validating it. |
| Preserve application/session safety while the communications subsystem is unavailable. | Explicitly specify motion quiescence/arming policy and failure state for reconfiguration. Do not assume A disarms motion. Keep USB/service observability independent of a radio-success flag; avoid copying the legacy selector clear as an architectural requirement. |
| Store the selected channel intentionally if persistence is required. | Use a versioned validated record and an explicit checkpoint policy. Do not clone the four-plane Remote layout or assume staging means durable coordinated commit. |

These findings refine the planned communications architecture: a compatible
legacy-RF adapter must own band/modem configuration and channel transitions,
not just forward strings. They do not require the rest of apfw2 to adopt Noxon's
radio globals or error loops. A new transport remains a product choice, but
transparent compatibility with the original Remote then requires a bridge or
peer change; it has not been demonstrated by these software replays.

The next **existing-capability** compatibility investigation should close only
the retained packet defaults/TX-RX mode and a selected channel-change loss/reset
sequence. The separate [write-watch tooling task](write-watch-instrumentation.md)
now supplies a tested execution workaround and bounded historical evidence audit.
Actual device readback/RF reliability and durable paired
recovery need new evidence. D remains unstarted; no broader radio census is
needed to use this A contract.

# D: reported serial number and replacement compatibility

2026-10-21; repository `f7640888d1811c8f1649163ca7ea54f183ac04d7`.
**Result: D's demonstrated product role is the AutoPilot serial number shown
by the Remote. Its original provisioning producer remains unresolved.**

D is returned unchanged in bulk-report **field9**, parsed into Remote RAM
`0x20001078`, and displayed beside the literal **SN:** as six decimal digits
when the session/visibility flag and value are nonzero. It is dimensionless
identity/display data in this recovered path. No motion, trigger, radio-setting
or calibration consumer was found in the bounded evidence reviewed.

**Correction to the plan:** the divide-by10 is applied to a different source,
`0x200000ec`, in field1. It is not D's wire scaling. The first-field range check
and the separate field8 cache/local-store path must not be attributed to D.

**Recommendation:** preserve field9's position and numeric representation for
the existing Remote. Use0 if no serial identity is provided, or an intentionally
assigned1–999999 serial for a conventional six-digit display. A user-configurable
D setting and persistent D storage are **not established functional requirements**
for the retained motion/trigger/communications features. If legacy provisioning
clients or stable displayed identity are required, implement an opaque identity
write/read contract and stable storage/metadata deliberately; the original
client workflow and physical uniqueness must not be assumed.

This completes the bounded D meaning package from the
[configuration plan](configuration-behavior-investigation-plan.md). It does not
start the durability/defaults package, change apfw2/APTrace/original images,
access hardware or promote claims/gates. A/B/C/D remain PARTIAL, E/F BLOCKED,
production NO-GO.

## Evidence and confidence

“Demonstrated” means original-code observations under the stated fixtures or
the cited native instruction relationship. It is not a newly admitted/VERIFIED
claim or proof that every aliasing consumer has been found.

| ID | Evidence |
|---|---|
| N1 | [New evidence packet](../../research/generated/d-meaning-2026-10-21/), [concrete commands/statuses](../../research/generated/d-meaning-2026-10-21/concrete-commands.json), [native query commands](../../research/generated/d-meaning-2026-10-21/static-commands.json), [checks](../../research/generated/d-meaning-2026-10-21/observations.json), [provenance](../../research/generated/d-meaning-2026-10-21/manifest.json). |
| R1 | [Persistence assessment](persistent-state-release-assessment.md) and [motor persistence](motor-config-persistence.md): established D1234/save/fresh-reset result and storage representation. Those mechanisms were reused, not investigated again. |
| R2 | [Protocol pipeline](protocol-pipeline.md) and [existing virtual-link scenario](../../scripts/virtual_link.py): actual11-field report and10-field Remote parser, framing and RF ring boundaries. |
| R3 | [A investigation](a-radio-reconfiguration.md): host/bridge forwarding path, variant-specific layout and write-watch instrumentation limitation. [AutoPilot variant audit](../replacement/autopilot-868-vs-915-audit.md): only the radio-base word differs between application variants. |

The manifest pins all four original images and native project identities.
Detailed discovery uses868; native/parser/display915 checks and two915 replays
cover the relevant meaning/representation boundaries without asserting full
product equivalence.

## The short field-to-product chain

| Layer/state | Demonstrated representation and consumer |
|---|---|
| Input command | `D<decimal>,|`; AutoPilot dispatcher `0x878a..0x87ae` resets the numeric-parser cursor, calls `0x799c`, writes runtime word and stages value/DE marker. No product-range clamp in this branch. |
| Persistent representation | R1: big-endian u32 at logical0x15..0x18, markerDE at0x19. Runtime word at0x200029d4 is little-endian RAM. Marker establishes the reader branch, not uniqueness, calibration or integrity. |
| Reporting | Native `0x8cfe..0x8d02` loads the full runtime word and passes it to decimal builder0x4644. It is the **ninth** comma-terminated field of0x8c70. No divide or decimal-unit scaling occurs here. |
| Remote parse | Native0xc86a parses field9;0xc86e/0xc870 stores it at0x20001078. Four-tail-field tests distinguish fields7,8,9,10 and leave a sentinel field11 unread. |
| User-facing display |0xfae8 tests flag0x20000fc9;0xfaf0 tests the serial word for nonzero.0xfb0e..0xfb26 produces six digits using divisor100000 down to1.0xfb30 requests the literal SN: at0x1cc18;0xfb3c requests the generated string. |
| Visibility/lifetime | Nonzero session/visibility flag plus nonzero serial enables the label. The incoming device/session handler sets/clears the flag around its connection/configuration flow. This is modeled application state, not independent proof of a physical link. Remote serial RAM is updated by configuration reception; no local persistent serial consumer was established. |

N1 `info-value-pointers.txt`, `info-labels.txt`, `serial-display-native.txt`
ground the label/word association directly; it is not inferred from adjacent
strings. The nearby Signal, Trigger and firmware-version labels refer to
different values. In particular, the separate field8 destination0x200002f4 and
its local index0x2c persistence path do **not** carry D; confusing that cache
with field9 would produce a false operational/persistence dependency.

## Discriminating observations

| Experiment | Result and limit |
|---|---|
| `d-command-{0,1234,12345}` | Real dispatcher returns with corresponding runtime word, big-endian staged bytes, markerDE and dirty1. Tests staging only; no checkpoint/reset repeated. |
| `d-report-{0,1234,12345}` | With unrelated field1 source200, field1 stays20 while field9 becomes0/1234/12345. This directly rejects a D÷10 interpretation. |
| `remote-serial-field9-{0,1234,12345}` | Explicit parser context, tail `1,88,D,10,777,`: field8 cache becomes88; serial word becomes D; done flag1; trailing `777,` remains unread. Entry is a bounded parser tail, not a complete handshake. |
| `serial-render-frame-{1234,12345}` | Original formatting reaches the second SN draw call with stack strings001234/012345. Drawing itself is opaque; no screenshot/hardware display is claimed. |
| Zero/hidden controls | Serial0 or visibility flag0 branches around SN drawing to0xfb40. A blank/default serial is not rejected here. |
| `serial-render-frame-1000000` | Produces `:00000`; no display-width validation/clamp. The six-digit formatter's capacity is not an enforced command-validity range. |
| Negative probe | `D-1,|` stores0xffffffff and reports `-1`. The Remote numeric parser skips the minus and produces1; no faithful signed-identity round trip exists for that probe. Negative values are accepted parser input, not evidence of legitimate product serials. |
|915 controls | AutoPilot915 reports1234 in field9; Remote915 renders001234. The relevant Remote parser/formatter instructions and pointer/label relationships match the868 interpretation. |

The display's well-formed decimal capacity is1–999999;0 suppresses SN display.
That is an apfw2 validation recommendation for this feature, not a recovered
factory allocation range. No physical units, tenths scaling, serial uniqueness
scheme, manufacturing assignment rule or authorization mechanism was established.
An application-programmable serial must not be equated with immutable silicon
identity or calibration rows.

The successful direct `D12345,|` test is deliberately scoped to the dispatcher.
It does not resolve R1's old eight-byte outer-RX framing failure; packet assembly
and command semantics are distinct. General malformed-input/overflow handling
was not investigated.

## What generates D, and what the Remote actually does

The preexisting persistence witness generates D by **operator-supplied packet
injection**. The protocol inventory establishes the AutoPilot handler, not a
named Remote UI producer. Reviewed compact transmitters, general settings,
configuration exchange and information-screen paths did not establish a native
UI action that creates D. Do not relabel that test as a user provisioning flow.

There is a demonstrated static **generic producer route**: the Remote host/
USB-RF bridge handler0xc10c null-terminates completed host input and forwards
non-`$` buffers through0x58a8. It can therefore relay a supplied D command;
the `$SC…` service route is separate. This is host-supplied forwarding, not
evidence of the original vendor tool, factory station, authorized writer or
an editable serial field in the Remote UI. Actual D provisioning remains open.

For reading, the Remote's configuration exchange consumes field9 and the
information screen displays it conditionally. The screen's trigger telemetry
subscription is unrelated to D. No user-facing D engineering unit or tuning
operation is established beyond the SN label.

## Operational role and limits of the negative result

AutoPilot's resolved D references are boot writes, command write and report
read. The examined command path stages the word/marker and returns; it does
not invoke a motor request, trigger threshold change or radio reinitialization.
The Remote serial-word references lead to configuration reception/fallback and
the conditional six-digit display; no control calculation or eligibility gate
depending on the numeric serial was found in this bounded chain.

This supports **identity/display behavior only in the examined paths**, not a
whole-image theorem that D can never affect anything else. Indirect aliases,
unexamined external clients and vendor provisioning policy remain outside this
result. R1 already demonstrates modeled normal default startup without a
nonzero D. No evidence makes a serial number a prerequisite for motion, trigger
processing, radio frequency selection, pairing or calibration.

Persisting D preserves displayed identity across AutoPilot restart through R1's
shared mechanism. That is useful if stable displayed identity is a retained
feature, but is distinct from making any demonstrated operational feature work.
No additional durability scheduling, power-loss or migration investigation was
performed. Intentional settings reset remains the agreed product baseline.

## apfw2 compatibility recommendation

| Requirement/choice | Recommendation |
|---|---|
| Existing Remote bulk-report parsing | Keep the field9 slot and decimal framing. Do not remove it or shift later fields. A value0 is compatible with the observed parser and hides the serial display. Complete session compatibility still depends on the other report fields. |
| Motion/trigger/radio configuration model | Do not add a distance, delay, calibration, radio or motor setting for D. No equivalent control parameter is justified by these findings. |
| Stable visible identity | Optional retained feature: provide an intentionally assigned six-digit serial/identity and persist it or source it from stable provisioned metadata. Uniqueness policy must be specified separately. Do not silently clone a Noxon serial or infer a serial from unrelated calibration data. |
| Legacy D writer compatibility | If external provisioning/service clients are retained, support an explicitly validated identity update and unchanged numeric report. An editable D command is not demonstrated necessary for the ordinary Remote UI; choose it only with that service compatibility requirement. |
| Persistence | Not established as functionally necessary for the retained operating features. Necessary only if the selected identity/update contract promises the same serial after reset. No byte-compatible DE blob or Remote cache persistence requirement follows. |
| Invalid values | Prefer a documented nonnegative six-digit domain and explicit unset0. Do not carry forward negative-sign loss, non-digit rendering above999999 or an unchecked32-bit setter as identity semantics. |

The replacement requirements change in a narrow way: retain an optional
reported identity field, rather than reserve an unexplained scaled control
parameter. There is no evidence-driven change to the motion/trigger or radio
architecture from D. The actual provisioning workflow remains a compatibility
question if an external vendor/service client must be supported.

## APTrace execution, failures and capability gaps

Used public persistent-project Ghidra native ranges, literals, xrefs and
decompilation, plus the established direct Unicorn CLI. No new analysis script,
framework test, backend fix, independent reversing engine or symbolic search was
needed. The prior write-watch discrepancy was avoided by using code boundaries,
code watches and final snapshots, without write watchpoints.

All30 concrete commands and their statuses are retained. Four initial parser
tails omitted the original exchange's context flag and drained the ring; four
subsequent diagnostic tails placed the varying value in field8. Native counting
of all10 parse calls corrected the mapping before any behavior conclusion.
The authoritative `remote-serial-field9-*` fixtures use the original flag value1
(set at0xc4a2) and distinct field8/9 markers. Three initial rendering probes
faulted by writing the caller's stack locals above the default top-of-RAM SP;
reserving the original formatter's local-frame space corrected the invocation.
Those failures are not firmware faults. Zero/visibility controls legitimately
skip that stack path. All corrected renderer and field9 witnesses reach their
declared boundaries. Rendering does not execute the LCD driver; parsing does
not establish RF reception or a naturally completed configuration exchange.

| Gap / unresolved evidence | Impact, needed work and priority |
|---|---|
| Original provisioning/UI producer unidentified | No supported claim about who assigns a serial, allocation range or external-client requirement. Generic bridge forwarding is not that evidence. Inspect the original provisioning client/documented workflow if retaining it; medium, otherwise defer. Existing static tooling can follow a concrete producer once identified. |
| Bounded consumer completeness | Xrefs and selected native chains do not exclude every indirect alias. No current blocker for the optional identity recommendation. A specific contrary control-flow witness would justify watchpoint-free replay or supported dataflow analysis; low absent such evidence. |
| Physical/whole-session observability | Fixtures do not measure actual display, RF, physical identity or safety. Existing model limitation, not a newly diagnosed framework defect. New device/client evidence would be needed for stronger compatibility claims; low for this software field contract. |

No missing framework capability prevented the bounded answer. No improvement
or physical operation is authorized by these recommendations. The best next
work is a product decision about retaining stable serial/service provisioning;
no broader D reversing or automatic durability/default investigation is needed
to make that decision.

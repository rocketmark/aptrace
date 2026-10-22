# AutoPilot bring-up Pass 2 evidence

Interpretation: [Pass2 report and condition matrix](../../../docs/investigations/autopilot-bring-up-pass2.md).
The [overall timeline](../../../docs/investigations/autopilot-bring-up-pass1.md)
incorporates these transitions. Scope is original868 software behavior, with
no new physical or915 execution claim.

## Reproduce and inspect

From repository root use the existing `tools/unicorn/.venv` environment. Run
an individual literal command from `commands.json`, changing `--out` to a new
destination. Use its canonical direct interpreter/script prefix. No subprocess
comparison wrapper, new harness, package/security change or modified image is
needed. Historical evidence packets remain intact.

`commands.json` records24 actual concrete invocations and exit statuses.
`execution-results.json` retains stop/error/completion/mode distinctions. Twenty-two
exit0; two exploratory cold Remote driver runs exit1. Most negative/control
windows end at explicit instruction/watch caps, with `completed=false`.
That is evidence of the bounded observation, not a product READY assertion.
The authoritative positive request vectors stop at0x6fd8 **before executing
the commit routine**. No physical motor operation was performed.

| Question | Primary artifacts / oracle |
|---|---|
| Retained A25 while waiting for peer | `radio-retained-a25-waiting-peer.json`: no peer bytes;30M instructions; setup remains1, runtime25, one A20-frequency request. |
| Retained A25 after MC4 and silence | `radio-retained-a25-silence-window.json`:35M instructions/4985 main-loop entries; runtime25, requested shadow864300000Hz. |
| Explicit correction | `radio-explicit-a25.json`: added A25 packet causes second original initialization/frequency call and shadow865800000Hz. |
| Continuous analog initialization | `analog-band-transition.json`: reset-selected mode1 and initialized alpha0.05; ADC225→900, filter259/291/321…, X1 first active587 at observed poll15. |
| X2 via real command | `analog-x2.json`: runtime band[250,750], first active755 at poll30 in this stream. |
| Actual program/analog accept | `analog-program-acceptance.json`: native program+MC4, then filtered587 reaches reload once; no G and no request. |
| Active reporting with accepted program | `analog-program-reporting-active.json`: `T291,0,\|` then `T900,1,\|`; TR1 blocks reload/request despite marker7b and active samples. |
| Producer bytes / sequence | `remote-plus-sequence.json` emits the program and counter1; exact byte carried into `remote-g-entry-boundary.json` yields G011 before ACK transport. Prior record delta500 is an explicit Remote fixture seed, not a new UI trace. |
| Continuous program→MC4→G→request | `program-causal-observed.json` / `program-causal-repeat.json`: byte-identical, `(channel,const,distance,rate)=(0,30,500,8119)` at0x6fd8. No AP program, position, validity, target or arm seed. |
| Authorization controls | `program-without-g.json` and `program-g-duplicate-sequence.json`: no request in14M. `program-g-trigger-high.json`: no trigger acceptance, same G request. |
| Concrete peripheral boundary | `program-natural-sequence.json` stalls at0x6280 waiting TC0 READSYNC. `program-with-readsync-completion.json` supplies the existing read-clear assumption; request entry is reached. |

Other snapshots retain preliminary controls rather than overwriting them:
`analog-continuous` uses raw900→3600, the initial TR1 run lacks the extra TX
buffer dump, and the shorter valid-program reporting run stops before its
second report deadline. They are not substituted for the primary table's
stronger observations. `radio-retained-a25-extended` is the initial20M window.

## Data, transitions and assertions

`observations.json` records70 passed scoped artifact assertions.
`sampling-summary.json` indexes first/last values, classification crossings,
ADC counts, acceptance entries and TX-buffer observations.
`program-events.json` extracts selected native watch hits for the positive
program sequence; it does not infer missing instructions or schedule events.
Raw snapshots are authoritative. The report maps routine/field lifetimes and
distinguishes local state, requests, confirmed hardware and peer communication.

For a replay regression, preserve inputs and budgets, then check the table's
oracles and `observations.json`. Compare the two positive program snapshots
byte-for-byte. The Remote counter carry and the exact program/G bytes embedded
in native AP RX-ring inputs are checked. No framework/source tests were added
in this operator investigation.

All full startups retain the existing tick, clock/SERCOM, calibration placeholder,
PA22 release and radio-ID assumptions. Analog results enter at the actual
ADC1.RESULT register, not through a filter return or initialization override.
Program input occurs at setup polling; MC4 arrives at original program-tail
PC0x81ca; G/TR1 arrives at setup return. Those delivery boundaries are explicit
external stimuli, not actual RF. TC0 command completion clears bit7 through
`--mmio-clear-bits 40003804:8000`; it provides no timer counting/interrupts.
Only the existing DWT delay is stubbed in the AutoPilot path.

## Static operations and failures

`static-commands.json` records the native public Ghidra operations, environment,
status and output files. Local SVD/source/native instructions ground the
READSYNC interpretation. The original resolved caller evidence is repeated,
not treated as a whole-image proof excluding every indirect transfer.

Two initially overlapping same-project Ghidra operations failed with
LockException; their logs are retained and serialized repeats succeeded. An
incorrect positional dump-length invocation exited2; the supported literal
query recovered the sequence-pointer table. The SVD resolver accepts addresses
directly; its unsupported `--help` attempt failed parsing, and the proper
address query succeeded. No lock or security bypass was used.

`remote-g-after-plus` and `remote-g-buffer-boundary` used CLI `--call` with
`--stop-at`; that call path owns a return trampoline and does not forward the
requested stop. Both build the frame then fault in the uninitialized cold
Remote driver. The supported `--entry` capture stops at0xb59c and is the
clean authoritative frame-boundary witness. No tool repair or successful RF
send is claimed from the failed runs.

`manifest.json` pins source/firmware inputs and the selected prior evidence.
`SHA256SUMS.json` binds all packet files except itself. Original image hashes,
case status, roadmap and investigation qualifications are validated separately
from physical release gates. USB, bootloader, RF/driver confirmation, position,
trajectory safety, STOP/reset while moving and actual motors remain outside
the observed software contract.

# AutoPilot bring-up, Pass 1 evidence

Interpretation and limits: [chronological report](../../../docs/investigations/autopilot-bring-up-pass1.md).
All paths/commands assume repository root and the existing Unicorn venv.
No original image, backend, hardware profile or dependency changed.

## Execution

`replay-commands.json` records six original persistence/motor startup commands,
their original manifest/output paths and fresh output destinations.
`targeted-commands.json` records five more exact historical readiness/negative
replays and seven bounded new experiments. All18 commands were executed
directly with their recorded canonical interpreter/script prefix and exited0.
Invoke an individual literal recorded command with a new `--out` path; do not
overwrite historical packets or use a native comparison subprocess wrapper.
No wrapper/security-policy modification was needed. Native interpreter is
Python3.9.6; Unicorn2.1.4 is unchanged.

`revalidation-summary.json` preserves per-run mode, error, completion, boundary,
counts and comparisons. All11 exact historical replays match final registers,
dumped memory, stop reason and instruction count. A native process exit0 is
not proof of the requested firmware milestone: three input controls and the
preconfig pending request exhaust their budgets; the configured response stops
at its2000-hit observation cap. These retain `completed=false`.

The memory-hook workaround is active (`memory-hook-single-step`) in all full
startups. The one-shot reader/filter helpers have no memory hooks and record
`continuous`. The mode is in each native snapshot.

## Bounded new experiments

| Run | Change from established interface/fixture | Oracle |
|---|---|---|
| `timeline-default` | Add code/memory observations and final dumps to packaged868 reset+MC4. No new behavior override. | Initial radio request before boot reader; dirty staging; no flash stores before first loop. |
| `timeline-retained-a25` | Same timeline, synthetic data-flash provision1 and A25. Other packaged data unchanged. | One initial864300000Hz setter request from A20; runtime25 loaded later. No claim of an operational physical RF pair. |
| `defaults-checkpoint` | Remove D input from prior configured/save scenario; PA22 HIGH at setup return rather than at D's handler. Keep geometry/DONE assumptions. | Original checkpoint performs1025 stores, provision1/A20, X remainsFF, dirty remains1. |
| `filter-initialized-alpha` | Existing due-sample helper old225/new900, coefficient bytes copied from full-reset observation (0.05). ADC/clock stand-ins remain disclosed. | Filter258.75, returned259. Zero-alpha freezing is conditional, not a demonstrated normal startup invariant. |
| `erased-reader` | Direct boot reader with all4097 data-flash bytesFF. | A20/X1/D0; provisionFF is retained. No full boot/physical erase claimed. |
| `invalid-fields-reader` | Direct reader with zero payload and provision1. | A20/X1/D0; only selected repairs, not a complete validity certificate. |
| `noncanonical-marker-reader` | Same reader, provision2. | Nonzero marker accepted; no CRC/schema validation supplied by this marker check. |

Data-flash seeds are test inputs in mapped memory; original files remain
unchanged. Reader controls seed the existing geometry object's source/length
fields. The motor startup fixture is synthetic saved program data, not a newly
executed flash-save of those records. Actual saved-D carry is different: its
4097 seeded bytes are checked against the newly revalidated save's actual
output. These distinctions matter to the three scenario interpretations.

## Evidence products and validation

- Native `.json` snapshots retain original registers, memory, hook observations
  and completion/error semantics. Original provenance is in the source manifests
  referenced in the command records; those packets were not rewritten.
- `timeline-events.json` extracts watched PCs, instruction indices, r0/r1 and
  selected memory. It is an observation index, not a disassembler or inferred
  event scheduler. Native snapshots are authoritative.
- `observations.json` records54 passed artifact checks: eleven historical
  comparisons, exact new-save carry, no-save-at-first-loop controls, checkpoint
  stores/dirty/X, requested frequency/order inputs, initialized coefficient and
  selected invalid-reader results. It contains the check scope rather than
  assigning a VERIFIED claim state.
- `manifest.json` pins source inputs, firmware identities, backend/test entry
  points, environment and the reports/static outputs used in the timeline.
  `SHA256SUMS.json` binds this packet's files except itself.

Regression vectors: rerun recorded commands separately into new paths; compare
`registers`, `memory`, `stop_reason`, and `instructions_executed` for each exact
historical replay. Check both carry commands' `--seed-mem 12000:…` against the
saved4097-byte dump. For new runs, apply the table's expected oracles and
`observations.json` predicates. Completion caps/budgets must not be relaxed to
convert observations into READY. These are case evidence regressions; this
operator pass adds no framework source or test implementation.

The default baseline assumes clock-ready masks, SERCOM SWRST/DRE behavior,
zero calibration placeholders, instruction-paced tick and a DWT delay stub.
Radio ID is forced and packet bytes are supplied to the real RAM RX ring.
NVM save uses forced geometry/DONE and flat writable memory. No actual RF,
USB host, bootloader, flash physics, interruption recovery, physical reference
or motor operation is validated. See report for the remaining Pass2 joins.

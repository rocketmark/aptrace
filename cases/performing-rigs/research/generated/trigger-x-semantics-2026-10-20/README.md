# X/trigger bounded replay packet

Interpretation: [investigation report](../../../docs/investigations/x-trigger-acceptance.md).
This packet contains original-firmware observations and fixture metadata, not
a new analysis engine, patched image, hardware test or admitted claim.

`concrete-commands.json` records every exact direct CLI invocation and process
status. `manifest.json` pins the image, project, tools, static queries,
assumptions and failed attempts. `observations.json` records324 artifact
assertions and expected values. `SHA256SUMS.json` binds all packet files.

Reproduce from repository root in the existing environment. Select a command
by name and invoke its literal `tools/unicorn/.venv/bin/python3
tools/unicorn/run_concrete.py ...` command directly, choosing a new `--out`
destination. Do not put native execution inside a Python comparison process,
shell redirection, or another interpreter prefix; see the runtime diagnosis.
No installation, firmware modification or additional script is needed.
For Ghidra commands use the two Java environment values in the manifest.
Serialize native queries against the same cached project.

Useful regression groups and their observable oracles:

| Commands | Oracle |
|---|---|
| `x-dispatch-{0,1,2,3}` | Clean AAPCS return, selector/staged byte/dirty values in observations. Invalid0/3 preserve prior runtime2 and unchanged stage. |
| `fresh-reader-x{0,1,2,3}` | Fresh RAM reader: 1→1,2→2,0/3→1; original invalid staged value not repaired. |
| `band-x{1,2}-{199,200,249,250,580,581,750,751}` | PC8f98 outside inclusive band; PC9232 inside. Threshold cells and effective sample match fixture. |
| `filter-clock-{before,at}-deadline` | No ADC-boundary watch at499; one at500, deadline1000; both return225 with alpha0/new900. |
| `filter-new-session`, `filter-alpha-one-control` | Return900. Alpha1 is a counterfactual control, not an available setting. |
| `latched-x{1,2}` | Both retain225 despite injected900; X1 rejects, X2 accepts. |
| `analog-report-*`, `digital-report-*`, `report-then-reject` | Frame flags and rate-limit behavior; TX entry recorded in `stub_hits` when TX is stubbed; continuation rejects with TR1. |
| `analog-{bad-program,busy-channel,not-idle,accept-window-spent}`, `digital-x*` | Individual guard/input differentials; telemetry deadline does not limit TR0 acceptance. |
| `plus-predecessor` → `reload-{valid,invalid}-record` | Native predecessor bytes in commands. Both accept and return status3; only valid record prepares channel0; neither arms/commits. |
| `held-low-followup` | Relevant valid post-state carried; returns without acceptance/commit. Not a whole-machine continuous scheduler. |
| `reload-reference-{preserved,resync}` | Current600, resync0→start0/end500; resync1→start600/end1100 and flag cleared. |
| `independent-arm-{commit,invalid}` | Valid arm2 stops before commit with distance−600; invalid record rejects. Explicit arm fixtures, not natural trigger causation. |

Retained diagnostics: `x-command-1/2` fail after the intended RX-wrapper stop,
and `x-command-0/3` are superseded wrapper probes. `filter-not-due` was actually
due because its initial interpretation conflated clock units; use the explicit
deadline pair instead. `observations-initial.json` preserves the initial
checker failure from expecting a watch at a stubbed function; the existing
hook records that event in `stub_hits` before it could reach the watch.
No failing firmware assertion was suppressed.

All inputs are software fixtures. No timing/electrical/ADC fidelity, safe
trajectory, physical reference, motor activation or physical reliability is
established. Existing seven-guard symbolic proofs are reused through the
report's trigger dossier reference, not relabeled as new solver results.

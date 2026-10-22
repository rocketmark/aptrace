# Trigger misfire counterexamples — 2026-10-21

See [investigation](../../../docs/investigations/trigger-misfire-failure-modes.md).
This packet uses existing APTrace direct concrete execution and a native Ghidra
query; no new harness, instruction evaluator or framework test was developed.

- `commands.json`: ten exact direct CLI commands, provenance/basis and observed
  exit statuses. Reproduce each from repository root with the documented
  `tools/unicorn/.venv/bin/python3`; use its command verbatim. Runs overwrite
  their own outputs, so retain this packet separately when comparing results.
- Named native JSON snapshots: original execution observations, hooks, forced
  input events and disclosed MMIO assumptions. Exit0/instruction-limit does not
  mean READY or a successful motion. All ten execute14M instructions, no error,
  with `memory-hook-single-step`, and none reaches request0x6fd8.
- `sampling-and-events.json`: extraction of returned sample series, acceptance
  snapshots and bounded outcomes from those native snapshots. It adds no model.
- `observations.json`:88/88 scoped artifact checks, including independent
  byte-identical X2 replay, acceptance controls, normal alpha, request absence
  and watch-capacity checks. These are evidence checks, not framework regression
  coverage, timing qualification or exhaustive claims.
- `static-commands.json`, `tr-handler-native.txt`: selected native TR branch and
  query record. Initial `--end` invocation was rejected with exit2; positional
  start/end syntax succeeded. The text file explicitly contains a selected
  branch transcription rather than claiming the entire query output.
- `manifest.json`: source/tool/report hashes and repository revision;
  `artifact-hashes.json`: packet file hashes, excluding itself.

Interpretation and controls:

| Case | Result |
|---|---|
| inactive-control | Constant225, X1: no acceptance. |
| one-acquisition-pulse |225→900 for one runtime acquisition→225: peak259, no acceptance. |
| low-excursion |225→0:214,203,193; one acceptance at193. |
| constant-input-x2 / repeat | Constant225; real X2 packet: one acceptance; snapshots byte-identical. |
| startup-active |900 from initialization onward: one acceptance, no runtime edge. |
| released-tail-tr1-control / released-tail-tr0 | Initial tail-isolation attempt is **confounded by earlier acceptance** before the setup-return TR1 packet is parsed. Preserved, not discarded or claimed as successful tail isolation. |
| pre-mc4-tr1-release-control | Program→TR1→MC4, ADC900 then225 at first T send: no acceptance. |
| pre-mc4-tr0-released-tail | Same, plus real TR0 after first report: accepts filtered866 while raw225. Common post-TR injection also queues a second MC4 after TR0; see report. |

All changes are external ADC.RESULT or RX-ring packet inputs at disclosed PCs.
No AutoPilot filter, program, reference, arm or acceptance state is seeded.
The new original-code fixtures are868 only. The firmware identity is unchanged:
`6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3`.
They do not exercise actual electrical inputs, RF, motor interrupts or movement.

Historical positive/negative controls are reused from
`../bring-up-pass2-2026-10-21/commands.json`: held225→900/TR0 acceptance,
TR1 active reporting without acceptance, no-program rejection, digital LOW one
reload/no-G, G duplicate-sequence rejection and G with trigger-HIGH requesting.
The earlier trigger-X helper fixtures remain conditional; their zero-alpha
initialization is not substituted for these full resets. See report for source
links, falsified interpretations, V1/V2 limits and minimal bench follow-ups.

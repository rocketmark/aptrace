# A/radio bounded evidence packet

Interpretation: [A investigation](../../../docs/investigations/a-radio-reconfiguration.md).
`manifest.json` pins four firmware images, project identities,61 public static
operations, source hashes, assumptions and limitations. `concrete-commands.json`
records52 exact direct CLI commands and process statuses. `observations.json`
contains301 artifact assertions, including separately labeled capability
diagnostics. `SHA256SUMS.json` binds the packet files.

Reproduce from repository root using the existing `tools/unicorn/.venv`
environment. Invoke a selected recorded command directly with its literal
`tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py` prefix and a
new `--out` destination. Do not use a comparison subprocess wrapper, shell
redirection or a new interpreter prefix for native execution. Ghidra commands
use the two Java environment values recorded in the manifest; serialize queries
against the same project. No new harness, package or firmware change is needed.

| Regression group | Original-code observation / oracle |
|---|---|
| `a-command-{19..26}-clean` | Valid20–25 updates runtime/stage and requests the six864-band frequencies. Invalid19/26 retains prior23, stages it and still reaches initialization. Native setter calls are code-watched. |
| `autopilot-a23-unchanged` | Existing staged23 stays dirty0 but still reaches probe. |
| `boot-reader-a{19,20,25,26}` | Fresh readers retain valid endpoints and default invalid values to20, including corrected staged value. Synthetic flash data; not a new checkpoint witness. |
| `remote868-stored-a{18,19,20,25,26}-load` | Bounded loader slice defaults18/26 to20 but retains19. |
| `remote-display-a{19,20,25}` |19→3 fallback;20→1;25→6. This display result does not change radio arithmetic. |
| `remote868-ui-a{20,25}` | Native UI handler builds `A20,|` / `A25,|`; local store requested before five TX calls and local initialization. Confirmation, TX, delay and local setter are opaque in these two controls. |
| `remote868-ui-a25-native-stage` | Runs the real initialized local setter; stage low byte25 and dirty1, then same five sends before initialization. No flash save is asserted. |
| `a20-radio-id-success` | With declared GPIO/SPI/delay stand-ins and constant readback0x12, returns through original code and requests common settings; selector0x20000018 clears, seeded phase-arm2 survives. Constant readbacks do not model coherent final modem state. |
| `a20-radio-id-failure-mapped` | Bad ID reaches original error-loop entry0x612e after staged A changes. No success-only selector clear. |
| `frequency-registers-{864300000,865800000}` | Real frequency arithmetic and write wrapper request bytes D8/13/33 and D8/73/33. Lower SPI/GPIO stubbed. |
| `mando{868,915}-a{20,25}-bringup-request`, `autopilot915-a{20,25}-bringup-request` | Both ends agree on band-specific endpoint Hz under the explicitly seeded initialized base. |
| `remote{868,915}-reset-data`, `remote915-setup-band-override` | Both resets copy864000000 and limit5; the915 setup fragment replaces the base with915000000. Separate fragments, not a whole paired boot. |

Important retained diagnostics:

- Initial `a-command-*-request` probes include write watches. A25 contradicts
  the native setter path; use the clean matrix for firmware findings.
- `a25-control-{no-write-watch,write-watch}` differ only by a watch on
 0x20000069 (and output path): runtime becomes25 in both, but stage/dirty is
 25/1 without the watch and0/0 with it. Matching A20 controls are nondiscrepant.
  This is a reproducible instrumentation finding, not a Noxon behavior or
  a diagnosed APTrace-versus-Unicorn root cause. No backend change was made.
- `a20-no-write-watch` / `a20-code-watch-only` are preliminary controls.
- `a20-radio-id-failure` exits1 at unmapped0x41018044 with the default MMIO
  range. The mapped retry uses the documented0x4000000 span and reaches its
  intended boundary. The failed snapshot remains evidence of fixture limits.

Native snapshots and all expected values remain fixture-scoped. No RF delivery,
physical register confirmation, actual transmission power, motor behavior,
paired durability, natural reconnect or hardware reliability is established.

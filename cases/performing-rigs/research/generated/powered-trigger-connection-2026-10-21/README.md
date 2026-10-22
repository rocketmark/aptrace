# Powered-source connection assessment — 2026-10-21

[Investigation and policy/scenario matrices](../../../docs/investigations/powered-trigger-connection.md).

This packet tests MCU-visible consequences of hypothetical powered-source
connection events and equivalent contact closures. It does **not** model a
validated jack circuit, capacitance value,12/24V-to-ADC transfer, calibrated
rise/fall time or measured waveform on either board revision.

- `commands.json`:11 exact original-firmware direct Unicorn CLI commands, all
  observed exit0. Run individually from repository root using the documented
  venv/context. Preserve the packet separately first: output files are replaced
  when commands are replayed. No comparison wrapper or policy bypass is used.
- Named native JSON snapshots: full original868 reset/program/MC4 through original
  acceptance/profile/rate/timer enable, or14M bounded negative. Positive cases
  stop at5fa6 after original enable/live-state write. No AP state/arm seeds and
  no W/G commands. The natural Remote-built nonzero profile and original startup
  assumptions come from `../trigger-request-campaign-2026-10-21/`.
- `events-and-outcomes.json`: extracted samples and acceptance/start snapshots;
  digital-mode ADC-cell contents are stale/unconsumed and must not be treated
  as digital classifications. `observations.json`:103/103 scoped artifact checks,
  including byte-identical independent same-history/contact-control replay.
  These are not framework regression tests or alternative-firmware executions.
- `macaw-expanded.json`: fresh vector-root-only `macaw-census-expand`, normal
  existing Haskell binary, original image and load base4000. No Ghidra seeds.
  `path-coverage-extract.json`: selected existing-engine records and residuals,
  not independently inferred/discovered control-flow edges.
- `profile-start-native.txt`, `analysis-commands.json`: native instruction query,
  caller-query observations and exact Macaw command. Macaw call-site/block labels
  are not treated as exact BL PCs; native663a validates the parsed6638 block.
- `request.txt`: user-provided investigation request, including the reported
  Noxon explanation. This is provenance for the premise, not independent physical
  evidence confirming it.
- `manifest.json`, `artifact-hashes.json`: source/tool/image/report identity and
  packet hashes. No firmware, apfw2, hardware or APTrace implementation change.

`digital-acquired-transient` forces GPIO LOW immediately before the qualified
read at9228 and HIGH before its result comparison at922c. Original acceptance
changes eligibility, so only one such qualified read occurs before timer start.
A different policy changing when reads occur would not receive a calibrated
identical time-domain waveform by simply reusing these PC hooks. Conceptual
policy comparisons in the report therefore state fixed-history assumptions and
tradeoffs; no replacement policy engine is hidden in this packet.

The analog startup-tail case begins with ADC0 during original baseline/filter
initialization and supplies225 at setup return. Alpha remains the original0.05;
filtered history, not a normally frozen first sample, causes the active decision.
The600 case changes only the input plateau amplitude from the previous900 case;
neither count has a recovered voltage interpretation.

Physical intent/source type is absent from the same-history replay. Its equality
shows the original execution is reproducible under equal observables. Whether
actual contact and supply insertion produce those equal observables requires
measurements. Nominally inactive powered output, dry contact and external voltage
are electrical labels, not values the harness can infer.

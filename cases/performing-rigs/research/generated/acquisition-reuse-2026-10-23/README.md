# Acquisition-reuse initial candidate — REJECTED

**A later focused return-edge witness demonstrates a new second start relative to
Phase3. This candidate fails the no-regression criterion. It is preserved unchanged
as counterexample evidence. The bounded correction is in the sibling
`acquisition-reuse-r1-2026-10-23` packet.**

**SIMULATION RESEARCH ONLY — NOT FOR HARDWARE DEPLOYMENT.** This applies to the
binary and intermediate ELF object. No physical flash/update ownership is established.

The [report](../../../docs/investigations/stateful-patch-acquisition-reuse.md)
contains the findings and scope. Original915, first patch, Phase3 patch, prior
motor-timing packet, formal models and completed gate evidence are immutable.
`protected-baselines.json` pins the prior files; `manifest.json` inventories this
packet and final verification. No emulator/framework implementation is added.

## Build

From repository root, with installed clang/Python:

```sh
python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/generate-patch.py
```

`reuse.S` implements the binary policy. The generator checks exact original915
identity, assembles Thumb code without unresolved relocations, emits the derived
`RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_reuse.bin`, and records every modified
range, appended byte, symbol and reserved-state offset in
`modification-manifest.json`. It does not overwrite a previous candidate.

The image SHA-256 is
`7a0824437f9620321632f141fdca6d755f13396da00a219e9b2d8f43c24f4e96`.
Size71,764 bytes;996 bytes appended at `[0x15470,0x15854)`,40 original bytes modified
across nine ranges. The same64-byte explicit BSS/heap reservation as Phase3 is
used. The evaluator, scheduler and existing data addresses are unchanged.

## Execute the matched campaigns

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/run-experiments.py --image original --suite
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/run-experiments.py --image phase3 --campaign
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/run-experiments.py --image optimized --campaign
```

Original suite has11 core histories. Each other campaign repeats all18 Phase3
histories and adds9 focused controls. `--case NAME` runs one recipe; `--adversarial`
runs only the9 controls. All65 campaign cases are fresh resets. Commands overwrite
only their own new snapshots; preserve this packet before editing a recipe or
candidate. Do not change the fixture, generator or image during a campaign.

This is a case-owned extension of Phase3's external-input recipe over the public
APTrace ConcreteMachine and CLI parser. It supplies GPIO/ADC/RX and explicitly
labeled adversarial memory/clock inputs. It does not supply trigger authorization,
a shadow state machine or instruction semantics. Native firmware decides. Basic
program/MC4 delivery, radio-ID, DWT, MMIO read-ready and no autonomous TC/NVIC
assumptions remain. Native millis advance once per4,000 guest instructions;
these are nominal firmware ticks, not calibrated physical milliseconds.

Ordinary cases run16M instructions; held-W, repress-W and release-during-motion
run65M. Small engine bound overruns (up to a few instructions) are recorded as
reported. Snapshots contain complete bounded watch/write observations, external
input events, source/image hashes, acquisition counts by pin, and executed
appended-region instruction counts. Main digital/analog500 controls add evaluator
and acquisition/provenance watches. Counts of appended code alone omit native
helper work: use the report's whole-function spans and acquisition counts too.

Focused cases:

- `cached-no-raw`: delay native ADC deadline after candidate formation.
- `cache-forged-filter`: also replace retained filter float with900 while no raw
  conversion occurs. Both deliberately perturb filter state, not an electrical
  field waveform.
- `stale-observation`: repeatedly age the optimized observation timestamp by21
  ticks before native policy evaluation. The Phase3 counterpart is the normal
  analog control because Phase3 has no observation cache to perturb.
- `gap20/gap21`: one disclosed clock step relative to the previous observed
  timestamp during qualification. Actual acquisition may cross another tick.
- `gate-age20/gate-age21`: one clock step at a qualified gate entry; boundary20
  is characterized, not assumed accepted despite possible tick crossing.
- `mode-flip-active`: explicit mode1→2 perturbation with GPIO already LOW; this
  is not a claim that a normal configuration packet writes the mode byte.
- `release-during-motion`: release100 ticks after live, keep inactive through
  completion and supplied W, then fresh500-tick press200 ticks after completion.

The last case tests independent inactive qualification during busy operation.
All W recipes supply exactly one real RX packet; no synthetic idle/live clear or
recurring command source replaces native STOP/return/completion.

## Direct, integrity and timing controls

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/run-direct.py
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/run-integrity.py
tools/unicorn/.venv/bin/python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/run-frozen.py
python3 cases/performing-rigs/research/generated/acquisition-reuse-2026-10-23/check-artifacts.py
```

The three `run-*.py` helpers only execute exact saved public CLI argument arrays
in `direct-commands.json`, `integrity-commands.json`, and `frozen-commands.json`.
Text command files preserve individually readable CLI commands too. They implement
no replacement analysis or execution engine. The existing reviewed native execution
context was used; no toolchain/framework installation or hardware access occurred.

Direct G/W1/B1 controls compare TC0/live endpoints and verify no consumed external
grant. Integrity controls observe wrapper/native-return frames, NZCVQ, common-gate
registers, raw-detour replay, reset and heap reservation. The frame witnesses use
a native armed-label input change for a fresh physical-input control; they do
not force qualification state. Frozen evaluator controls repeat the preceding
timing investigation's exact original prepared-state/clock input at ages51/52/53
in the new image. They bypass admission deliberately to isolate motor arithmetic.

`check-artifacts.py` evaluates saved artifacts only. `outcomes.json` exposes all
counts, timers, profile-age samples, acquisitions and performance measurements;
`checks.json` preserves individual assertions. `--partial` supports reviewing
in-progress output but is not the final completion check.

`initial-smoke/` preserves three preliminary positive runs and the exact source
hash version used before the campaign CLI option was added. They are not part of
the65-case campaign. The archived source is retained for identity; run the current
root-level recipe for reproduction.

## Static evidence and limitations

`static-commands.txt` records existing APTrace Ghidra operations. The generated
listings independently decode original acquisition sites, inserted hooks and
branch destinations. `native-filter-callers.txt` resolves two direct original
callers (voltage learning and background trigger service), not universal indirect
or interrupt closure. Engine versions are recorded in the final manifest.

Recurring analog observations require a raw conversion in the current poll,
mode/X consistency and age<=20, paired with that native filter invocation's
returned integer. Cached filter returns alone invalidate qualification. Digital
uses the native acceptance read when present; a single fallback sample preserves
busy release observation. The unchanged final gate still performs fresh Phase3
acquisition before consuming authorization. Sample stamps are firmware millis
captured just after native return, not independently timed hardware conversions.

Read the report for the digital workload cost, analog acquisition/latency changes,
near-boundary outcomes, retained sustained-fault/post-commit limitations and missing
continuous physical STEP/TC/NVIC/clock validation. No absolute CC0 equality, physical
speed/distance equivalence, safety certification or field deployment follows.

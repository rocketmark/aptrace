# Gate 3 fresh-session initialization

2026-10-22. Repository baseline `c703230ca4df40c69a238dfff53a7b9a5c92298d`.
Research only; hardware deployment NOT APPROVED.

## Result and authority

Initialization completed from persistent repository evidence. Read root
`AGENTS.md`, `docs/codex-operator.md`, case `status.md` and `roadmap.md`, and
the Gate 1 and Gate 2 reports. Recovered the authoring packet and its relevant
counterexample command records. No prior conversation conclusions were used.
This document records initialization, not a completed Gate 3 investigation.
No firmware execution, symbolic exploration or counterexample replay was run
during initialization; no Gate 3 verdict is assigned.

The authoritative current case record is `status.md`. Gate reports establish
their own bounded evidence. Historical counterexamples remain historical until
freshly reproduced; Gate 2 explicitly did not rerun them.

## Artifact identity

Fresh `shasum -a 256` checks agree with both gate reports:

| Artifact | SHA-256 |
|---|---|
| `research/firmware/originals/firmware_autopilot915.bin` | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| `research/generated/trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin` | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |
| Repository `tools/unicorn/concrete.py` | `fcf4529322de345b3f6dd7f4c373084b1957348ade2bb4c1d6acf285d6266f3b` |
| Repository `tools/unicorn/run_concrete.py` | `e91dce33ec855c883dd9ba8ca7c1976020c096552e3300649399b682c3256735` |

Both images load at `0x4000`; recorded sizes are 70,768 and 70,796 bytes.
The patch replaces six bytes at `0x922c` and appends 28 bytes at `0x15470`.
Recorded execution uses Python 3.9.6 and Unicorn 2.1.4; interpreter/package
versions were not freshly queried. Hash agreement does not validate physical
flash ownership, bootloader compatibility or identity with a field-tested release.

## Recovered counterexamples and smallest operations

All paths in this section are relative to
`research/generated/trigger-patch-2026-10-22/`.

| Witness | Persistent evidence and recipe | Recorded behavior and boundary |
|---|---|---|
| Post-read release | `late-release-patched.json.gz`, `late-release-patched-command.txt` | LOW acquired; at `0x1547c` the new read has returned r0=0 while the injected PB05 input is HIGH. Acceptance at instruction 12,098,797; rate start 12,327,030; `0x5810` 12,327,164. Bound 14M instructions. |
| Held input plus W | `held-w-patched.json.gz`, `held-w-patched-command.txt`; matched `held-w-original` pair | PB05 LOW from reset; original execution completes the profile, with W bytes supplied at `0x6056`. Patched acceptance occurs at 12,098,797 and 52,167,801; rate starts at 12,327,030 and 52,400,236. Bound 60M. No new input edge. |
| Release/fresh-input control | `release-fresh-w-patched.json.gz`, matching command file | Release, eligible HIGH observation and subsequent LOW permit another start; no duration qualification established. |
| Analog controls | `analog-x1-patched.json.gz`, `analog-x2-patched.json.gz`, matching command files | Recorded X1 initiation and X2 negative control bypass the added digital routine. Detailed evidence is deferred until P5 investigation. |

`outcomes.json` supplies derived event summaries; raw gzip snapshots, recipes
and `native-hashes.json` preserve the underlying evidence and provenance.
`checks.json` and `check-artifacts.py` are authoring checks, not an independent
safety oracle. Snapshot digests were not freshly verified in this initialization.

The smallest selected operations are direct invocations of the existing public
`tools/unicorn/run_concrete.py` CLI using the late-release and held/W recipes,
changing only `--out` to a new evidence directory. Preserve historical snapshots
and recipes. First replay the patched late-release witness, then the patched
held/W witness and its original control. Compare recorded boundaries and state
before broadening exploration. No patch generation or new harness is needed.

These recipes start at application reset entry `0xcc24`, supply program/MC4
payloads at parser boundaries, use explicit MMIO overrides, a stubbed call,
radio response and an instruction-paced tick. W delivery and input changes are
modeled environmental events. They are not physical radio exchanges, calibrated
electrical waveforms, autonomous interrupt service or proof of motor movement.

## Current verification state and obligations

| Item | Persistent state |
|---|---|
| Gate 1 | INCONCLUSIVE |
| Gate 2 | INCONCLUSIVE |
| Gates 3, 4, 5 | NOT RUN |
| Full safety policy | NOT ESTABLISHED |
| Hardware deployment | NOT APPROVED |

Gate 1 supports local decoding/routing and byte confinement. Integrated caller
register/stack preservation, runtime write confinement, exhaustive incoming CFG,
interrupt interaction and peripheral-read timing remain unresolved. Fragment
effects aborted all paths; unsatisfiable queries after abort are not proofs.

Gate 2 records 16 fresh executions: 14 exact historical replays and two
write-watch-disabled controls. Targeted transient rejection, intentional G/W1/B1
initiation and the ordered 29,236-write intentional projection reproduce.
The 138 assertions include six historical inputs and are not 20 fresh runs.
Fresh-input global ordering differs (357 recorded differing indices); unacquired
polling/write differences, sparse RAM/stack coverage and missing ordered direct
producer peripheral traffic remain unresolved. Equal named streams do not
establish harmless global interleaving.

Gate 3 must test P1–P6 under explicit bounds, preserve held/W and release
counterexamples, distinguish reachable startup histories from arbitrary RAM,
and investigate alternative producers and timing/interruption limits. An
ENABLE precursor or CPU store request does not establish physical activation.
Gate 4 must not run as part of this investigation.

## Execution, gaps and recommended next work

Initialization used repository reads, command/evidence inspection, `git status`,
`git rev-parse`, and standard artifact hashing. The initial working tree was
clean. No APTrace analysis operations were executed, and no implementation,
firmware, historical evidence, case status or roadmap was changed.

No critical chat-only continuity dependency was identified for beginning the
known-witness replays: recipes, images and snapshots exist persistently. This
does not certify completeness of all historical research. Physical release
identity and waveform evidence remain missing engineering evidence, rather
than facts to reconstruct from conversation.

Existing reports identify high-priority reusable gaps in differential replay,
event-aligned comparison, complete boundary-state/write coverage, framed
relational verification and interrupt/peripheral modeling. This initialization
does not freshly test those capabilities. Their impact is to limit future
claim scope and require manual orchestration through existing interfaces.

Next existing-capability work is fresh counterexample replay with preserved
provenance, followed by targeted sampling-boundary controls and property-specific
state exploration. Framework improvements require a separate development task;
physical timing, source intent and field-release correspondence require new
evidence. Do not infer either from finite emulator results.

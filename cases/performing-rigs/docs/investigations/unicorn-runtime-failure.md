# Unicorn initialization failure: root cause and validation

2026-10-19. Repository revision: `76dda0bece8ed613cd3bc9ec97eb384b0389e0f4`.
Scope: execution-tooling diagnosis only. Historical reports, firmware, ledger,
census data, profiles and apfw2 were not modified. No environment was rebuilt,
dependency changed, permission rule edited, or firmware reversing undertaken.

## Result

**The failure is command-context dependent: a restricted host query triggers
an unsafe Unicorn native fallback. It is neither Feather-specific nor evidence
of a broken installation or an APTrace execution regression.**

In the failing context, `sysctlbyname("hw.cachelinesize")` returns `-1` with
`errno=1` (`EPERM`). Unicorn's installed ARM64 library then executes
`mrs x8, CTR_EL0` in `init_cache_info` at library offset `0x10c78`, causing
host `EXC_BAD_INSTRUCTION` / SIGILL (shell exit 132). This occurs during
lazy native initialization at the first `uc_mem_map`, after successful Python
import and `Uc` construction, before firmware bytes or instructions execute.

The command-policy explanation is strongly supported by the inspected local
allow rules and controlled command comparisons. The direct canonical test
command passes; the same test with `-u` or shell redirection crashes. Direct
`run_concrete.py` invocations pass, including the previously failing reset
configuration and both hardware-profile configurations. No low-level sandbox
audit trace was collected, so the precise sandbox rule denying the sysctl is
not independently named. The syscall denial, native fallback and faulting
instruction themselves are directly observed.

## Original failure and environment

The previous [Feather report](feather-minimum-ready.md) and its
[`execution-manifest.md`](../../research/generated/feather-ready-2026-10-19/execution-manifest.md)
record the comparison invocation:

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/feather_m4_compare.py --out-dir cases/performing-rigs/research/generated/feather-ready-2026-10-19/baseline
```

It exited 132 immediately after announcing its **AutoPilot868 / AutoPilot**
run, before the Feather leg. This session repeated that script with a new
output directory and obtained the same failure. Its empty comparison output
directory is not passing evidence. The earlier reduced reset command failed
in that session's execution context; invoked directly now, the same reset
configuration executes ten guest instructions successfully.

| Item | Observed value |
|---|---|
| Interpreter | `tools/unicorn/.venv/bin/python3`, Python 3.9.6, Xcode-provided ARM64 |
| Venv configuration | `home=/Applications/Xcode.app/Contents/Developer/usr/bin`, no system site packages |
| Host | macOS 26.6.2, ARM64 |
| Python package | Unicorn 2.1.4 in that venv |
| Native library | `tools/unicorn/.venv/lib/python3.9/site-packages/unicorn/lib/libunicorn.2.dylib` |
| Wheel tag | `cp37-abi3-macosx_11_0_arm64` |
| Native SHA-256 | `7207c8e3d7a63118fb0bca73e01816797fd51b1d8a39a4cbc7abfd562ee59c85` |
| Installation integrity | Native library digest matches installed package RECORD |
| Guest configuration | `UC_ARCH_ARM`, `UC_MODE_THUMB | UC_MODE_MCLASS` |

No missing-library exception or architecture-mismatch loader error occurs.
The exact interpreter and native binary pass execution in the authorized
direct invocation context, which argues against replacing either one.

## Isolation and evidence

New artifacts are under
[`research/generated/unicorn-runtime-2026-10-19/`](../../research/generated/unicorn-runtime-2026-10-19/).

| Operation | Result | Interpretation |
|---|---|---|
| Existing synthetic `tools/unicorn/test_call_observation.py` | Exit 132 after decoder assertions | No proprietary firmware is required to reproduce |
| Bare Unicorn diagnostic, no APTrace imports | Import and `Uc` construction pass; mapping one page crashes | Failure independent of APTrace implementation, profile, MMIO geometry and firmware |
| Canonical `cases/performing-rigs/test/test_concrete.py` | Exit 0, all checks pass; repeated successfully | Existing concrete-execution regression works |
| Same test with Python `-u` | Exit 132 after parsing assertions | Buffering-option placement changes command-prefix matching |
| Same test with `> PATH 2>&1` | Exit 132 | Shell wrapper/redirection also changes this environment's command handling |
| Doctor's AutoPilot868 ampersand check via direct CLI | Exit 0, three instructions, stop `0x8890` | Smallest documented real-firmware smoke check passes |
| Reset `cc24`, ten-instruction cap via direct CLI | Exit 0, ten instructions, no error | Earlier reduced failure is not inherent to reset configuration |
| Standard AutoPilot868 startup assumptions via direct CLI | Exit 0, 450000 instructions, no error, eleven receive-entry watch hits | Standard configuration executes |
| Feather startup assumptions via direct CLI | Exit 0, 500000 instructions, no error, setup entry reached | Feather configuration executes; its expected startup wait remains distinct from native failure |
| Comparison wrapper | Exit 132 on first standard-profile machine | Wrapper launch context fails before profile divergence |

The bare probe's exact command, stdout and exit are in `native-probe.log`.
It imports the installed Unicorn package directly and maps `0x1000` bytes
at `0x1000`; no firmware or harness hooks exist. The diagnostic is for native
runtime isolation, not a substitute firmware-analysis implementation.

`native-probe-crash.ips` is a fresh copy of host report
`Python-2026-10-19-163702.ips` from a bare probe. Its fault has the same
library offset `68728` (`0x10c78`) and instruction encoding `0xd53b0028`
as the preserved earlier crash. `native-cache-init.txt` is `otool -tvV`
output from the installed dylib, showing the sysctl call, its conditional
branch to the fallback and the faulting `mrs` instruction. The probe prints
`sysctl -1 errno 1 value 0` and `Uc constructed`, never `mapped`.
Thus there is no Python exception traceback to catch and no guest-state
snapshot to interpret for these failures.

`environment.json` records the interpreter, native path, hash and wheel tag.
`test-concrete-direct.log` preserves the passing suite output. The suite
checks real calls, failure snapshots, fresh-state isolation, default SP,
carry-forward behavior, scenario order independence and RAM logging. Those
existing assertions were not suppressed or changed. The separate
`test-concrete.log` is empty because the redirected failed run had buffered
stdout; its recorded status is 132, not success.

## Execution context and recent changes

The project `.codex/config.toml` sets workspace-write sandboxing with approval
policy `never`. Read-only inspection of
`/Users/mstalzer/.codex/rules/default.rules` found allow prefixes for:

```text
["tools/unicorn/.venv/bin/python3", "cases/performing-rigs/test/test_concrete.py"]
["tools/unicorn/.venv/bin/python3", "tools/unicorn/run_concrete.py"]
```

No equivalent prefix was present for the Feather comparison or synthetic
observation test. Putting `-u` between interpreter and script no longer
matches those two-token prefixes. This explains the observed launch-context
split; `-u` does not intrinsically break Unicorn. Shell output redirection
also reproduced the restricted behavior here. This investigation did not
change policy, request escalation, inject a sysctl replacement, patch the
dylib, or alter an allowed script to execute unrelated work.

Relevant Git history was inspected after reproduction. The Unicorn version
pin has been 2.1.4 since backend introduction (`ed93f16`, 2026-09-07);
the subsequent requirements change added Capstone. Recent harness changes
include call-observation support (`29b8bbc`, 2026-10-14), while the Feather
profile was added in `484a69e` on 2026-10-17. The same current implementation
passes the existing suite, and the bare external-library probe fails without
importing any implementation. An older checkout or dependency rollback is
not justified by these results. No historical checkout was made.

## Correction and reproducible validation

**No APTrace code repair is justified.** The operational correction is to
use the already authorized, documented direct command form, with the
documented interpreter. Do not add `-u`, shell redirection, or a compound
wrapper while assuming it retains the same command authorization. Use the
CLI's `--out` to save execution evidence; capture test output from the tool
result afterward. No dependency or interpreter change is required for the
validated commands.

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_concrete.py
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py --firmware cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin --entry 0x888c --reg r3=0x26 --stop-at 0x8890 --stop-at 0x889e --out cases/performing-rigs/research/generated/unicorn-runtime-2026-10-19/doctor-ampersand.json
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py --firmware cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin --entry cc24 --max-instructions 10 --out cases/performing-rigs/research/generated/unicorn-runtime-2026-10-19/reset-ten-instructions.json
```

The standard/Feather configuration comparison uses that same existing generic
CLI and the existing profile parameters; exact commands are in
[`profile-commands.md`](../../research/generated/unicorn-runtime-2026-10-19/profile-commands.md).
The new snapshots distinguish an error-free instruction-budget stop from
completion. No READY, USB, physical hardware or motor claim is drawn from
these tooling validation runs.

## Classification, gaps and recommended next work

| Candidate cause | Finding |
|---|---|
| General corrupt Unicorn installation/native loading problem | Not supported: expected native binary loads, matches RECORD and executes successfully |
| Recent APTrace regression | Not supported: native-only reproduction plus passing current regression |
| Feather-specific configuration | Ruled out for this initialization failure: standard wrapper fails first; both configurations work through direct CLI |
| Interpreter/package/native ABI mismatch | Not supported: same interpreter/package/library works; wheel and host are ARM64 |
| Host execution policy plus dependency fallback | Supported: denied cache-line query, observed fallback instruction and native SIGILL; command-prefix-dependent outcomes |

Confidence is restored for the tested direct CLI and canonical regression,
not for every command wrapper under the current policy. The failing wrapper
has not been repaired and must not be reported as passing.

Meaningful gaps:

- **Native initialization diagnostics (medium):** import succeeds although
  mapping fails. Impact: a native process crash gives no structured target
  result. Evidence: bare probe and crash reports. Needed capability: an
  isolated native initialization smoke check reporting host failure distinctly
  from firmware exceptions. APTrace development would be a separate change.
- **Execution-context visibility (medium):** command wrappers change outcomes
  without an APTrace-level explanation. Evidence: paired direct/`-u`/redirect
  tests and local rules. Likely cause: differing sandbox decisions. Needed:
  explicit reporting of launch context and stable authorized entry points;
  avoid a broad permission exception.
- **Unicorn restricted-host fallback (dependency issue, medium):** the denied
  query reaches an illegal instruction. A robust upstream fallback/error path
  would be preferable. No candidate dependency correction was evaluated, and
  a speculative upgrade, downgrade or binary patch is not recommended here.

Existing APTrace work can continue through the validated generic CLI within
its established authorization. To support the comparison wrapper or synthetic
test under another launch context, the environment owner must deliberately
provide an appropriate supported execution policy or evaluate a dependency
fix; this report does not authorize bypassing current restrictions. Additional
OS sandbox audit evidence would identify the precise deny rule. No new firmware
evidence is needed to explain this crash, and no new regression was added
because no APTrace implementation defect was demonstrated.

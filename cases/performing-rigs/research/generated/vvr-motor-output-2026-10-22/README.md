# VVR motor-output comparison

[Report](../../../docs/investigations/vvr-trigger-motor-output.md).
Original915 image; same native program/MC4 and boot assumptions as the VVR
connection witness. No firmware, formal-model, apfw2, tool implementation or
hardware changes. Exact correspondence to Nathan's tested release is unproven.

## Reproduce and inspect

Run a `*-command.txt` file's single command directly from the repository root,
using the documented `tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py`
prefix. Do not add interpreter flags, Python subprocess wrappers, redirection or
security changes to work around the context-dependent macOS initialization issue.
Each command uses `--out` and preserves all fixture bytes and observability.

Native snapshots are stored losslessly as `*.json.gz`, with raw and compressed
hashes in `native-hashes.json`. Commands reproduce the uncompressed logical
filenames. `check-artifacts.py` reads a raw file if present, otherwise its gzip
copy. All originals were compressed only after verifying byte-for-byte round
trip; no native fields were edited. If rerunning, compare against preserved
hashes rather than replacing the compressed reference.

```
python3 cases/performing-rigs/research/generated/vvr-motor-output-2026-10-22/check-artifacts.py
```

**95/95 checks pass.** The script only checks/extracts saved observations; it
does not launch Unicorn, execute instruction semantics or model a peripheral.

| Logical native result / matching command | Scope |
|---|---|
| `transient` | AcquiredLOW, then inputHIGH before acceptance/start;14M, no truncation. |
| `intentional` | Matched heldLOW;14M; all29,236 captured CPU stores identical to transient. |
| `unacquired` | HIGH on every qualified acquisition, LOW afterward;14M; negative, no truncation. |
| `transient-count-observation` / `intentional-count-observation` | **Rejected continuation attempts.** Force COUNT21858 at every0x5fa6; repeated38 times, feedback changes, no handler/STEP. Do not present their repeated rate starts as a physical failure mechanism. |
| Three `*-watch-cap` | Initial diagnostic runs stopped at12,000 code-watch hits because generic GPIO helper logging was too broad. Retained, not used for bounded-negative claims. |
| `unacquired-write-cap` | First14M negative had322 dropped stores at30,000 cap. Retained; final negative increases cap to50,000 and has no dropped stores. |

Nine native process executions, all exits0/native error=null. Cap filenames
preserve relocated earlier snapshots; their reproducibility recipes change only
the output destination to the preservation name. Main runs removed the noisy
generic GPIO entry watch while retaining actual PORT CLR/SET/TGL write watches,
and added SERCOM5.DATA write capture. Write-hook mode remains single-step.

## Artifacts and interpretation

- `comparison.json`: acceptance, rate/period, output, driver setter and final-state observations.
- `timeline.json`: ordered TC0, ch0 STEP/DIR and setter records for every main/diagnostic counter run.
- `driver-transactions.json`: all3258 complete CS-bounded datagrams from transient; captured writes are identical in intentional. Logical requests, no hardware response.
- `checks.json`:95 concrete saved-artifact comparisons, including startup pulses, negative control, pre-trigger configuration and rejected counter behavior.
- `variant-region-identity.json`: byte equality of selected868/915 output/evaluator ranges, not whole-image or release identity.
- `output-path-decompile.txt`: existing868 helper explanations; `prescaler-store-disasm.txt` and `counter-read-decompile.txt`: direct915 queries.
- `manifest.json`, `artifact-hashes.json`: source/tool identities and packet hashes.

Static commands used existing public persistent Ghidra queries (serialized):

```
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py decompile autopilot868 0x5c00 0x54b8 0x5570 0x5898
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot868 0x5be8 0x5c74
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot915 0x56e8 0x5730
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py literal autopilot915 0x41ec --count 1
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py decompile autopilot915 0x6260
```

Vector query returns0x607d, Thumb handler0x607c. This is static linkage, not
delivery. Existing Target2 SMT and Target3 isolated services are cited with their
scope; no new solver run or direct helper/IRQ execution was substituted here.

The period and timer force/read-clear assumptions are disclosed in each command.
No automatic TC counting, match/reset flag behavior, NVIC dispatch or physical
GPIO/driver semantics is supplied. Startup STEP requests are genuine observed
CPU stores but precede the trigger and occur in the negative control. No observed
post-trigger STEP train may be inferred from this packet.

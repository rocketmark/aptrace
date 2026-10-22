# VVR physical-failure correlation — 2026-10-22

[Assessment and failure-mode matrix](../../../docs/investigations/vvr-trigger-failure-correlation.md).
[Primary PDFs / provenance](../../validation/nathan-vvr/README.md).

Seven direct, unmodified-original-firmware executions, all process exit0 and
native `error=null`. Three intentionally continue to an instruction bound;
the X2 negative also stops at its14M bound. A bound is not successful physical
completion or a whole-program absence result. No framework implementation,
formal model, apfw2 or physical hardware was modified.

| Command file | Result | Controlled question |
|---|---|---|
| `replay-command.txt` | `digital-acquired-transient.json` | Revalidate868 original saved-LOW/current-HIGH initiation; identical to prior decoded artifact. |
| `replay-915-command.txt` | `digital-acquired-transient-915.json` | Same full-reset input/packet scenario on original915. |
| `analog-x1-command.txt` | `analog-517-to600-x1-915.json` | Rev1-like diagnostic band, default X1, through original timer initiation. |
| `analog-x2-command.txt` | `analog-517-to600-x2-915.json` | Same ADC history/program, actual X2 command; negative through14M. |
| `held-completion-command.txt` | `held-completion.json` |65M original868 continuation, held900; natural profile completion, idle2, no second acceptance. |
| `held-completion-w-command.txt` | `held-completion-w.json` |60M, W delivered at original completion; native phase/idle9, second acceptance and timer initiation, input still900. |
| `released-completion-w-command.txt` | `released-completion-w.json` |Same W; ADC released to225 at first acceptance; natural completion/re-arm but no second acceptance or start. |

To reproduce, run a command file's single command from repository root directly
in the documented `tools/unicorn/.venv` CLI context. Preserve these saved outputs
before another run: commands intentionally name their corresponding files.
Do not launch Unicorn through a Python comparison subprocess, add `-u`, alter
its backend or disable security restrictions. Its macOS initialization remains
execution-context-dependent as documented in the runtime-failure investigation.

RX packets are placed in the original application's ring, not transmitted RF.
MMIO status/radio-ID/DWT and instruction-paced clock assumptions are fully
visible in each command. PC-forced input changes are hypothetical acquisition
histories; they do not simulate impedances, capacitance or analog board transfer.
W at completion is an explicit modeled Remote input, not a proven automatic
Remote exchange. No STEP clock/NVIC schedule advances position; return distance0
is a material limitation on the repeated-start test. No firmware states downstream
of acquisition/parsed packets are seeded.

`outcomes.json` extracts the meaningful native boundaries. `check-artifacts.py`
only reads saved outputs/PDFs; it is not a firmware implementation or launcher.
Run from any directory with Python3; **64/64 checks pass**. Original PDFs and
extractions have separate hashes. `artifact-hashes.json` protects this packet's
files; `firmware-identity.json` records each image and equality to its vendor copy.
`manifest.json` records source dependencies and scope. Limited memory-write logs
are not used to assert all-write completeness; chosen code watches are below cap.

Static native queries used the existing persistent Ghidra interface:

```
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot868 0x5fac 0x6058
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py literal autopilot868 0x6058 --count 9
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py decompile autopilot868 0x8e18
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot868 0x905e 0x9108
```

`completion-disasm.txt` and `rearm-disasm.txt` preserve instruction evidence;
`phase-service-decompile.txt` is explanatory decompiler output. Cached xrefs for
idle0x200000d8 and decompiles0x5fac/0x5958/0x6338/0xccdc located the bounded
completion test; they are not independent dynamic proofs. Existing Target2
Crucible/What4/SMT gate results and formal-model comparisons are cited unchanged;
no new solver query, theorem, model run or binary-refinement claim was needed.

The seven native runs include no framework failure. One mistaken historical
filename (`held-extended.json` rather than `profile-held-extended.json`) and
one nonexistent outcomes filename were corrected during artifact inspection;
neither changed a firmware execution or evidence result.

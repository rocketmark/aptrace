# Execution manifest — 2026-10-19

Working directory: `/Users/mstalzer/github/aptrace`.
Revision: `7d8c44dd6711430c5ffed3fe985cd27322138712`.
Backend: existing `tools/unicorn/.venv`, Unicorn 2.1.4,
macOS 26.6.2 ARM64. No dependencies installed or implementation changed.
Interpret results with
[`feather-minimum-ready.md`](../../../docs/investigations/feather-minimum-ready.md).

## Concrete operations

```sh
tools/unicorn/.venv/bin/python3 cases/performing-rigs/scripts/feather_m4_compare.py --out-dir cases/performing-rigs/research/generated/feather-ready-2026-10-19/baseline
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py --firmware cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin --entry cc24 --max-instructions 10 --out /tmp/aptrace-startup-check.json
tools/unicorn/.venv/bin/python3 -u cases/performing-rigs/test/test_feather_m4_profile.py
```

All exited 132. Comparison printed only `=== autopilot868 / autopilot profile ===`.
Reduced reset generated no snapshot. Regression stdout is in `regression.log`;
the unbuffered retry preserves assertions preceding the same host crash.
No complete fresh firmware run exists in this directory. `baseline/` is empty.
Crash report copied unchanged from
`~/Library/Logs/DiagnosticReports/Python-2026-10-19-162849.ips` to
`unicorn-host-crash.ips`; capture time is 16:28:47 local. Its fault stack
starts in host `init_cache_info`, not guest ARM firmware.

## Static operations

The first decompile attempt exited 1 because Java selection could not be
saved under `~/Library/ghidra`. A temporary settings directory resolved this
configuration failure. Successful commands (exit 0):

```sh
mkdir -p /tmp/aptrace-ghidra-home
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py decompile autopilot868 0x9464 0x6968 0x610c
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py decompile autopilot868 0x7770 0x8c10 0x6190
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot868 0x94b0 0x94e8
python3 tools/ghidra/aptrace_ghidra.py literal autopilot868 0x94f0
python3 tools/census/aptrace_census.py writers autopilot868 0x20002548
```

Outputs respectively: `startup-decompile.txt`, `ready-output-decompile.txt`,
`ready-loop-disasm.txt`, literal result `0x20002548` (recorded here), and
`ready-buffer-writers.txt`. Empty `*-stderr.txt` files accompany successful
Ghidra calls. No Ghidra rebuild or firmware modification was performed.

## Controller operations

Three normal `agent/.venv/bin/aptrace-agent research` calls used `--ledger`
and `--output` under `research/runs/agent/`. Full objective, arguments,
trajectory, evidence and ledger-run identifier are preserved in each JSON:

- `feather-ready-2026-10-19.json`: maximum 12 steps, no seed;
  stopped `discovery_finished`, one evidence record, no established claims.
- `feather-ready-startup-2026-10-19.json`: maximum 8 steps,
  `--function FUN_00009464`; stopped `step_budget_exhausted`, ten evidence
  records, structural results only.
- `feather-usb-2026-10-19.json`: maximum 5 steps, no seed;
  stopped `discovery_finished`, one evidence record, no established claims.

Historical comparison JSONs were inspected without rerunning their contents;
their hashes match the current originals as listed in the report. These remain
historical evidence, not passing regressions from this session.

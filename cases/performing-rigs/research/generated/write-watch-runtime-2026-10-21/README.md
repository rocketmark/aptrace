# Write-watch runtime evidence, 2026-10-21

Interpretation: [investigation report](../../../docs/investigations/write-watch-instrumentation.md).
Run commands from repository root with the existing Unicorn venv. No target
image was modified. Historical A packet and hashes remain unchanged.

## Reproduction and provenance

The baseline backend is `tools/unicorn/concrete.py` at git revision
`667fe2e912e9b35b19eb8cb3c7deb62d7ec4bba7`, SHA256
`5420ed465dc3459493d86ea070f00b85e5244cae501c0b1a446a72b257e6c4ee`.
`before-a25-watched.json` repeats the original
`a25-control-write-watch` command from
`../a-radio-semantics-2026-10-20/concrete-commands.json`, changing only `--out`.
The same command produces `fixed-a25-watched.json` with the repaired backend.
The original control pair is the authoritative exact failing invocation and
fixture provenance. All new CLI diagnostic snapshots were emitted by successful
direct `run_concrete.py` invocations; the earlier compound invocation failed
native initialization with132 and produced no snapshot.

Synthetic original-fault CLI recipe (baseline backend, new output destination):

```
tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py --firmware cases/performing-rigs/research/generated/write-watch-runtime-2026-10-21/minimal-thumb-flags.bin --entry 4000 --reg r1=0x20000000 --reg r2=5 --stop-at 4030 --dump-mem 20000000:8 --collect-coverage --watch-mem-write 20000000:1 --max-instructions 100 --out /tmp/write-watch-flags.json
```

Remove only `--watch-mem-write 20000000:1` for the plain control. Baseline
`flags-{plain,watched}.json` record42 versus99 in the second word.
`native-noop-flags.json` is the same watched experiment with an immediate
`return` inserted as the first statement of the nested write-hook callback
returned by `make_mem_write_hook`: still99, empty write log. `minimal-*` and
`thunk-*` use their correspondingly named binary with otherwise the same
register/dump/stop controls; the thunk control lacks the later flags change.
The final maintained fixtures can be regenerated without native execution:

```
python3 tools/unicorn/test_write_watch.py --emit-fixtures /tmp/aptrace-watch-fixtures
```

Temporary diagnostic callback changes against the pinned baseline, all reverted:

| Snapshot | Isolated change |
|---|---|
| `cached-pc-a25-watched` | Write-hook PC obtained from the last code-hook PC instead of native reg_read. |
| `cached-registers-a25-watched` | Both PC and LR obtained from cached code-hook state. |
| `no-callback-reads-a25-watched` | Remove previous-memory and PC/LR reads from write callback; retain write observation. |
| `noop-hook-a25`, `native-noop-flags` | Immediate return from write callback, retaining hook installation. |
| `global-noop-hook-a25` | Immediate-return callback, write hook spans the whole address space rather than the selected range. |
| `stepped-{plain,watched}` | Temporary unconditional one-instruction engine calls, same flags fixture; both42. |

These diagnostics localize the fault; they are not released alternate backends.
To independently repeat baseline work, use a separate checkout at the pinned
revision and new output paths, keeping the current repair and historical packet
intact. No dependency change is required.

## Repaired execution and audit

`fixed-cli-commands.json` lists18 direct CLI invocations and exit statuses,
using the checked-in LS/EQ/NE byte-store fixtures. `impact-commands.json`
records15 selected historical commands, original manifest/output paths and new
destinations. Only their output path changes. `impact-comparison.json` compares
full saved registers, dumped memory, stop reasons and instruction counts. All
15 commands exit0; state and stops agree. X1/X2 instruction counts76→75 are
retained as differences, not suppressed.

`instrumentation-inventory.json` inventories the four relevant historical
manifests by actual memory-hook flags. It does not include implicit library
dirty hooks, whose exposure is established from backend source. It does not
assert that every exposed historical run was wrong.

`regression.log` is captured tool output from the successful case test runner;
the final run with added write-hit-content assertions also exited0. The generic
test and case test are the maintained executable oracles. `validation.json`
records passed checks and separately blocked standalone/doctor commands.
`manifest.json` binds source, dependency and original-reproducer inputs;
`SHA256SUMS.json` binds all packet files other than itself.

This packet certifies the bounded regression cases, not physical behavior or
all prior persistent-state traces. The report identifies the selected long
checkpoint/startup witnesses still needing replay before durability work.

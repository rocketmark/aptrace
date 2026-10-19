# Native executable static analysis

APTrace supports registered Windows PE32/x86 inputs through the persistent
Ghidra backend. Ghidra owns PE recognition, sections, relocations, imports,
x86 decoding, calling conventions, references, function creation and CFGs.
APTrace owns target policy, identity, cache freshness, bounds and routing.
No executable is launched. This capability does not emulate Windows or serial
APIs and does not admit host-derived claims into the ARM verification pipeline.

## Target and lifecycle

The case composition configuration supplies `EXECUTABLE_REGISTRY` entries:
`{"key": {"path": "case-owned/path.exe", "format": "pe32-x86", "sha256": "..."}}`.
Pinning the hash is recommended and enforced when supplied. The suffix alone
never selects a loader. Native import must report `Portable Executable (PE)`
and `x86:LE:32:default` and the same SHA-256 before a cache is admitted.
Unknown executable objectives fail closed rather than falling back to ARM.
Additional formats require a separately tested policy, not a language override.

```sh
python3 tools/ghidra/aptrace_ghidra.py build TARGET
python3 tools/ghidra/aptrace_ghidra.py exe-query TARGET inventory --limit 100
python3 tools/ghidra/aptrace_ghidra.py exe-query TARGET search --pattern erase
python3 tools/ghidra/aptrace_ghidra.py exe-query TARGET xrefs --address 0x00402000
python3 tools/ghidra/aptrace_ghidra.py exe-query TARGET function --address 0x00401001
```

`build` reuses a fresh cache; an incomplete/stale executable cache requires
explicit `rebuild TARGET`. Identity includes input path/hash, policy, Ghidra
version, scripts and exports. Raw Cortex-M identities and build arguments are
unchanged. Executables receive no BinaryLoader, ARM language, Thumb address
normalization, vector seeding, provenance labels or Cortex-M census pass.
`literal` and `dump` refuse executable targets: file offset is not virtual address.

Use `APTRACE_GHIDRA_CACHE_ROOT` for isolated cache roots and optionally
`APTRACE_GHIDRA_SEEDS_ROOT` for ARM seed inputs. Merely moving a development
cache does not redirect or rewrite canonical derived seeds. Java must be
configured as described in the existing Ghidra backend documentation; on this
macOS host the tested settings were Java 21 at
`/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home` and
`JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home` (create that writable
directory first). No dependency installation or backend security bypass is needed.

## Bounded observations

`exe-query` emits JSON or writes `--out PATH`. Kinds:

- `inventory`, `imports`, `functions`, `search`: native metadata or cached
  structural exports; substring `--pattern` filtering for table queries.
- `references`: search the instruction-origin data-reference export by pattern.
  It is not a complete inventory of pointer tables. `xrefs` matches exact
  memory addresses; stack/register spaces remain in exports but are never
  misparsed as numeric virtual addresses.
- `callers`, `callees`: direct cached call observations. Callees require an
  exact exported entry and an unambiguous exported name. Computed calls remain
  unresolved; these queries do not prove a complete call graph.
- `function`, `cfg`: reopen the existing project read-only with `-noanalysis`.
  Ghidra supplies containing function/body, bounded instruction text, decompiler
  status/text or native block edges. An odd x86 entry is preserved.
- `data`: read at most `--limit` native mapped bytes and their native outgoing
  references. An unmapped/uninitialized boundary ends the window explicitly
  through `bytes_returned`; no raw-file arithmetic is involved.
- `entry-function`: explicitly request Ghidra disassembly/function creation at
  an executable address, then query it. Refuses non-executable memory and
  overlapping attributed entries. Analysis is transient in a read-only project;
  later queries do not inherit it. The result records this additional assumption.
  A vtable pointer is a candidate entry, not independent proof of a function.

Limit is 1..1000; pattern length at most 256. Table counts/truncation, instruction
and edge totals, decompiler completion/error/truncation, mapped byte count and
body ranges make scope visible. Decompilation is capped at 30 seconds and
`limit * 120` characters; native invocations at 420 seconds; import analysis at
300 seconds. Ghidra script errors that exit the native process successfully but
produce no JSON are reported as failures, with `_last_headless.log`; never
converted to an empty successful observation.

Each envelope records arguments, input/tool/export identity, query script and
Python provider hashes, result hash and static-evidence limitations. Ghidra
boundaries and decompiled C remain heuristic. Instructions and native data are
the structural anchors; C helps interpretation. Repeatability within Ghidra is
not independent corroboration. Absence of attribution/reference is incompleteness,
not absence of behavior. No query establishes hardware protection or reachability.

## Objective routing

`aptrace-agent research 'TARGET.exe erase offset' --max-steps 12 --output run.json`
and `investigate` automatically select an unambiguous registered name/basename;
`research --target KEY` selects explicitly. The bounded static host strategy
chooses objective-related strings, follows concrete references into functions,
records every observation and remaining queries, and stops at its budget.
It runs before the ARM executor/controller. Unrelated ARM objectives retain
existing research behavior. Ambiguous/unregistered EXE names are explicit errors.

Host results have `claims: []`: this initial capability has an evidence journal,
not host semantic admission rules. `--ledger`, work items, ARM function seeds,
experimental ARM tools and structured objective specifications are refused for
host research. The host budget does not imply the objective is resolved. Follow
specific native queries, evaluate their limits, and write the investigation report.
Future typed host claims need new admission/replay rules before canonical use.

## Regression coverage

`agent/.venv/bin/python -m pytest tools/ghidra/test_executable.py` uses a
synthetic PE with an odd entry, import, string, conditional branch and direct
call in isolated projects. It checks native import/query/discovery, read-only
repeatability, malformed import, unsupported metadata, bounds, missing evidence,
mixed spaces, stale/tampered exports, and routing before ARM execution.
Existing `tools/ghidra/test_aptrace_ghidra.py`, direct concrete regressions and
agent CLI suites cover the retained Cortex-M path. Native integration tests
require installed Ghidra/Java; no executable is run as a host program.

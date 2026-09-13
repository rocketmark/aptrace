# Ghidra Backend

`tools/ghidra/aptrace_ghidra.py` maintains persistent headless Ghidra projects,
validates cache identity, and exposes repeatable queries for decompilation,
disassembly, callers, references, containing functions, symbols, literals, and
raw bytes.

The generic backend owns project lifecycle, script hashing, cache freshness,
headless invocation, and query/export mechanics. A case supplies its firmware
registry, load base, provenance labels, and cache root.

```sh
python3 tools/ghidra/aptrace_ghidra.py status FIRMWARE_KEY
python3 tools/ghidra/aptrace_ghidra.py build FIRMWARE_KEY
python3 tools/ghidra/aptrace_ghidra.py decompile FIRMWARE_KEY ADDRESS
python3 tools/ghidra/aptrace_ghidra.py xrefs FIRMWARE_KEY ADDRESS
```

Run `python3 tools/ghidra/aptrace_ghidra.py --help` for the complete command
surface. Cache identity includes the firmware digest, load configuration,
Ghidra version, analysis version, scripts, and optional provenance input; stale
projects are rejected rather than silently reused.

The current Performing Rigs configuration is explicitly wired at the backend
entry point. Its concrete backend history and examples are preserved in
[`ghidra-backend-results.md`](../../cases/performing-rigs/docs/investigations/ghidra-backend-results.md).

# Gate 1 evidence packet

Report: [trigger-patch-gate1.md](../../../docs/investigations/trigger-patch-gate1.md). Research only. No Gate 2 runs.

Original/derived identities, byte comparison and raw dumps are recorded in `image-identity-and-diff.log`, `original-bytes.log`, `patched-site-bytes.log`, `appended-bytes.log`. Gzip digests associate the preserved 20 prior native records with their original `native-hashes.json`; these are not new native runs.

Ghidra outputs cover original/derived `0x9200..0x9238`, inserted `0x15470..0x1548c`, helper `0xd3dc`, original acceptance/epilogue `0x8f98`, callers of `0x8e18`, continuation at `0x943a`, and next routine `0x9268`. `ghidra-patched-meta.json` and `ghidra-patched-census.json` preserve the identity-aware cached metadata/typed export used for interpretation. Xref outputs are **data references**, not exhaustive incoming CFG references.

Existing public command families used, from repository root (write fresh output names on reproduction):

```sh
python3 tools/ghidra/aptrace_ghidra.py dump autopilot915 0x922c --length 6
python3 tools/ghidra/aptrace_ghidra.py dump autopilot915_freshness_research 0x922c --length 6
python3 tools/ghidra/aptrace_ghidra.py dump autopilot915_freshness_research 0x15470 --length 28
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot915_freshness_research 0x15470 0x1548c
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot915 0x9200 0x9238
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py callers autopilot915_freshness_research 0x8e18
```

Macaw public CLI is `external/macaw/dist-newstyle/build/aarch64-osx/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace`. Its invocations used the derived binary path from the report:

```text
aptrace explore PATCH.bin 15470
aptrace explore PATCH.bin 9230
aptrace macaw-census-expand PATCH.bin 4000
aptrace function-effects PATCH.bin d3dc r0=39 out=NEW_PREFIX
aptrace function-effects PATCH.bin 15470 out=ANOTHER_NEW_PREFIX
```

`PATCH.bin` and prefixes are explanatory placeholders, not new scripts. Addresses use the existing CLI's hexadecimal convention. Function-effects emits raw and enriched JSON. `r0=39` adds solver specialization `arg_r0 == 0x39`; it does not replace the symbolic invocation argument. The helper completes; **the patch effects operation aborts all paths**. Preserve the latter result and do not interpret vacuous UNSAT guards as absence-of-writes proofs.

`macaw-rooted-census.json` is independent vector-rooted discovery; `macaw-patch-explore.log` is explicitly seeded local decoding. The census includes unresolved control flow. Datasheet excerpts preserve local Microchip IN semantics and sampling latency, not observed physical behavior.

No authoring generator or artifact checker was rerun; neither firmware was regenerated. No original named evidence was overwritten. SHA-256 listing of this packet is in `packet-sha256.txt` (excludes itself).

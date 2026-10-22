# Experimental trigger-freshness binary patch

**RESEARCH ONLY — NOT FOR HARDWARE DEPLOYMENT. PARTIAL POLICY.**

[Investigation](../../../docs/investigations/experimental-trigger-freshness-patch.md)
and [Noxon-facing summary](../../../docs/investigations/experimental-trigger-freshness-noxon-summary.md).
The delivered image rejects one reproduced stale-read history and preserves
intentional motor requests. It does **not** implement initial arming, timed
qualification, release-to-rearm or analog protection.138 passing artifact checks
include known negative policy outcomes and are not a complete safety pass.

## Generate the real modified image

From repository root:

```
python3 cases/performing-rigs/research/generated/trigger-patch-2026-10-22/generate-patch.py
```

[Experimental binary](RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin)
is70796 bytes. Its SHA-256 is
`ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616`.
Generator requires original915 SHA-256
`0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920`.
It refuses incompatible input and leaves the original unchanged. The six-byte
replacement and28-byte extension are enumerated in `modification-manifest.json`.
No original code cave, permanent RAM slot, linker metadata or framework routine
is silently reused. The extension is explicitly allocated by the simulation
image, not certified free physical flash.

Normal Ghidra inspection uses the additive research-only case key:

```
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py build autopilot915_freshness_research
JAVA_HOME=/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home JAVA_TOOL_OPTIONS=-Duser.home=/tmp/aptrace-ghidra-home python3 tools/ghidra/aptrace_ghidra.py disasm autopilot915_freshness_research 0x15470 0x1548c
```

`inserted-routine-disasm.txt` is the independent decoded authoring result. Original
keys remain unchanged. No assembler/analysis framework was installed; the small
branch emitter is patch-authoring code, validated against an original BL and
Ghidra, not a replacement disassembler or emulator.

## Reproduce native tests

Each `*-command.txt` contains one direct documented CLI invocation from repository
root. Original commands reference the exact original915 image; patched commands
reference the emitted modified file. Twenty native executions complete with no
native error. Input/RX/tick/MMIO/DWT/radio assumptions remain explicit in every
recipe. No counter forces or interrupt trains from the rejected experiment are
used. Do not add Python subprocess wrappers, `-u`, output redirection or security
changes to force macOS Unicorn initialization.

Native snapshots are losslessly stored as `.json.gz`. `native-hashes.json`
records decompressed and compressed hashes; commands emit raw `.json` names.
Keep gzip references when reproducing, then compare the newly emitted raw files.

```
python3 cases/performing-rigs/research/generated/trigger-patch-2026-10-22/check-artifacts.py
```

This reads saved records only, preferring a raw result if present; it implements
no firmware or peripheral behavior. `outcomes.json` captures observed boundaries
and request comparisons; `checks.json` holds138 assertions. Full-policy failures
in C and late-release tests are asserted/documented, not suppressed.

| Recipes | Native comparison / policy status |
|---|---|
| `transient-{original,patched}` | Original starts; patched rejects savedLOW/currentHIGH and never reaches0x571c/0x5810/0x5f8c through14M. |
| `intentional-{original,patched}` | One start each, identical29,236 captured requests after removing timestamps;24 added instructions. |
| `fresh-intentional-{original,patched}` | HIGH read thenLOW; one start each.29,260 records each; named peripheral/motor streams equal, global interleaving differs. |
| `unacquired-{original,patched}` | HIGH at acquisition, LOW after; no start. |
| `late-release-patched` | LOW returned by fresh read, HIGH before its compare: still starts. Residual stale window. |
| `held-w-{original,patched}` | LOW from boot; native time completion plus explicitly supplied W: two starts each. Initial/re-arm protection absent. |
| `release-fresh-w-patched` | Release after first acceptance, then eligibleHIGH observation before newLOW; subsequent start works. No duration qualification. |
| `analog-{x1,x2}-patched` | Reuses prior915 original controls; analog X1 fault band still starts, X2 remains inactive. Digital patch never entered. |
| `B1-full-reset`, `G-to-enable`, `W1-nonzero-to-enable` original/patched | Direct producers still reach their original live-store stop; final TC0/live states match. |

Startup STEP requests are shared with negative controls. No trigger-caused
continuous STEP train, driver electrical result or physical movement is proved.
No calibrated500ms electrical waveform is modeled. PC forces repeat on every
hit: the rejected transient rule repeats as the patched loop continues polling.
Physical source intent and exact Noxon tested-release identity remain unknown.

`fresh-control-ordering-difference.json` preserves the failed initial hypothesis
that the fresh-input case had identical global write ordering. The corrected
claim explicitly separates per-stream equality from global ordering differences.
`storage-boundary-evidence.json` records why a no-xref word is not automatically
free RAM. Neither artifact claims the larger patch is impossible.

Existing target/IRQ regression was run unchanged; output in
`target-regression.log`. Source/tool hashes and preservation checks are in
`manifest.json`, native identities in `native-hashes.json`, and packet hashes in
`artifact-hashes.json`. No apfw2, original image, existing test, model, hardware,
ledger or release-gate modification was made.

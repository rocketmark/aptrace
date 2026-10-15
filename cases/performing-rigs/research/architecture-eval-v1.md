# Architecture Evaluation v1 — AutoPilot grounding results

Case-side record of the AutoPilot experiments behind the framework spike
[`docs/spikes/architecture-evaluation.md`](../../../docs/spikes/architecture-evaluation.md).
The spike's subject is engine choice. This note keeps only what it measured
on this firmware.

Firmware: `firmware_autopilot868.bin`, sha256 `6dcdb4c1…52e3`, flash base
`0x4000`. Census DB (read-only copy) sha256 `31376900…f66c`. Ghidra
12.1.3, project copied from `runs/ghidra_cache/autopilot868` and opened
`-readOnly`. Raw outputs: [`runs/architecture-eval-v1/`](runs/architecture-eval-v1/).

**Not changed:** the canonical ledger, its claims, the census DB, Beads
state and every historical evidence identity. No callback-provenance
result is re-graded here.

## Question

Does the value `0xec49` loaded at `0xea54` (`ldr r3,[pc,#0xa4]`, from the
flash word `0xeafc`) flow into a control transfer, a store, an argument, a
return value, or only a local presence check?

## Verified premises [static]

- `0xec49` occurs as an aligned or halfword-aligned flash word **only** at
  `0xeafc`. No word equals `0xec48`, `0xf190` or `0xf191`. `0xe883` occurs
  only at `0xeb00`.
- The census has one `literal_refs` READ of `0xeafc`, from `0xea54`
  (Ghidra ref manager), and one `function_pointers` row (`0xeafc` →
  `0xec48`, raw flash-word scan).
- Disassembly (Capstone and Ghidra agree):
  `0xea54 ldr r3,[pc,#0xa4]` → `0xea56 cbnz r3,0xeaa0`. The taken path
  starts `0xeaa0 add r3,sp,#0xc`. The fall-through starts
  `0xea58 ldr r3,[sp,#0xc]`.

## Results

| Method | Evidence | Result for `0xea54` |
|---|---|---|
| Ghidra raw p-code forward walk (`PointerUseProbe`, raw) | static, complete | `COMPARE` at `0xea56` (`INT_NOTEQUAL`), then `DEAD` at `0xeaa0` and at `0xea58`. No store, argument, return or transfer. |
| Ghidra decompiler forward slice (`PointerUseProbe`, high) | static, heuristic | Only uses: `INT_EQUAL` → `CBRANCH` at `0xea56`. C: `if (DAT_0000eafc == 0) {`. The other 24 slice ops are memory-SSA bookkeeping, because flash is a writable block in this project. |
| Capstone forward walk (`capstone_forward_use.py` v2) | static, complete | `COMPARE` at `0xea56`, `DEAD` at `0xea58` and `0xeaa0` |
| Macaw IR (after APTrace `MacawExpand`) | static | `r15991 := read_mem 0xeafc` → `eq r15991 0` → `branch`. The fall-through block's abstract state carries `_R3 in {0}`. |
| Unicorn, mid-function start at `0xea54` | concrete, one path; harness state | `cbnz` is taken. `r3` holds `0xec49` only until `0xeaa0`. No store of the value before the call at `0xeaac`. |

The four static methods agree: **the value loaded at `0xea54` is used only
by the `cbnz` presence test and is overwritten on both successors.**
Evidence level: static, cross-engine (Ghidra p-code, Capstone, Macaw IR).
It is consistent with one concrete path under harness state.

Same-function controls, from the same probe:

| Load | Result |
|---|---|
| `0xeaa6` / `0xeada` (`0xe883`) | `ARGUMENT` (`r3`) at `bl 0xec48` / `bl 0xf190` |

This matches the `CONCRETE 0xe883` caller values in callback-provenance v1.

Pattern-matched, **probable only**: the shape matches newlib's
`_vfprintf_r`. It reads as `if (_printf_float != NULL)`, a weak-symbol
presence test, with `ec48` being `_printf_float` and `e882` being
`__sfputs_r`. This is not used as evidence.

## Every flash code-pointer load in the image

These are the Ghidra READ references to a census `function_pointers`
flash word with a known target. There are 8 loads.

| Load | Function | Result |
|---|---|---|
| `0xbc76` | `FUN_0000bc44` | ARGUMENT at `bl 0xccc4` |
| `0xea54` | `FUN_0000e8a8` | COMPARE only |
| `0xeaa6`, `0xeada` | `FUN_0000e8a8` | ARGUMENT |
| `0x10412`, `0x10416`, `0x1041a` | `FUN_000103f0` | STORE to `[r4,#0x24/0x28/0x2c]` |
| `0x10438` | unattributed stub | INCOMPLETE: not inside a Ghidra function. The Capstone walker, given the stub range, reports a tail-transfer ARGUMENT into `0x1059c`. |

The first probe version reported `0x10438` as "complete, no uses". That
defect was fixed during the spike. The current version reports it as
INCOMPLETE.

## Side finding [static, concrete tool result]

`aptrace function-effects … 0xe8a8` returns `failed: all paths aborted`
after 1 Macaw block and 12 Crucible steps. The production effects path
uses upstream Macaw discovery without `MacawExpand`. Upstream
classification fails at the first `cbz` (`0xe8b6`, "IP is not a mux").
The `MacawExpand` state reaches 66 blocks for the same function. Neither
status.md nor the effects limitations name this. They name only
`tbb`/`tbh`.

## What this does not establish

- No composition is made. The 17 `ec48` callback target sets are not
  closed here.
- The closing rule (CLOSED only if every address-taken load is
  NO_ESCAPE) and its scope (assumptions A1–A4 of callback-provenance v1,
  plus "no non-literal materialization of `0xec49`") belong to a recorded
  operation, not to this note.
- Nothing here bears on whether `0xc744` is reached.

## Reproduce

Copy the Ghidra project first, so the case cache is never opened
writable.

```sh
X=docs/spikes/architecture-evaluation/experiments
FW=cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin
H=$(brew --prefix ghidra)/libexec/support/analyzeHeadless
mkdir -p /tmp/gproj && cp -R cases/performing-rigs/research/runs/ghidra_cache/autopilot868/aptrace.{gpr,rep} /tmp/gproj/
$H /tmp/gproj aptrace -process firmware_autopilot868.bin -noanalysis -readOnly -scriptPath $X/ghidra \
   -postScript PointerUseProbe.java out.json 0xea54 noncreate 0xec49 0xeafc
tools/unicorn/.venv/bin/python3 $X/python/capstone_forward_use.py $FW 4000 0xea54 0xeaa6 0xeada --fn e8a8:eae6
tools/unicorn/.venv/bin/python3 $X/python/unicorn_ea54.py $FW
(cd external/macaw && cabal exec -v0 -- runghc ../../$X/macaw/DumpBlocks.hs ../../$FW 0x4000 0xe8a8 0xea40 0xeab0)
external/macaw/dist-newstyle/build/aarch64-osx/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace \
   function-effects $FW 0xe8a8 out=/tmp/fx_e8a8
```

The all-loads run passes the comma-joined `literal_refs.from_addr` of
`function_pointers` rows with `matches_known_function=1` in place of
`0xea54`.

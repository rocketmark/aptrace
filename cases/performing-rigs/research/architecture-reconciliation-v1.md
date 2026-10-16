# Architecture Reconciliation v1: the `FUN_0000b4b4` workflow

Case-side companion to the framework report
[`docs/spikes/architecture-reconciliation.md`](../../../docs/spikes/architecture-reconciliation.md).
It records the firmware-specific results of the read-only capability checks
and maps the `FUN_0000b4b4` investigation onto the target-function workflow.

No investigation was repeated. Nothing canonical changed: the ledger, census DB,
Ghidra projects, claims and Beads state are untouched. All runs wrote to a
session scratch directory or to a scratch copy of the census DB. The compact run
summary is
[`runs/architecture-reconciliation-v1/capability-checks.json`](runs/architecture-reconciliation-v1/capability-checks.json).

Firmware `firmware_autopilot868.bin`, sha256 `6dcdb4c1…52e3`, flash base
`0x4000`. Engines: `aptrace` built from the current tree (cabal reports it up
to date); Macaw `593a918d`, Crucible `a98310893`, What4 `4ce24dc4`, Z3 5.1.0,
Ghidra 12.1.3, Unicorn 2.1.4, Capstone 5.0.9.

## 1. Prior results, re-verified against the records

| Prior result | Record | Status |
|---|---|---|
| 4 direct callers (`0xa068`, `0xa088`, `0xa0ac`, `0xb5c2`), all observed in boot; 278 entries with RAM `r0`; no MMIO from the function | `sercom0-semantic-investigation.md` §2, §5, §6 | Confirmed as recorded. Evidence level: concrete under the boot recipe's 14 assumptions. |
| `r0` is read as RAM, never dereferenced as MMIO; the SERCOM0 base is only a comparison operand | same, §6 (RAW summary over all inputs) | Confirmed. Reproduced here: `function-effects 0xb4b4` is `complete`, 14 blocks, 11 s, 1.06 GB. |
| Unexecuted path `c7c0 → b658 → b5bc → b4b4`; `b4b4.r0 = *(this+0x10)` if `c7c0` runs | `indirect-dispatch-resolution-v1.md` §2 | Confirmed, and now also derived mechanically (§3 below). |
| Slot-7 thunk `0xc744` has no known entry; only its own `bx r3` (`0xc74c`) can load slot 8 | same, §3–§5 | Confirmed as recorded. Ghidra also shows no references to `0xc744` (`runs/pcode-migration-baseline/migration-interruption.md`). |
| 27 unresolved register-indirect sites; 20 of the 23 callback sites have CONCRETE caller values; `0xc744` is a candidate nowhere | `callback-argument-provenance-v1.md`; `status.md` | Confirmed as recorded. |
| `C9:v1` ("definitively reachable") is unsupported in that form | `status.md`; `call-relation-admission-benchmark.md` | Unchanged. |

The census agrees with these records: `b4b4`, `b5bc`, `b6b4` and `a064` are
`DEFINITELY_REACHABLE`, while `b658` and `c7c0` are `NO_KNOWN_PATH`. The census
stores hop counts but no path witness: `nearest_root_addr` is null for 391 of
its 438 functions.

## 2. Macaw on this path

| Check | Result |
|---|---|
| Stored Macaw census used by the agent (`runs/macaw/autopilot868.macaw-census.json`) | **Base** vector-root census: 193 functions, 1,712 blocks. It is not the expanded census. |
| Fresh `macaw-census-expand` (scratch) | 263 functions, 3,521 blocks, 26,658 bytes, 151 normalized terminators, 48 residual classify failures, 5 rounds. 13 s, 2.3 GB. The case dossier still quotes 233 / 3,368 / 26,014 / 136 / 39. |
| Expanded coverage of the path | `b4b4`, `b5bc`, `b6b4` and `a064` are discovered as functions. `b658`, `c7c0` and `c744` are not covered, and neither are the callback-region functions (`ec48`, `f0b4`, `e8a8`). |
| Same-root comparison with Ghidra (`macaw_compare.py`, scratch DB copy) | 256 shared, 40 Ghidra-only, 7 Macaw-only. Neither engine's root-forward closure reaches `c7c0`. |
| Rooted discovery, `aptrace explore … 0xc7c0` | 12 functions in 0.31 s, including `b658`, `b5bc` and `b4b4`, with 3 classify failures. Macaw recovers the whole downstream chain once it is given the path head. |
| Rooted discovery, `explore … 0xc744` | 1 block. The thunk lifts exactly: `r3 = [r0]`, `r2 = 0x413`, `r3 = [r3 + 0x20]`, `bx r3`. |
| ISA classification over the expanded census | All 1,206 direct `BL_i_T1` ParsedCalls carry `semantic_kind = true_indirect_call`. The 23 real register-indirect `BLX_r_T1` calls carry the same label. This is a labeling defect (framework report §F); no current consumer reads the field. |

## 3. Crucible `function_effects` on the path functions (scratch)

| Function | Status | Blocks / steps | Call records |
|---|---|---|---|
| `b4b4` | complete | 14 | none |
| `b658` | complete | 5 / 40 | `0xb662`, `0xb668` |
| `c7c0` | **bounded: step limit 3000** | 17 / 3001 | 10 records. `0xc84a → 0xb658` appears twice, under `*(u8*)(r0+0x2e8) == 0xff` and under its negation; `args_expr` gives `r0 = load32(arg_r0 + 0x10)`, `r1 = r2 = 1`. |
| `c744` | complete | 1 / 17 | `0xc74c`: computed target (the `bx r3`) |
| `b5bc` | raw `partial (some paths aborted)` in 1.4 s | 13 / 329 | Solver enrichment query #41 ran over 13 min in Z3 (1.4 GB) and was killed. The agent wrapper would record `bounded: timeout 300s` and lose the raw result. |

What this shows:

- **Macaw + Crucible already derive the per-hop facts that §2 of
  `indirect-dispatch-resolution-v1.md` derived by hand.** For each call site
  Crucible records the target, the argument terms in the caller's inputs and
  memory, and the path guard. The `c7c0 → b658` call is made under both values
  of the `+0x2e8` guard. That is "on every explored path", which matches the
  manual "on every path" result within the 3,000-step bound.
- These facts reach the ledger only inside `raw`. The typed `calls` field keeps
  only `pc`, the concrete target and concrete arguments. Call guards are never
  solved; enrichment covers accesses and the return value.
- Calls are opaque. There is no mode that follows `c7c0 → b658 → b5bc → b4b4`
  as one path. Each hop has to be summarized separately, and composing the
  hops is manual.
- The recorded runs under `runs/function_effects/` show the same pattern:
  6 of 12 complete (all small functions), 1 partial, 2 at the step bound, and
  2 failed. `e8a8` failed with "all paths aborted" after 1 block (the unrepaired
  `cbz` gap); `ec48` failed on missing `VSTMDB_T1` semantics.

## 4. The workflow, applied to `FUN_0000b4b4`

Key: **auto** = a planner-callable operation produced it; **manual** = it
needed a development session; **gap** = nothing produces it.

| Step | What the records established | How it was produced | Component that could produce it mechanically today |
|---|---|---|---|
| 1. Invocation mechanisms | 4 direct `BL`s; no tail branch; no pointer word to `b4b4` | function_facts (auto) + manual sweep | census edges + `slot_dispatch` sweep: exist, but no single operation |
| 2. Upstream paths | `a064/a084/a0a8` and `b6b4` chains; `b5bc ← b658 ← c7c0` | manual, plus `observed_call_arguments` one level at a time | census graph (backward walk not implemented) |
| 3. Entry-point connectivity | `c7c0` is reached only through vtable `0x14900` slot 8; slot 7 `c744` has no entry; 27 unresolved sites | manual inventory, then `indirect_call_target` / `callback_argument_provenance` (auto, one site at a time) | census `function_pointers` + indirect results: exist, never composed into a frontier object |
| 4. Path conditions | `c7c0` reaches `0xc84a` on every path; `r0` passes through unchanged | manual disassembly | **Macaw rooted + Crucible `function_effects`** (this note §3): exists, untyped, per hop only |
| 5. Feasibility | not attempted | — | `runGateReachability` pattern (the trigger gate's Query A/B/C): exists, but as a case script and intraprocedural only |
| 6. Argument and state | `b4b4.r0 = *(this+0x10)`; the three `0x14900` objects bind SERCOM3/4/1 objects | manual constructor tracing + boot RAM | `function_effects` arg terms + watched fields (auto); composition is a gap |
| 7. Concrete observations | 278 entries; 29 of 86 indirect sites executed; no scenario reaches the path | `observed_call_arguments` (auto) | exists |
| 8. Conclusions | H2 supported in observed contexts; the global negative is not established; one precise missing edge | manual reports; `C9:v1` unsupported | admission has typed path checks; no path evidence feeds them |

A mechanical rerun of the case would answer steps 1–3 with one
`invocation_paths` result whose frontier names `c744` and the unresolved sites.
Steps 4–6 would come from one `path_feasibility` run over
`c7c0 → b658 → b5bc → b4b4`. That run would derive `b4b4.r0 = load32(head.r0 +
0x10)`. Under recorded assumptions (head ∈ the three `0x14900` objects, field
values from boot evidence), "`r0` in the SERCOM0 window" would be UNSAT.
Without them it would be SAT. That is the framework report's milestone (§H).

## 5. Why `b4b4` is a good demonstration, and what it cannot show

It is a good demonstration because every stage has recorded ground truth:
concrete callers, a static unexecuted path, one precise unresolved edge, a
mechanically derivable argument relation, and a hardware-meaningful property
(SERCOM0 window) that can be posed as a solver query.

It cannot show a newly discovered path whose head *is* rooted. A second target
with a rooted, condition-gated path is needed for that. The trigger gate
(`0x8e18 → 0x8f98`, solver-confirmed in `docs/investigations/trigger-input.md`)
is the intraprocedural regression target. A Remote-image target is needed to
show that nothing is AutoPilot-specific. `mando868` has no census build yet.

## 6. Reproduce (scratch only)

```sh
S=<scratch dir>; B=external/macaw/dist-newstyle/build/aarch64-osx/ghc-9.6.7/aptrace-0.1.0.0/x/aptrace/build/aptrace/aptrace
F=cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin
$B macaw-census-expand $F > $S/expand.json
$B explore $F 0x4000 0xc7c0 > $S/explore_c7c0.txt
$B function-effects $F 0xc7c0 out=$S/fx_c7c0     # bound with an external timeout
cp cases/performing-rigs/research/runs/census/census.sqlite3 $S/census-copy.sqlite3
tools/unicorn/.venv/bin/python3 tools/census/macaw_compare.py autopilot868 $S/expand.json --db $S/census-copy.sqlite3
```

# Spike: REA as APTrace's Mechanical Reverse-Engineering Interface

Status: **spike complete, verdict C (Defer)**. Run 2026-10-13 on branch
`spike/beads-workstore` (`4fdfaa3`), with no source changes. Artifacts are in
[`runs/rea-spike/`](runs/rea-spike/). Every number below comes from those
artifacts unless it is marked *interpretation* or *proposal*.

## 1. Verdict

**C — Defer.** REA runs reliably and its evidence format is good. On this
firmware it fails the question that matters.

1. **It cannot represent the target.** REA's raw-binary ARM lane forces
   `ARM:LE:32:v7`. It rejects language overrides and states that "Thumb-only,
   Cortex-M … variants are unsupported in this increment." Execution confirmed
   this:
   - the vector table was decoded as A32 code;
   - none of the 42 vector handlers, including `Reset_Handler` at 0xcc24,
     became a procedure;
   - seeding the handlers produced A32 garbage.

   REA found Thumb code only through Ghidra's byte-pattern function-start
   search. None of the 202 REA procedures can be reached from the vector roots
   through REA's own call graph.
2. **It adds no independent lineage.** REA's engine is Ghidra (12.1.3), the
   same engine as APTrace's Ghidra backend and the census derived from it. As a
   discovery source it can corroborate only Macaw, which APTrace's own
   Cortex-configured Ghidra already does with better coverage:
   - APTrace's Ghidra export has 414 functions; REA found 202.
   - REA found one function entry the export lacks (0xca58).
   - REA found nothing new for the TMC5160 question.
3. **It is not released.** Raw-binary support landed on `main` on 2026-10-12
   (#1868). The current npm release, 6.4.0, cannot open the firmware. Both the
   release and `main` report version `6.4.0`, so the version string does not
   identify the build.

The verdict is not D: the incompatibility is a declared scope limit of REA's
current raw-binary increment, not an architectural one.

## 2. Version and environment

| Item | Value (observed) |
|---|---|
| Host | Mac mini, Apple M4 Pro, 12 cores, 24 GiB, macOS 26.6.2 (25G83) |
| Firmware | `firmware_autopilot868.bin`, 70,768 B, sha256 `6dcdb4c1…2e3`, from a read-only, hash-verified copy |
| Target assumptions (case) | load base 0x4000, ATSAMD51J19A, Cortex-M4F, Thumb-only, 16 + 136 vector words |
| REA tested | `morluto/rea` `main` @ `ddcdb3c37837fb8eda0fdee92853774453f1b4ef`, built from source |
| REA release tried | npm `rea-agents@6.4.0` (gitHead `a56f7bb6`): cannot open the target |
| Node | 24.21.0 official tarball (SHASUMS256 verified), isolated |
| Ghidra | existing Homebrew 12.1.3 (REA verified against 12.1.4; accepts any 12.1.x). Native decompiler `mac_arm_64` present. Not modified (0 files newer than the spike start). |
| JDK | existing Homebrew OpenJDK 21.0.12.1 |
| REA Ghidra profile | `BinaryLoader`, `ARM:LE:32:v7`, cspec `default`, `ghidra-default` analyzers, profile digest `fe8301bf…` |
| Macaw | APTrace `aptrace macaw-census`, binary sha256 `30ee4e92…`, Macaw checkout `593a918d`, `cabal build --dry-run`: up to date |
| APTrace Ghidra (reference) | `ARM:LE:32:Cortex` plus vector seeds (`tools/ghidra/aptrace_ghidra.py`); committed export `runs/ghidra/firmware_autopilot868.json` |

Isolation: REA, Node, and REA's `HOME` lived in a scratch directory outside the
repository. The existing Ghidra was used read-only. REA itself imports into an
ephemeral project with `-readOnly -deleteProject`.

## 3. Capability matrix (on this firmware)

| # | Capability | Result | Evidence |
|---|---|---|---|
| 1 | Firmware identity / digest | **Working.** REA's digest equals the file digest. The evidence id is content-derived and independent of the file path. | `01-load-image.json`, `path-a/b.json` |
| 2 | Cortex-M / Thumb interpretation | **Failed / unsupported.** `ARM:LE:32:v7`, empty entry context (no TMode). A Cortex override is rejected. | `01`, `06-cortex-override.json` |
| 3 | Address mapping | **Working.** File offset 0 maps to 0x4000–0x1546f, verified. | `01` |
| 4 | Entry-point handling | **Failed for MCUs.** The entry is also the load base and is decoded as an ARM function, so the initial-SP word reads as `andcs r0,r3,r0`. | `02-instr-entry.json` |
| 5 | Code / function discovery | **Partial.** 202 procedures: 201 Thumb by pattern search, 1 A32 (the vector table). No vector handlers. | `05-procs.json`, `compare.json` |
| 6 | Disassembly of a known region | **Working where Thumb was found** (for example 0x99c2, 0xb4b4). **Failed at Reset_Handler** (`not_found`). | `04-instr-reset.json`, dossiers |
| 7 | Function inspection | **Working.** Dossier with body ranges, blocks, typed references, p-code effects, and limitations. | `pass1.dossiers.jsonl.gz` |
| 8 | Cross-references | **Working, untyped.** `xrefs` returns bare source addresses. Typed edges are in the dossiers. | `tmc.json`, `probe-b17e.jsonl` |
| 9 | Call relationships | **Working** for resolved direct calls. Callers are missing wherever the caller is not an REA procedure. | `compare.json` |
| 10 | Decompilation | **Working** (for example 0x9f60, 0xb4b4). | `tmc.calls` (latency below) |
| 11 | Errors and limitations surfaced | **Working.** Typed errors with remediation. Limitations state the Cortex-M gap verbatim. | `04`, `06`, dossiers |
| 12 | Reproducibility | **Working.** Two independent sessions gave 202/202 identical dossier values and identical evidence ids. | `pass1/2.summary.json` |
| — | Byte fidelity | **Working.** `read_bytes` equals file bytes at 0x4000, 0x99c2, 0xa000, 0xcc24, 0x15400. | `tmc.json` |
| — | Seeds (`REA_GHIDRA_SEED_FILE`) | **Harmful here.** 42 vector-handler seeds gave 20 A32 functions and 22 failures. Reset_Handler decoded as `ldmdami r10,{…}`; its bytes `194b` are Thumb `ldr r3,[pc,#0x64]`. | `07-vector-seeds.json` |
| — | MMIO / memory-access semantics | **Untested as such.** P-code memory effects exist but carry no peripheral model. Literal search and xrefs work. | `tmc.json` |

Two documented, no-patch attempts were made at the Thumb/Cortex blocker: the
language override and vector seeds. Both failed. Work on the blocker stopped
there, per the spike rules.

## 4. AutoPilot observations (TMC5160 experiment)

Scope: one fixed query set built only from external grounding:

- SVD/datasheet constants for SERCOM5 and PORT;
- the user-supplied pins PB03/PB02/PB01 (SPI) and PB08/PA18/PB09/PA19 (CS).

No Macaw output was used as input. Script: `scripts/rea_tmc_session.py`.
Output: `evidence/tmc.json` and `tmc.calls.jsonl` (the latter reproducible but
not committed).

**Observations (REA, single Ghidra lineage, static):**

| Query | Result |
|---|---|
| Literal 0x43000400 (SERCOM5 base) | At 0xb1dc, 0xb508, 0x14878. Referenced from 0xb4d8 (procedure 0xb4b4) and 0xb17e (no procedure). 0x14878 has no xrefs. |
| Literal 0x43000418 (INTFLAG) / 0x43000428 (DATA) | none / 0x1417c with no xrefs |
| PORT GROUP1 (PB) base, PB OUTSET/OUTCLR/PMUX0/PINCFG0 literals | **none** |
| PA OUTSET 0x41008018 / OUTCLR 0x41008014 literals | 0xc898 / 0xc89c, referenced at 0xc824 / 0xc830 in procedure 0xc7c0 |
| PORT base 0x41008000 literal | 0x6108 (ref 0x60f6, no REA procedure), 0xbd58 (no xrefs), 0xd3d8 (in 0xd388), 0xd4bc (in 0xd40c) |
| `{port,pin}` u32 pairs PB08 / PB09 / PA18 / PA19 | 2 hits each: 0x14434/0x147ac, 0x1444c/0x147c4, 0x14374/0x14584, 0x1438c/0x1459c. Spacing PB08→PB09 and PA18→PA19 is 0x18. |
| Pairs PB01 / PB02 / PB03 | 8 / 10 / 3 hits; small integers, low information |
| Strings `SPI\|SERCOM\|TMC\|Trinamic\|motor` | `p_sercom != NULL`, `SPIClass::SPIClass(SERCOM*, …)`, Adafruit samd 1.7.11 `SPI.cpp` path; no TMC/motor strings |
| 0xb4b4 pseudocode | Returns 0..5 when `*param_1` equals 0x40003000, +0x400, 0x41012000, +0x2000, 0x43000000, or 0x43000400; otherwise −1 |
| 0xc7c0 at 0xc818–0xc840 | Loads a byte at `[r4+0x2e8]`, multiplies by 0x18, and indexes a table. Adds `port×0x80` to OUTSET/OUTCLR. Stores both pointers and `1<<pin` at `[r4+0x2ec..0x2f4]`, then writes the mask to OUTCLR. |
| 0x9f60 callers (`get_call_graph` backward) | none resolved |
| 0xb148–0xb1cc | Thumb instructions in no procedure (REA, Macaw, or APTrace Ghidra). The literal pool holds SERCOM0/1/2/3/5 bases and 0x20004c3c-range RAM addresses; repeated `bl 0xb312`. |

**Interpretations (hypotheses; not claims, not ledgered):**

- 0xb4b4 matches ArduinoCore's SERCOM-instance → index lookup. It is generic
  library code and not specific to TMC5160.
- 0xb148–0xb1cc matches static constructors (`sercomN` objects) reached only
  through the init-array pointer table. That would explain why no root-seeded
  or flow-based discovery owns it.
- 0xc7c0 matches a driver object caching a chip-select pin's PORT registers.
  **Which pin is runtime state.** It may be the radio's known PA15 CS or a
  motor-driver CS; static analysis does not decide.
- The 0x18-spaced `{port,pin}` hits match two 24-byte pin-description tables
  (Arduino variant). Arduino pin numbers were not derived.

**Answer to the bounded question:** REA surfaced SERCOM/PORT plumbing
candidates (0xb4b4, 0xc7c0, 0xd388, 0xd40c, 0x9f60, orphan 0xb148–0xb1cc). It
established no routine as TMC5160 configuration or communication. Static
analysis found no PB-group constant-address access, consistent with the
census, which has no SERCOM constant-MMIO access for this image. TMC5160
configuration mode stays **UNKNOWN**. Everything REA surfaced here was already
present in APTrace's Ghidra export: the same functions, plus the orphan
references with `fromFunction: None`.

## 5. REA vs Macaw independent comparison

Inputs:

- **REA:** one whole-image session, `evidence/pass1.dossiers.jsonl.gz`.
- **Macaw:** `aptrace macaw-census FW 0x4000`, vector-root seeded,
  `evidence/macaw-census.autopilot868.json`. Two runs had identical sha256
  `605a8fce…`.

Neither run received anything from the other. Comparator:
`scripts/compare_rea_macaw.py`, deterministic. It replays byte-identically from
the committed artifacts. The REA side's `analysis_profile` digest is bound to
an `ARM:LE:32:v7` configuration, while Macaw's is Thumb-only. The instruction
set is therefore **not** a shared target configuration. Every code-level row
below holds only after the declared, mechanical per-function decode-mode
normalization N2, which classifies 201/202 REA procedures as Thumb from their
listed instruction lengths and bytes.

Declared normalizations, all mechanical:

| | Rule |
|---|---|
| N1 | Thumb bit cleared |
| N2 | REA decode mode from instruction lengths and bytes |
| N3 | Call-site containment (REA instruction ∈ Macaw block) |
| N4 | Macaw call-return block starts dropped (Macaw splits blocks at calls; Ghidra does not) |
| N5 | CFG compared as per-function intra-function branch-target sets |

| Observation | Outcome |
|---|---|
| Function entries | `AGREE` 61 |
| | REA-only Thumb 140: `INCOMPARABLE` (scope). REA's call graph reaches none of them from the vector roots, and Macaw is root-scoped. |
| | REA-only A32 1 (0x4000, the vector table decoded as code): REA error by architecture fact |
| | Macaw-only 132: 131 root-reachable via Macaw calls, so `COVERAGE_GAP` for REA |
| Code coverage (bytes) | both 4,526; Macaw-only 10,320; REA-Thumb-only 14,894; REA-A32 112 (vector table) |
| Decode-mode conflicts on common bytes | 0 |
| Instruction boundaries | 460/460 Macaw block starts inside REA-decoded bytes fall on REA instruction addresses: `AGREE` |
| Function extent (61 common) | `AGREE` 32, `DISAGREE` 29 |
| Block starts (N4) | `AGREE` 28, `DISAGREE` 33 |
| CFG targets (N5) | `AGREE` 30, `DISAGREE` 31 |
| Direct calls (N3) | 39 agree; 17 REA-only, 21 Macaw-only |
| Memory / MMIO accesses | `UNAVAILABLE`: the Macaw census emits no memory-access relation |

Disagreement causes seen in samples (not exhaustively attributed):

- **Tail calls.** Macaw absorbs `b.w` tail-call targets into the caller (0x99c2
  absorbs 0x9984; 0x990e absorbs 0xe648…). Ghidra records a terminal call.
- **Non-contiguous bodies.** Ghidra's bodies can be non-contiguous; 0xa000
  includes 0x9fc4 and 0xb43e….
- **Shorter Macaw extents.** REA blocks lie beyond Macaw's function extent at
  0x5858 and 0xa03c, probably because of Macaw's unresolved terminators. This
  was not verified.
- **Call-site attribution.** REA calls originate from bytes outside the Macaw
  function's blocks.

All disagreements are preserved in `compare.json`. No winner was chosen.

**Independently discovered vs analyzed after shared seeds.** Every observation
above comes from runs that received no other engine's findings. The REA run
with vector seeds (`07-vector-seeds.json`) is derived from an architecture fact
(the vector table), not from Macaw. It is excluded from the comparison because
it is a configuration change, not because it is assisted.

**Lookups that are not discovery:** for the TMC candidates, Macaw's
independently produced census was *looked up*, without seeding:

- 0xb4b4: `AGREE` on entry, extent, blocks, and CFG. Macaw records 5 direct
  call sites into it; REA records 1.
- 0xd388 and 0xd40c: entries `AGREE`. 0xd40c has a one-block and one-call
  difference.
- 0xc7c0 and 0x9f60: REA-only (`INCOMPARABLE` scope).
- 0x60ec: Macaw-only, an REA `COVERAGE_GAP`.

## 6. Evidence interoperability (findings, then proposal)

**Observed REA evidence record** (`analyze_function`, 0xb4b4):

- `evidence_id` `ev_457c052c…`: content-derived, path-independent, and stable
  across sessions;
- `subject.digest.sha256` (REA-computed), `subject.local_path`;
- `provider` {ghidra, 12.1.3};
- `analysis_profile` {parameters, `digest`};
- `operation`, `parameters`;
- `raw_result` / `normalized_result`;
- `limitations` (verbatim; includes the Cortex-M gap);
- `confidence: "observed"`, `authority: "shipped-artifact"`.

**Absent:** the REA version or commit. The provider is Ghidra, and `rea
--version` prints `6.4.0` for both the release and `main`. Also absent are any
lineage or assisted marker and any bounded-scope descriptor beyond the
operation arguments.

**Fit with the existing gate:** `structural_source_agreement` sources already
carry an APTrace-set envelope (`lineage`, `firmware_sha256`, `engine_version`,
`assisted`; `source_agreement.py`, `ledger/policy.py`). An REA-backed
`CodeSource` could plug in with no schema change.

**Proposal (not implemented): minimal envelope, adapter-set fields only.**

```json
{
  "engine": {"name": "ghidra", "version": "12.1.3",
             "configuration": {"loader": "BinaryLoader", "language_id": "ARM:LE:32:v7",
                               "compiler_spec_id": "default", "analyzer_preset": "ghidra-default",
                               "rea_profile_digest": "fe8301bf080e4f9dff950435b6742f65b4d5abbdbe4f46e42a2f4e828b67fbf7"}},
  "wrapper": {"name": "rea", "commit": "ddcdb3c37837fb8eda0fdee92853774453f1b4ef"},
  "lineage": ["ghidra"], "assisted": false, "seeds_sha256": null,
  "firmware_sha256": "6dcdb4c1cbe5cae08704d5ff5d9db33173bc2c69c563b4b694fe0c28492c52e3",
  "target_configuration": {"load_base": "0x4000", "entry": "0x4000", "isa": "arm-v7-generic",
                           "matches_case_target": false},
  "scope": {"kind": "whole-image-heuristic", "operation": "analyze_function", "arguments": {"procedure": "0xb4b4"}},
  "native_evidence_id": "ev_457c052caaa5e1fa7c65029f0eaada6f68e54f9b1fc10e1c43bb9fa1d330c480",
  "native_result_sha256": "<sha256 of canonical REA record, stored as a ledger blob>",
  "limitations": ["<REA limitations verbatim>", "REA raw ARM lane is not Cortex-M/Thumb; Thumb code found only by pattern search"],
  "corroboration_eligible": false,
  "ineligibility": ["TARGET_CONFIGURATION_MISMATCH (isa)"]
}
```

Trust boundary (proposal):

- **Set by the adapter, never by a caller or model:**
  - `firmware_sha256`: the adapter hashes the bytes it hands REA and rejects a
    mismatch with REA's `subject.digest`.
  - `lineage` is the constant `["ghidra"]`. REA is a wrapper, and the contract
    identifies engines, not operations.
  - The Ghidra version: REA's `provider.version`, cross-checked against the
    installation's `application.properties`.
  - The REA commit and package-tree hash, from the adapter's pinned
    configuration.
  - `assisted`: true if any seed, name, or annotation was applied.
- **Never accepted from a caller:** the mutation tools (`annotate_*`, `set_*`,
  comments).
- **Model's inputs:** an operation from a whitelist plus an address.
- **Separation:** REA's `confidence` and `authority` stay inside the native
  record and are never mapped to APTrace grades.
- **Eligibility:** with `isa` ≠ the case target, corroboration eligibility is
  false. The gate's existing fail-closed `UNEVALUABLE` / `UNMET` behavior is
  unchanged.

## 7. Performance on the Mac mini

| Measure | Observed |
|---|---|
| Install | Node tarball 199 MB. REA source checkout 678 MB (540 MB `node_modules`); `npm ci` 18.4 s; `npm run compile` 3.2 s. The npm 6.4.0 package is 93 MB / 7.3 s, but unusable here. |
| Cold import + auto-analysis | MCP first query 10.31 / 10.47 / 10.54 s. CLI end-to-end 11.4–12.1 s (first-ever run 15.2 s). |
| `analyze_function`, warm, ×202 | median 9 ms, p95 46 ms, max 0.69 s; 4.0 s total. Whole session 14.4–14.6 s. |
| `xrefs` warm / repeated | 0.5–4.6 ms / 0.5–0.6 ms |
| Decompile (`procedure_pseudo_code`) warm | 4–13 ms |
| `get_call_graph` warm | 3 ms |
| CLI snapshot | exact repeat 0.42–0.43 s (vs 11.4 s); **different** query on the same snapshot 11.7 s, because the snapshot caches results, not the Ghidra database |
| Peak memory | MCP session process tree (node + JVM, sampled every 0.2 s) 1.43 GiB. CLI max single-process RSS 531–660 MiB. Macaw census 3.2 s, 1.6 GiB. |
| Cleanup | No JVM/node left after close. No new temp directories. Ghidra install and `~/.ghidra` untouched. |

Each CLI call performs a full import and analysis unless it is an exact
snapshot hit. A persistent MCP session amortizes that cost to milliseconds.
Any production use would need a long-lived session per firmware digest.
REA's snapshot is not an alternative to `aptrace_ghidra.py`'s persistent
project.

## 8. Recommended production slice

None now (verdict C). Revisit only if **both** of these become true:

- an REA release admits Cortex-M/Thumb raw images, through a Cortex language
  or Thumb entry context plus vector-table roots or Thumb-mode seeds;
- REA's evidence and interface are judged better than extending
  `tools/ghidra/aptrace_ghidra.py`.

Because REA is the Ghidra lineage, its value would be interface and evidence
quality, never independent corroboration. The re-evaluation should repeat
sections 4–5 with that release.

## 9. Blockers and open questions

- **Blocker:** no Cortex-M/Thumb raw import in REA. The language override is
  rejected and seeds decode as A32. Two attempts, both failed.
- **Blocker:** raw-binary support is unreleased. The version string does not
  identify the build.
- **Open:** 0xca58 is an REA-only function entry, reached through the pointer
  table at 0x14900 (0xca59, 0xb1f5, 0xc975, 0xc923). APTrace Ghidra's
  `FUN_0000c980` (224 B) overlaps it, which is a boundary disagreement between
  two Ghidra configurations. Same-engine; not corroboration.
- **Open:** 0xb148–0xb1cc (SERCOM-base static-init code) is owned by no
  function in any engine. This is a coverage limitation shared by all current
  discovery.
- **Open:** which pin 0xc7c0 caches is runtime state. Answering it needs
  concrete execution (Unicorn), not more static queries.
- **Not settled:** whether REA's shared Ghidra decoder would count as
  *correlated* with APTrace Ghidra if both were ever proposed as separate
  lineages. The contract's open question on correlated components applies.

No work items were created.

## 10. Reproduce

```sh
export REA_SPIKE_ROOT=/absolute/scratch/dir      # outside the repo
SP=$PWD/cases/performing-rigs/research/runs/rea-spike
mkdir -p "$REA_SPIKE_ROOT"/{node,fw,out,rea-home,rea-src}
# Node 24.21.0, isolated
cd "$REA_SPIKE_ROOT" && curl -sLO https://nodejs.org/dist/v24.21.0/node-v24.21.0-darwin-arm64.tar.gz \
  && curl -sLO https://nodejs.org/dist/v24.21.0/SHASUMS256.txt \
  && grep node-v24.21.0-darwin-arm64.tar.gz SHASUMS256.txt | shasum -a 256 -c - \
  && tar -xzf node-v24.21.0-darwin-arm64.tar.gz -C node --strip-components=1
# REA at the pinned commit
git clone https://github.com/morluto/rea.git rea-src/rea && git -C rea-src/rea checkout ddcdb3c37837fb8eda0fdee92853774453f1b4ef
(cd rea-src/rea && HUSKY=0 HOME="$REA_SPIKE_ROOT/rea-home" PATH="$REA_SPIKE_ROOT/node/bin:$PATH" \
   npm ci --no-audit --no-fund && HOME="$REA_SPIKE_ROOT/rea-home" PATH="$REA_SPIKE_ROOT/node/bin:$PATH" npm run compile)
# Firmware: read-only copy, verify digest
cp <repo>/cases/performing-rigs/research/firmware/originals/firmware_autopilot868.bin fw/ && chmod 444 fw/*.bin && shasum -a 256 fw/*.bin
# Smoke test (CLI); outputs land in $REA_SPIKE_ROOT/out
$SP/scripts/rea doctor --json
$SP/scripts/q.sh 01-load-image inspect-native-load-image
$SP/scripts/q.sh 02-instr-entry instructions 0x4000
$SP/scripts/q.sh 03-inspect inspect
$SP/scripts/q.sh 04-instr-reset instructions 0xcc24
$SP/scripts/q.sh 05-procs search . --kind procedures --mode regex
# Blocker attempts
REA_GHIDRA_LANGUAGE_ID=ARM:LE:32:Cortex $SP/scripts/q.sh 06-cortex-override instructions 0xcc24
REA_GHIDRA_SEED_FILE=$SP/evidence/vector-seeds.tsv $SP/scripts/q.sh 07-vector-seeds instructions 0xcc24
# Snapshot cache
for i in 1 2 3; do REA_SNAP=$REA_SPIKE_ROOT/out/snap.json $SP/scripts/q.sh snap-$i function 0x99c2; done
REA_SNAP=$REA_SPIKE_ROOT/out/snap.json $SP/scripts/q.sh snap-4-different function 0xa000
# Full MCP passes (repeatability, latency, memory) and the TMC query set
$SP/scripts/peakrss.sh "$REA_SPIKE_ROOT/out/pass1.peakrss" python3 -I $SP/scripts/rea_full_pass.py "$REA_SPIKE_ROOT/out/pass1"
python3 -I $SP/scripts/rea_full_pass.py "$REA_SPIKE_ROOT/out/pass2"
python3 -I $SP/scripts/rea_tmc_session.py
# Macaw (independent; vector roots only)
"$(cd external/macaw && cabal list-bin aptrace)" macaw-census "$REA_SPIKE_ROOT/fw/firmware_autopilot868.bin" 0x4000 > "$REA_SPIKE_ROOT/out/macaw-census.json"
# Comparison (deterministic)
python3 -I $SP/scripts/compare_rea_macaw.py "$REA_SPIKE_ROOT/out/pass1.dossiers.jsonl" "$REA_SPIKE_ROOT/out/macaw-census.json" \
  "$REA_SPIKE_ROOT/fw/firmware_autopilot868.bin" cases/performing-rigs/research/runs/ghidra/firmware_autopilot868.json "$REA_SPIKE_ROOT/out/compare.json"
```

The release attempt was `npm install rea-agents@6.4.0`. It returned `Unknown
flag: --architecture` and, for header detection, `unsupported binary format`.

## 11. Files created or changed

Created only. No existing file, firmware image, or ledger record was modified.

- `cases/performing-rigs/research/rea-integration-spike.md` (this report)
- `cases/performing-rigs/research/runs/rea-spike/scripts/`: `rea`, `q.sh`,
  `peakrss.sh`, `mcp_client.py`, `rea_full_pass.py`, `rea_tmc_session.py`,
  `compare_rea_macaw.py` (disposable spike tooling, not a framework comparator)
- `cases/performing-rigs/research/runs/rea-spike/evidence/` (22 files and
  `SHA256SUMS`, 1.6 MB):
  - native REA records (`01`–`07`, `path-a/b`, `probe-b17e.jsonl`);
  - `pass1.dossiers.jsonl.gz`;
  - `pass1/2.summary.json`;
  - `tmc.json`, `compare.json`;
  - `macaw-census.autopilot868.json`, `vector-seeds.tsv`;
  - timing files.

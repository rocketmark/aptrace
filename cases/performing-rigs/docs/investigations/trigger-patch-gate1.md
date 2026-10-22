# Binary patch verification — Gate 1

2026-10-22. Research only; NOT FOR HARDWARE DEPLOYMENT. Operator investigation using existing APTrace interfaces. Baseline repository HEAD: `e3a308d1e3bee601b05fb16176c9423af4793794`.

## A. Executive verdict

**INCONCLUSIVE.** Independent Ghidra and Macaw results corroborate the declared byte changes, valid Thumb instructions, direct branch destinations, and intended local decision graph. No local instruction defect was demonstrated. Material obligations remain unverified: integrated register/stack preservation with the original caller frame, absence of unexpected writes across successfully completed paths, exhaustive incoming control flow, interrupt interactions, and the added peripheral read's timing effects.

This is not a failed behavioral control or evidence that the patch corrupts state. It is an evidence boundary: the fragment effects operation aborts, and its vacuous solver results cannot certify confinement. Gate 2 was **not executed**. No firmware, analysis implementation, test harness, formal model, or physical device was changed.

## B. Artifact identity and provenance

Both images map as Cortex-M Thumb at `0x4000`. Paths below are relative to the case.

| Image | Path | Bytes | SHA-256 |
|---|---|---:|---|
| Original915 | `research/firmware/originals/firmware_autopilot915.bin` | 70768 | `0e8e807ac987a61659c95111c0532083d761ca01f0b7def51e6acd409bfd7920` |
| Research derivative | `research/generated/trigger-patch-2026-10-22/RESEARCH_ONLY_NOT_FOR_HARDWARE_autopilot915_freshness.bin` | 70796 | `ae9e6a749426fc3d800a0e26d016cc58f818ce8f84d5a7ba12c41d6d727bc616` |

The [authoring packet](../../research/generated/trigger-patch-2026-10-22/) contains `generate-patch.py`, `modification-manifest.json`, `manifest.json`, `native-hashes.json`, `checks.json`, `outcomes.json`, command records and 20 compressed native records. The generator was inspected, **not rerun**. Its interpretation is not the independent decoding evidence.

The recorded firmware hashes in `native-hashes.json` match these images. Fresh standard SHA-256 digests of all 20 compressed records match its corresponding gzip digests by inspection; see [digest listing](../../research/generated/patch-gate1-2026-10-22/saved-native-gzip-sha256.log). This establishes the association with the preserved test packet, not a new behavioral validation or proof that historical execution was faithful. The 138 saved assertions are authoring-stage checks, not 138 independent Gate 1 proofs. The reported rejection, 29,236-write preservation, +24 instructions, and G/W1/B1 controls remain recorded behavioral results; they were not rerun in this gate. In particular the fresh-input control already records changed global write ordering despite equal per-stream contents. No timing equivalence is inferred.

There is no established hash correspondence to the physically tested Nathan release. Appended physical flash ownership and bootloader integrity remain unqualified.

## C. Independent reconstruction

Evidence packet: [patch-gate1-2026-10-22](../../research/generated/patch-gate1-2026-10-22/). `image-identity-and-diff.log` records independent `shasum`, `wc`, and `cmp` output. `cmp` reports six changed bytes at one-based positions 21037–21042, followed by original EOF; its nonzero status is expected. Public APTrace raw dumps independently show:

| File offset / VA | Original | Derived |
|---|---|---|
| `0x522c` / `0x922c`, 6 bytes | `00283ff4b3ae` | `0cf020b900bf` |
| `0x11470` / `0x15470`, 28 bytes | EOF | `002809d11fb53920f7f7b0ff0028bde81f4001d1f3f788bdf3f7d3be` |

No other original byte changes. Original image end is exclusive `0x15470`; derived end is `0x1548c`. This is an extension, not a recovered code cave. Original configuration bytes at `0x12000..0x13000` are unchanged. Physical ownership of the extension does not follow from file confinement.

Original site: `CMP r0,#0; BEQ.W 0x8f98`, falling through to `0x9232` on nonzero. New site: `B.W 0x15470; NOP` (`0x9230`). Ghidra's listing omits the unreachable padding instruction; Macaw explicitly decodes that NOP when supplied as an entry. No declared normal path falls through the unconditional branch to it.

```text
15470 CMP r0,#0
15472 BNE 15488             original nonzero -> original rejection exit
15474 PUSH {r0,r1,r2,r3,r4,lr}
15476 MOVS r0,#57
15478 BL d3dc              existing digitalRead leaf
1547c CMP r0,#0
1547e POP.W {r0,r1,r2,r3,r4,lr}
15482 BNE 15488             fresh nonzero -> original rejection exit
15484 B.W 8f98              original acceptance continuation
15488 B.W 9232              original rejection continuation
```

`ghidra-original-tail.log`, `ghidra-patched-tail.log`, `ghidra-inserted.log`, `macaw-patch-explore.log` and `macaw-rooted-census.json` provide the independent decoding/CFG evidence. All branch destinations are aligned decoded instructions; no overwritten half-instruction remains. The relocated comparison is reproduced at entry. The relocated equality branch becomes a conditional route through the fresh read, then an unconditional jump to the original destination.

The original channel gates, marker `0x7b`, idle `9`, TR check, and first `digitalRead(57)` remain before the site. The acceptance continuation `0x8f98` still writes original state byte `0x200025bd = 3`, restores its frame, and tail-calls `0x6e4c`. Rejection `0x9232` still adds 12 to SP and pops `{r4-r11,pc}`. No new local loop or recursion appears. The rooted Macaw census independently discovers `0x922c -> 0x15470` in function `0x8e18` without supplying the patch as a root; it also retains 199 incomplete/unresolved terminators (48 residual classification failures). It is not an exhaustive global control-flow proof.

## D. Verification matrix

“Verified” below is bounded structural evidence, not a replacement for an unavailable relational proof. Filenames refer to the Gate 1 evidence packet.

| Property | Disposition | Evidence, method and scope |
|---|---|---|
| All modified bytes accounted for | **Verified** | Standard full-file `cmp`/length/hash observations and APTrace raw dumps: exactly six replacements and 28 appended bytes. |
| Changed instructions decode correctly | **Verified** | Ghidra listings plus independent Macaw lifted instructions; explicit padding exploration covers NOP omitted from cached listing. Cortex-M Thumb mapping only. |
| Patch branch targets valid | **Verified** | Both decoders and rooted census agree on direct targets `15470`, `15474`, `1547c`, `15484`, `15488`, `d3dc`, `8f98`, `9232`. No claim about arbitrary indirect entry. |
| Patch entry/exit flow correct | **Verified** | Local decoded CFG: nonzero old sample rejects; zero old sample performs second read; fresh zero reaches original acceptance, fresh nonzero rejects. This verifies routing, not temporal safety or all interrupt interleavings. |
| Required original instructions preserved | **Verified** | Original/derived tails and acceptance-return listing: comparison recreated, acceptance state write and both original epilogues retained. Intentional fresh-read veto qualifies original equality route. |
| Register/stack obligations preserved | **Inconclusive** | Macaw shows six 4-byte saves/restores, balanced 24-byte temporary frame and restored LR; leaf decode uses r0-r3 and no stack. 24-byte decrement preserves existing 8-byte alignment if present. No completed framed relational proof, stack-headroom proof, or interrupt-state proof. |
| Relevant flags preserved or intentionally changed | **Verified** | Local IR/listings: entry CMP supplies old predicate; second CMP intentionally supplies fresh predicate; POP.W does not overwrite NZCV. Known direct caller and next routine overwrite flags before their next conditional. This is operator interpretation of decoded dataflow, not a general all-callers flag-liveness theorem. |
| Unexpected memory writes absent within analyzed paths | **Inconclusive** | Successful helper effects show zero writes. Patch prefix shows six stack stores and original acceptance store, but all fragment paths abort; no complete integrated absence proof. Opaque-call assumptions cannot stand in for the helper's actual effects. |
| New read has no unintended peripheral side effects | **Inconclusive** | Exact MMIO address established and documented read-only input semantics found; read-triggered synchronization/timing and asynchronous changes are unmodeled. No physical side-effect equivalence proof. |
| No unintended CFG edges within analyzed scope | **Inconclusive** | Enumerated direct local edges match intent. Global discovery is incomplete; data-only xrefs cannot exclude other/indirect entries. No exhaustive incoming-edge/confinement certificate. |
| Modification confined to declared scope | **Verified** | Whole-file comparison confines modification to the site and append. This does not certify runtime memory confinement or physical flash allocation. |

## E. Problems, execution state, and hardware read

**No demonstrated instruction defect.** The local save/pop sequence supports balanced stack and restored r0-r4/LR. r5-r11 and r12 have no decoded writer in the inserted code or this leaf. The +24-byte frame does not establish available stack space, exception-stack margin, correct inherited alignment, or interrupt preservation. Starting `function-effects` at the inserted fragment lacks the original caller frame. Its result is `failed: all paths aborted`, 51 steps, 10 reads, seven writes, one opaque call. Several guard queries are unsatisfiable after abort; they are **not accepted as proof that writes cannot occur**. Saved raw/enriched failures are part of the result.

The fresh-HIGH rejection restores old r0 (zero), whereas original nonzero rejection had r0 nonzero. This is an intentional local-state difference that needs caller context, not automatic ABI corruption. `ghidra-original-callers.log`/`ghidra-patched-callers.log` identify the direct call at `0x943a`; `ghidra-caller-continuation.log` shows immediate calls without a conditional consumer. `ghidra-next-call.log` shows `0x9268` overwriting flags before its branch. A whole-program r0/flag liveness proof was not obtained. Exceptions or unrecognized callers are outside that observation.

**Exact read:** leaf `0xd3dc`, argument 57 (`0x39`), literal `0xd408 -> 0x14284`, descriptor `0x147dc`: group B, bit 5. It reads validity at `0x147e4`, group at `0x147dc`, bit at `0x147e0`, and the 32-bit hardware input register **PORT GROUP1.IN `0x410080a0`**, then returns bit 5 (PB05). `read-effects.raw.json` completes in 22 steps: five reads, zero writes, zero calls. Under solver specialization `arg_r0 == 0x39`, the enriched result proves these addresses unique, MMIO membership for the IN read, and bit-valued return; both 0 and 1 remain possible. The specialization is a solver assumption, not a concrete invocation override.

Local Microchip DS60001507N text (`research/runs/tmc5160-datasheet-reconstruction/samd5x-extracted.txt`, sections 32.6.2.2 and 32.8.9; preserved excerpts in this packet) describes IN as hardware-sampled/read-only, with no read-to-clear or acknowledge action documented. The local `config/svd/ATSAMD51J19A.svd` agrees on base/stride/offset and read-only access. However INEN must enable the input buffer. By default an input read requests synchronization, delaying it by two PORT-clock cycles unless the relevant CTRL.SAMPLING group is always active. Therefore “ordinary read with no output/acknowledge write” is supported; “no timing/sampling side effects” is not established. This investigation did not establish the runtime INEN/SAMPLING/clock settings at every possible entry.

APTrace's effects MMIO is symbolic memory, and recorded Unicorn scenarios model register observations; neither certifies the physical synchronizer, interrupts, noise, or read latency. A peripheral update can occur between reads or after the new read. The second comparison narrows the stale-observation interval but does not remove the read-to-acceptance time-of-check/time-of-use window. Gate 3 must retain this limitation. No new release-timing experiment was performed here.

**Conflicting static metadata:** Ghidra's data-reference export associates a reference to `0x200025ac` with `0x15474`, whose decoded instruction is PUSH. That metadata is not accepted as a real absolute-address write; Macaw shows stack-relative stores. Its source is not resolved in this operator pass. Ghidra's public `xrefs` queries are data-only, so “no references to 15470” is not “no incoming branches.” Typed exports also report some CFG/call sources by basic-block start rather than instruction PC. These limitations do not demonstrate a binary defect.

## F. APTrace execution and capability assessment

APTrace directly supplied raw byte dumps; identity-aware Ghidra instruction listings/callers/data references; independently lifted Macaw instructions, local and vector-rooted discovery; and Crucible/What4/Z3 function-effects records. The operator interpreted these outputs into the local graph and matrix. No new verifier, custom analysis algorithm, harness, or manual-proof substitute was introduced. Standard file tools established artifact identity. Small JSON field displays inspected existing results only.

The helper effects operation completed, with 48 solver queries in one process (about 162 seconds enrichment). The patch fragment operation failed despite producing useful prefix effects. Both are retained. Explicit-entry Macaw exploration corroborates decoding but alone is not independent reachability discovery; the subsequent rooted census addresses that distinction. The extra padding exploration resolved a cached-listing omission. Serial Ghidra queries reuse its normal cache and may update its scratch last-disassembly output; no prior named evidence packet was overwritten. No native execution or behavioral differential tests were launched.

| Gap / priority | Observed limitation and impact | Needed reusable capability |
|---|---|---|
| Framed fragment/relational verification — high | Public fragment effects reaches stack-based original returns without the original frame and aborts. Opaque calls clobber caller-saved state and assume no memory effects. Cannot certify integrated state or writes. | Original/derived boundary comparison with explicit live register/stack preconditions, callee summaries or inlining, designated exits, non-vacuity/path-completion checks, and interruption assumptions. |
| CFG confinement certificate — high | Rooted census retains unresolved terminators; xrefs is data-only. Cannot exclude arbitrary indirect/interior entries. | Bounded incoming-edge report with unresolved coverage and original/derived CFG comparison. |
| Hardware-read equivalence — high for physical claims | Plain/symbolic MMIO lacks PORT synchronization and asynchronous semantics. | Documented peripheral contracts and explicit model coverage/unsupported-effect reporting; hardware evidence remains separate. |
| Reliable evidence-query semantics — medium | PUSH-address data-reference anomaly; block source versus instruction source; disasm lists cached units and omits padding. | Typed distinction between inferred data references and instruction memory effects, instruction PCs, explicit decode coverage. |

No repeated behavioral campaigns were needed. Further reruns of the same failed fragment workflow would not close the caller-frame gap. These are recommendations for subsequent APTrace development, not changes authorized or implemented here.

## G. Gate 2 readiness and next work

The identified image is a reproducible candidate for **bounded research differential testing**, with no demonstrated local decode/branch blocker. However Gate 1 is not closed: do not describe it as structurally certified or give an unconditional gate approval. Carry the unverified register/stack, write, CFG and MMIO obligations explicitly into any decision to authorize Gate 2. This report does not initiate it.

With current interfaces, future work can inspect complete-function effects or existing saved caller-state observations, while retaining their bounds. The highest-value missing capability is a non-vacuous caller-frame-aware original/derived fragment check at both exits. Stack margin/interrupt policy, exact input synchronization configuration, and physical flash ownership require additional evidence. Timing qualification, release-to-rearm and full safety-policy verification belong to later gates. No hardware deployment recommendation follows from this report.

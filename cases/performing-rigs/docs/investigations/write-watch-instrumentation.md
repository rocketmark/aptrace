# Memory-hook execution noninterference

Date: 2026-10-21. Scope: APTrace tooling diagnosis and the explicitly requested
repair, not further A/radio or configuration analysis. No firmware image,
apfw2 source, dependency, security policy or hardware was changed.

## Result

**The A25 discrepancy is resolved in APTrace by an automatically selected
execution workaround.** Unicorn 2.1.4 continuous Thumb execution with a memory
hook can skip a later branch after a conditional store and a subsequent flags
change. This occurs even with an immediate-return hook callback. APTrace now
returns to Unicorn's execution boundary after each instruction whenever memory
hooks are installed, including its otherwise implicit dirty-page tracker.
The native dependency itself is unchanged.

The demonstrated root cause is the native engine/hook/Thumb execution interaction.
APTrace's callback reads and fixture construction are ruled out as necessary
causes. Stale IT/predication state is the instruction-level explanation supported
by the traces; an exact Unicorn C/TCG source defect has not been located. This
report does not claim every engine defect or instruction sequence is covered.

## Evidence and isolation

The original single-variable reproducer remains intact in
[`a-radio-semantics-2026-10-20`](../../research/generated/a-radio-semantics-2026-10-20/README.md),
including commands, snapshots, provenance and hashes. The backend at the start
of this investigation was revision `667fe2e912e9b35b19eb8cb3c7deb62d7ec4bba7`;
its `tools/unicorn/concrete.py` SHA256 was
`5420ed465dc3459493d86ea070f00b85e5244cae501c0b1a446a72b257e6c4ee`.
The new [diagnostic packet](../../research/generated/write-watch-runtime-2026-10-21/README.md)
preserves fresh reproduction, isolation, repaired runs and audit results.

Environment: the documented `tools/unicorn/.venv/bin/python3`, Python 3.9.6
ARM64, Unicorn 2.1.4. No rebuild, upgrade or package substitution was needed.

| Experiment | Observation | Implication |
|---|---|---|
| Original A25, continuous execution | Unwatched stages25/dirty1; watched stages0/dirty0. Watched144 versus plain148 recorded instructions. | Reproduced real instrumentation-dependent behavior. |
| A20 controls | Equivalent final staging and dirty state. | Input-sensitive, not a general seed/loading failure. |
| Omit previous-value reads; omit PC/LR reads; immediate-return callback | A25 still diverges. | Neither callback inspection nor Python logging is necessary. |
| Global no-op write hook | A25 still diverges. | Not peculiar to the one-byte watch range. |
| Small synthetic Thumb fixture, no target data/peripherals | Plain writes42; hooked writes99. Hooked execution skips the branch at0x4020 and reaches the fall-through at0x4024. | Firmware semantics and radio modeling are unnecessary to reproduce the defect. |
| Same synthetic fixture, immediate-return write callback | Still writes99, no recorded writes. | Native hook execution itself suffices. |
| Synthetic controls without later flags change | Both write42. | Merely encountering an IT store is insufficient for this reproducer. |
| One-instruction execution boundaries | Both synthetic paths write42; original A25 stages25/dirty1. | A bounded engine-execution workaround is sufficient for the demonstrated fault. |

The synthetic program compares r2 to5, conditionally stores it inside an IT
block, changes flags with `movs`, calls a branch thunk, and returns. The proper
callee writes42; falling through the skipped thunk branch writes99. Fixture
bytes and CLI snapshots are retained; `tools/unicorn/test_write_watch.py`
emits the maintained synthetic fixtures. These are new test programs, not
modified Noxon firmware. Early diagnostic variants were temporary callback-only
changes against the pinned source and were removed before the final repair.
Their precise isolation scope is recorded in the packet README.

## Tooling change

`ConcreteMachine.run` automatically selects `memory-hook-single-step` when any
of dirty tracking, write watches, RAM logging, MMIO logging or MMIO read
force/clear hooks is active. Other runs keep `continuous` execution. The mode is
recorded as `execution_mode` in each result/snapshot. Budgets continue to use the
existing code-hook instruction counter; stop reasons, failures, seeds, observer
callbacks and fresh/reset behavior retain their existing interfaces. The
workaround is general and contains no Noxon-specific branches.

This includes reusable machines' default `track_dirty=True`: an apparently
unwatched library run already has a memory hook. CLI one-shot machines disable
that tracker. Disabling only the explicit write watch was therefore not a
sufficient universal control before this fix.

The cost is a host call boundary per instruction in observed/tracked runs;
long startup traces can take substantially longer. There is no unsafe opt-out
for observed execution. This is an execution scheduling workaround, not an
assertion suppression, fabricated state correction or replacement firmware.

## Regression results and execution limits

Validated command, exit0:

```
tools/unicorn/.venv/bin/python3 cases/performing-rigs/test/test_concrete.py
```

The [saved log](../../research/generated/write-watch-runtime-2026-10-21/regression.log)
records the existing suite and new tests. Generic regression coverage includes
135 observer combinations: LS/EQ/NE predicates, values4/5/6, byte/halfword/word
stores, aligned and unaligned-byte addresses, narrow/broad watches, truncated
write logs, RAM logging, default dirty tracking and a zero-length recent-PC
trace. It checks registers, final bytes and executed-PC coverage against the
unobserved oracle; write-hit PC/address/size/value/previous bytes, counts and
dropped counts are checked. Repeated fresh runs and MMIO logging/read-hook
controls also pass. The case suite tests original A20/A25 in all four
tracked/untracked × watched/unwatched combinations, with the same full
registers, dumped bytes and instruction counts. Eighteen additional direct CLI
synthetic runs agree across observed/unobserved pairs.

Existing direct-call, carry/reset, mapped-region isolation, structured failure,
instruction-limit, fake-tick logging and virtual-link scenario-order regressions
pass. The new generic tests are also registered in the existing call-observation
test entry point, but that standalone entry point could not run in this context.

Separate environment limitations persist: standalone new/call-observation tests
and `virtual_link.py all` / `plus` exited132 during native initialization. Their
coverage through the successful case test runner must not be described as a
successful standalone run. `tools/doctor.sh` exited1: Ghidra could not write its
Java-home save file and the native smoke did not reach its expected address.
The initial compound-shell native reproduction also exited132; the direct CLI
then worked. These are the previously diagnosed execution-context-dependent
macOS initialization boundary, distinct from the guest execution fault here.
No policy bypass was attempted. Syntax checking used a writable temporary
`PYTHONPYCACHEPREFIX` after the default macOS cache destination denied writes.

## Impact on earlier evidence

The [inventory](../../research/generated/write-watch-runtime-2026-10-21/instrumentation-inventory.json)
identifies exposed commands in the relevant A, motor, X and persistence packets:
respectively10/52,6/20,14/59 and8/12 commands install memory hooks. Exposure is
not proof of corrupted results: it additionally depends on the executed
instruction sequence. Code watches, register/pointee captures and final dumps
alone do not install these hooks in the one-shot CLI. Static/Ghidra, Macaw,
solver evidence and preserved firmware identities are unaffected by this fault.

| Evidence dependency | Assessment/action |
|---|---|
| Original watched A25 failure and its missing staging/dirty writes | Instrumentation artifact; do not interpret as firmware behavior. Repaired A25 agrees with the already-used clean A25 behavior witness. A20 control remains valid. |
| Motor chain, resync and second-channel resync; MC4 driver-update and recent-config controls | All five replayed. Identical final registers, dumped memory, stop reason and instruction count. No change to these bounded conclusions. |
| X dispatch0/1/2/3 and six validity/reload/reference/held-input/independent-arm controls | All ten replayed. Identical final registers, memory and stop reasons. X1/X2 counts change76→75; replace count-dependent comparisons, not the demonstrated state outcomes. |
| Existing virtual-link reused-machine scenarios | Implicit dirty hook made historical library runs potentially exposed. Current plus/G/S/ampersand assertions pass in both orders in the case suite. This is bounded revalidation, not a blanket validation of all historical scenarios. |
| D meaning/reporting static chain and its one-shot code-watch/dump experiments | No affected memory-hook dependency in that bounded chain; no D conclusion requires reopening for this defect. |
| Full persistence checkpoint/reset witnesses and long motor saved-record startup | Memory hooks were present. Not replayed in this tooling audit; retained bytes remain historical observations, not newly certified fault-free startup/checkpoint behavior. Revalidate the selected end-to-end witnesses with this backend at the start of durability work. |

Exact replay commands and per-field comparisons are in `impact-commands.json`
and `impact-comparison.json`. These compare state and stops, not only console
success. Historical evidence packets were not overwritten. The audit does not
prove absence of every historical effect, and no broad project rerun is justified
by the unchanged selected motor/trigger outcomes. Negative conclusions based
solely on old hooked traces should be rechecked before stronger use; a missing
write in such a trace cannot now establish a firmware prohibition.

## Remaining gaps and next work

High priority correctness gap addressed: memory observation could silently
alter guest execution. The workaround and noninterference regression now guard
the demonstrated cases. Trust new supported write-watch results within their
tested, bounded model; keep observer caps, assumptions and execution mode visible.
This does not establish physical flash, RF or motor behavior.

Medium priority: the exact upstream native defect and a faster safe execution
strategy remain unresolved. A future dependency evaluation should use the
synthetic reproducer and original A20/A25 controls before removing this
workaround. Native initialization in restricted command contexts remains a
separate documented environment limitation.

Next existing-capability work is the planned durability package, beginning with
replay of the selected original checkpoint and fresh-restart witnesses using
the corrected backend and new output paths. That is necessary to strengthen
those particular persistence conclusions, not authorization to expand this
tooling investigation into configuration semantics. No release gate is promoted.

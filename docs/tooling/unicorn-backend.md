# Unicorn Concrete-Execution Backend

`tools/unicorn/concrete.py` provides the reusable Cortex-M/Thumb concrete
execution engine. It maps caller-supplied firmware and RAM geometry, executes
bounded instruction ranges, and records state without assigning target-specific
meaning to addresses.

Reusable facilities include direct ARM-AAPCS function calls, hooks and bounded
PC traces, RAM/MMIO logging, explicit state carry-forward, structured failure
snapshots, and narrow interrupt delivery through real handler code.

`tools/unicorn/run_concrete.py --help` describes the generic command-line
surface. Cases should wrap it with their own firmware registry, target geometry,
boot assumptions, device behavior, checkpoints, and scenarios.

`tools/unicorn/call_observation.py` turns the watch hits recorded at one
function entry into per-call-site argument observations: the call
instruction that ends at LR is decoded (a `BL` whose target is the entry, a
`BLX rm`, or `OTHER` when the entry was reached by a tail branch and LR names
an earlier frame), and each argument value, plus the word it points at when
`run(watch_reg_pointee=...)` captured it, is classified against
caller-supplied regions. Pointee capture uses `mem_read`, which fires no
memory hooks, so it never perturbs the MMIO model or logs. The agent exposes
this as the `observed_call_arguments` ledger operation over a case scenario.

The same module summarizes watched fields: `run(watch_mem_write=...)` records
every CPU store to a small named range, with the bytes it overwrote (read in
the write hook, before the store commits) and a count of stores the log
could not hold (`mem_write_dropped`). `summarize_watched_writes` reports each
store in run order with width, previous and new value, and the addressing
form of the store instruction (`base+imm`, with the base compared to a
declared object base when the field is not at offset 0; `base+reg`;
`multiple`). `correlate_calls_with_fields` joins entry observations to those
fields: which field an argument points into and whether it held its
initialized value at each call. A field with no observed store was not
written in that run; that is not evidence it cannot change.

Concrete execution is authoritative for what a chosen input does in the modeled
environment. It is not proof over all inputs, and a peripheral stand-in remains
a harness assumption that must be disclosed.

## Memory-hook execution boundaries

Unicorn 2.1.4 continuous Thumb execution can diverge when a memory hook fires
inside an IT block and later flags change; even a no-op callback reproduces a
skipped later branch. `ConcreteMachine.run` automatically executes one
instruction per engine invocation whenever memory hooks are active: dirty-page
tracking (the reusable-machine default), write watches, RAM/MMIO logging or
MMIO read force/clear hooks. One-shot CLI runs without these hooks retain
continuous execution. Results expose `execution_mode` as
`memory-hook-single-step` or `continuous`. Expect greater host overhead for long
observed/tracked runs. Observers and log caps retain their normal meaning.

The generic noninterference regression is `tools/unicorn/test_write_watch.py`;
it is included in the existing call-observation and Performing Rigs concrete
test runners. It compares registers, memory and executed-PC coverage with an
unobserved oracle and checks write-hit contents and truncation. Run through an
authorized documented test entry point; initialization restrictions below still
apply. The [diagnosis and evidence audit](../../cases/performing-rigs/docs/investigations/write-watch-instrumentation.md)
preserve the original failure and repaired A20/A25 controls. Older hooked
snapshots, including implicit dirty-tracked library runs, are potentially exposed;
replay relevant witnesses before strengthening conclusions based solely on them.

## Native initialization failures on sandboxed macOS ARM64

An import/version check does not exercise native engine initialization.
Unicorn 2.1.4 can construct a `Uc` object, then fail with host SIGILL on the
first `mem_map`. In the inspected macOS ARM64 library, `init_cache_info`
queries `sysctlbyname("hw.cachelinesize")`; a failed query falls back to
`mrs CTR_EL0`. A sandbox denial of the query can therefore lead to a native
illegal-instruction failure before any guest instruction executes.

First check the host crash report and the actual native-library path. Compare
an existing regression and the documented CLI under the same interpreter;
do not reinstall packages or change firmware to diagnose this boundary.
The functional Unicorn check in `tools/doctor.sh` supplies a small existing
execution example. A native process crash has no `RunResult`; preserve its
exit status and host diagnostics separately.

Command-policy matching can change the execution context. Where an existing
policy authorizes a canonical command prefix, invoke that documented command
directly. Adding interpreter options such as `-u`, shell redirection, or a
compound shell wrapper may cause a different policy decision. This is not a
Unicorn requirement about Python buffering. Do not broaden policy or disguise
unapproved commands to make a test pass. Use `run_concrete.py --out PATH` for
snapshots, or save the tool's returned output after a direct invocation.
Record context-dependent failures even when an authorized invocation passes.

The Performing Rigs case preserves its concrete scenario results and backend
development record in
[`cases/performing-rigs/docs/investigations/unicorn-backend-results.md`](../../cases/performing-rigs/docs/investigations/unicorn-backend-results.md).

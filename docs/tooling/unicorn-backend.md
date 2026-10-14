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

Concrete execution is authoritative for what a chosen input does in the modeled
environment. It is not proof over all inputs, and a peripheral stand-in remains
a harness assumption that must be disclosed.

The Performing Rigs case preserves its concrete scenario results and backend
development record in
[`cases/performing-rigs/docs/investigations/unicorn-backend-results.md`](../../cases/performing-rigs/docs/investigations/unicorn-backend-results.md).

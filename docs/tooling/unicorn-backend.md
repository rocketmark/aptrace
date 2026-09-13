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

Concrete execution is authoritative for what a chosen input does in the modeled
environment. It is not proof over all inputs, and a peripheral stand-in remains
a harness assumption that must be disclosed.

The Performing Rigs case preserves its concrete scenario results and backend
development record in
[`cases/performing-rigs/docs/investigations/unicorn-backend-results.md`](../../cases/performing-rigs/docs/investigations/unicorn-backend-results.md).

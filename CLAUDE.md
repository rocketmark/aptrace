# APTrace — Operating Rules for Claude Code

Mandatory, not advisory. Read [`docs/tooling/tool-selection.md`](docs/tooling/tool-selection.md)
before doing any firmware-analysis work in this repo — it has the full
rationale, decision guidance, examples, and anti-patterns behind the rules
below.

## Tool selection

APTrace is a workbench, not a monolith: it orchestrates specialist tools
rather than reimplementing what they already do well.

- **Ghidra** — static RE, decompilation, cross-references, structure/table
  recovery, MMIO/global naming. `tools/ghidra/analyze_firmware.sh`.
- **Unicorn** — concrete Cortex-M/Thumb execution and state capture.
  `tools/unicorn/run_concrete.py`.
- **Macaw** — independent machine-code CFG discovery and ARM/Thumb lifting.
  Used via the `aptrace` CLI (`APTrace.FirmwareLoader`, `APTrace.VectorTable`).
- **Crucible + What4 + Z3** — targeted symbolic reachability and input
  solving, once the question and code region are already understood. Used
  via `APTrace.SymbolicRunner` / `APTrace.ProtocolHarness`.

**Do not use Crucible to approximate ordinary concrete execution when
Ghidra or Unicorn can establish the needed context/state more directly.**
Symbolic execution is for "what input satisfies this property," not "what
does this code do from a known state" — that second question is Unicorn's
job, and it's much cheaper.

**Do not hand-reimplement a capability a mature tool already provides.** If
APTrace is missing something, stop and find an appropriate Galois or other
open-source tool for that gap before building a custom substitute — see
"Known capability gaps" in `docs/tooling/tool-selection.md`.

**Tool disagreements are signal, not noise — investigate them, don't pick a
side by default.** Concretely: **do not trust Macaw's A32/ARM-mode
interpretation of anything on this ATSAMD51/Cortex-M4F target without
resolving the discrepancy first.** Cortex-M has no ARM execution state; an
A32 lift here is either a real Macaw/dismantle decode limitation or a sign
you've mis-seeded discovery. Ghidra's `ARM:LE:32:Cortex` language is
Thumb-only by construction (see `tool-selection.md`) and is the standard
cross-check.

## Project sequencing

**Do not move to the Remote (`mando`) firmware until the documented
AutoPilot-only milestone is complete.** See
[`docs/project-status.md`](docs/project-status.md) for the exact milestone,
current blocker, and next steps — it is the single authoritative source of
current project state; if anything else in the repo conflicts with it,
`project-status.md` wins.

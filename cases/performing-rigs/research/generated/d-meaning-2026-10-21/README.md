# D/SN bounded evidence packet

Interpretation: [D serial-number contract](../../../docs/investigations/d-serial-number-and-compatibility.md).
The manifest pins images, queried projects, tools, operations and assumptions.
`concrete-commands.json` records all30 direct runs; `static-commands.json` lists
native queries. `observations.json` records153 artifact checks.

Reproduce selected commands directly from repository root with the documented
`tools/unicorn/.venv/bin/python3 tools/unicorn/run_concrete.py` prefix, changing
only `--out` to a new destination. Do not wrap native execution in a comparison
subprocess, redirect it through the shell or change the interpreter prefix.
Use the two Java environment settings in the manifest for Ghidra operations;
serialize operations on one project. No new harness/dependency is required.

| Authoritative group | Oracle |
|---|---|
| `d-command-*` | Original dispatcher returns with exact32-bit runtime/staged value and DE marker. These runs test value semantics, not save durability. |
| `d-report-*` | Eleven comma-terminated fields; first stays20 from unrelated source200; ninth equals D without scaling. Negative-1 serializes as-1. |
| `remote-serial-field9-*` | Original parser context1; four-field tail starts at field7, with distinct field8 marker88, D in field9, field10 value10 and trailing777 sentinel. Field8 cache88, serial word D (minus sign discarded), four bytes left unread. |
| `serial-render-frame-*` | Original renderer generates001234,012345 or out-of-display-range`:00000` before numeric draw. Label-call site selects original SN: literal. |
| `serial-render-0-visible1`, `serial-render-1234-visible0` | Original branches suppress SN display. |
| Two915 runs | Same field9 report and six-digit formatting as868. Relevant native915 ranges/pointers accompany them. |

Retained diagnostics: four `remote-field9-*` probes omit original context and
drain the ring. Four `remote-field9-context-*` probes vary field8 rather than9.
Use the distinct-marker serial fixtures above. Three initial enabled/nonzero
`serial-render-*-visible1` probes fault because a mid-function entry needs local
stack space above SP; corrected frame probes reserve that space. The failures
are invocation limits, not evidence of a firmware defect. No assertion was
weakened or firmware/tooling modified to obtain successful witnesses.

These are bounded command/parser/formatter observations, not natural RF session,
physical display or identity-uniqueness evidence. The original D provisioning
producer remains unknown; a generic host-to-radio forwarding path is not proof
of a vendor provisioning workflow. The established persistence round trip is
referenced by the report rather than repeated here.

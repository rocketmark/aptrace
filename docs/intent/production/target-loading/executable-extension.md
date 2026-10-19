# Format-aware executable analysis: bounded extension

Scope authorized by the 2026-10-19 capability-development request. This is a
scoped design/acceptance contract, not approval of the skeleton HLD.

Extend the existing Ghidra lifecycle rather than create another importer.
Legacy raw Cortex-M registry entries, arguments, cache identities and scripts
remain unchanged. A separate declarative executable registry selects native
executable import; Ghidra recognizes PE, language, compiler, sections and
imports. Validate the resulting PE32/x86 identity before admitting its cache.
Never apply raw load-base arithmetic, Thumb normalization or vector seeding
to an executable. Reuse the static exporter; add native inventory/function/CFG
queries with bounded output and explicit static-evidence limitations.

Host evidence carries input/tool/script/configuration identity and query bounds.
It is not passed through ARM census resolvers or the firmware claim derivation
that labels session facts PROVEN. The research CLI selects the host capability
from an explicit target or an unambiguous registered executable name in the
objective, before creating any ARM executor. Host results are raw static
observations, never newly VERIFIED claims or implied Windows execution.

Acceptance: native PE32/x86 import, imports/strings/xrefs/functions/CFG and
decompilation; reject unsupported formats/architectures and raw-file address
queries; stale identity rejection; bounded result/truncation accounting;
automatic/explicit routing and ambiguous-target refusal; fresh synthetic PE
positive/negative controls and existing ARM regressions. Use isolated test
caches/ledgers. The vendor acceptance target and findings stay in its case.

No physical flasher execution or hardware inference. No host OS emulation,
new instruction semantics, general census redesign or claim-policy weakening.

Implementation also exposes bounded mapped-data windows and explicit transient
native entry discovery for pointer-derived entries left unattributed by initial
Ghidra analysis. This does not persist seeds or reinterpret instructions.
The host controller journals a deterministic bounded discovery strategy; typed
host semantic admission and Windows/serial execution remain future capabilities.

# P-code migration v2: interruption record

Status: halted by an external tooling blocker. This is not a failed technical
evaluation of Ghidra p-code.

- Writing the new walker source file was stopped by the session's
  safety classifier before the file was saved. The tool interface reported
  no reason code or diagnostic beyond "stopped by a safety classifier".
- On the user's instruction, the implementation is not retried in any form.

Preserved:
- Safety-gate commit 1bdeaef on main (575 passed, 1 skipped).
- Branch feat/pcode-indirect-target at 1bdeaef; working tree clean.
- v2 baseline over 86 sites: v2-all.json (this directory).
- Protected-state fingerprints: protected-before.sha256. They were
  re-verified and are unchanged.

Ghidra findings (read-only probe on a scratch copy of the project):
- The flash image is one writable block, so immutability must come from
  APTrace target configuration.
- The cspec gives parameters r0-r3, then Stack[0x0] as parameter 4; the
  call-clobber list and the unaffected list come from the cspec.
- `bx/blx rN` lower to BRANCHIND/CALLIND of (rN & ~1).
- Switch tables appear as COMPUTED_JUMP references plus a DATA reference to
  the table.
- 0xc744 (slot 7) has no fall-from and no references in Ghidra. Finding
  pointer-entered code needs a memory scan of pointer words.

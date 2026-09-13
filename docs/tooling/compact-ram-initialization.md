# Compact RAM Initialization for Symbolic Queries

A symbolic harness should not materialize every byte of a large zero-filled RAM
segment as an individual solver term. Represent the default region compactly and
apply only the bounded symbolic or concrete overlays required by the query.

This keeps What4 expressions proportional to the question rather than to the
target's total RAM size. The important correctness constraints are:

- preserve normal byte-addressed read/write semantics;
- make overlay precedence explicit;
- separate concrete initialization from symbolic variables and assumptions;
- validate the compact representation against concrete execution for the same
  bounded region.

The concrete investigation that motivated and validated this technique is kept
with its case at
[`cases/performing-rigs/docs/investigations/compact-ram-initialization.md`](../../cases/performing-rigs/docs/investigations/compact-ram-initialization.md).

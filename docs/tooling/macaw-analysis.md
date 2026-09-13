# Macaw Static Analysis

APTrace uses Macaw as an independent Cortex-M machine-code discovery and lifting
path. The reusable layer loads raw firmware, seeds normalized Thumb entry
points, preserves unresolved transfers, and iteratively feeds safely recovered
targets back into discovery.

The pipeline separates the machine-level meaning of ambiguous parsed transfers
from higher-level function-call assumptions. Normalized evidence records its
provenance, and deterministic exports can be compared with Ghidra without
treating either tool as infallible ground truth.

Framework modules include `APTrace.MacawCensus`, `APTrace.MacawExpand`,
`APTrace.MacawIsaClassify`, `APTrace.MacawNormalize`, and
`APTrace.MacawRefinement`. Target geometry and firmware roots are caller inputs.

Material boundaries and disagreements should be cross-checked against Ghidra or
concrete execution. The detailed Performing Rigs results that motivated the
normalization and classification layers are preserved in
[`macaw-analysis-results.md`](../../cases/performing-rigs/docs/investigations/macaw-analysis-results.md).

# Adding an APTrace Case

A case is a concrete firmware/hardware investigation that consumes APTrace's
reusable engines. Put it under `cases/<case-name>/` and keep its target identity
out of framework directories.

At minimum, a case should provide a README describing its targets and entry
points. Add status, roadmap, instructions, configuration, scripts, source, tests,
documentation, and research directories only when the case actually needs them.

## Ownership rule

The framework owns mechanisms: loaders, execution engines, discovery,
normalization, evidence schemas, and generic backend interfaces. A case owns
recipes: firmware registries, memory geometry, known addresses, scenarios,
device models, experiments, and generated or collected evidence.

Case code may depend on framework code. Framework libraries must not depend on
a case. An application may wire a case to framework entry points explicitly.

## Documentation and evidence

Ask whether a document could exist substantially unchanged if the target had
never existed. If not, place it in the case. Preserve raw evidence and
provenance under the case even when extracting a reusable methodological lesson
into root documentation.

Do not create a root `research/` directory for case evidence. Case-local and
proprietary files should be covered by case-specific ignore rules and paths.

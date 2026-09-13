# Framework/Case Boundary and Deferred Coupling

The physical ownership rule is established: framework mechanisms live at the
root and Performing Rigs recipes/evidence live under
`cases/performing-rigs/`. A few explicit integration seams remain to preserve
the working single-case application.

## Intentional current seams

- `app/Main.hs` is the composition root and imports the Performing Rigs case
  modules to expose the existing case commands.
- `aptrace.cabal` includes `cases/performing-rigs/src` and the case Haskell test
  directory. This retains one build and the existing module namespace without
  inventing a multi-package/plugin design.
- `tools/ghidra/aptrace_ghidra.py` loads the current firmware registry from the
  case configuration and defaults its cache to the case research tree.
- The census CLI/build/reducer imports case boot, SVD/pin, reference-source,
  semantic-classification, and hardware-contract recipes. The generic schema,
  ingestion, reachability, fingerprinting, comparison, and reduction mechanics
  remain in `tools/census/`.
- `tools/doctor.sh` optionally uses the Performing Rigs firmware as an installed
  smoke fixture. Missing proprietary firmware is already a supported skip.
- `ConcreteMachine` and `run_concrete.py` retain the historical flash/RAM
  defaults used by the current case. Callers can override all of them; changing
  defaults in this organizational pass would risk existing workflows.

## Deferred extraction

If a second case is added, make case selection explicit at the CLI boundary and
inject registries, cache/output roots, SVD resolvers, boot recipes, and hardware
contract builders rather than importing the Performing Rigs configuration.
Likewise, decide whether case Haskell modules become a second Cabal package only
when another real case makes that separation useful.

These are bounded composition/configuration couplings, not framework-library
dependencies on concrete findings. Moving them further now would require API
design beyond the scope of this repository-organization refactor.

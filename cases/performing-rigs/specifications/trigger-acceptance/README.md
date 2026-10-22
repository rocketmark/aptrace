# Reference trigger acceptance contract — 2026-10-22

**A proposed parameterized contract, checked with TLC in finite scopes.** This
is TLA+ specification and evidence, not executable replacement firmware, a proof
of an implementation, or proof of physical trigger reliability.

Start with [HANDOFF.md](HANDOFF.md) for the implementation contract and
[VERIFICATION.md](VERIFICATION.md) for exact claims, assumptions and limitations.
The formal authority for the checked transition system is
[TriggerAcceptance.tla](TriggerAcceptance.tla). Unsafe mutation constants must
all be FALSE. [behavioral-tests.json](behavioral-tests.json) is a declarative
implementation test suite; [original-fixtures.json](original-fixtures.json)
binds selected original-firmware comparisons to prior native execution.

The chosen policy requires fresh inactive qualification after readiness,
configuration, completion or cancellation. Only a subsequent qualified active
episode can create an event. Recognition, acceptance and motion start are
separate transitions. A single-use authorization gate covers both profile
playback and direct request routes. STOP/reset invalidate pending events;
completion does not replay held input. See the handoff for deliberate costs:
preexisting asserted inputs, pulses while busy, and release before commitment
are intentionally not guaranteed to start motion.

Five positive configurations completed exhaustive finite graph searches, with
all listed properties satisfied. Eight expected-failure checks retain meaningful
counterexamples: three unsafe mutations, two invalid progress assumptions and
three evidence-linked Noxon abstractions. The Noxon abstraction is **not** formal
verification of the original binary. No new firmware reversing was needed.

Timing values, electrical thresholds/transfer, filter implementation, physical
reference validation and hardware completion integration remain external
parameters/obligations. This package is sufficient to implement the parameterized
controller and tests without inventing transitions; it is not a production
configuration or authorization to run motors. An implementation still needs a
refinement/conformance review, especially all timer-start entry points.

## Reproduction

TLC was absent from the existing APTrace environment. The user's explicit
TLA+/TLC assignment authorizes this case-owned specification/checking workflow;
no APTrace framework capability or dependency was changed. The tools were fetched
into `/private/tmp/aptrace-tla-2026-10-22/`, not installed into APTrace.

Upstream CLI usage and releases are documented by the
[TLA+ project](https://github.com/tlaplus/tlaplus) and its
[pinned v1.7.4 release](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4).
The downloaded `tla2tools.jar` SHA1 is
`bee4a54f3ee3d4afc347c3240ec2d9e93b075104`, matching upstream. SHA256, Java and
binary identity are in `verification/toolchain.json`. Download example:

```sh
curl -fL -o /private/tmp/tla2tools-1.7.4.jar https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
```

From this directory, with a trusted matching jar:

```sh
TLA_TOOLS_JAR=/private/tmp/tla2tools-1.7.4.jar sh check-models.sh
```

The script only invokes TLC. It does not implement a reference controller.
It checks expected exit codes and named success/violation diagnostics; a parser
failure cannot count as a successful counterexample. It writes `verification/replay/`
and temporary TLC state storage. Historical logs are preserved. Single-worker
runs avoid conflating parallel liveness behavior with this evidence. Full exact
commands used for the recorded results are in `verification/commands.json`.

`MaxEvents` limits the explored event-history budget, not an intended runtime
capacity. TLC bounds of1/2 do not prove arbitrary event counts, all timings or
all parameter combinations. Event IDs must not be reused in an implementation;
see the handoff's wrap/boot-generation rules. No state constraints, symmetry
reduction or random-simulation-only claim is used in the recorded checks.

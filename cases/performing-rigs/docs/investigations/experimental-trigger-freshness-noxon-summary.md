# Noxon discussion: experimental digital-trigger freshness patch

**Simulation-only research. NOT FOR HARDWARE DEPLOYMENT. Partial mitigation,
not a validated corrective firmware release.**

The analyzed original915 image accepts a saved digital LOW and prepares the
programmed move even when the modeled input has returned HIGH. Its requested
motor-control writes match a held intentional trigger. This is consistent with
one possible software contribution to VVR-005; Nathan's actual MCU waveform and
exact tested-release binary identity remain unverified.

A real modified binary now re-reads the original digital input before accepting
the saved LOW. In matched native execution, the reproduced transient is rejected
before acceptance or TC0 enable, including the early0x571c store. A held
intentional trigger still starts the same program; all29,236 captured output
requests match after instruction timestamps are removed. A fresh inactive-to-
active control also starts, with equal named peripheral/motor streams but
different global housekeeping interleaving. No physical movement or continuous
trigger-caused STEP train is established.

The patch is deliberately small: six existing bytes replaced and28 executable
bytes appended, with no permanent RAM use. It adds a second input observation,
not a debounce timer. Release just after that second observation still permits
initiation. Already-active input, repeated starts after supplied W, and analog
fault-band behavior remain unmitigated. The experiment therefore demonstrates
one firmware-only improvement, **not a solution to all VVR-003/004/005 failures**.

Noxon's source-level corrective work should reserve explicit trigger state,
qualify inactive and active intervals from fresh acquisitions, require release
before re-arm, invalidate stale history across session/readiness changes and
keep direct/manual producers separate. Validate intentional approximately500ms
pulses and connection waveforms on the exact release and hardware. A source that
electrically presents the same history as a legitimate closure cannot be
distinguished by intent alone; polarity/leakage and interface corrections remain
independent electrical requirements.

See the [full report](experimental-trigger-freshness-patch.md) and
[reproducible evidence](../../research/generated/trigger-patch-2026-10-22/README.md).

# AutoPilot static protocol inventory v0.3

This pass follows v0.2 by tracing **AutoPilot outbound event producers** and the Remote's **synchronous response parsers**.

Major additions / corrections:

- Exhaustive survey of direct writes to the AutoPilot pending-event array at `0x200025bc`.
- Producer sites identified for active events 1, 4, 5, 6, 7, 10, 13, 15, 16, and 17.
- `&|` is now identified with high confidence as the **AutoPilot firmware-version query**; this build returns `V01R39` and the Remote displays that buffer on its firmware-information screen.
- `S|` -> `P...` response grammar mapped on both sides.
- `!0|` / `!1|` -> event-7 bulk CSV mapped on both sides, including a significant **11-fields-emitted / 10-fields-parsed** discrepancy.
- Dynamic `I<channel><mode>|` request linked to the AutoPilot per-channel state machine and event-15 numeric reply.
- `G<d><d><seq>|` -> `#` synchronous acknowledgement strengthened; sequence digit cycles 1..9.
- `W1|` conditionally schedules event 17 with count 5; the Remote waits only for one `#`.
- Event 13 resolved structurally as `a0`, `a1`, or `a2`, repeated five times at startup and once on later state changes.
- No direct producer was found for events 2, 3, 8, 9, 11, 12, or 14. `M1`/`M2`/`M3` also have no matching active Remote parser in this build, so they are now classified as likely dormant/legacy/compatibility endpoints rather than harness priorities.
- The earlier v0.2 suggestion that event 8 might be the firmware-version response is downgraded: event 8 is a three-part numeric formatter with no producer found, while `&| -> V01R39` is the proven firmware-version path.

Key files:

- `pending-writes.csv` — direct pending-event producer sites and trigger contexts.
- `pending-events.md` — interpretation of the producer survey and dormant-event findings.
- `synchronous-responses.md` — Remote request/response routines and exact grammars recovered so far.
- `event7-schema.md` — exact event-7 output fields and the 11-vs-10 parser mismatch.
- `responses.csv` — updated outbound event table.
- `commands.csv` — updated command inventory and response links.
- `protocol-bidirectional.md` — validated software-only transactions for the harness.
- `functions-of-interest.md` — revised hook/entry-point list.
- `open-questions.md` — next static-analysis targets.

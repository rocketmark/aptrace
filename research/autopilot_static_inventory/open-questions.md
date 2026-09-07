# Open questions — v0.3

Priority order for the next static pass:

1. **Name event-7 fields** by tracing the Remote stores after each of its ten `0xb51c` parses and matching those RAM locations to UI labels / behavior. Preserve the 11th AutoPilot field as a separate compatibility question.
2. **Resolve the `I<channel><mode>|` numeric semantic** by tracing table `0x20002064` producers and the per-channel state machine around `0x20001b14` / `0x200029d8`.
3. **Name `a0/a1/a2` states** by tracing producers of `0x2000209d` and `0x20002529` and the Remote-side state variable written by the lowercase parser.
4. Trace all five backing values in periodic `MTddddx|` to prove motor-presence/external-input semantics.
5. Trace `T...|` outbound telemetry values back to motion/state globals and separate them from the inbound non-TR `T` command path that can schedule `##`.
6. Resolve the `PN...` branch known to Remote `0xc440`: determine whether it is unreachable in this build or produced through a non-event path.
7. Reconcile Remote-originating packets not accepted by the visible AutoPilot main parser: `MS|`, `MR|`, `MM|`, `N|`, `KK|`, `E1...|`, bare `W|`, and the short `I9|`/`I1|` query forms.
8. Determine whether events 8, 9, 11, 12, and 14 are truly unreachable in this build or can be scheduled through computed-pointer/indirect writes missed by the direct-reference survey. This is a good symbolic-execution/reachability target for the harness team.

# APTrace UI/UX Brainstorm

> **Status:** Early product thinking, not an implementation plan.
>
> APTrace is still defining its core evidence, scenario, and execution models. This document captures UI/UX ideas that may help guide those models without committing the project to a frontend too early.

## 1. Product idea

APTrace should eventually feel like an **evidence-first firmware investigation workbench**.

The UI should not try to replace Ghidra, Unicorn, Macaw, Crucible, or other specialist tools. Those remain analysis and execution engines. APTrace should organize the questions we ask of firmware, the runs we perform, the evidence those tools produce, and the conclusions we can responsibly draw from that evidence.

The primary thing a user works on should therefore be an **investigation** or **scenario**, not a backend, function, or disassembly listing.

Examples:

- What happens when the remote sends `I02F|`?
- Which timer controls motor channel 2?
- Which GPIO pin ultimately receives the step pulse?
- Does a particular command reach a physical output?
- What input causes this firmware behavior?
- Which parts of this claim are inferred statically, observed concretely, or proven symbolically?

The UI should make it easy to move from a high-level question to the exact evidence supporting each answer.

---

## 2. Core design principle: show both logic and physical behavior

APTrace likely needs **both a logical trace view and a physical hardware view**.

These should not be separate products or separate data models. They should be two projections of the same entities, observations, claims, and evidence.

A third view, a chronological execution timeline, would complement both.

### The three main views

| View | Primary question |
| --- | --- |
| **Trace** | Why did this happen? |
| **Hardware** | Where did this happen? |
| **Timeline** | When did this happen? |

A user should be able to switch among these views without changing the selected scenario or run.

Selecting a timer, function, GPIO, packet, or claim in one view should select the same underlying entity in the others whenever applicable.

---

## 3. Proposed application shell

A useful starting point is the general structure of an impact-analysis workbench:

```text
+--------------------------------------------------------------------------+
| APTrace                         firmware / target            run controls |
+------------------+--------------------------------------+----------------+
|                  |                                      |                |
| Investigations   |      Trace | Hardware | Timeline     | Evidence /     |
|                  |                                      | Details        |
| Scenarios        |           Main canvas                |                |
|                  |                                      |                |
| Saved runs       |                                      |                |
|                  |                                      |                |
+------------------+--------------------------------------+----------------+
| Run status | assertions | warnings | report / export                     |
+--------------------------------------------------------------------------+
```

### Left sidebar

The left side should be oriented around user intent rather than backend machinery.

Possible sections:

- Investigations
- Scenarios
- Saved runs
- Firmware
- Protocol
- Hardware

Early versions may need far fewer sections. The important idea is that command-line tools are not the top-level navigation model.

### Center canvas

The center is the current investigation rendered as one of:

- Trace
- Hardware
- Timeline

### Right inspector

The inspector explains the selected object or relationship:

- claim
- evidence level
- source observations
- function/address/peripheral identity
- concrete run context
- static provenance
- solver result
- unresolved assumptions
- suggested next investigation

The inspector is where APTrace answers:

> Why should I believe this?

### Bottom status area

Potential contents:

- scenario pass/fail
- assertions
- warnings
- unresolved evidence
- run duration
- backend failures
- report generation

This should remain secondary to the investigation itself.

---

## 4. Trace view

The **Trace** view is probably the most useful first UI for APTrace during active reverse engineering.

It should show a semantic/provenance graph rather than a raw control-flow graph.

For example:

```text
I<channel><mode>|
        |
        v
 command handler
        |
        | writes
        v
 per-channel state
        |
        v
 timer configuration
        |
        v
      TC2.CC0
        |
        v
      IRQ109
        |
        v
 FUN_00005898
        |
        v
 FUN_0000d388
        |
        v
 pin_index_table[2]
        |
        v
        ?
```

The nodes do not all have to be functions. They can represent different kinds of entities:

- protocol messages
- parser states
- functions
- variables
- memory locations
- peripheral registers
- interrupts
- GPIO pins
- connectors
- physical outputs
- invariants
- tests

Edges should describe meaningful relationships:

- calls
- reads
- writes
- receives
- transmits
- configures
- triggers
- interrupts
- pulses
- constrains
- verifies
- maps to

The goal is to expose the **chain of reasoning**, not every instruction executed.

### Why this matters

A semantic graph allows an investigation to span multiple kinds of evidence:

```text
protocol -> firmware -> MMIO -> ISR -> GPIO -> hardware
```

That is much closer to the questions APTrace is trying to answer than a traditional call graph.

---

## 5. Hardware view

The **Hardware** view should answer the same investigation spatially.

For the current AutoPilot work, an eventual view might show:

```text
Remote
+------------------------+
| USB/UART          RF   |
|                    o   |
| MCU                    |
+----------+-------------+
           |
           | RF packet
           v
AutoPilot
+--------------------------------+
| RF RX                          |
|                                |
| MCU                            |
|                                |
| TC0   TC1   TC2   TC3          |
|  o     o     *     o           |
|              |                 |
|              v                 |
|         pulse helper           |
|              |                 |
|              v                 |
| GPIO / connector ? --------+   |
+----------------------------|---+
                             v
                         motor driver
```

This should begin as a **schematic representation**, not a photorealistic board renderer.

A schematic is easier to maintain, easier to annotate with confidence and evidence, and better suited to partially recovered hardware.

Later, a board photograph, connector diagram, or PCB representation could become another projection if useful.

### Execution highlighting

During a concrete run, hardware elements could highlight in execution order:

1. UART/RF input receives a command.
2. Parser/command handler activates.
3. A timer is configured.
4. An interrupt fires.
5. A GPIO toggles.
6. A connector or physical output highlights.

This should represent actual execution evidence rather than decorative animation.

### Unknown hardware should remain unknown

If the firmware clearly reaches a table-indexed GPIO helper but the table contents have not been recovered, the UI should show:

```text
TC2 -> IRQ109 -> pulse helper -> GPIO ?
```

It should not invent the final pin merely to complete the diagram.

---

## 6. Timeline view

The **Timeline** view shows the chronological story of a concrete execution.

Example:

```text
0 us       UART RX  'I'
13 us      UART RX  '0'
26 us      UART RX  '2'
39 us      UART RX  'F'
52 us      UART RX  '|'

61 us      command accepted
66 us      channel_state[2] <- FORWARD
72 us      TC2.CC0 <- 0x0138
...
319 us     IRQ109 entered
323 us     GPIO HIGH
326 us     GPIO LOW
```

The exact timing may not always be available or meaningful. APTrace can fall back to sequence numbers or logical steps when wall-clock or cycle timing is unavailable.

The timeline should be filterable by category, for example:

- protocol
- calls
- memory
- MMIO
- interrupts
- GPIO
- stubs
- assertions

The timeline is likely the best place to expose detailed concrete-run information without overwhelming the higher-level trace graph.

---

## 7. Evidence should be a first-class visual concept

One of APTrace's strongest potential differentiators is that it can communicate not only a conclusion, but **how strongly that conclusion is established**.

A useful initial evidence vocabulary is:

### Static

Recovered or inferred from static analysis.

Examples:

- vector table maps IRQ109 to a handler
- a function references TC2 registers
- a parser branch handles an `I` command

### Concrete

Observed during an actual emulated or hardware-backed execution.

Examples:

- TC2.CC0 was written
- IRQ109 executed
- the pulse helper toggled a GPIO register

### Solver-confirmed

Established through symbolic execution or a solver-backed proof/query.

Examples:

- some input necessarily reaches a target behavior under stated assumptions
- an invariant holds over modeled execution

### Unknown / unresolved

A connection is suspected or structurally implied but not yet sufficiently established.

The UI should not treat this as an error state. Unknowns are active research targets.

---

## 8. Uncertainty is part of the product

APTrace should **make uncertainty visible instead of smoothing it over**.

For example:

```text
Per-channel GPIO pin

Status: UNRESOLVED

Known:
- TC1/TC2/TC3 reach a shared table-indexed pulse helper.
- The helper consumes one byte per channel from a RAM table.
- Concrete cold-RAM execution reaches the mechanism.

Not yet known:
- What production startup code writes the real table contents.
- Therefore, which MCU pin corresponds to each channel.

Next useful proof:
- Identify the producer of the pin-index table, or execute a sufficient startup slice.
```

This is better than showing a weakly inferred result as though it were a fact.

It also turns APTrace into an active research assistant: unresolved links naturally suggest the next experiment.

---

## 9. Same entity, multiple projections

The UI architecture should avoid creating view-specific copies of knowledge.

For example, `TC2` may appear as:

- a node in Trace
- a peripheral block in Hardware
- a series of MMIO events in Timeline
- an address/register group in Firmware

These should all refer to the same underlying entity.

Likewise, selecting `IRQ109` anywhere should permit the inspector to show:

- vector-table identity
- handler address
- static references
- concrete executions
- associated scenario observations
- claims that depend on it

This is the strongest argument for building the underlying information model before building much UI.

---

## 10. Suggested core data model

The UI should not drive the core model toward generic "graph nodes and edges." The graph is only one visualization.

A more durable conceptual model might be:

### Entity

Something that exists in the investigation domain.

Potential entity kinds:

```text
FirmwareImage
Device
Function
MemoryRegion
Variable
Peripheral
Register
Interrupt
GPIO
Connector
ProtocolMessage
Scenario
Test
Invariant
ExternalDevice
```

### Observation

Something APTrace actually observed during analysis or execution.

Potential kinds:

```text
Call
Branch
Read
Write
MMIORead
MMIOWrite
InterruptEnter
InterruptExit
GPIOTransition
Transmit
Receive
StubCall
AssertionResult
```

### Claim

A semantic statement built from evidence.

Example:

```text
source: IRQ109
relationship: drives
 target: motor_channel_2_step_mechanism
```

A claim should carry:

- evidence level
- supporting observations
- supporting static analysis
- assumptions
- confidence/status
- provenance

### Scenario

A repeatable experiment or question.

Examples:

```text
Remote version query
Remote go/ack transaction
Remote status request
Motor channel 2 forward command
```

### Run

One execution of a scenario under a particular environment.

Potential contents:

- firmware hash/version
- inputs
- backend configuration
- initial memory/register state
- stubs
- MMIO log
- observations
- assertions
- outputs
- warnings

### Investigation

A higher-level research question that may include multiple scenarios, runs, claims, and unresolved links.

---

## 11. Scenario UX

A scenario should feel like a reproducible experiment.

Possible scenario header:

```text
Scenario: Move channel 2 forward

Input
  I02F|

Environment
  Remote firmware: ...
  AutoPilot firmware: ...
  Backend: Unicorn

Expected observations
  [x] command accepted
  [x] channel 2 state changed
  [x] TC2 configured
  [x] IRQ109 reached
  [x] pulse helper reached
  [ ] physical GPIO identified
```

Running the scenario should update all three primary views:

```text
Run
 |
 +--> Trace: highlights path taken
 +--> Hardware: highlights components activated
 +--> Timeline: records ordered observations
```

A saved run should be reproducible and attachable to claims as evidence.

---

## 12. Investigation UX

An investigation is larger than one execution.

Example:

```text
Investigation
Which physical output is controlled by I02F|?

Claims
[x] I command selects a channel/mode state
[x] channel 2 uses TC2
[x] TC2 maps to IRQ109
[x] IRQ109 reaches shared pulse helper
[?] channel 2 pin-index value
[?] physical connector pin
```

This turns reverse engineering into something closer to an evidence checklist.

An investigation can be considered "closed" only when its required claims reach an acceptable evidence level.

That threshold may differ by use case. A researcher may accept static evidence while a firmware-validation report may require concrete or solver-backed evidence.

---

## 13. Reports as a natural output

Reports should emerge directly from the investigation model rather than being a separate documentation exercise.

Potential report sections:

- question investigated
- firmware versions/hashes
- scenarios executed
- conclusions
- evidence chain
- unresolved assumptions
- concrete traces
- solver results
- relevant addresses/peripherals/pins
- reproduction steps

This is particularly useful for APTrace's original practical goal: producing a technically defensible report about problematic vendor firmware.

The report should distinguish clearly between:

```text
Observed
Inferred
Proven
Unresolved
```

---

## 14. A possible AutoPilot example

A future end-to-end investigation might look like this.

### Question

```text
What physical output does I02F| control?
```

### Trace

```text
I02F|
  |
  v
I command handler
  |
  v
channel_state[2]
  |
  v
TC2.CC0
  |
  v
IRQ109
  |
  v
FUN_00005898
  |
  v
FUN_0000d388
  |
  v
pin_index_table[2]
  |
  v
PB??
  |
  v
AutoPilot connector ??
```

### Hardware

```text
Remote                        AutoPilot

USB -> UART -> RF TX  ~~~>  RF RX -> MCU
                                  |
                                  v
                                 TC2
                                  |
                               IRQ109
                                  |
                                  v
                              GPIO PB??
                                  |
                                  v
                          motor connector ??
```

### Evidence panel

```text
Selected: IRQ109

Claim
  IRQ109 is the TC2 interrupt handler used by motor channel 2.

Evidence
  STATIC
  - vector table slot resolves to handler ...
  - handler accesses TC2 MMIO base ...

  CONCRETE
  - run #42 entered handler ...
  - MC0/OVF acknowledgement observed ...

Used by claims
  - channel 2 uses TC2
  - TC2 reaches pulse helper
```

---

## 15. What not to build yet

Several UI ideas are attractive but probably premature.

### Avoid a full IDE

APTrace does not need to compete with Ghidra's disassembly/decompiler UI.

Deep inspection can link or hand off to specialist tools where appropriate.

### Avoid backend-centric workflows

The first question should not be:

```text
Which backend would you like to run?
```

It should be something closer to:

```text
What are you trying to determine?
```

Backend selection can be automatic, recommended, or an advanced control.

### Avoid photorealistic hardware too early

A schematic hardware model is more useful while the hardware mapping itself is incomplete.

### Avoid hiding uncertainty

Do not auto-complete missing links merely because the UI graph looks cleaner when everything connects.

### Avoid designing the persistent data format around the current UI

Trace graphs, hardware diagrams, and timelines should all be derived from a shared investigation/evidence model.

---

## 16. What is worth implementing before the UI

Even if there is no frontend for some time, several pieces of work would make the eventual UI substantially easier.

### Normalize run output

A reusable structured run format could include:

```text
run metadata
firmware identity
inputs
register snapshots
memory snapshots
watches
MMIO observations
interrupt observations
GPIO transitions
stubs
assertions
warnings
```

### Give observations stable identities

Claims need to be able to reference concrete observations without depending on console text.

### Normalize scenarios

The current Python scenarios are useful experiments. Eventually their inputs, expected observations, assertions, and outputs should be representable as structured data.

### Introduce claims/evidence

Even a minimal representation would help:

```yaml
claim:
  subject: irq:109
  relation: interrupt_for
  object: peripheral:TC2
  status: established
  evidence:
    - static:vector-table
    - concrete:run-0042
```

The exact schema can come later. The important thing is separating claims from raw observations.

### Start a hardware entity registry

For example:

```text
MCU
ports
pins
peripherals
interrupts
connectors
known external devices
```

Unknown mappings should be representable explicitly.

---

## 17. Potential progressive UI stages

The UI does not need to arrive all at once.

### Stage 0 — structured CLI

Current command-line workflow, but with stable JSON artifacts for:

- scenarios
- runs
- observations
- claims

### Stage 1 — investigation report viewer

A read-only interface that renders saved APTrace artifacts.

Useful first features:

- investigation list
- trace graph
- evidence inspector
- saved-run timeline

No execution controls required.

### Stage 2 — interactive scenario runner

Add:

- edit scenario inputs
- run/re-run
- compare runs
- attach observations to claims

### Stage 3 — hardware projection

Add schematic representation of:

- devices
- MCU peripherals
- interrupts
- GPIO
- connectors
- external hardware

### Stage 4 — symbolic investigation

Surface Macaw/Crucible/What4 questions through the same investigation model.

Examples:

```text
Find an input that reaches this node.
Can this GPIO toggle without this command?
What values can this state variable have here?
Prove this invariant under these assumptions.
```

The solver should add evidence to existing claims rather than creating a completely separate UX universe.

---

## 18. Possible interactions worth exploring later

These are ideas, not requirements.

### "Why?"

Click any relationship and ask:

```text
Why does APTrace think TC2 leads to IRQ109?
```

The inspector expands the supporting evidence.

### "Show me"

From a claim:

```text
Show me the concrete run that proves this.
```

APTrace opens the timeline at the relevant observations.

### "Find an input"

From a trace or hardware node:

```text
Find an input that reaches this behavior.
```

This could dispatch to a symbolic backend and attach the resulting proof/witness to the investigation.

### "What is missing?"

For an unresolved endpoint:

```text
What would we need to prove this link?
```

APTrace can suggest missing producers, initialization state, concrete runs, symbolic queries, or hardware evidence.

### Compare runs

Example:

```text
I01F| vs I02F|
```

The Trace view could highlight where execution diverges, while Hardware shows which timer/GPIO changes.

This could be particularly powerful for recovering channel tables and dispatch logic.

---

## 19. UX tone

APTrace is a technical evidence tool. The UI should feel:

- precise
- restrained
- inspectable
- reproducible
- comfortable with incomplete knowledge

It should avoid visual language that implies certainty where none exists.

Useful labels are explicit:

```text
Observed
Static evidence
Concrete evidence
Solver-confirmed
Assumed
Unresolved
Conflicting evidence
```

Less useful labels would be vague confidence scores without provenance.

---

## 20. Working product statement

A possible product definition:

> **APTrace is an evidence-first firmware investigation workbench that connects protocol inputs, firmware behavior, concrete execution, symbolic reasoning, peripherals, and physical hardware into a reproducible chain of claims.**
>
> Rather than replacing specialist reverse-engineering tools, APTrace orchestrates them around questions: what happened, why it happened, where it happened, and how strongly we can prove it.

The key UI idea follows naturally:

```text
                    one investigation
                           |
             +-------------+-------------+
             |             |             |
             v             v             v
           TRACE        HARDWARE      TIMELINE
            why?          where?         when?
             |             |             |
             +-------------+-------------+
                           |
                           v
                    shared evidence
```

That shared evidence model is more important to define now than the frontend technology or final visual design.

---

## 21. Near-term design questions

Questions worth revisiting as APTrace develops:

1. What constitutes a stable `Entity` identity across static and concrete backends?
2. What is the smallest useful structured representation of a `Scenario`?
3. How should a `Run` reference firmware versions, initial state, stubs, and assumptions?
4. What distinguishes an `Observation` from a `Claim`?
5. Can claims depend on other claims as well as raw evidence?
6. How should conflicting observations be represented?
7. What evidence level is required before APTrace labels a relationship established?
8. How do hardware entities map to firmware entities without assuming the mapping is complete?
9. Which parts of the current Unicorn/Ghidra output can already populate this model?
10. Which scenario information is currently trapped in Python code or log strings and should become structured data?
11. What should be included in a reproducibility bundle for another engineer or firmware vendor?
12. How should symbolic results be rendered alongside concrete evidence without overstating what the model proves about real hardware?

These questions are likely more valuable to answer now than choosing React, Tauri, Electron, Swift, or another UI stack.

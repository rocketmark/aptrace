# Trigger / PA22 autonomous research benchmark

## Objective

Determine the role of `FUN_0000d3dc(1)` in the AutoPilot, reconcile it
with the existing trigger-input evidence, identify what is proven versus
still unresolved, and independently verify any load-bearing firmware
claims needed for the conclusion.

## Purpose

This is a regression benchmark for APTrace's generic autonomous
researcher.

It must not be implemented as a fixed sequence of obligations or
case-specific controller rules.

## Reference findings

These are grading facts, not instructions for the controller.

- `FUN_0000d3dc` is read-only in the observed machine code.
- It retrieves a one-bit GPIO state.
- Its argument indexes the firmware pin-description table.
- Logical pin index `1` maps to `PA22`.
- A real caller loads `r0 = 1` immediately before calling
  `FUN_0000d3dc`.
- Existing case evidence associates `PA22` with the startup
  reference/input path.
- Existing evidence distinguishes `PA22` from `PB05`, which is the
  established trigger-input mapping.
- The physical identity/connectivity of `PA22` remains unresolved.

## Qwen 4-bit reference trajectory

With `Qwen3-Coder-30B-A3B-Instruct-4bit`, the old autonomous prototype
made these useful autonomous choices:

1. inspect `FUN_0000d3dc` function facts;
2. inspect its disassembly;
3. inspect caller `FUN_00006968` at `0x000069a4`.

The same run exposed generic failure modes:

- repeated the same callsite action;
- repeated already-collected function facts;
- confused GPIO name `PA22` with pin-table index `22`;
- followed that mistake with a `PB02` evidence search;
- crashed after an invalid or empty model response.

## Required generic protections

The production researcher should retain:

- fresh bounded model decisions;
- hard research/action budgets;
- duplicate-action rejection;
- bounded suppression of repeated duplicates;
- model-response validation;
- clean retry or termination on invalid responses;
- typed and bounded APTrace operations;
- evidence provenance and deduplication;
- no arbitrary shell, filesystem, or network access.

Structural firmware arguments should normally come from
APTrace-generated leads.

For example:

- `L12`: inspect caller `FUN_00006968` at `0x000069a4`;
- `L13`: resolve logical pin-table argument `1`;
- `L14`: reconcile observed GPIO `PA22` with case evidence.

The model should choose a lead without needing to manufacture the
underlying address or index.

## Do not encode in production

Do not encode fixed benchmark obligations, forced PA22 searches,
forced literal-1 sequences, benchmark-specific finish conditions,
special prose validators, or deterministic rendering of the known
answer.

## Model roles

Primary research model:

`Qwen3-Coder-30B-A3B-Instruct-4bit`

Optional deep-review model:

`gemma-4-26b-a4b-it-4bit`

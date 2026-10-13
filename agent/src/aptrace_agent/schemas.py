from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, SerializerFunctionWrapHandler, model_serializer


class CallSite(BaseModel):
    function: str
    address: str


class FunctionFacts(BaseModel):
    name: str
    entry: str
    size: int | None = None

    callers: list[CallSite] = Field(default_factory=list)
    callees: list[CallSite] = Field(default_factory=list)

    unique_caller_count: int = 0
    callsite_count: int = 0

    unique_callee_count: int = 0
    outgoing_callsite_count: int = 0

    callers_truncated: bool = False
    callees_truncated: bool = False


class Instruction(BaseModel):
    address: str
    size: int
    bytes_hex: str
    mnemonic: str
    operands: str


class FunctionDisassembly(BaseModel):
    name: str
    entry: str
    size: int
    architecture: str
    mode: str
    bounds_source: str
    decoder: str
    bytes_requested: int
    bytes_decoded: int
    complete: bool
    instructions: list[Instruction] = Field(default_factory=list)


class FunctionFactsArgs(BaseModel):
    function: str


class FunctionDisassemblyArgs(BaseModel):
    function: str


class InvestigationPlan(BaseModel):
    """
    Internal APTrace execution plan.

    Created by APTrace code, never by the model.
    """

    function_facts: list[FunctionFactsArgs] = Field(
        default_factory=list,
        max_length=3,
    )

    function_disassembly: list[FunctionDisassemblyArgs] = Field(
        default_factory=list,
        max_length=3,
    )


class EvidenceObservation(BaseModel):
    id: str
    tool: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    # Durable evidence id when this session entry is a historical result
    # used by reference (research/history.py), not a new execution.
    reused_from: str | None = None

    @model_serializer(mode="wrap")
    def _omit_unset_reuse(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data = handler(self)

        if data.get("reused_from") is None:
            data.pop("reused_from", None)

        return data


class EvidenceBundle(BaseModel):
    objective: str
    observations: list[EvidenceObservation] = Field(default_factory=list)

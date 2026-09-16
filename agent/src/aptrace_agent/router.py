from __future__ import annotations

import re

from aptrace_agent.schemas import (
    FunctionDisassemblyArgs,
    FunctionFactsArgs,
    InvestigationPlan,
)


FUNCTION_RE = re.compile(r"\bFUN_[0-9a-fA-F]{8}\b")


def _unique_functions(question: str) -> list[str]:
    return list(dict.fromkeys(FUNCTION_RE.findall(question)))


def route_question(question: str) -> InvestigationPlan | None:
    """
    Route direct firmware queries to deterministic APTrace operations.

    Return None when the question requires an analysis capability APTrace
    does not yet expose.
    """

    functions = _unique_functions(question)

    if not functions:
        return None

    q = question.lower()

    disassembly_query = any(
        phrase in q
        for phrase in (
            "disassemble",
            "disassembly",
            "instructions",
            "assembly",
        )
    )

    if disassembly_query:
        return InvestigationPlan(
            function_disassembly=[
                FunctionDisassemblyArgs(function=function)
                for function in functions
            ]
        )

    incoming_call_query = any(
        phrase in q
        for phrase in (
            "what calls",
            "who calls",
            "called by",
            "caller",
            "call-site",
            "call site",
        )
    )

    if incoming_call_query:
        return InvestigationPlan(
            function_facts=[
                FunctionFactsArgs(function=function)
                for function in functions
            ]
        )

    outgoing_call_query = (
        "callee" in q
        or any(
            re.search(
                rf"what does\s+{re.escape(function.lower())}\s+call",
                q,
            )
            for function in functions
        )
    )

    if outgoing_call_query:
        return InvestigationPlan(
            function_facts=[
                FunctionFactsArgs(function=function)
                for function in functions
            ]
        )

    metadata_query = any(
        phrase in q
        for phrase in (
            "entry address",
            "function size",
            "how large",
        )
    )

    if metadata_query:
        return InvestigationPlan(
            function_facts=[
                FunctionFactsArgs(function=function)
                for function in functions
            ]
        )

    return None

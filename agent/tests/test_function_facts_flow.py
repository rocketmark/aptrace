from aptrace_agent.executor import EvidenceExecutor
from aptrace_agent.ghidra_index import autopilot_ghidra_index
from aptrace_agent.router import route_question


QUESTION = (
    "What calls FUN_0000d3dc? "
    "Report the exact call-site addresses."
)


def test_function_facts_route_and_execution():
    plan = route_question(QUESTION)

    assert plan is not None
    assert len(plan.function_facts) == 1
    assert plan.function_facts[0].function == "FUN_0000d3dc"

    evidence = EvidenceExecutor().execute(
        QUESTION,
        plan,
    )

    assert len(evidence.observations) == 1

    result = evidence.observations[0].result

    assert result["name"] == "FUN_0000d3dc"
    assert result["entry"] == "0x0000d3dc"
    assert result["size"] == 44

    assert result["unique_caller_count"] == 3
    assert result["callsite_count"] == 5

    assert result["callers"] == [
        {
            "function": "FUN_00005dd0",
            "address": "0x00005e10",
        },
        {
            "function": "FUN_00006968",
            "address": "0x00006976",
        },
        {
            "function": "FUN_00006968",
            "address": "0x000069a4",
        },
        {
            "function": "FUN_00006968",
            "address": "0x000069c2",
        },
        {
            "function": "FUN_00008e18",
            "address": "0x000091ca",
        },
    ]


def test_inconsistent_ghidra_caller_attribution_is_retained():
    index = autopilot_ghidra_index()

    rejected = index.rejected_edges(
        to_function="FUN_0000d3dc"
    )

    observed = {
        (
            edge.from_function,
            edge.address,
        )
        for edge in rejected
    }

    assert observed == {
        (
            "FUN_000093fc",
            "0x000078f2",
        ),
        (
            "FUN_000093fc",
            "0x00007934",
        ),
        (
            "FUN_00008e18",
            "0x00009228",
        ),
        (
            "FUN_0000abf8",
            "0x0000aaba",
        ),
        (
            "FUN_0000abf8",
            "0x0000aaf2",
        ),
    }

    for edge in rejected:
        assert "lies outside" in edge.reason

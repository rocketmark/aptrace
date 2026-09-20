from aptrace_agent.research import (
    LeadRegistry,
)
from aptrace_agent.research.lead_generation import (
    generate_function_fact_leads,
)


class FakeCallsiteReader:
    def context(
        self,
        function,
        address,
        before=8,
        after=8,
    ):
        return {
            "function": function,
            "address": address,
        }


class FakeFunctionFactsReader:
    def function_facts(self, function):
        if function == "FUN_00002000":
            return {
                "name": function,
                "entry": "0x00002000",
            }

        raise KeyError(function)


def test_outgoing_callee_becomes_function_leads():
    registry = LeadRegistry()

    result = generate_function_fact_leads(
        {
            "name": "FUN_00001000",
            "callers": [],
            "callees": [
                {
                    "function": "FUN_00002000",
                    "address": "0x00001010",
                }
            ],
        },
        evidence_id="E1",
        registry=registry,
        callsite_reader=(
            FakeCallsiteReader()
        ),
        function_facts_reader=(
            FakeFunctionFactsReader()
        ),
    )

    actions = [
        registry.resolve(lead.id)
        for lead in result.leads
    ]

    assert {
        action.tool
        for action in actions
    } == {
        "callsite_context",
        "function_facts",
        "function_disassembly",
    }

    function_actions = [
        action
        for action in actions
        if action.tool
        in {
            "function_facts",
            "function_disassembly",
        }
    ]

    assert all(
        action.arguments["function"]
        == "FUN_00002000"
        for action in function_actions
    )

    assert result.issues == ()


def test_incoming_callsite_leads_are_bounded():
    registry = LeadRegistry()

    callers = [
        {
            "function": f"FUN_{0x3000 + i * 0x10:08x}",
            "address": f"0x{0x1000 + i * 4:08x}",
        }
        for i in range(12)
    ]

    result = generate_function_fact_leads(
        {
            "name": "FUN_00002000",
            "callers": callers,
            "callees": [],
        },
        evidence_id="E1",
        registry=registry,
        callsite_reader=(
            FakeCallsiteReader()
        ),
        max_incoming_calls=8,
    )

    actions = [
        registry.resolve(lead.id)
        for lead in result.leads
    ]

    assert len(actions) == 8

    assert all(
        action.tool == "callsite_context"
        for action in actions
    )

    assert result.issues == ()

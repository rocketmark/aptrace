from aptrace_agent.research import (
    LeadDeriver,
    LeadRegistry,
)
from aptrace_agent.schemas import (
    EvidenceObservation,
)


class NeverCallsiteReader:
    def context(self, *args, **kwargs):
        raise AssertionError("not used")


class FakeFunctionFactsReader:
    def function_facts(self, function):
        if function == "FUN_00001234":
            return {
                "name": function,
            }

        raise KeyError(function)


def test_discovery_case_evidence_yields_validated_function_leads():
    registry = LeadRegistry()

    deriver = LeadDeriver(
        registry=registry,
        callsite_reader=NeverCallsiteReader(),
        function_facts_reader=(
            FakeFunctionFactsReader()
        ),
    )

    observation = EvidenceObservation(
        id="E1",
        tool="search_case_evidence",
        arguments={
            "query": "TMC5160",
            "max_results": 8,
            "purpose": "discovery",
        },
        result={
            "query": "TMC5160",
            "matches": [
                {
                    "source": "status.md",
                    "line": 10,
                    "kind": "status",
                    "excerpt": (
                        "TMC5160 analysis references "
                        "FUN_00001234 and FUN_deadbeef."
                    ),
                    "score": 10,
                }
            ],
            "files_scanned": 1,
            "truncated": False,
        },
    )

    result = deriver.derive(
        observation
    )

    assert len(result.leads) == 2
    assert len(result.issues) == 1

    actions = [
        registry.resolve(lead.id)
        for lead in result.leads
    ]

    assert {
        action.tool
        for action in actions
    } == {
        "function_facts",
        "function_disassembly",
    }

    assert all(
        action.arguments["function"]
        == "FUN_00001234"
        for action in actions
    )


def test_reconciliation_case_search_does_not_generate_function_leads():
    registry = LeadRegistry()

    deriver = LeadDeriver(
        registry=registry,
        callsite_reader=NeverCallsiteReader(),
        function_facts_reader=(
            FakeFunctionFactsReader()
        ),
    )

    observation = EvidenceObservation(
        id="E1",
        tool="search_case_evidence",
        arguments={
            "query": "PA22",
            "max_results": 8,
        },
        result={
            "query": "PA22",
            "matches": [],
            "files_scanned": 1,
            "truncated": False,
        },
    )

    result = deriver.derive(
        observation
    )

    assert result.leads == ()


def test_discovery_promotes_exact_valid_function_address():
    registry = LeadRegistry()

    deriver = LeadDeriver(
        registry=registry,
        callsite_reader=NeverCallsiteReader(),
        function_facts_reader=(
            FakeFunctionFactsReader()
        ),
    )

    observation = EvidenceObservation(
        id="E1",
        tool="search_case_evidence",
        arguments={
            "query": "SPI transport",
            "max_results": 8,
            "purpose": "discovery",
        },
        result={
            "query": "SPI transport",
            "matches": [
                {
                    "source": "status.md",
                    "line": 10,
                    "kind": "status",
                    "excerpt": (
                        "A real call at 0x1234 reaches "
                        "the transport. Stale address "
                        "0x9999 is also mentioned."
                    ),
                    "score": 10,
                }
            ],
            "files_scanned": 1,
            "truncated": False,
        },
    )

    result = deriver.derive(
        observation
    )

    assert len(result.leads) == 2
    assert result.issues == ()

    actions = [
        registry.resolve(lead.id)
        for lead in result.leads
    ]

    assert all(
        action.arguments["function"]
        == "FUN_00001234"
        for action in actions
    )

    assert {
        action.tool
        for action in actions
    } == {
        "function_facts",
        "function_disassembly",
    }

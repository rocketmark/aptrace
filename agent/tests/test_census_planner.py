import json
from types import SimpleNamespace

from aptrace_agent.research import (
    LeadFollower,
    LeadRegistry,
    ResearchController,
    ResearchSession,
)
from aptrace_agent.schemas import EvidenceObservation


class RecordingExecutor:
    def __init__(self):
        self.calls = []

    def execute_operation(self, tool, arguments, *, evidence_id):
        self.calls.append((tool, dict(arguments)))

        if tool == "census_peripheral_usage":
            result = {
                "status": "ok",
                "peripheral": arguments["peripheral"],
                "total_mmio_sites": 0,
                "total_address_constants": 1,
                "total_functions": 1,
                "functions": [{"function": "FUN_00001000"}],
                "unattributed_sites": [],
                "provenance": {"reduction_status": "present"},
            }
        else:
            result = {"query": arguments.get("query"), "matches": []}

        return EvidenceObservation(
            id=evidence_id,
            tool=tool,
            arguments=dict(arguments),
            result=result,
        )


class RecordingCompletions:
    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.requests = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        name, arguments = self.decisions[len(self.requests) - 1]

        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=None,
                        tool_calls=[
                            SimpleNamespace(
                                function=SimpleNamespace(
                                    name=name,
                                    arguments=json.dumps(arguments),
                                )
                            )
                        ],
                    )
                )
            ]
        )


class NoReconciler:
    def run(self, session):
        raise AssertionError("no case evidence to reconcile")


def _setup(decisions, *, peripherals=("SERCOM2", "TC0"), **kwargs):
    registry = LeadRegistry()
    executor = RecordingExecutor()
    session = ResearchSession(
        objective="Determine interface to motor drivers",
        registry=registry,
        follower=LeadFollower(registry=registry, executor=executor),
    )
    completions = RecordingCompletions(decisions)
    controller = ResearchController(
        planner_client=SimpleNamespace(
            chat=SimpleNamespace(completions=completions)
        ),
        planner_model="test",
        reconciler=NoReconciler(),
        census_peripherals=peripherals,
        **kwargs,
    )
    return session, executor, completions, controller


def _tool(request, name):
    for tool in request["tools"]:
        if tool["function"]["name"] == name:
            return tool["function"]
    return None


def test_discovery_offers_census_analysis_with_validated_enum():
    session, executor, completions, controller = _setup(
        [
            ("analyze_peripheral", {"peripheral": "SERCOM2"}),
            ("finish", {"reason": "enough"}),
        ],
        max_steps=2,
    )

    result = controller.run(session)

    first = completions.requests[0]
    analysis = _tool(first, "analyze_peripheral")
    assert analysis["parameters"]["properties"]["peripheral"]["enum"] == [
        "SERCOM2",
        "TC0",
    ]
    assert analysis["parameters"]["additionalProperties"] is False
    assert "analyze_peripheral" in first["messages"][-1]["content"]
    assert first["max_tokens"] == 512

    assert result.steps[0].action == "analyze"
    assert executor.calls == [
        (
            "census_peripheral_usage",
            {"peripheral": "SERCOM2", "limit": 25},
        )
    ]
    assert session.state.lead(result.steps[0].lead_id).kind == "census"

    # SERCOM2 is not offered twice.
    second = completions.requests[1]
    assert _tool(second, "analyze_peripheral")["parameters"]["properties"][
        "peripheral"
    ]["enum"] == ["TC0"]


def test_planner_cannot_supply_sql_paths_or_limits():
    session, executor, completions, controller = _setup(
        [
            (
                "analyze_peripheral",
                {
                    "peripheral": "TC0",
                    "db_path": "/etc/passwd",
                    "sql": "DROP TABLE functions",
                    "limit": 100000,
                    "firmware": "mando868",
                },
            ),
            ("finish", {"reason": "enough"}),
        ],
        max_steps=2,
    )

    controller.run(session)

    assert executor.calls == [
        (
            "census_peripheral_usage",
            {"peripheral": "TC0", "limit": 25},
        )
    ]


def test_unlisted_peripheral_is_rejected_then_retried():
    session, executor, completions, controller = _setup(
        [
            ("analyze_peripheral", {"peripheral": "../census.sqlite3"}),
            ("analyze_peripheral", {"peripheral": "SERCOM9"}),
        ],
    )

    action, arguments = controller._request_discovery(session, set())

    assert action == "finish"
    assert "listed peripherals" in arguments["reason"]
    assert executor.calls == []
    correction = completions.requests[1]["messages"][-1]["content"]
    assert "analyze_peripheral" in correction


def test_decision_phase_prefers_structural_analysis_guidance():
    session, executor, completions, controller = _setup(
        [
            ("analyze_peripheral", {"peripheral": "TC0"}),
            ("finish", {"reason": "enough"}),
        ],
        max_steps=3,
    )
    lead = session.registry.register(
        kind="function",
        description="Inspect FUN_00002000",
        tool="function_facts",
        arguments={"function": "FUN_00002000"},
    )
    session.state.add_lead(lead)

    result = controller.run(session)

    prompt = completions.requests[0]["messages"][-1]["content"]
    assert "STRUCTURAL ANALYSIS" in prompt
    assert prompt.index("analyze_peripheral for a peripheral") < prompt.index(
        "caller/callee expansion only"
    )
    assert [tool["function"]["name"] for tool in completions.requests[0]["tools"]] == [
        "follow_lead",
        "analyze_peripheral",
        "finish",
    ]
    assert [step.action for step in result.steps] == ["analyze", "finish"]

    digest = completions.requests[1]["messages"][-1]["content"]
    assert "census_peripheral_usage TC0: status=ok" in digest
    assert "FUN_00001000" in digest


def test_structural_analysis_budget_is_enforced():
    session, executor, completions, controller = _setup(
        [
            ("analyze_peripheral", {"peripheral": "SERCOM2"}),
            ("finish", {"reason": "enough"}),
        ],
        max_steps=2,
        max_structural_analyses=1,
    )

    controller.run(session)

    assert _tool(completions.requests[1], "analyze_peripheral") is None
    assert "STRUCTURAL ANALYSIS" not in (
        completions.requests[1]["messages"][-1]["content"]
    )


def test_no_census_keeps_existing_discovery_contract():
    session, executor, completions, controller = _setup(
        [
            ("search_case_evidence", {"query": "TMC5160 SPI"}),
            ("finish", {"reason": "enough"}),
        ],
        peripherals=(),
        max_steps=2,
    )

    result = controller.run(session)

    names = [
        tool["function"]["name"]
        for tool in completions.requests[0]["tools"]
    ]
    assert names == ["search_case_evidence", "finish"]
    assert "analyze_peripheral" not in (
        completions.requests[0]["messages"][-1]["content"]
    )
    assert result.steps[0].action == "discover"
    assert executor.calls[0][0] == "search_case_evidence"


def test_reanalysis_request_is_retried_without_analysis_tool():
    session, executor, completions, controller = _setup(
        [
            ("analyze_peripheral", {"peripheral": "SERCOM2"}),
            ("analyze_peripheral", {"peripheral": "SERCOM2"}),
            ("search_case_evidence", {"query": "motor driver bus"}),
            ("finish", {"reason": "enough"}),
        ],
        max_steps=3,
    )

    result = controller.run(session)

    retry = completions.requests[2]
    # Fresh, smaller request: no appended correction turn, no analysis
    # tool and no analysis guidance.
    assert len(retry["messages"]) == 2
    assert len(retry["messages"][-1]["content"]) < len(
        completions.requests[1]["messages"][-1]["content"]
    )
    assert "analyze_peripheral" not in retry["messages"][-1]["content"]
    assert _tool(retry, "analyze_peripheral") is None
    assert [step.action for step in result.steps] == [
        "analyze",
        "discover",
        "finish",
    ]


def test_repeated_analysis_in_decision_phase_falls_back_to_leads():
    session, executor, completions, controller = _setup(
        [
            ("analyze_peripheral", {"peripheral": "TC0"}),
            ("analyze_peripheral", {"peripheral": "TC0"}),
            ("follow_lead", {"lead_id": "L1"}),
        ],
        max_steps=3,
    )
    lead = session.registry.register(
        kind="function",
        description="Inspect FUN_00002000",
        tool="function_facts",
        arguments={"function": "FUN_00002000"},
    )
    session.state.add_lead(lead)

    result = controller.run(session)

    assert _tool(completions.requests[2], "analyze_peripheral") is None
    assert [step.action for step in result.steps] == [
        "analyze",
        "follow_lead",
    ]
    assert result.stop_reason == "research_graph_exhausted"

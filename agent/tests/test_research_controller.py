from types import SimpleNamespace

from aptrace_agent.research import (
    LeadFollower,
    LeadRegistry,
    ResearchController,
    ResearchSession,
)
from aptrace_agent.schemas import (
    EvidenceObservation,
)


class FakeExecutor:
    def execute_operation(
        self,
        tool,
        arguments,
        *,
        evidence_id,
    ):
        return EvidenceObservation(
            id=evidence_id,
            tool=tool,
            arguments=arguments,
            result={
                "value": "executed"
            },
        )


class ToolCallCompletions:
    def __init__(self, decisions):
        self.decisions = list(
            decisions
        )
        self.calls = 0

    def create(self, **kwargs):
        decision = self.decisions[
            self.calls
        ]
        self.calls += 1

        if decision is None:
            message = SimpleNamespace(
                content="plain text",
                tool_calls=[],
            )
        else:
            name, arguments = decision

            message = SimpleNamespace(
                content=None,
                tool_calls=[
                    SimpleNamespace(
                        function=SimpleNamespace(
                            name=name,
                            arguments=__import__(
                                "json"
                            ).dumps(
                                arguments
                            ),
                        )
                    )
                ],
            )

        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=message
                )
            ]
        )


class FakePlannerClient:
    def __init__(self, decisions):
        self.completions = (
            ToolCallCompletions(
                decisions
            )
        )

        self.chat = SimpleNamespace(
            completions=self.completions
        )


class FakeReconciler:
    def __init__(self):
        self.calls = 0

    def run(self, session):
        self.calls += 1


def make_session():
    registry = LeadRegistry()

    follower = LeadFollower(
        registry=registry,
        executor=FakeExecutor(),
    )

    session = ResearchSession(
        objective="test objective",
        registry=registry,
        follower=follower,
    )

    return (
        session,
        registry,
    )


def add_lead(
    session,
    registry,
    *,
    tool="test_operation",
):
    lead = registry.register(
        kind="test",
        description="Test lead",
        tool=tool,
        arguments={"x": 1},
        source_evidence_ids=[],
    )

    session.state.add_lead(
        lead
    )

    return lead


def test_zero_open_leads_stops_without_planner_call():
    session, _ = make_session()

    planner = FakePlannerClient(
        []
    )

    reconciler = FakeReconciler()

    controller = ResearchController(
        planner_client=planner,
        planner_model="test",
        reconciler=reconciler,
    )

    result = controller.run(
        session
    )

    assert result.stop_reason == (
        "research_graph_exhausted"
    )

    assert result.steps == ()
    assert result.reconciled is False
    assert planner.completions.calls == 0
    assert reconciler.calls == 0


def test_planner_can_follow_lead_then_graph_exhausts():
    session, registry = make_session()

    lead = add_lead(
        session,
        registry,
    )

    planner = FakePlannerClient(
        [
            (
                "follow_lead",
                {
                    "lead_id": lead.id,
                },
            )
        ]
    )

    reconciler = FakeReconciler()

    controller = ResearchController(
        planner_client=planner,
        planner_model="test",
        reconciler=reconciler,
    )

    result = controller.run(
        session
    )

    assert result.stop_reason == (
        "research_graph_exhausted"
    )

    assert len(result.steps) == 1
    assert result.steps[0].lead_id == (
        lead.id
    )
    assert result.steps[0].evidence_id == (
        "E1"
    )


def test_planner_finish_is_respected():
    session, registry = make_session()

    add_lead(
        session,
        registry,
    )

    planner = FakePlannerClient(
        [
            (
                "finish",
                {
                    "reason": (
                        "Evidence is sufficient."
                    ),
                },
            )
        ]
    )

    reconciler = FakeReconciler()

    controller = ResearchController(
        planner_client=planner,
        planner_model="test",
        reconciler=reconciler,
    )

    result = controller.run(
        session
    )

    assert result.stop_reason == (
        "planner_finished"
    )

    assert len(result.steps) == 1
    assert result.steps[0].action == (
        "finish"
    )


def test_terminal_case_evidence_triggers_reconciliation():
    session, _ = make_session()

    session.record(
        EvidenceObservation(
            id="E1",
            tool="search_case_evidence",
            arguments={
                "query": "PA22"
            },
            result={
                "query": "PA22",
                "matches": [],
                "files_scanned": 1,
                "truncated": False,
            },
        )
    )

    reconciler = FakeReconciler()

    controller = ResearchController(
        planner_client=FakePlannerClient(
            []
        ),
        planner_model="test",
        reconciler=reconciler,
    )

    result = controller.run(
        session
    )

    assert result.reconciled is True
    assert reconciler.calls == 1


def test_planner_gets_one_retry_for_missing_tool_call():
    session, registry = make_session()

    lead = add_lead(
        session,
        registry,
    )

    planner = FakePlannerClient(
        [
            None,
            (
                "follow_lead",
                {
                    "lead_id": lead.id,
                },
            ),
        ]
    )

    controller = ResearchController(
        planner_client=planner,
        planner_model="test",
        reconciler=FakeReconciler(),
    )

    result = controller.run(
        session
    )

    assert result.stop_reason == (
        "research_graph_exhausted"
    )

    assert planner.completions.calls == 2

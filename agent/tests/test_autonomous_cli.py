from __future__ import annotations

import json
import sys
from types import SimpleNamespace

from aptrace_agent import cli
from aptrace_agent.research import (
    ResearchRunResult,
    ResearchState,
)


def test_research_cli_json(
    monkeypatch,
    capsys,
):
    run = SimpleNamespace(
        objective="Determine the role.",
        seed_function="FUN_0000d3dc",
        result=ResearchRunResult(
            stop_reason=(
                "research_graph_exhausted"
            ),
            steps=(),
            reconciled=True,
        ),
        state=ResearchState(
            objective="Determine the role."
        ),
        evidence=(),
    )

    def fake_run(
        objective,
        *,
        seed_function,
        max_steps,
    ):
        assert objective == (
            "Determine the role."
        )

        assert seed_function == (
            "FUN_0000d3dc"
        )

        assert max_steps == 7

        return run

    monkeypatch.setattr(
        cli,
        "run_autonomous_investigation",
        fake_run,
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aptrace-agent",
            "research",
            "--function",
            "FUN_0000d3dc",
            "--max-steps",
            "7",
            "--json",
            "Determine",
            "the",
            "role.",
        ],
    )

    cli.main()

    payload = json.loads(
        capsys.readouterr().out
    )

    assert payload["objective"] == (
        "Determine the role."
    )

    assert payload["seed_function"] == (
        "FUN_0000d3dc"
    )

    assert payload["stop_reason"] == (
        "research_graph_exhausted"
    )

    assert payload["reconciled"] is True
    assert payload["trajectory"] == []
    assert payload["evidence"] == []

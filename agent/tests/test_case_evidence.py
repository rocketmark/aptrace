from pathlib import Path

import pytest

from aptrace_agent.case_evidence import CaseEvidenceSearch


def make_case(tmp_path: Path) -> Path:
    case = (
        tmp_path
        / "cases"
        / "performing-rigs"
    )

    for path in (
        case / "docs" / "investigations",
        case / "research" / "generated",
        case / "research" / "workflows",
        case / "research" / "provenance",
    ):
        path.mkdir(parents=True)

    return case


def test_search_finds_existing_case_evidence(
    tmp_path: Path,
):
    case = make_case(tmp_path)

    (
        case
        / "research"
        / "generated"
        / "pin-map.json"
    ).write_text(
        '{\n'
        '  "signal": "STARTUP_REF_INPUT",\n'
        '  "gpio": "PA22",\n'
        '  "remaining_unknown": "physical identity"\n'
        '}\n'
    )

    search = CaseEvidenceSearch(repo_root=tmp_path)

    result = search.search(
        "PA22 startup input",
        max_results=8,
    )

    assert result.matches

    assert any(
        match.source.endswith("pin-map.json")
        for match in result.matches
    )


def test_search_is_bounded_to_case_roots(
    tmp_path: Path,
):
    case = make_case(tmp_path)

    (case / "status.md").write_text(
        "PA22 is a startup reference input."
    )

    (tmp_path / "secret.txt").write_text(
        "PA22 SHOULD NOT BE SEARCHED HERE"
    )

    search = CaseEvidenceSearch(repo_root=tmp_path)

    result = search.search("PA22")

    sources = {
        match.source
        for match in result.matches
    }

    assert (
        "cases/performing-rigs/status.md"
        in sources
    )

    assert all(
        "secret.txt" not in source
        for source in sources
    )


def test_search_rejects_bad_limits(
    tmp_path: Path,
):
    make_case(tmp_path)

    search = CaseEvidenceSearch(repo_root=tmp_path)

    with pytest.raises(ValueError):
        search.search(
            "PA22",
            max_results=1000,
        )


def test_duplicate_nearby_hits_are_collapsed(
    tmp_path: Path,
):
    case = make_case(tmp_path)

    (
        case
        / "docs"
        / "investigations"
        / "one.md"
    ).write_text(
        "\n".join(
            [
                "PA22 startup input",
                "PA22 startup input detail",
                "PA22 startup input detail",
                "",
                "",
                "",
                "",
                "",
                "PA22 separate later discussion",
            ]
        )
    )

    search = CaseEvidenceSearch(repo_root=tmp_path)

    result = search.search("PA22")

    hits = [
        match
        for match in result.matches
        if match.source.endswith("one.md")
    ]

    assert len(hits) == 2

from __future__ import annotations

from pydantic_ai import Agent, UsageLimits

from aptrace_agent.model import build_model
from aptrace_agent.schemas import EvidenceBundle


synthesizer = Agent(
    build_model(),
    instructions=(
        "You are the synthesis stage of APTrace, a firmware-analysis system. "
        "Answer the user's objective using only the supplied evidence. "
        "Do not invent firmware behavior or evidence. "
        "Preserve exact function names and addresses. "
        "If the evidence cannot answer the question, say exactly what remains "
        "unresolved. "
        "For direct factual questions, answer directly and concisely. "
        "Do not restate the user's question. "
        "Do not present the same evidence twice. "
        "Prefer one compact answer."
    ),
)


def synthesize(
    bundle: EvidenceBundle,
) -> tuple[str, object]:
    prompt = (
        "Objective:\n"
        f"{bundle.objective}\n\n"
        "APTrace evidence:\n"
        f"{bundle.model_dump_json(indent=2)}"
    )

    result = synthesizer.run_sync(
        prompt,
        usage_limits=UsageLimits(
            request_limit=1,
            per_request_input_tokens_limit=4000,
        ),
    )

    return result.output, result.usage

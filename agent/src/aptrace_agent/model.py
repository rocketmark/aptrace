from __future__ import annotations

import os
from urllib.parse import urlparse

from openai import AsyncOpenAI
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.profiles.openai import OpenAIModelProfile
from pydantic_ai.providers.openai import OpenAIProvider


DEFAULT_BASE_URL = "http://127.0.0.1:8000/v1"
DEFAULT_MODEL = "Qwen3-Coder-30B-A3B-Instruct-3bit"


def build_model() -> OpenAIChatModel:
    base_url = os.getenv("OMLX_BASE_URL", DEFAULT_BASE_URL)
    model_name = os.getenv("APTRACE_MODEL", DEFAULT_MODEL)
    api_key = os.getenv("OMLX_API_KEY")

    if not api_key:
        raise RuntimeError("OMLX_API_KEY is not set")

    parsed = urlparse(base_url)
    if parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError(
            f"Refusing non-local model endpoint: {base_url}"
        )

    client = AsyncOpenAI(
        base_url=base_url,
        api_key=api_key,
        max_retries=0,
        timeout=120.0,
    )

    return OpenAIChatModel(
        model_name,
        provider=OpenAIProvider(openai_client=client),
        profile=OpenAIModelProfile(
            openai_supports_strict_tool_definition=False,
            openai_chat_supports_multiple_system_messages=False,
            openai_chat_supports_max_completion_tokens=False,
        ),
    )

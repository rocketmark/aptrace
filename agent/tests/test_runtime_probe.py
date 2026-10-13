"""Model-runtime determinism probe (no live runtime needed)."""

import json

from aptrace_agent.runtime_probe import CURRENT, EXPLICIT_GREEDY, build_request, request_bytes, run_probe, sha256

MESSAGES = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]


# 24
def test_request_hash_covers_the_exact_bytes_and_parameters():
    current = build_request("m", MESSAGES, config=CURRENT, max_tokens=64)
    greedy = build_request("m", MESSAGES, config=EXPLICIT_GREEDY, max_tokens=64)

    assert current == {"model": "m", "messages": MESSAGES, "max_tokens": 64, "temperature": 0.0}
    assert {"top_k", "top_p", "min_p", "seed"} <= set(greedy)
    assert sha256(request_bytes(current)) == sha256(request_bytes(dict(reversed(list(current.items())))))
    assert sha256(request_bytes(current)) != sha256(request_bytes(greedy))
    assert json.loads(request_bytes(greedy)) == greedy


# 25
def test_identical_requests_are_captured_and_compared():
    sent = []
    replies = iter(["a", "a", "b"])

    def send(body):
        sent.append(body)
        return {"choices": [{"message": {"content": next(replies)}}], "usage": {"completion_tokens": 1, "prompt_tokens_details": {"cached_tokens": 5}}, "model": "m"}, 0.1

    result = run_probe(build_request("m", MESSAGES, config=CURRENT, max_tokens=8), repeat=3, send=send)

    assert len(set(sent)) == 1
    assert {c["request_sha256"] for c in result["calls"]} == {result["request_sha256"]}
    assert result["distinct_responses"] == 2 and not result["byte_identical"]
    assert result["calls"][0]["cached_tokens"] == 5
    assert result["generation"] == {"max_tokens": 8, "temperature": 0.0}

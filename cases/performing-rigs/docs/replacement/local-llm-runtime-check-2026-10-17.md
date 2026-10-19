# Local LLM invocation check — 2026-10-17

## Result

Partial: APTrace has implemented local-model invocation paths and historical successful responses. Current server health is unconfirmed because the sandbox denied the live localhost connection. The preceding datasheet reconstruction did not invoke these LLM paths: its Ghidra raw dump and offline interpretation do not call a model.

Current process configuration, inspected without exposing credentials: OMLX_BASE_URL=http://127.0.0.1:8000/v1; OMLX_API_KEY present; APTRACE_MODEL=Qwen3-Coder-30B-A3B-Instruct-4bit; APTRACE_REVIEW_MODEL unset. ResearchController explicitly defaults its reconciler to gemma-4-26b-a4b-it-4bit, and the auditor uses that default as well. The separate one-shot build_model default is Qwen3-Coder-30B-A3B-Instruct-3bit, but the current APTRACE_MODEL override selects4bit. Configuration alone does not prove a request succeeded.

## Evidence and confidence

High confidence in inspected configuration/code and saved probe results; no new hardware/firmware claim or VERIFIED ledger entry.

- `agent/src/aptrace_agent/model.py`: build_model uses OpenAI-compatible AsyncOpenAI, local endpoint validation, API-key requirement,120-second timeout and no SDK retries.
- `agent/src/aptrace_agent/research/controller.py`: ResearchController creates OpenAI planner client from OMLX_BASE_URL/OMLX_API_KEY, planner model from APTRACE_MODEL; controller supplies the Gemma review-model default explicitly.
- `agent/src/aptrace_agent/research/reconciliation.py`: accepts the controller-supplied review model. Direct construction without an explicit model instead falls back to APTRACE_MODEL.
- `research/runs/agent/tmc5160-interface-2026-09-20-r5.json`: names Qwen4bit/Gemma4bit and records five research actions before a planner-prefill-memory rejection ended progress; reconciled=false. Historical calling occurred, but the investigation did not finish successfully.
- `research/runs/agent/runtime-probe-2026-10-12.json`: generated2026-10-13T01:16:55Z (October12 Eastern). The recorded endpoint is localhost. All32 Gemma requests answered without recorded HTTP errors; each response reports served_model=gemma-4-26b-a4b-it-4bit. Two short-prompt groups produced identical content8/8 each. Identical longer audit prompts produced7 and8 distinct content responses across8 calls, including explicit greedy settings. This demonstrates successful serving, not deterministic audit output or correctness of every audit.

## Execution

Read existing CLI/model/controller/probe implementation and historical records. Invoked the existing supported CLI:

```
agent/.venv/bin/aptrace-agent runtime-probe --ledger-dir /private/tmp/aptrace-local-llm-check-ledger --repeat 1 --configs current --max-tokens 128 --model Qwen3-Coder-30B-A3B-Instruct-4bit --output cases/performing-rigs/research/runs/agent/local-llm-check-2026-10-17-qwen.json
```

The command exited1 with urllib.error.URLError wrapping PermissionError errno1, Operation not permitted, at socket.connect. No model response or output JSON was produced. This is a sandbox denial before connectivity could be assessed, not evidence that oMLX is down or the model rejected a request. No escalation/repeated connection attempt, dependency installation, implementation change or commit was performed. No framework suite was run; the runtime probe itself was the requested bounded operational check. Only this report was added to the repository for this check; the ledger argument isolates any initialization under temporary storage.

## Gaps and next work

| Gap / priority | Impact / observed evidence | Cause assessment / needed next work |
|---|---|---|
| Current localhost access / HIGH for health confirmation | Live probe denied before socket connection | Session sandbox restriction. Run the same existing runtime-probe from a permitted operator environment for Qwen and Gemma; do not diagnose server failure from this denial |
| Repeatability / MEDIUM | Longer saved audit prompts yield7/8 distinct responses despite identical request bytes | Runtime behavior demonstrated, underlying cause unproven. Existing runtime-probe can recheck the current runtime; deterministic verification must remain separate from model output |
| Prefill capacity / MEDIUM | Historical TMC research ended with planner-prefill-memory rejection and unreconciled evidence | Serving memory/context limit, not failure to invoke API. Existing bounded research options/context projection can be used; success must be judged from run termination and reconciliation, not model names alone |
| Consistent local endpoint enforcement / LOW in this configuration | build_model checks localhost; controller/reconciler/probe directly consume endpoint environment | Code-path inconsistency, no remote endpoint used here. Centralized enforcement would require separate APTrace development, not an operator edit |

Existing-capability next work: repeat supported short probes when localhost is accessible, then use a small bounded research run only if end-to-end planning/tool/reconciliation validation is needed. No new model client, independent network probe or replacement test implementation is needed.

## Follow-up retry — successful live Qwen response

At the user’s request, repeated the identical bounded runtime-probe. The sandboxed attempt again failed at socket.connect with errno1. A single approved invocation outside the sandbox then exited0: one request answered, no recorded errors, served_model Qwen3-Coder-30B-A3B-Instruct-4bit,20 completion tokens,53.419seconds. Response content was the requested JSON listing primes2,3,5,7,11. The result is saved in `research/runs/agent/local-llm-check-2026-10-17-qwen.json`. This supersedes the earlier inability to confirm current Qwen serving health. It establishes a working APTrace→local oMLX→Qwen completion path, not current Gemma health, determinism or a complete research/tool/reconciliation loop. No implementation or ledger files changed.

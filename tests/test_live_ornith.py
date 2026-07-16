"""Optional live tests against LM Studio / Ornith.

Skip unless ``VF_LIVE=1`` is set **and** the endpoint is reachable.
Does not require FakeLLM.
"""

from __future__ import annotations

import os

import pytest

from vulnforge.cli import load_config
from vulnforge.llm import LLMClient, ResponseClass


def _live_enabled() -> bool:
    return os.environ.get("VF_LIVE", "").strip() in ("1", "true", "yes", "YES")


@pytest.fixture(scope="module")
def live_client():
    if not _live_enabled():
        pytest.skip("set VF_LIVE=1 to run live Ornith tests")
    cfg = load_config()
    client = LLMClient(cfg)
    try:
        client.fingerprint_model()
    except Exception as e:
        client.close()
        pytest.skip(f"LLM endpoint not reachable: {e}")
    yield client
    client.close()


@pytest.mark.live
def test_live_fingerprint_resolves_listed_id(live_client: LLMClient):
    mid = live_client.fingerprint_model()
    assert mid
    # Should match a listed id after resolve_listed_model (not a dead alias only)
    r = live_client._client.get("/models")
    r.raise_for_status()
    ids = [m.get("id") for m in (r.json().get("data") or []) if m.get("id")]
    assert mid in ids or any(mid.lower() == i.lower() for i in ids)
    print("live model:", mid)


@pytest.mark.live
def test_live_chat_not_empty_success(live_client: LLMClient):
    r = live_client.chat(
        [{"role": "user", "content": "Reply with exactly one word: pong"}],
        temperature=0.1,
        max_tokens=256,
    )
    if r.classification in (
        ResponseClass.TRANSPORT,
        ResponseClass.EMPTY,
        ResponseClass.CONTEXT_LENGTH,
    ):
        pytest.skip(f"model response unusable: {r.classification} {r.error}")
    assert r.ok
    assert r.content and r.content.strip()
    print("content:", repr(r.content[:80]))


@pytest.mark.live
def test_live_tool_call_probe_soft(live_client: LLMClient):
    """Soft check: tool_calls help recon/hunt; toolgen itself is text-only."""
    tools = [
        {
            "type": "function",
            "function": {
                "name": "ping",
                "description": "Acknowledge. Call once with message=pong.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string"},
                    },
                    "required": ["message"],
                },
            },
        }
    ]
    r = live_client.chat(
        [
            {
                "role": "user",
                "content": "Call the ping tool with message pong. Do not answer in plain text.",
            }
        ],
        tools=tools,
        temperature=0.0,
        max_tokens=512,
    )
    if not r.ok and r.classification in (
        ResponseClass.TRANSPORT,
        ResponseClass.CONTEXT_LENGTH,
    ):
        pytest.skip(f"tool probe unusable: {r.classification} {r.error}")
    has_tools = bool(r.tool_calls)
    print(
        "tool_calls:",
        has_tools,
        "content:",
        repr((r.content or "")[:60]),
        "classification:",
        r.classification,
    )
    # Soft: do not fail the suite — document weakness for recon/hunt
    if not has_tools:
        pytest.xfail(
            "model did not emit tool_calls (recon/hunt may need salvage; "
            "toolgen JSON path is unaffected)"
        )

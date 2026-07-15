"""Optional live tests against LM Studio (Ornith). Skip if endpoint down."""

from __future__ import annotations

import pytest

from vulnforge.cli import load_config
from vulnforge.llm import LLMClient, ResponseClass


@pytest.fixture(scope="module")
def live_client():
    cfg = load_config()
    client = LLMClient(cfg)
    try:
        client.fingerprint_model()
    except Exception as e:
        client.close()
        pytest.skip(f"LM Studio not reachable: {e}")
    yield client
    client.close()


def test_live_fingerprint(live_client: LLMClient):
    mid = live_client.fingerprint_model()
    assert mid
    print("live model:", mid)


def test_live_chat_not_empty_success(live_client: LLMClient):
    r = live_client.chat(
        [{"role": "user", "content": "Reply with exactly one word: pong"}],
        temperature=0.1,
        max_tokens=128,
    )
    # Must never treat empty length as success
    if r.classification in (
        ResponseClass.TRANSPORT,
        ResponseClass.EMPTY,
        ResponseClass.CONTEXT_LENGTH,
    ):
        pytest.skip(f"model response unusable: {r.classification} {r.error}")
    assert r.ok
    assert r.content and r.content.strip()

"""Tests for llm.classify_response and classify_llm_failure."""

from __future__ import annotations

from vulnforge.llm import (
    LLMResult,
    ResponseClass,
    chat_messages_to_anthropic,
    chat_messages_to_responses_input,
    classify_llm_failure,
    classify_messages_api,
    classify_response,
    classify_responses_api,
    looks_like_error,
    openai_tools_to_anthropic,
    openai_tools_to_responses,
)


def test_empty_choices_not_ok():
    r = classify_response(200, {"choices": []}, model="x")
    assert not r.ok
    assert r.classification == ResponseClass.EMPTY


def test_error_text_in_200():
    r = classify_response(
        200,
        {
            "choices": [
                {"message": {"content": "Error: model unloaded from GPU"}, "finish_reason": "stop"}
            ]
        },
        model="x",
    )
    assert not r.ok
    assert r.classification == ResponseClass.ERROR_TEXT


def test_tool_calls_ok():
    r = classify_response(
        200,
        {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "1",
                                "function": {
                                    "name": "submit_none",
                                    "arguments": '{"reason":"clean"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ]
        },
        model="x",
    )
    assert r.ok
    assert len(r.tool_calls) == 1
    assert r.tool_calls[0]["name"] == "submit_none"
    assert r.tool_calls[0]["arguments"]["reason"] == "clean"


def test_http_error():
    r = classify_response(500, {"error": "x"}, model="x")
    assert not r.ok
    assert r.classification == ResponseClass.TRANSPORT


def test_looks_like_error():
    assert looks_like_error("rate limit exceeded")
    assert not looks_like_error("found SQL injection in search")


def test_classify_responses_api_tool_call():
    r = classify_responses_api(
        200,
        {
            "output": [
                {
                    "type": "function_call",
                    "call_id": "c1",
                    "name": "submit_none",
                    "arguments": '{"reason":"clean"}',
                }
            ],
            "status": "completed",
        },
        model="x",
    )
    assert r.ok
    assert r.tool_calls[0]["name"] == "submit_none"
    assert r.tool_calls[0]["arguments"]["reason"] == "clean"


def test_classify_responses_api_text():
    r = classify_responses_api(
        200,
        {
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "hello"}],
                }
            ],
            "output_text": "hello",
            "status": "completed",
        },
        model="x",
    )
    assert r.ok
    assert "hello" in (r.content or "")


def test_classify_messages_api_tool_use():
    r = classify_messages_api(
        200,
        {
            "content": [
                {
                    "type": "tool_use",
                    "id": "tu1",
                    "name": "submit_none",
                    "input": {"reason": "clean"},
                }
            ],
            "stop_reason": "tool_use",
        },
        model="x",
    )
    assert r.ok
    assert r.tool_calls[0]["name"] == "submit_none"
    assert r.tool_calls[0]["id"] == "tu1"


def test_tool_schema_conversions():
    tools = [
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": "search",
                "parameters": {
                    "type": "object",
                    "properties": {"q": {"type": "string"}},
                },
            },
        }
    ]
    resp = openai_tools_to_responses(tools)
    assert resp[0]["type"] == "function"
    assert resp[0]["name"] == "grep"
    assert "parameters" in resp[0]
    anth = openai_tools_to_anthropic(tools)
    assert anth[0]["name"] == "grep"
    assert "input_schema" in anth[0]


def test_chat_to_responses_and_anthropic_roundtrip_shape():
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "go"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "1",
                    "type": "function",
                    "function": {
                        "name": "grep",
                        "arguments": '{"pattern":"x"}',
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "1",
            "name": "grep",
            "content": '{"ok":true}',
        },
    ]
    items = chat_messages_to_responses_input(messages)
    types = [i.get("type") or i.get("role") for i in items]
    assert "system" in types or any(i.get("role") == "system" for i in items)
    assert any(i.get("type") == "function_call" for i in items)
    assert any(i.get("type") == "function_call_output" for i in items)

    system, anth = chat_messages_to_anthropic(messages)
    assert "sys" in system
    assert anth[0]["role"] == "user"
    assert any(
        b.get("type") == "tool_use"
        for m in anth
        if isinstance(m.get("content"), list)
        for b in m["content"]
        if isinstance(b, dict)
    )


def _fail(
    classification: ResponseClass, error: str | None = None, content: str | None = None
) -> LLMResult:
    return LLMResult(
        ok=False,
        classification=classification,
        content=content,
        tool_calls=[],
        raw=None,
        model_id="x",
        error=error,
    )


def test_classify_llm_failure_max_tool_rounds_is_task():
    r = _fail(ResponseClass.TRUNCATED, error="max_tool_rounds")
    assert classify_llm_failure(r) == "failed_task"


def test_classify_llm_failure_transport_is_infra():
    r = _fail(ResponseClass.TRANSPORT, error="connection refused")
    assert classify_llm_failure(r) == "failed_infra"


def test_classify_llm_failure_empty_length_is_task():
    r = _fail(
        ResponseClass.CONTEXT_LENGTH,
        error="finish_reason=length (empty content; raise llm.max_tokens for reasoning models)",
    )
    assert classify_llm_failure(r) == "failed_task"


def test_classify_llm_failure_empty_message_is_task():
    r = _fail(ResponseClass.EMPTY, error="empty message")
    assert classify_llm_failure(r) == "failed_task"


def test_classify_llm_failure_platform_error_text_is_infra():
    r = _fail(
        ResponseClass.ERROR_TEXT,
        error="error-like content",
        content="Error: model unloaded from GPU",
    )
    assert classify_llm_failure(r) == "failed_infra"


def test_classify_llm_failure_non_platform_error_text_is_task():
    """Model-ish ERROR_TEXT without platform markers must not retry as infra."""
    r = _fail(
        ResponseClass.ERROR_TEXT,
        error="error-like content",
        content="I cannot complete this analysis without more context",
    )
    assert classify_llm_failure(r) == "failed_task"


def test_classify_llm_failure_unknown_is_task():
    r = _fail(ResponseClass.UNKNOWN, error="unexpected shape")
    assert classify_llm_failure(r) == "failed_task"


def test_classify_llm_failure_truncated_without_max_rounds_is_task():
    r = _fail(ResponseClass.TRUNCATED, error="finish_reason=length")
    assert classify_llm_failure(r) == "failed_task"


def test_classify_llm_failure_error_marker_in_error_string_only():
    """Platform markers in result.error (not content) still count as infra."""
    r = _fail(
        ResponseClass.ERROR_TEXT,
        error="HTTP 503 overloaded upstream",
        content="please try again later",
    )
    assert classify_llm_failure(r) == "failed_infra"

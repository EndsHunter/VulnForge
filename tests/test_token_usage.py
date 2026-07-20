"""Token usage parse, aggregate, and persistence."""

from __future__ import annotations

from pathlib import Path

from vulnforge.llm import (
    FakeLLMClient,
    LLMResult,
    ResponseClass,
    TokenUsage,
    classify_messages_api,
    classify_response,
    parse_usage_from_body,
)
from vulnforge.packet import Packet
from vulnforge.usage import load_usage_summary, record_usage, usage_fields_for_result


def test_parse_openai_usage():
    body = {
        "choices": [
            {
                "message": {"content": "hi", "tool_calls": None},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 20,
            "total_tokens": 120,
        },
    }
    r = classify_response(200, body, model="m")
    assert r.ok
    assert r.usage is not None
    assert r.usage.prompt_tokens == 100
    assert r.usage.completion_tokens == 20
    assert r.usage.total_tokens == 120
    assert r.usage.source == "provider"


def test_parse_anthropic_usage():
    body = {
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 50, "output_tokens": 10},
    }
    r = classify_messages_api(200, body, model="m")
    assert r.ok
    assert r.usage is not None
    assert r.usage.prompt_tokens == 50
    assert r.usage.completion_tokens == 10
    assert r.usage.total_tokens == 60
    assert r.usage.source == "provider"


def test_parse_usage_from_body_empty():
    u = parse_usage_from_body({"choices": []})
    assert u.source == "none"


def test_token_usage_add():
    a = TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15, source="provider")
    b = TokenUsage(prompt_tokens=20, completion_tokens=5, total_tokens=25, source="provider")
    s = a.add(b)
    assert s.prompt_tokens == 30
    assert s.total_tokens == 40
    assert s.llm_calls == 2
    assert s.source == "provider"


def test_fake_tool_loop_sums_usage(tmp_path: Path):
    responses = [
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="",
            tool_calls=[
                {
                    "id": "1",
                    "name": "submit_none",
                    "arguments": {"reason": "clean enough for unit test"},
                }
            ],
            raw=None,
            model_id="fake",
            usage=TokenUsage(
                prompt_tokens=11,
                completion_tokens=3,
                total_tokens=14,
                source="provider",
            ),
        )
    ]
    client = FakeLLMClient(responses=responses)
    packet = Packet(system="sys", user="user", tools_schema=[])

    def handler(name, args):
        return {"ok": True, "stored": "none"}

    result = client.run_tool_loop(packet, handler, max_rounds=4, temperature=0.1)
    assert result.ok
    assert result.usage is not None
    assert result.usage.prompt_tokens == 11
    assert result.usage.llm_calls >= 1

    record_usage(
        tmp_path,
        task_id=1,
        kind="hunt:injection",
        model_id="fake",
        usage=result.usage,
        extra={"class": "injection", "area": "api"},
    )
    summary = load_usage_summary(tmp_path)
    assert summary["total_tokens"] == 14
    assert summary["by_kind"]["hunt:injection"]["total_tokens"] == 14
    assert summary["by_task"]["1"]["total_tokens"] == 14
    assert summary["by_task"]["1"]["kind"] == "hunt:injection"
    assert summary["by_task"]["1"]["class"] == "injection"
    assert summary["by_task"]["1"]["area"] == "api"
    fields = usage_fields_for_result(result.usage)
    assert fields["total_tokens"] == 14


def test_rebuild_by_task_from_jsonl(tmp_path: Path):
    from vulnforge.usage import rebuild_by_task_from_jsonl

    record_usage(
        tmp_path,
        task_id=7,
        kind="hunt:memory-safety",
        model_id="m",
        usage=TokenUsage(
            prompt_tokens=100,
            completion_tokens=20,
            total_tokens=120,
            source="provider",
            llm_calls=3,
        ),
        extra={"class": "memory-safety", "area": "libopensc"},
    )
    # Drop by_task from summary as if older format
    summary_path = tmp_path / "llm_usage_summary.json"
    data = load_usage_summary(tmp_path)
    data.pop("by_task", None)
    summary_path.write_text(__import__("json").dumps(data), encoding="utf-8")
    rebuilt = rebuild_by_task_from_jsonl(tmp_path)
    assert "7" in rebuilt
    assert rebuilt["7"]["total_tokens"] == 120
    assert rebuilt["7"]["kind"] == "hunt:memory-safety"
    assert rebuilt["7"]["class"] == "memory-safety"

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
    assert rebuilt["7"]["cache_read_tokens"] == 0
    assert rebuilt["7"]["cache_source"] == "none"
    assert rebuilt["7"]["cache_hit_rate"] is None


def test_parse_openai_cached_tokens():
    body = {
        "usage": {
            "prompt_tokens": 2000,
            "completion_tokens": 20,
            "total_tokens": 2020,
            "prompt_tokens_details": {"cached_tokens": 1500, "audio_tokens": 0},
        }
    }
    u = parse_usage_from_body(body)
    assert u.source == "provider"
    assert u.prompt_tokens == 2000
    assert u.cache_read_tokens == 1500
    assert u.cache_creation_tokens == 0
    assert u.cache_source == "provider"
    assert u.to_dict()["cache_hit_rate"] == 0.75


def test_parse_openai_responses_cached_tokens():
    body = {
        "usage": {
            "input_tokens": 1000,
            "output_tokens": 10,
            "total_tokens": 1010,
            "input_tokens_details": {"cached_tokens": 250},
        }
    }
    u = parse_usage_from_body(body)
    assert u.prompt_tokens == 1000
    assert u.completion_tokens == 10
    assert u.cache_read_tokens == 250
    assert u.cache_source == "provider"
    assert u.to_dict()["cache_hit_rate"] == 0.25


def test_parse_anthropic_cache_tokens():
    body = {
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 21,
            "output_tokens": 10,
            "cache_creation_input_tokens": 100,
            "cache_read_input_tokens": 1800,
        },
    }
    r = classify_messages_api(200, body, model="m")
    assert r.ok
    assert r.usage is not None
    assert r.usage.prompt_tokens == 21
    assert r.usage.completion_tokens == 10
    assert r.usage.cache_read_tokens == 1800
    assert r.usage.cache_creation_tokens == 100
    assert r.usage.cache_source == "provider"
    # input_tokens excludes cache read/create, so basis is 21+1800+100.
    assert r.usage.to_dict()["cache_hit_rate"] == round(1800 / 1921, 6)


def test_parse_usage_missing_cache_fields():
    u = parse_usage_from_body(
        {
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 2,
                "total_tokens": 12,
            }
        }
    )
    assert u.source == "provider"
    assert u.cache_read_tokens == 0
    assert u.cache_creation_tokens == 0
    assert u.cache_source == "none"
    assert u.to_dict()["cache_hit_rate"] is None


def test_parse_usage_explicit_zero_cache_is_provider():
    u = parse_usage_from_body(
        {
            "usage": {
                "prompt_tokens": 40,
                "completion_tokens": 4,
                "total_tokens": 44,
                "prompt_tokens_details": {"cached_tokens": 0},
            }
        }
    )
    assert u.cache_source == "provider"
    assert u.cache_read_tokens == 0
    assert u.to_dict()["cache_hit_rate"] == 0.0


def test_parse_usage_odd_shapes_do_not_raise():
    assert parse_usage_from_body(None).source == "none"
    assert parse_usage_from_body("nope").source == "none"
    assert parse_usage_from_body({"usage": None}).source == "none"
    u = parse_usage_from_body(
        {
            "usage": {
                "prompt_tokens": 3,
                "completion_tokens": 1,
                "total_tokens": 4,
                "prompt_tokens_details": "nope",
            }
        }
    )
    assert u.cache_source == "none"
    u = parse_usage_from_body(
        {
            "usage": {
                "prompt_tokens": 3,
                "completion_tokens": 1,
                "total_tokens": 4,
                "prompt_tokens_details": {"cached_tokens": "nope"},
            }
        }
    )
    assert u.cache_source == "none"
    assert u.prompt_tokens == 3


def test_token_usage_add_sums_cache():
    a = TokenUsage(
        prompt_tokens=100,
        completion_tokens=5,
        total_tokens=105,
        source="provider",
        cache_read_tokens=40,
        cache_creation_tokens=0,
        cache_source="provider",
    )
    b = TokenUsage(
        prompt_tokens=50,
        completion_tokens=5,
        total_tokens=55,
        source="provider",
        cache_source="none",
    )
    s = a.add(b)
    assert s.cache_read_tokens == 40
    assert s.cache_creation_tokens == 0
    assert s.cache_source == "mixed"
    assert s.prompt_tokens == 150


def test_record_usage_rolls_cache_hit_rate(tmp_path: Path):
    record_usage(
        tmp_path,
        task_id=3,
        kind="hunt:injection",
        model_id="claude",
        usage=TokenUsage(
            prompt_tokens=21,
            completion_tokens=10,
            total_tokens=31,
            source="provider",
            cache_read_tokens=1800,
            cache_creation_tokens=100,
            cache_source="provider",
        ),
    )
    record_usage(
        tmp_path,
        task_id=4,
        kind="hunt:injection",
        model_id="ornith",
        usage=TokenUsage(
            prompt_tokens=80,
            completion_tokens=8,
            total_tokens=88,
            source="provider",
            cache_source="none",
        ),
    )
    summary = load_usage_summary(tmp_path)
    assert summary["cache_read_tokens"] == 1800
    assert summary["cache_creation_tokens"] == 100
    assert summary["prompt_tokens"] == 101
    assert summary["cache_source"] == "mixed"
    # Anthropic call: read+create > its prompt, but the rollup basis uses
    # summed prompt (101) which is still below read+create (1900).
    assert summary["cache_hit_rate"] == round(1800 / (101 + 1800 + 100), 6)
    kind = summary["by_kind"]["hunt:injection"]
    assert kind["cache_read_tokens"] == 1800
    assert kind["cache_source"] == "mixed"
    task = summary["by_task"]["3"]
    assert task["cache_read_tokens"] == 1800
    assert task["cache_source"] == "provider"
    assert task["cache_hit_rate"] == round(1800 / 1921, 6)
    omitted = summary["by_task"]["4"]
    assert omitted["cache_source"] == "none"
    assert omitted["cache_hit_rate"] is None
    fields = usage_fields_for_result(
        TokenUsage(
            prompt_tokens=2000,
            completion_tokens=1,
            total_tokens=2001,
            source="provider",
            cache_read_tokens=500,
            cache_source="provider",
        )
    )
    assert fields["cache_read_tokens"] == 500
    assert fields["cache_hit_rate"] == 0.25


def test_default_yaml_prompt_cache_off():
    import yaml

    root = Path(__file__).resolve().parents[1]
    cfg = yaml.safe_load((root / "config" / "default.yaml").read_text(encoding="utf-8"))
    assert cfg["llm"]["prompt_cache"] is False


def test_prompt_cache_flag_only_pins_messages_mode():
    from vulnforge.llm import LLMClient, anthropic_system_payload, prompt_cache_enabled

    assert prompt_cache_enabled({}) is False
    assert prompt_cache_enabled({"llm": {}}) is False
    assert prompt_cache_enabled({"llm": {"prompt_cache": False}}) is False
    assert prompt_cache_enabled({"llm": {"prompt_cache": "false"}}) is False
    assert prompt_cache_enabled({"llm": {"prompt_cache": True}}) is True
    assert anthropic_system_payload("STABLE", cache=False) == "STABLE"
    pinned = anthropic_system_payload("STABLE", cache=True)
    assert pinned == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}}
    ]

    captured: dict = {}

    def _client(api_mode: str, prompt_cache: bool) -> LLMClient:
        return LLMClient(
            {
                "llm": {
                    "base_url": "http://127.0.0.1:9/v1",
                    "api_mode": api_mode,
                    "api_key": "test-key",
                    "model": "m",
                    "prompt_cache": prompt_cache,
                    "timeout_seconds": 1,
                }
            }
        )

    def _fake_post(path, payload, model, timeout=None):
        captured["path"] = path
        captured["payload"] = payload
        if api_mode_box["mode"] == "messages":
            body = {
                "content": [{"type": "text", "text": "ok"}],
                "stop_reason": "end_turn",
                "usage": {
                    "input_tokens": 8,
                    "output_tokens": 1,
                    "cache_read_input_tokens": 6,
                    "cache_creation_input_tokens": 0,
                },
            }
        else:
            body = {
                "choices": [
                    {"message": {"content": "ok"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 8, "completion_tokens": 1, "total_tokens": 9},
            }
        return {"status_code": 200, "body": body}

    api_mode_box = {"mode": "messages"}
    on = _client("messages", True)
    try:
        on._post_json = _fake_post  # type: ignore[method-assign]
        result = on.chat(
            [
                {"role": "system", "content": "STABLE"},
                {"role": "user", "content": "hi"},
            ],
            temperature=0.0,
            max_tokens=16,
        )
    finally:
        on.close()
    assert captured["path"] == "/messages"
    assert captured["payload"]["system"] == [
        {"type": "text", "text": "STABLE", "cache_control": {"type": "ephemeral"}}
    ]
    assert result.usage is not None
    assert result.usage.cache_read_tokens == 6
    assert result.usage.cache_creation_tokens == 0
    assert result.usage.cache_source == "provider"

    api_mode_box["mode"] = "messages"
    off = _client("messages", False)
    try:
        off._post_json = _fake_post  # type: ignore[method-assign]
        off.chat(
            [
                {"role": "system", "content": "STABLE"},
                {"role": "user", "content": "hi"},
            ],
            temperature=0.0,
            max_tokens=16,
        )
    finally:
        off.close()
    assert captured["payload"]["system"] == "STABLE"

    api_mode_box["mode"] = "chat_completions"
    chat = _client("chat_completions", True)
    try:
        chat._post_json = _fake_post  # type: ignore[method-assign]
        chat.chat(
            [
                {"role": "system", "content": "STABLE"},
                {"role": "user", "content": "hi"},
            ],
            temperature=0.0,
            max_tokens=16,
        )
    finally:
        chat.close()
    assert captured["path"] == "/chat/completions"
    messages = captured["payload"]["messages"]
    assert messages[0] == {"role": "system", "content": "STABLE"}
    assert "cache_control" not in captured["payload"]


def test_strands_cache_config_and_usage_mapping():
    from vulnforge.agent_runtime.strands_loop import (
        _usage_from_result,
        strands_anthropic_cache_config,
    )

    assert strands_anthropic_cache_config({}) is None
    assert strands_anthropic_cache_config({"llm": {"prompt_cache": False}}) is None
    cfg = strands_anthropic_cache_config({"llm": {"prompt_cache": True}})
    assert cfg is not None
    assert cfg.strategy == "anthropic"
    assert cfg.system_prompt_ttl is True
    assert cfg.tools_ttl is False

    class _Metrics:
        def get_summary(self):
            return {
                "total_cycles": 2,
                "accumulated_usage": {
                    "inputTokens": 2000,
                    "outputTokens": 20,
                    "totalTokens": 2020,
                    "cacheReadInputTokens": 1500,
                },
            }

    class _Result:
        metrics = _Metrics()

    usage = _usage_from_result(_Result())
    assert usage is not None
    assert usage.cache_read_tokens == 1500
    assert usage.cache_creation_tokens == 0
    assert usage.cache_source == "provider"
    assert usage.to_dict()["cache_hit_rate"] == 0.75

    class _NoCache:
        def get_summary(self):
            return {
                "total_cycles": 1,
                "accumulated_usage": {
                    "inputTokens": 10,
                    "outputTokens": 2,
                    "totalTokens": 12,
                },
            }

    class _Plain:
        metrics = _NoCache()

    plain = _usage_from_result(_Plain())
    assert plain is not None
    assert plain.cache_source == "none"
    assert plain.to_dict()["cache_hit_rate"] is None

    try:
        import anthropic  # noqa: F401
    except ImportError:
        return
    from vulnforge.agent_runtime.strands_loop import _model_from_client

    class Client:
        api_mode = "messages"
        base_url = "http://10.0.0.1:1234/v1"
        model = "claude"
        api_key = "k"
        timeout = 30
        max_tokens = 128
        _cfg = {"llm": {"prompt_cache": True}}

    model = _model_from_client(Client(), 0.1)
    assert model.config.get("cache_config") is not None
    assert model.config["cache_config"].system_prompt_ttl is True

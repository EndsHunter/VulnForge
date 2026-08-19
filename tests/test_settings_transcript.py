from __future__ import annotations

from pathlib import Path

from vulnforge.settings import (
    apply_ui_settings_to_cfg,
    build_llm_base_url,
    load_ui_settings,
    normalize_api_key,
    save_ui_settings,
)
from vulnforge.transcript import save_transcript, load_transcript, list_transcript_ids


def test_ui_settings_merge(tmp_path: Path, monkeypatch):
    # isolate settings file
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    save_ui_settings(
        {
            "host": "192.168.1.5",
            "port": 9999,
            "model": "test-model",
            "api_mode": "responses",
            "api_key": "sk-test",
            "max_concurrent_agents": 2,
            "context_tokens": 16384,
            "max_context_fraction": 0.2,
            "model_hunt": "hunt-model",
            "validate_models": ["m1", "m2", "m1"],
            "validate_consensus": "all",
            "validate_poc_referee": True,
            "validate_llm": True,
        }
    )
    ui = load_ui_settings()
    assert ui["host"] == "192.168.1.5"
    assert ui["port"] == 9999
    assert ui["api_mode"] == "responses"
    assert ui["api_key"] == "sk-test"
    assert ui["model_hunt"] == "hunt-model"
    assert ui["validate_models"] == ["m1", "m2"]  # deduped
    assert ui["validate_consensus"] == "all"
    assert ui["validate_poc_referee"] is True
    assert ui["validate_llm"] is True
    cfg = apply_ui_settings_to_cfg({"llm": {}, "run": {}, "stages": {}}, ui)
    assert cfg["llm"]["base_url"] == "http://192.168.1.5:9999/v1"
    assert cfg["llm"]["model"] == "test-model"
    assert cfg["llm"]["api_mode"] == "responses"
    assert cfg["llm"]["api_key"] == "sk-test"
    assert cfg["llm"]["model_hunt"] == "hunt-model"
    assert cfg["llm"]["validate_models"] == ["m1", "m2"]
    assert cfg["llm"]["validate_consensus"] == "all"
    assert cfg["stages"]["validate_poc_referee"] is True
    assert cfg["stages"]["validate_llm"] is True
    assert cfg["run"]["max_leases_parallel"] == 2
    assert cfg["llm"]["context_tokens"] == 16384


def test_build_llm_base_url_https_and_local():
    assert build_llm_base_url("10.0.0.232", 1234) == "http://10.0.0.232:1234/v1"
    assert build_llm_base_url("192.168.1.5", 9999) == "http://192.168.1.5:9999/v1"
    # Full HTTPS hostname — port field ignored; empty path → /v1
    assert build_llm_base_url("https://random.something", 1234) == "https://random.something/v1"
    assert build_llm_base_url("https://random.something/", 9999) == "https://random.something/v1"
    assert build_llm_base_url("https://random.something/v1", 1) == "https://random.something/v1"
    assert (
        build_llm_base_url("https://api.example.com/openai/v1", 443)
        == "https://api.example.com/openai/v1"
    )
    assert build_llm_base_url("http://10.0.0.5:8080", 1) == "http://10.0.0.5:8080/v1"
    assert build_llm_base_url("https://gw.example.com:8443", 1234) == "https://gw.example.com:8443/v1"
    # host:port in host field without scheme
    assert build_llm_base_url("10.0.0.5:8080", 1234) == "http://10.0.0.5:8080/v1"


def test_ui_settings_https_host(tmp_path: Path, monkeypatch):
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    save_ui_settings(
        {
            "host": "https://random.something",
            "port": 1234,
            "model": "my-model",
        }
    )
    ui = load_ui_settings()
    assert ui["host"] == "https://random.something"
    cfg = apply_ui_settings_to_cfg({"llm": {}, "run": {}}, ui)
    assert cfg["llm"]["base_url"] == "https://random.something/v1"


def test_api_key_blank_and_none_accepted(tmp_path: Path, monkeypatch):
    assert normalize_api_key(None) == ""
    assert normalize_api_key("") == ""
    assert normalize_api_key("  ") == ""
    assert normalize_api_key("none") == ""
    assert normalize_api_key("None") == ""
    assert normalize_api_key("null") == ""
    assert normalize_api_key("n/a") == ""
    assert normalize_api_key("blank") == ""
    assert normalize_api_key("sk-live") == "sk-live"
    assert normalize_api_key("  sk-live  ") == "sk-live"

    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    save_ui_settings({"api_key": "sk-keep"})
    assert load_ui_settings()["api_key"] == "sk-keep"
    # clear with explicit blank
    save_ui_settings({"api_key": ""})
    assert load_ui_settings()["api_key"] == ""
    # clear with placeholder
    save_ui_settings({"api_key": "sk-again"})
    save_ui_settings({"api_key": "none"})
    assert load_ui_settings()["api_key"] == ""

    ui = load_ui_settings()
    cfg = apply_ui_settings_to_cfg({"llm": {"api_key": "from-yaml"}, "run": {}}, ui)
    assert cfg["llm"]["api_key"] == ""


def test_llm_client_optional_api_key_headers():
    from vulnforge.llm import LLMClient

    c = LLMClient({"llm": {"base_url": "http://127.0.0.1:9/v1", "api_key": ""}})
    try:
        assert c.api_key == ""
        assert "Authorization" not in c._client.headers
    finally:
        c.close()

    c2 = LLMClient({"llm": {"base_url": "http://127.0.0.1:9/v1", "api_key": "none"}})
    try:
        assert c2.api_key == ""
        assert "Authorization" not in c2._client.headers
    finally:
        c2.close()

    c3 = LLMClient({"llm": {"base_url": "http://127.0.0.1:9/v1", "api_key": "secret"}})
    try:
        assert c3.api_key == "secret"
        assert c3._client.headers.get("Authorization") == "Bearer secret"
    finally:
        c3.close()

    # Omitted key keeps local OpenAI-compatible dummy
    c4 = LLMClient({"llm": {"base_url": "http://127.0.0.1:9/v1"}})
    try:
        assert c4.api_key == "lm-studio"
        assert c4._client.headers.get("Authorization") == "Bearer lm-studio"
    finally:
        c4.close()


def test_api_mode_aliases_and_default(tmp_path: Path, monkeypatch):
    from vulnforge.settings import normalize_api_mode

    assert normalize_api_mode("chat-completions") == "chat_completions"
    assert normalize_api_mode("Responses") == "responses"
    assert normalize_api_mode("anthropic") == "messages"
    assert normalize_api_mode("nope") == "chat_completions"

    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    save_ui_settings({"api_mode": "chat-completions"})
    ui = load_ui_settings()
    assert ui["api_mode"] == "chat_completions"
    cfg = apply_ui_settings_to_cfg({"llm": {"api_mode": "messages"}, "run": {}}, ui)
    # UI wins over bare cfg default when applying ui settings
    assert cfg["llm"]["api_mode"] == "chat_completions"


def test_model_candidates_resolve_prefix():
    from vulnforge.settings_probe import model_candidates, resolve_listed_model

    listed = ["ornith-1.0-35b", "gpt-oss-20b"]
    c = model_candidates("models/Ornith-1.0-35b", listed)
    assert "ornith-1.0-35b" in c
    assert c[0] == "models/Ornith-1.0-35b" or "ornith" in c[0].lower()
    assert resolve_listed_model("models/Ornith-1.0-35B@4bit", ["ornith-1.0-35b@4bit"]) == (
        "ornith-1.0-35b@4bit"
    )
    assert resolve_listed_model("Ornith-1.0-35B@4bit", ["ornith-1.0-35b@4bit"]) == (
        "ornith-1.0-35b@4bit"
    )


def test_optimize_unreachable_endpoint(tmp_path: Path, monkeypatch):
    from vulnforge import settings_probe

    monkeypatch.setattr(
        "vulnforge.settings_probe.load_ui_settings",
        lambda: {
            "host": "127.0.0.1",
            "port": 1,
            "model": "nope",
            "api_mode": "chat_completions",
            "api_key": "",
            "max_concurrent_agents": 1,
            "context_tokens": 8192,
            "max_context_fraction": 0.25,
            "max_tokens": 1024,
            "max_tool_rounds": 8,
            "timeout_seconds": 30,
            "max_tasks": 10,
        },
    )
    r = settings_probe.optimize_ui_settings(
        host="127.0.0.1", port=1, model="nope", apply=False, timeout_seconds=2.0
    )
    assert r["ok"] is False
    assert r.get("error")
    assert r["applied"] is False
    assert any(t.get("id") == "models" for t in r.get("tests") or [])


def test_extract_context_tokens_nested():
    from vulnforge.settings_probe import _coerce_context_int, _extract_context_tokens

    assert _extract_context_tokens({"context_length": 32768}) == 32768
    assert _extract_context_tokens(
        {"id": "m", "architecture": {"max_position_embeddings": 131072}}
    ) == 131072
    assert _extract_context_tokens({"parameters": {"max_seq_len": 32768}}) == 32768
    assert _extract_context_tokens({"settings": {"n_ctx": 8192}}) == 8192
    assert _extract_context_tokens({"llama.cpp": {"n_ctx_train": 65536}}) == 65536
    assert _extract_context_tokens({"meta": {"context_length": 16384}}) == 16384
    assert _extract_context_tokens({"metadata": {"max_context_length": 4096}}) == 4096
    assert _extract_context_tokens({"max_input_tokens": 4096}) == 4096
    assert _extract_context_tokens({"max_sequence_length": "32k"}) == 32768
    assert _extract_context_tokens({"context_size": "64k"}) == 65536
    assert _extract_context_tokens({"max_model_len": 28672}) == 28672
    # n_embd must not be mistaken for a context window
    assert (
        _extract_context_tokens({"meta": {"n_ctx_train": 32768, "n_embd": 4096}})
        == 32768
    )
    assert _extract_context_tokens({"id": "thin", "object": "model"}) is None
    assert _coerce_context_int("8b") is None
    assert _coerce_context_int(512) is None


def test_recommend_runtime_settings_table():
    from vulnforge.settings_probe import recommend_runtime_settings

    small = recommend_runtime_settings(
        ctx=8192, reasoning_heavy=False, tool_ok=True, avg_latency_s=1.0, p95_latency_s=1.5
    )
    assert small["max_tokens"] == 4096
    assert small["max_tool_rounds"] == 12
    assert small["max_context_fraction"] == 0.25
    assert small["max_concurrent_agents"] == 2

    weak = recommend_runtime_settings(
        ctx=8192, reasoning_heavy=False, tool_ok=False, avg_latency_s=1.0, p95_latency_s=1.5
    )
    assert weak["max_tool_rounds"] == 16
    assert weak["max_context_fraction"] == 0.20
    assert weak["max_concurrent_agents"] == 1

    mid = recommend_runtime_settings(
        ctx=32768, reasoning_heavy=False, tool_ok=True, avg_latency_s=4.0, p95_latency_s=5.0
    )
    assert mid["max_tokens"] == 5461
    assert mid["max_tokens"] > 4096
    assert mid["max_tool_rounds"] == 20
    assert mid["max_context_fraction"] == 0.30
    assert mid["max_concurrent_agents"] == 1

    big = recommend_runtime_settings(
        ctx=131072, reasoning_heavy=False, tool_ok=True, avg_latency_s=1.0, p95_latency_s=1.2
    )
    assert big["max_tokens"] == 8192
    assert big["max_tool_rounds"] == 24
    assert big["max_context_fraction"] == 0.35
    assert big["timeout_seconds"] >= 900
    assert big["max_concurrent_agents"] == 2

    reason = recommend_runtime_settings(
        ctx=131072, reasoning_heavy=True, tool_ok=True, avg_latency_s=1.0, p95_latency_s=2.0
    )
    assert reason["max_tokens"] == 16384
    assert reason["max_tool_rounds"] == 24
    assert reason["timeout_seconds"] >= 900
    assert reason["max_concurrent_agents"] == 1

    weak_big = recommend_runtime_settings(
        ctx=131072, reasoning_heavy=False, tool_ok=False, avg_latency_s=1.0, p95_latency_s=1.0
    )
    assert weak_big["max_tool_rounds"] == 28


def test_is_over_context_and_recommend_tokens():
    from vulnforge.settings_probe import (
        _is_over_context,
        _recommend_context_tokens,
    )

    assert _is_over_context(400, "nope") is False
    assert _is_over_context(400, "requested tokens exceed n_ctx") is True
    assert _is_over_context(413, "") is True
    assert _is_over_context(500, {"error": {"message": "n_ctx exceeded"}}) is True
    assert _is_over_context(500, "CUDA OOM") is True
    assert _is_over_context(401, "invalid api token") is False
    assert _is_over_context(200, {"choices": []}) is False

    rec, measured, src = _recommend_context_tokens(
        last_ok=20000, claimed=65536, heuristic=8192
    )
    assert src == "empirical"
    assert measured == 20000
    assert rec == 18000
    rec2, measured2, src2 = _recommend_context_tokens(
        last_ok=None, claimed=32768, heuristic=8192
    )
    assert src2 == "model_card" and rec2 == 32768 and measured2 == 32768
    rec3, _, src3 = _recommend_context_tokens(
        last_ok=None, claimed=None, heuristic=8192
    )
    assert src3 == "heuristic" and rec3 == 8192


def test_probe_context_window_binary_search():
    from vulnforge.settings_probe import probe_context_window

    limit = 16384

    def fake_post(client, url, body, timeout=None):
        msgs = body.get("messages") or []
        text = "".join(str(m.get("content") or "") for m in msgs if isinstance(m, dict))
        tokens = max(1, len(text) // 4)
        assert int(body.get("max_tokens") or 0) <= 8
        if tokens > limit:
            return 400, {"error": {"message": "requested tokens exceed n_ctx"}}, 0.001
        return 200, {"choices": [{"message": {"content": "ok"}}]}, 0.001

    result = probe_context_window(
        None,
        "http://example.invalid/v1/chat/completions",
        "fake-model",
        claimed=None,
        budget_s=30.0,
        post_json=fake_post,
    )
    assert result["ok"] is True
    last_ok = result["last_ok"]
    assert last_ok is not None
    assert last_ok <= limit
    assert last_ok >= 8192
    assert result["first_fail"] is None or result["first_fail"] > last_ok

    claimed_fail = probe_context_window(
        None,
        "http://example.invalid/v1/chat/completions",
        "fake-model",
        claimed=65536,
        budget_s=30.0,
        post_json=fake_post,
    )
    assert claimed_fail["ok"] is True
    assert claimed_fail["last_ok"] <= limit
    assert claimed_fail["last_ok"] >= 8192


def test_optimize_empirical_context_and_ferocious_recs(monkeypatch):
    import json

    from vulnforge import settings_probe

    monkeypatch.setattr(
        "vulnforge.settings_probe.load_ui_settings",
        lambda: {
            "host": "127.0.0.1",
            "port": 1234,
            "model": "big-model",
            "api_mode": "chat_completions",
            "api_key": "",
            "max_concurrent_agents": 1,
            "context_tokens": 8192,
            "max_context_fraction": 0.2,
            "max_tokens": 1024,
            "max_tool_rounds": 8,
            "timeout_seconds": 30,
            "max_tasks": 10,
        },
    )

    window_limit = 20000

    class _Resp:
        def __init__(self, status: int, payload):
            self.status_code = status
            self._payload = payload
            self.text = (
                json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
            )

        def json(self):
            if isinstance(self._payload, (dict, list)):
                return self._payload
            raise ValueError("not json")

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, **kwargs):
            if str(url).rstrip("/").endswith("/models"):
                return _Resp(
                    200,
                    {
                        "data": [
                            {
                                "id": "big-model",
                                "object": "model",
                                "architecture": {"max_position_embeddings": 65536},
                            }
                        ]
                    },
                )
            if "/models/" in str(url):
                return _Resp(200, {"id": "big-model", "max_model_len": 65536})
            return _Resp(404, {"error": "nope"})

        def post(self, url, json=None, timeout=None, **kwargs):
            body = json or {}
            path = str(url)
            if path.endswith("/responses") or path.endswith("/messages"):
                return _Resp(404, {"error": "nope"})
            if body.get("tools"):
                return _Resp(
                    200,
                    {
                        "choices": [
                            {
                                "message": {
                                    "tool_calls": [
                                        {
                                            "id": "1",
                                            "type": "function",
                                            "function": {
                                                "name": "ping",
                                                "arguments": '{"message":"pong"}',
                                            },
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                )
            msgs = body.get("messages") or []
            text = "".join(
                str(m.get("content") or "") for m in msgs if isinstance(m, dict)
            )
            tokens = max(1, len(text) // 4)
            if tokens > window_limit:
                return _Resp(
                    400, {"error": {"message": "context length exceeded (n_ctx)"}}
                )
            return _Resp(200, {"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(settings_probe.httpx, "Client", _FakeClient)

    r = settings_probe.optimize_ui_settings(
        host="127.0.0.1",
        port=1234,
        model="big-model",
        apply=False,
        timeout_seconds=30.0,
        test_context=True,
    )
    assert r["ok"] is True
    assert r["applied"] is False
    assert r["context_source"] == "empirical"
    measured = r["measured_context_tokens"]
    assert measured is not None
    assert 8192 <= measured <= window_limit
    rec_ctx = r["recommended"]["context_tokens"]
    assert rec_ctx == measured or rec_ctx == int(measured * 0.9)
    ctx_test = next(t for t in r["tests"] if t.get("id") == "context_window")
    assert ctx_test["ok"] is True
    assert ctx_test.get("source") == "empirical"
    # Ferocious table uses the discovered window (~20k here), not the old 4k/12/0.2 defaults.
    assert r["recommended"]["max_tokens"] >= 4096
    assert r["recommended"]["max_tool_rounds"] >= 12
    assert r["recommended"]["max_context_fraction"] >= 0.25
    assert r["tool_calls_ok"] is True
    # Instant fake latency + tools ok + not reasoning → workers=2 + VRAM warning
    assert r["recommended"]["max_concurrent_agents"] == 2
    assert any("VRAM" in w or "OOM" in w or "concurrent" in w.lower() for w in r["warnings"])


def test_optimize_unverified_window_keeps_card(monkeypatch):
    import json

    from vulnforge import settings_probe

    monkeypatch.setattr(
        "vulnforge.settings_probe.load_ui_settings",
        lambda: {
            "host": "127.0.0.1",
            "port": 1234,
            "model": "card-model",
            "api_mode": "chat_completions",
            "api_key": "",
            "max_concurrent_agents": 1,
            "context_tokens": 8192,
            "max_context_fraction": 0.2,
            "max_tokens": 1024,
            "max_tool_rounds": 8,
            "timeout_seconds": 30,
            "max_tasks": 10,
        },
    )

    class _Resp:
        def __init__(self, status: int, payload):
            self.status_code = status
            self._payload = payload
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, **kwargs):
            return _Resp(
                200,
                {
                    "data": [
                        {
                            "id": "card-model",
                            "max_model_len": 32768,
                        }
                    ]
                },
            )

        def post(self, url, json=None, timeout=None, **kwargs):
            body = json or {}
            if str(url).endswith("/responses") or str(url).endswith("/messages"):
                return _Resp(404, {"error": "nope"})
            if int(body.get("max_tokens") or 0) <= 8 and any(
                len(str(m.get("content") or "")) > 2000
                for m in (body.get("messages") or [])
                if isinstance(m, dict)
            ):
                return _Resp(500, {"error": "internal"})
            if body.get("tools"):
                return _Resp(
                    200,
                    {
                        "choices": [
                            {
                                "message": {
                                    "tool_calls": [
                                        {
                                            "id": "1",
                                            "function": {
                                                "name": "ping",
                                                "arguments": "{}",
                                            },
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                )
            return _Resp(200, {"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(settings_probe.httpx, "Client", _FakeClient)

    r = settings_probe.optimize_ui_settings(
        host="127.0.0.1",
        port=1234,
        model="card-model",
        apply=False,
        timeout_seconds=20.0,
        test_context=True,
    )
    assert r["ok"] is True
    assert r["context_source"] == "model_card"
    assert r["recommended"]["context_tokens"] == 32768
    assert any("not empirically verified" in w for w in r["warnings"])
    ctx_test = next(t for t in r["tests"] if t.get("id") == "context_window")
    assert ctx_test["ok"] is False


def test_optimize_skips_empirical_when_disabled(monkeypatch):
    import json

    from vulnforge import settings_probe

    monkeypatch.setattr(
        "vulnforge.settings_probe.load_ui_settings",
        lambda: {
            "host": "127.0.0.1",
            "port": 1234,
            "model": "card-only",
            "api_mode": "chat_completions",
            "api_key": "",
            "max_concurrent_agents": 1,
            "context_tokens": 8192,
            "max_context_fraction": 0.2,
            "max_tokens": 1024,
            "max_tool_rounds": 8,
            "timeout_seconds": 30,
            "max_tasks": 10,
        },
    )

    class _Resp:
        def __init__(self, status: int, payload):
            self.status_code = status
            self._payload = payload
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, **kwargs):
            if str(url).rstrip("/").endswith("/models"):
                return _Resp(
                    200,
                    {
                        "data": [
                            {
                                "id": "card-only",
                                "object": "model",
                                "owned_by": "org",
                            }
                        ]
                    },
                )
            return _Resp(
                200,
                {
                    "id": "card-only",
                    "parameters": {"max_seq_len": 32768},
                },
            )

        def post(self, url, json=None, timeout=None, **kwargs):
            body = json or {}
            if str(url).endswith("/responses") or str(url).endswith("/messages"):
                return _Resp(404, {"error": "nope"})
            if body.get("tools"):
                return _Resp(200, {"choices": [{"message": {"content": "pong"}}]})
            msgs = body.get("messages") or []
            text = "".join(
                str(m.get("content") or "") for m in msgs if isinstance(m, dict)
            )
            # Fail loudly if a large empirical prompt slipped through
            assert len(text) < 2000
            return _Resp(200, {"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(settings_probe.httpx, "Client", _FakeClient)

    r = settings_probe.optimize_ui_settings(
        host="127.0.0.1",
        port=1234,
        model="card-only",
        apply=False,
        timeout_seconds=20.0,
        test_context=False,
    )
    assert r["ok"] is True
    assert r["context_source"] == "model_card"
    assert r["recommended"]["context_tokens"] == 32768
    assert r["recommended"]["max_tokens"] == 5461
    assert r["recommended"]["max_tool_rounds"] == 24  # 20 + 4 weak tools
    assert r["recommended"]["max_context_fraction"] == 0.30
    ctx_test = next(t for t in r["tests"] if t.get("id") == "context_window")
    assert "skipped" in (ctx_test.get("detail") or "")


def test_transcript_roundtrip(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    save_transcript(
        run,
        7,
        kind="hunt",
        model_id="fake",
        messages=[
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "done"},
        ],
        result={"ok": True},
    )
    data = load_transcript(run, 7)
    assert data is not None
    assert data["kind"] == "hunt"
    assert len(data["messages"]) == 3
    assert 7 in list_transcript_ids(run)


def test_loop_profile_default(tmp_path: Path, monkeypatch):
    from vulnforge import loop_profiles

    d = tmp_path / "harnesses"
    d.mkdir()
    monkeypatch.setattr(loop_profiles, "HARNESSES_DIR", d)
    p = loop_profiles.ensure_default_profile()
    assert p["id"] == "default-campaign"
    listed = loop_profiles.list_profiles()
    assert any(x["id"] == "default-campaign" for x in listed)
    kw = loop_profiles.profile_to_start_kwargs(p)
    assert kw["max_iterations"] == 10000
    assert kw["task_timeout"] == 900
    assert kw["loop_profile_id"] == "default-campaign"

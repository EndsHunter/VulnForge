"""Auto-tune recommendations for local reasoning models.

The Flint-style fake answers the way that server does: thinking lives in
``reasoning`` (not ``reasoning_content``), ``usage.prompt_tokens`` runs ahead
of the chars/4 estimate, a large prompt times out, and two requests serialize.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from vulnforge.llm import classify_response


def test_message_reasoning_reads_flint_field():
    from vulnforge.settings_probe import message_reasoning_text

    assert message_reasoning_text({"reasoning": " thinking "}) == "thinking"
    assert message_reasoning_text({"reasoning_content": "llama"}) == "llama"
    assert message_reasoning_text({"content": "ok"}) == ""
    assert (
        message_reasoning_text({"reasoning_details": [{"text": "step"}]}) == "step"
    )


def test_classify_response_keeps_flint_reasoning():
    result = classify_response(
        200,
        {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"role": "assistant", "content": "", "reasoning": "still thinking"},
                }
            ]
        },
        "flint",
    )
    assert result.ok is False
    assert result.reasoning_content == "still thinking"
    assert "max_tokens" in (result.error or "")


def test_context_walk_stops_on_timeout_and_uses_server_tokens():
    from vulnforge.settings_probe import probe_context_window

    seen: list[int] = []

    def fake_post(client, url, body, timeout=None):
        text = "".join(
            str(m.get("content") or "")
            for m in (body.get("messages") or [])
            if isinstance(m, dict)
        )
        tokens = max(1, len(text) // 4)
        seen.append(tokens)
        if tokens > 10000:
            return 0, "ReadTimeout: timed out", 25.0
        server = int(tokens * 1.3)
        return (
            200,
            {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": server, "completion_tokens": 1},
            },
            0.2,
        )

    result = probe_context_window(
        None,
        "http://example.invalid/v1/chat/completions",
        "flint",
        claimed=None,
        budget_s=45.0,
        post_json=fake_post,
    )
    assert seen[0] <= 8192
    assert max(seen) <= 40000
    assert result["time_bounded"] is True
    assert result["last_ok"] is not None
    assert 9000 <= result["last_ok"] <= 12000
    assert result["token_scale"] is not None
    assert result["token_scale"] > 1.2


def test_flint_style_optimize_recommends_a_usable_window(monkeypatch):
    from vulnforge import settings_probe

    monkeypatch.setattr(
        "vulnforge.settings_probe.load_ui_settings",
        lambda: {
            "host": "10.0.0.146",
            "port": 11501,
            "model": "flint",
            "api_mode": "chat_completions",
            "api_key": "",
            "max_concurrent_agents": 2,
            "context_tokens": 32768,
            "max_context_fraction": 0.25,
            "max_tokens": 5461,
            "max_tool_rounds": 20,
            "timeout_seconds": 180,
            "max_tasks": 10,
        },
    )

    aimed: list[int] = []
    gate = threading.Lock()

    class _Resp:
        def __init__(self, status: int, payload):
            self.status_code = status
            self._payload = payload
            self.text = json.dumps(payload) if not isinstance(payload, str) else payload

        def json(self):
            if isinstance(self._payload, str):
                raise ValueError("not json")
            return self._payload

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url, **kwargs):
            if str(url).rstrip("/").endswith("/models"):
                return _Resp(200, {"data": [{"id": "flint", "object": "model"}]})
            return _Resp(404, {"error": "no card"})

        def post(self, url, json=None, timeout=None, **kwargs):
            body = json or {}
            path = str(url)
            if path.endswith("/responses") or path.endswith("/messages"):
                return _Resp(404, {"error": "nope"})
            msgs = body.get("messages") or []
            text = "\n".join(
                str(m.get("content") or "") for m in msgs if isinstance(m, dict)
            )
            if body.get("tools"):
                return _Resp(
                    200,
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": None,
                                    "tool_calls": [
                                        {
                                            "id": "call-1",
                                            "type": "function",
                                            "function": {
                                                "name": "ping",
                                                "arguments": '{"message":"pong"}',
                                            },
                                        }
                                    ],
                                }
                            }
                        ]
                    },
                )
            if any(isinstance(m, dict) and m.get("role") == "tool" for m in msgs):
                return _Resp(
                    200,
                    {"choices": [{"message": {"role": "assistant", "content": "pong"}}]},
                )
            if "concurrency-probe" in text:
                with gate:
                    time.sleep(0.08)
                return _Resp(
                    200,
                    {"choices": [{"message": {"content": "ok"}}]},
                )
            tokens = max(1, len(text) // 4)
            if int(body.get("max_tokens") or 0) <= 8 and tokens > 2000:
                aimed.append(tokens)
                if tokens > 10000:
                    return _Resp(0, "ReadTimeout: timed out")
                server = int(tokens * 1.3)
                return _Resp(
                    200,
                    {
                        "choices": [{"message": {"content": "ok"}}],
                        "usage": {"prompt_tokens": server, "completion_tokens": 1},
                    },
                )
            if int(body.get("max_tokens") or 0) < 64:
                return _Resp(
                    200,
                    {
                        "choices": [
                            {
                                "finish_reason": "length",
                                "message": {
                                    "role": "assistant",
                                    "content": "",
                                    "reasoning": "thinking about ok",
                                },
                            }
                        ],
                        "usage": {"prompt_tokens": 12, "completion_tokens": 32},
                    },
                )
            return _Resp(
                200,
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": "ok",
                                "reasoning": "done",
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 40},
                },
            )

    monkeypatch.setattr(settings_probe.httpx, "Client", _FakeClient)
    events: list[str] = []
    result = settings_probe.optimize_ui_settings(
        host="http://10.0.0.146:11501/v1",
        port=11501,
        model="flint",
        api_key="not-stored",
        apply=False,
        timeout_seconds=30.0,
        test_context=True,
        on_progress=lambda event: events.append(str(event.get("id"))),
    )

    assert result["ok"] is True
    assert result["resolved_model"] == "flint"
    assert result["context_source"] == "empirical"
    assert result["time_bounded"] is True
    assert result["recommended"]["context_tokens"] < 20000
    assert result["recommended"]["max_tokens"] >= 8192
    assert result["recommended"]["timeout_seconds"] >= 900
    assert result["recommended"]["max_concurrent_agents"] == 1
    assert result["tool_calls_ok"] is True
    assert any(t.get("id") == "tool_loop" and t.get("ok") for t in result["tests"])
    assert any(t.get("id") == "generation" and t.get("ok") for t in result["tests"])
    assert aimed and aimed[0] <= 8192
    assert max(aimed) <= 40000
    assert not any("VRAM" in w or "OOM" in w for w in result["warnings"])
    by_key = {row["key"]: row for row in result["recommendations"]}
    assert by_key["context_tokens"]["confidence"] == "medium"
    assert by_key["context_tokens"]["scope"] == "pair"
    assert "practical" in by_key["context_tokens"]["reason"]
    assert by_key["max_concurrent_agents"]["value"] == 1
    assert by_key["max_concurrent_agents"]["confidence"] == "high"
    assert "reasoning" in by_key["max_tokens"]["reason"]
    assert "models" in events and "context" in events
    assert result["recommended"]["api_key"] == "not-stored"


def test_optimize_job_cancel():
    from vulnforge import settings_probe

    started = threading.Event()

    def block(**kwargs):
        started.set()
        kwargs["cancel_event"].wait(2)
        raise settings_probe.ProbeCancelled("cancelled")

    original = settings_probe.optimize_selected_pairs
    settings_probe.optimize_selected_pairs = block
    try:
        job_id = settings_probe.start_optimize_job(
            targets=[{"host_id": "a", "model_id": "flint"}]
        )
        assert started.wait(2)
        assert settings_probe.cancel_optimize_job(job_id) is True
        status = ""
        for _ in range(50):
            job = settings_probe.get_optimize_job(job_id)
            assert job is not None
            status = job["status"]
            if status in ("cancelled", "done", "error"):
                break
            time.sleep(0.02)
        assert status == "cancelled"
    finally:
        settings_probe.optimize_selected_pairs = original


def test_settings_page_exposes_autotune_panel():
    root = Path(__file__).resolve().parents[1]
    html = (root / "vulnforge/ui/templates/settings.html").read_text(encoding="utf-8")
    script = (root / "vulnforge/ui/static/settings.js").read_text(encoding="utf-8")
    assert 'id="settings-optimize-panel"' in html
    assert "Auto-tune selected" in html
    assert "/api/settings/optimize/jobs" in script
    assert "Accept" in script

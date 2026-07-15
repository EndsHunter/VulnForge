from __future__ import annotations

from pathlib import Path

from vulnforge.settings import apply_ui_settings_to_cfg, save_ui_settings, load_ui_settings
from vulnforge.transcript import save_transcript, load_transcript, list_transcript_ids


def test_ui_settings_merge(tmp_path: Path, monkeypatch):
    # isolate settings file
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    save_ui_settings(
        {
            "host": "192.168.1.5",
            "port": 9999,
            "model": "test-model",
            "api_mode": "responses",
            "max_concurrent_agents": 2,
            "context_tokens": 16384,
            "max_context_fraction": 0.2,
        }
    )
    ui = load_ui_settings()
    assert ui["host"] == "192.168.1.5"
    assert ui["port"] == 9999
    assert ui["api_mode"] == "responses"
    cfg = apply_ui_settings_to_cfg({"llm": {}, "run": {}}, ui)
    assert cfg["llm"]["base_url"] == "http://192.168.1.5:9999/v1"
    assert cfg["llm"]["model"] == "test-model"
    assert cfg["llm"]["api_mode"] == "responses"
    assert cfg["run"]["max_leases_parallel"] == 2
    assert cfg["llm"]["context_tokens"] == 16384


def test_api_mode_aliases_and_default(tmp_path: Path, monkeypatch):
    from vulnforge.settings import normalize_api_mode

    assert normalize_api_mode("chat-completions") == "chat_completions"
    assert normalize_api_mode("Responses") == "responses"
    assert normalize_api_mode("anthropic") == "messages"
    assert normalize_api_mode("nope") == "chat_completions"

    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    save_ui_settings({"api_mode": "chat-completions"})
    ui = load_ui_settings()
    assert ui["api_mode"] == "chat_completions"
    cfg = apply_ui_settings_to_cfg({"llm": {"api_mode": "messages"}, "run": {}}, ui)
    # UI wins over bare cfg default when applying ui settings
    assert cfg["llm"]["api_mode"] == "chat_completions"


def test_model_candidates_resolve_prefix():
    from vulnforge.settings_probe import _model_candidates

    listed = ["ornith-1.0-35b", "gpt-oss-20b"]
    c = _model_candidates("models/Ornith-1.0-35b", listed)
    assert "ornith-1.0-35b" in c
    assert c[0] == "models/Ornith-1.0-35b" or "ornith" in c[0].lower()


def test_optimize_unreachable_endpoint(tmp_path: Path, monkeypatch):
    from vulnforge import settings_probe

    monkeypatch.setattr(
        "vulnforge.settings_probe.load_ui_settings",
        lambda: {
            "host": "127.0.0.1",
            "port": 1,
            "model": "nope",
            "api_mode": "chat_completions",
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

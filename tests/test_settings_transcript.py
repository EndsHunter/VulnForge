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

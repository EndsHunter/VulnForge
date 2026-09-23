"""Multi-host catalog: migration, role refs, and no cross-host fallback."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.llm import ConfigError, make_client
from vulnforge.llm_models import bind_role_cfg, make_client_for_stage
from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings, save_ui_settings


def _isolate(tmp_path: Path, monkeypatch) -> Path:
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    return p


def test_flat_file_migrates_once_and_hunt_client_uses_that_host(tmp_path, monkeypatch):
    p = _isolate(tmp_path, monkeypatch)
    p.write_text(
        json.dumps(
            {
                "host": "10.1.2.3",
                "port": 1234,
                "model": "ornith-1.0-35b",
                "api_mode": "chat_completions",
                "api_key": "sk-hunt",
                "model_hunt": "hunt-m",
                "validate_models": ["v-a"],
                "hunt_perspectives": [
                    {"id": "sink_driven", "prompt": "hunt_sink.md", "model": "hunt-m"}
                ],
            }
        ),
        encoding="utf-8",
    )
    ui = load_ui_settings()
    host = ui["hosts"][0]
    assert host["id"] == "default"
    assert host["base_url"] == "http://10.1.2.3:1234/v1"
    assert host["api_key"] == "sk-hunt"
    assert ui["model"] == {"host_id": "default", "model_id": "ornith-1.0-35b"}
    assert ui["model_hunt"] == {"host_id": "default", "model_id": "hunt-m"}
    assert ui["hunt_perspectives"][0]["model"] == {
        "host_id": "default",
        "model_id": "hunt-m",
    }
    pairs = {(row["host_id"], row["model_id"]) for row in ui["available"]}
    assert ("default", "ornith-1.0-35b") in pairs
    assert ("default", "hunt-m") in pairs
    assert ("default", "v-a") in pairs
    saved = json.loads(p.read_text(encoding="utf-8"))
    assert "hosts" in saved
    assert "host" not in saved
    again = load_ui_settings()
    assert again["hosts"] == ui["hosts"]

    cfg = apply_ui_settings_to_cfg(
        {"llm": {"model": "yaml-model", "base_url": "http://yaml/v1", "api_key": "yaml"}, "run": {}, "stages": {}},
        ui,
    )
    cfg["llm"]["fake"] = True
    client = make_client_for_stage(cfg, "hunt")
    try:
        assert client.model_id == "hunt-m"
    finally:
        client.close()
    bound = bind_role_cfg(cfg, ui["model_hunt"])
    assert bound["llm"]["base_url"] == "http://10.1.2.3:1234/v1"
    assert bound["llm"]["api_key"] == "sk-hunt"
    assert bound["llm"]["model"] == "hunt-m"


def test_empty_ui_keeps_yaml_connection(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ui = load_ui_settings()
    assert ui["hosts"] == []
    cfg = apply_ui_settings_to_cfg(
        {
            "llm": {
                "base_url": "http://yaml.example/v1",
                "model": "yaml-model",
                "api_key": "yaml-key",
                "api_mode": "messages",
            },
            "run": {},
            "stages": {},
        },
        ui,
    )
    assert cfg["llm"]["base_url"] == "http://yaml.example/v1"
    assert cfg["llm"]["model"] == "yaml-model"
    assert cfg["llm"]["api_key"] == "yaml-key"
    assert cfg["llm"]["api_mode"] == "messages"
    assert cfg["llm"]["max_tokens"] == 4096


def test_no_cross_host_fallback():
    cfg = {
        "llm": {
            "base_url": "http://should-not-use/v1",
            "api_key": "wrong",
            "api_mode": "chat_completions",
            "model": "same",
            "hosts": [
                {
                    "id": "a",
                    "base_url": "http://host-a/v1",
                    "api_mode": "chat_completions",
                    "api_key": "key-a",
                },
                {
                    "id": "b",
                    "base_url": "http://host-b/v1",
                    "api_mode": "messages",
                    "api_key": "key-b",
                },
            ],
            "available": [
                {"host_id": "a", "model_id": "same"},
                {"host_id": "b", "model_id": "same"},
            ],
            "model_ref": {"host_id": "a", "model_id": "same"},
            "model_hunt": {"host_id": "b", "model_id": "same"},
            "fake": True,
        }
    }
    bound = bind_role_cfg(cfg, {"host_id": "b", "model_id": "same"})
    assert bound["llm"]["base_url"] == "http://host-b/v1"
    assert bound["llm"]["api_key"] == "key-b"
    assert bound["llm"]["api_mode"] == "messages"
    assert bound["llm"]["model"] == "same"
    client = make_client_for_stage(cfg, "hunt")
    try:
        assert client.model_id == "same"
    finally:
        client.close()
    # The stage client is host B, not the default host A.
    stage_cfg = bind_role_cfg(cfg, cfg["llm"]["model_hunt"])
    assert stage_cfg["llm"]["api_key"] == "key-b"
    assert "key-a" not in stage_cfg["llm"]["api_key"]

    with pytest.raises(ConfigError, match="not configured"):
        bind_role_cfg(cfg, {"host_id": "gone", "model_id": "same"})
    with pytest.raises(ConfigError, match="not available"):
        bind_role_cfg(cfg, {"host_id": "a", "model_id": "other"})
    with pytest.raises(ConfigError, match="cross-host"):
        bind_role_cfg(cfg, "same")
    with pytest.raises(ConfigError, match="not available"):
        make_client(cfg, {"host_id": "b", "model_id": "missing"})


def test_refresh_and_verify_are_explicit(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    _isolate(tmp_path, monkeypatch)
    save_ui_settings(
        {
            "hosts": [
                {
                    "id": "local",
                    "base_url": "http://127.0.0.1:9/v1",
                    "api_mode": "chat_completions",
                    "api_key": "sek",
                }
            ]
        }
    )
    app = create_app(runs_root=tmp_path / "runs")

    def _boom(*_a, **_k):
        raise AssertionError("catalog must not refresh on GET /api/settings")

    monkeypatch.setattr("vulnforge.settings_probe.list_model_ids", _boom)
    monkeypatch.setattr("vulnforge.settings_probe.verify_model_pair", _boom)
    with TestClient(app) as client:
        got = client.get("/api/settings")
        assert got.status_code == 200
        assert got.json()["settings"]["catalog"] == []
        assert got.json()["settings"]["available"] == []

        def _list(base_url, api_key="", timeout=20.0):
            assert base_url == "http://127.0.0.1:9/v1"
            assert api_key == "sek"
            return ["alpha", "beta"]

        monkeypatch.setattr("vulnforge.settings_probe.list_model_ids", _list)
        refreshed = client.post("/api/settings/hosts/local/catalog")
        assert refreshed.status_code == 200
        body = refreshed.json()
        assert body["ok"] is True
        assert body["models"] == ["alpha", "beta"]
        ids = [row["model_id"] for row in body["settings"]["catalog"]]
        assert ids == ["alpha", "beta"]
        assert body["settings"]["available"] == []

        def _bad(**kwargs):
            assert kwargs["model_id"] == "alpha"
            assert kwargs["api_key"] == "sek"
            return {"ok": False, "detail": "HTTP 401"}

        monkeypatch.setattr("vulnforge.settings_probe.verify_model_pair", _bad)
        failed = client.post("/api/settings/hosts/local/verify", json={"model_id": "alpha"})
        assert failed.status_code == 200
        assert failed.json()["ok"] is False
        assert load_ui_settings()["available"] == []

        monkeypatch.setattr(
            "vulnforge.settings_probe.verify_model_pair",
            lambda **kwargs: {"ok": True, "detail": "HTTP 200 chat_completions"},
        )
        ok = client.post("/api/settings/hosts/local/verify", json={"model_id": "alpha"})
        assert ok.status_code == 200
        assert ok.json()["ok"] is True
        avail = load_ui_settings()["available"]
        assert avail[0]["host_id"] == "local"
        assert avail[0]["model_id"] == "alpha"

        # Same model id on a second host is a different pair.
        save_ui_settings(
            {
                "hosts": [
                    {
                        "id": "local",
                        "base_url": "http://127.0.0.1:9/v1",
                        "api_mode": "chat_completions",
                        "api_key": "sek",
                    },
                    {
                        "id": "other",
                        "base_url": "http://10.0.0.8:9/v1",
                        "api_mode": "responses",
                        "api_key": "other-key",
                    },
                ],
                "model": {"host_id": "local", "model_id": "alpha"},
            }
        )
        ui = load_ui_settings()
        assert {(a["host_id"], a["model_id"]) for a in ui["available"]} == {("local", "alpha")}
        # other/alpha was never verified. Assigning it is rejected.
        denied = client.put(
            "/api/settings",
            json={
                "hosts": ui["hosts"],
                "model": {"host_id": "other", "model_id": "alpha"},
            },
        )
        assert denied.status_code == 400
        assert "not available" in denied.json()["detail"]


def test_role_save_rejects_free_text_when_hosts_exist(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    save_ui_settings(
        {
            "hosts": [
                {
                    "id": "local",
                    "base_url": "http://127.0.0.1:9/v1",
                    "api_mode": "chat_completions",
                    "api_key": "",
                }
            ]
        }
    )
    save_ui_settings(
        {
            "catalog": [{"host_id": "local", "model_id": "alpha"}],
            "available": [{"host_id": "local", "model_id": "alpha"}],
            "model": {"host_id": "local", "model_id": "alpha"},
        }
    )
    with pytest.raises(ValueError, match="free-text"):
        save_ui_settings({"model_hunt": "alpha"})


def _two_hosts() -> list[dict]:
    return [
        {
            "id": "a",
            "base_url": "http://host-a/v1",
            "api_mode": "chat_completions",
            "api_key": "key-a",
        },
        {
            "id": "b",
            "base_url": "http://host-b/v1",
            "api_mode": "messages",
            "api_key": "key-b",
        },
    ]


def test_pair_budget_does_not_change_the_other_model(tmp_path, monkeypatch):
    """Override on pair A stays off pair B, including the same model id on another host."""
    _isolate(tmp_path, monkeypatch)
    hosts = _two_hosts()
    save_ui_settings({"hosts": hosts, "context_tokens": 32768, "max_tokens": 4096, "max_context_fraction": 0.25})
    # Verify-style write: available without hosts. A `model` key without hosts is
    # the legacy connection update, so roles are set on the next save.
    save_ui_settings(
        {
            "catalog": [
                {"host_id": "a", "model_id": "alpha"},
                {"host_id": "b", "model_id": "beta"},
                {"host_id": "b", "model_id": "alpha"},
            ],
            "available": [
                {"host_id": "a", "model_id": "alpha", "verified_at": "t0"},
                {"host_id": "b", "model_id": "beta", "verified_at": "t0"},
                {"host_id": "b", "model_id": "alpha", "verified_at": "t0"},
            ],
        }
    )
    # Settings form always posts hosts. Budgets ride along; the verified set does not.
    save_ui_settings(
        {
            "hosts": hosts,
            "available": [
                {"host_id": "a", "model_id": "alpha", "max_tokens": 1111, "context_tokens": 2222},
                {"host_id": "b", "model_id": "beta", "max_tokens": None, "context_tokens": None},
                {"host_id": "b", "model_id": "alpha"},
            ],
            "model": {"host_id": "a", "model_id": "alpha"},
            "model_hunt": {"host_id": "b", "model_id": "beta"},
        }
    )
    ui = load_ui_settings()
    by = {(row["host_id"], row["model_id"]): row for row in ui["available"]}
    assert by[("a", "alpha")]["max_tokens"] == 1111
    assert by[("a", "alpha")]["context_tokens"] == 2222
    assert "max_tokens" not in by[("b", "beta")]
    assert "context_tokens" not in by[("b", "beta")]
    assert "max_tokens" not in by[("b", "alpha")]
    assert ui["max_tokens"] == 4096
    assert ui["context_tokens"] == 32768
    assert ui["max_context_fraction"] == 0.25

    cfg = apply_ui_settings_to_cfg({"llm": {"fake": True}, "run": {}, "stages": {}}, ui)
    bound_a = bind_role_cfg(cfg, {"host_id": "a", "model_id": "alpha"})
    bound_b = bind_role_cfg(cfg, {"host_id": "b", "model_id": "beta"})
    bound_same = bind_role_cfg(cfg, {"host_id": "b", "model_id": "alpha"})
    assert bound_a["llm"]["max_tokens"] == 1111
    assert bound_a["llm"]["context_tokens"] == 2222
    assert bound_a["llm"]["base_url"] == "http://host-a/v1"
    assert bound_b["llm"]["max_tokens"] == 4096
    assert bound_b["llm"]["context_tokens"] == 32768
    assert bound_b["llm"]["base_url"] == "http://host-b/v1"
    assert bound_same["llm"]["max_tokens"] == 4096
    assert bound_same["llm"]["context_tokens"] == 32768
    assert bound_a["llm"]["max_context_fraction"] == 0.25
    assert bound_b["llm"]["max_context_fraction"] == 0.25

    client_a = make_client(cfg, {"host_id": "a", "model_id": "alpha"})
    client_b = make_client_for_stage(cfg, "hunt")
    try:
        assert client_a.max_tokens == 1111
        assert client_a.context_tokens == 2222
        assert client_a.model_id == "alpha"
        assert client_b.max_tokens == 4096
        assert client_b.context_tokens == 32768
        assert client_b.model_id == "beta"
    finally:
        client_a.close()
        client_b.close()

    with pytest.raises(ConfigError, match="not available"):
        make_client(cfg, {"host_id": "a", "model_id": "missing"})

    # Clearing A's override returns it to the global seed and still leaves B alone.
    save_ui_settings(
        {
            "hosts": hosts,
            "available": [
                {"host_id": "a", "model_id": "alpha", "max_tokens": None, "context_tokens": None},
                {"host_id": "b", "model_id": "beta", "max_tokens": 7777, "context_tokens": 8888},
            ],
            "model": {"host_id": "a", "model_id": "alpha"},
        }
    )
    ui2 = load_ui_settings()
    by2 = {(row["host_id"], row["model_id"]): row for row in ui2["available"]}
    assert "max_tokens" not in by2[("a", "alpha")]
    assert by2[("b", "beta")]["max_tokens"] == 7777
    assert by2[("b", "beta")]["context_tokens"] == 8888
    assert "max_tokens" not in by2[("b", "alpha")]
    cfg2 = apply_ui_settings_to_cfg({"llm": {}, "run": {}, "stages": {}}, ui2)
    assert bind_role_cfg(cfg2, {"host_id": "a", "model_id": "alpha"})["llm"]["max_tokens"] == 4096
    assert bind_role_cfg(cfg2, {"host_id": "b", "model_id": "beta"})["llm"]["context_tokens"] == 8888


def test_budget_seed_comes_from_globals_until_override(tmp_path, monkeypatch):
    """Flat settings migrate without copying globals onto pairs. Resolve uses them."""
    p = _isolate(tmp_path, monkeypatch)
    p.write_text(
        json.dumps(
            {
                "host": "10.0.0.5",
                "port": 1234,
                "model": "m-a",
                "model_hunt": "m-b",
                "max_tokens": 1500,
                "context_tokens": 9000,
                "max_context_fraction": 0.2,
            }
        ),
        encoding="utf-8",
    )
    ui = load_ui_settings()
    assert ui["max_tokens"] == 1500
    assert ui["context_tokens"] == 9000
    ids = {row["model_id"] for row in ui["available"]}
    assert ids == {"m-a", "m-b"}
    for row in ui["available"]:
        assert "max_tokens" not in row
        assert "context_tokens" not in row
    saved = json.loads(p.read_text(encoding="utf-8"))
    for row in saved["available"]:
        assert "max_tokens" not in row
    cfg = apply_ui_settings_to_cfg({"llm": {"fake": True}, "run": {}, "stages": {}}, ui)
    for ref in (ui["model"], ui["model_hunt"]):
        bound = bind_role_cfg(cfg, ref)
        assert bound["llm"]["max_tokens"] == 1500
        assert bound["llm"]["context_tokens"] == 9000
        assert bound["llm"]["max_context_fraction"] == 0.2
    client = make_client_for_stage(cfg, "hunt")
    try:
        assert client.model_id == "m-b"
        assert client.max_tokens == 1500
        assert client.context_tokens == 9000
    finally:
        client.close()


def test_optimize_selected_is_explicit_and_isolated(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    _isolate(tmp_path, monkeypatch)
    hosts = _two_hosts()
    save_ui_settings({"hosts": hosts, "max_tokens": 4096, "context_tokens": 32768})
    save_ui_settings(
        {
            "available": [
                {"host_id": "a", "model_id": "m-a"},
                {"host_id": "b", "model_id": "m-b"},
            ],
            "catalog": [
                {"host_id": "a", "model_id": "m-a"},
                {"host_id": "b", "model_id": "m-b"},
            ],
            "model": {"host_id": "a", "model_id": "m-a"},
            "model_hunt": {"host_id": "b", "model_id": "m-b"},
        }
    )
    calls: list[dict] = []

    def _probe(**kwargs):
        calls.append(kwargs)
        assert kwargs.get("strict_model") is True
        model = kwargs.get("model")
        if model == "m-a":
            assert kwargs.get("host") == "http://host-a/v1"
            assert kwargs.get("api_key") == "key-a"
            ctx, mt = 11111, 100
        else:
            assert model == "m-b"
            assert kwargs.get("host") == "http://host-b/v1"
            assert kwargs.get("api_key") == "key-b"
            ctx, mt = 22222, 200
        return {
            "ok": True,
            "error": None,
            "recommended": {
                "context_tokens": ctx,
                "max_tokens": mt,
                "max_context_fraction": 0.99,
                "max_tool_rounds": 99,
                "timeout_seconds": 9,
                "max_concurrent_agents": 2,
            },
            "warnings": [],
            "tests": [{"id": "models", "ok": True, "detail": model}],
            "measured_context_tokens": ctx,
            "context_source": "model_card",
            "summary": model,
            "applied": False,
        }

    monkeypatch.setattr("vulnforge.settings_probe.optimize_ui_settings", _probe)
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as client:
        opened = client.get("/api/settings")
        assert opened.status_code == 200
        assert calls == []
        page = client.get("/settings")
        assert page.status_code == 200
        assert calls == []

        empty = client.post("/api/settings/optimize", json={"targets": []})
        assert empty.status_code == 400
        assert "select" in empty.json()["detail"]
        assert calls == []

        denied = client.post(
            "/api/settings/optimize",
            json={"targets": [{"host_id": "a", "model_id": "nope"}], "apply": True},
        )
        assert denied.status_code == 200
        assert denied.json()["ok"] is False
        assert calls == []
        assert "max_tokens" not in load_ui_settings()["available"][0]

        probed = client.post(
            "/api/settings/optimize",
            json={
                "targets": [
                    {"host_id": "a", "model_id": "m-a"},
                    {"host_id": "b", "model_id": "m-b"},
                ],
                "apply": False,
            },
        )
        assert probed.status_code == 200
        body = probed.json()
        assert body["ok"] is True
        assert body["applied"] is False
        assert [row["max_tokens"] for row in body["targets"]] == [100, 200]
        assert [row["context_tokens"] for row in body["targets"]] == [11111, 22222]
        # Not saved, and the global seed is not rewritten from either probe.
        ui = load_ui_settings()
        assert ui["max_tokens"] == 4096
        assert ui["max_context_fraction"] == 0.25
        assert all("max_tokens" not in row for row in ui["available"])

        applied = client.post(
            "/api/settings/optimize",
            json={"targets": [{"host_id": "a", "model_id": "m-a"}], "apply": True},
        )
        assert applied.status_code == 200
        assert applied.json()["applied"] is True
        ui = load_ui_settings()
        by = {(row["host_id"], row["model_id"]): row for row in ui["available"]}
        assert by[("a", "m-a")]["max_tokens"] == 100
        assert by[("a", "m-a")]["context_tokens"] == 11111
        assert "max_tokens" not in by[("b", "m-b")]
        assert "context_tokens" not in by[("b", "m-b")]
        assert ui["max_tokens"] == 4096
        assert ui["context_tokens"] == 32768
        assert ui["max_context_fraction"] == 0.25
        assert ui["max_tool_rounds"] == 12

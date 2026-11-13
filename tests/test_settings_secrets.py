"""API keys never leave the server; omitted keys survive a round-trip save."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.settings import load_ui_settings, redact_secrets, save_ui_settings
from vulnforge.ui.app import create_app

SECRET = "sk-test-SECRET-do-not-echo"


def _isolate(tmp_path: Path, monkeypatch) -> Path:
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    return p


def _seed() -> None:
    save_ui_settings(
        {
            "hosts": [
                {"id": "a", "base_url": "http://127.0.0.1:9/v1", "api_key": SECRET},
                {"id": "b", "base_url": "http://127.0.0.1:10/v1", "api_key": ""},
            ]
        }
    )


def _key(host_id: str) -> str:
    return next(h for h in load_ui_settings()["hosts"] if h["id"] == host_id)["api_key"]


def test_redact_secrets_nested():
    out = redact_secrets(
        {"api_key": "x", "hosts": [{"id": "a", "api_key": SECRET}, {"id": "b", "api_key": "none"}]}
    )
    assert out == {
        "api_key_set": True,
        "hosts": [{"id": "a", "api_key_set": True}, {"id": "b", "api_key_set": False}],
    }
    assert SECRET not in json.dumps(out)


def test_settings_routes_never_echo_keys(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _seed()
    monkeypatch.setattr("vulnforge.settings_probe.list_model_ids", lambda *a, **k: ["m1"])
    monkeypatch.setattr(
        "vulnforge.settings_probe.verify_model_pair", lambda *a, **k: {"ok": True}
    )
    with TestClient(create_app(runs_root=tmp_path / "runs")) as client:
        got = client.get("/api/settings")
        assert got.status_code == 200
        assert SECRET not in got.text
        hosts = {h["id"]: h for h in got.json()["effective"]["hosts"]}
        assert hosts["a"]["api_key_set"] is True
        assert hosts["b"]["api_key_set"] is False

        # Round-trip exactly what the page received (no api_key fields).
        put = client.put("/api/settings", json={"hosts": got.json()["settings"]["hosts"]})
        assert put.status_code == 200, put.text
        assert SECRET not in put.text
        assert _key("a") == SECRET

        cat = client.post("/api/settings/hosts/a/catalog")
        assert cat.status_code == 200, cat.text
        assert "settings" in cat.json()
        assert SECRET not in cat.text
        ver = client.post("/api/settings/hosts/a/verify", json={"model_id": "m1"})
        assert ver.status_code == 200, ver.text
        assert "settings" in ver.json()
        assert SECRET not in ver.text

        exp = client.get("/api/dev-setup/export")
        assert exp.status_code == 200
        assert SECRET not in exp.text


def test_omitted_key_kept_explicit_key_sets_or_clears(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _seed()
    base = [
        {"id": "a", "base_url": "http://127.0.0.1:9/v1"},
        {"id": "b", "base_url": "http://127.0.0.1:10/v1"},
    ]
    save_ui_settings({"hosts": base})
    assert _key("a") == SECRET

    save_ui_settings({"hosts": [{**base[0], "api_key": "sk-new"}, base[1]]})
    assert _key("a") == "sk-new"

    save_ui_settings({"hosts": [{**base[0], "api_key": ""}, base[1]]})
    assert _key("a") == ""


def test_new_host_without_id_does_not_inherit_a_key(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _seed()
    save_ui_settings(
        {
            "hosts": [
                {"id": "a", "base_url": "http://127.0.0.1:9/v1"},
                {"base_url": "http://127.0.0.1:11/v1"},
            ]
        }
    )
    hosts = load_ui_settings()["hosts"]
    assert hosts[0]["api_key"] == SECRET
    assert hosts[1]["api_key"] == ""


def test_settings_page_never_renders_a_key(tmp_path, monkeypatch):
    """#202 redesign: the page HTML and its key input never carry a stored key."""
    import re

    from vulnforge.paths import PROJECT_ROOT

    _isolate(tmp_path, monkeypatch)
    _seed()
    with TestClient(create_app(runs_root=tmp_path / "runs")) as client:
        page = client.get("/settings")
        assert page.status_code == 200
        assert SECRET not in page.text
        html = page.text
        # Regrouped by job: Connections → Roles → Validation and MoA → Budgets → Sandbox.
        order = [
            'id="settings-connections"',
            'id="settings-roles"',
            'id="settings-validation"',
            'id="settings-budget"',
            'id="settings-poc-iterate"',
        ]
        assert [html.index(x) for x in order] == sorted(html.index(x) for x in order)
        assert "/static/pages/settings.css" in html
        assert "/static/pages/settings_helpers.js" in html
    js = (PROJECT_ROOT / "vulnforge/ui/static/settings.js").read_text(encoding="utf-8")
    # The key input is created empty and only ever read; nothing assigns host.api_key into it.
    assert not re.search(r"api_key\s*[^=!]=\s*host", js)
    assert "host?.api_key_set" in js
    assert not re.search(r"\.value\s*=\s*[^;]*api_key", js)

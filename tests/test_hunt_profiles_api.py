"""API tests for hunt profile Dev dashboard endpoints."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.hunt_profiles import (
    COLLECTION_FORMAT,
    ensure_collection,
    set_collection_root,
    reset_collection_root_override,
)
from vulnforge.ui.app import create_app


@pytest.fixture
def client(tmp_path: Path):
    root = tmp_path / "hunt_profiles"
    set_collection_root(root)
    ensure_collection()
    app = create_app(runs_root=tmp_path / "runs")
    with TestClient(app) as c:
        yield c
    reset_collection_root_override()


def test_list_and_get(client: TestClient):
    r = client.get("/api/hunt-profiles")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"]
    assert "active" in data["catalog"]
    assert "all" in data["catalog"]
    assert data["profiles"]
    pid = data["profiles"][0]["id"]
    g = client.get(f"/api/hunt-profiles/{pid}")
    assert g.status_code == 200
    assert g.json()["profile"]["body_md"]


def test_create_update_delete(client: TestClient):
    r = client.post(
        "/api/hunt-profiles",
        json={
            "id": "api-custom",
            "title": "API Custom",
            "active": True,
            "body_md": "# Hunt class: api-custom\n\nbody\n",
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["profile"]["id"] == "api-custom"

    u = client.put(
        "/api/hunt-profiles/api-custom",
        json={"active": False, "title": "Updated"},
    )
    assert u.status_code == 200
    assert u.json()["profile"]["active"] is False
    assert u.json()["profile"]["title"] == "Updated"

    d = client.delete("/api/hunt-profiles/api-custom")
    assert d.status_code == 200
    assert d.json()["deleted"] == "api-custom"


def test_export_import_via_dev_setup(client: TestClient):
    """Hunt collection round-trips through the single Dev setup pack."""
    client.post(
        "/api/hunt-profiles",
        json={
            "id": "export-me",
            "active": True,
            "body_md": "# export-me\n\nhello export\n",
        },
    )
    exp = client.get("/api/dev-setup/export")
    assert exp.status_code == 200
    blob = exp.json()
    hunts = blob["sections"]["hunt_profiles"]
    assert hunts["format"] == COLLECTION_FORMAT
    assert any(p["id"] == "export-me" for p in hunts["profiles"])

    client.delete("/api/hunt-profiles/export-me")
    imp = client.post(
        "/api/dev-setup/import",
        json={"data": blob, "mode": "merge", "include": ["hunt_profiles"]},
    )
    assert imp.status_code == 200
    out = imp.json()["sections"]
    assert set(out) == {"hunt_profiles"}
    assert "export-me" in out["hunt_profiles"]["profiles"]
    assert client.get("/api/hunt-profiles/export-me").status_code == 200


def test_legacy_collection_routes_removed(client: TestClient):
    assert client.get("/api/hunt-profiles/export").status_code in (404, 405)
    assert client.post("/api/hunt-profiles/import", json={"data": {}}).status_code in (404, 405)
    assert client.get("/api/recon-agents/export").status_code in (404, 405)
    assert client.post("/api/recon-agents/import", json={"data": {}}).status_code in (404, 405)


def test_dev_page(client: TestClient):
    r = client.get("/dev")
    assert r.status_code == 200
    assert "Hunt skills" in r.text

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


def test_export_import(client: TestClient):
    client.post(
        "/api/hunt-profiles",
        json={
            "id": "export-me",
            "active": True,
            "body_md": "# export-me\n\nhello export\n",
        },
    )
    exp = client.get("/api/hunt-profiles/export")
    assert exp.status_code == 200
    blob = exp.json()
    assert blob["format"] == COLLECTION_FORMAT
    assert any(p["id"] == "export-me" for p in blob["profiles"])

    client.delete("/api/hunt-profiles/export-me")
    imp = client.post(
        "/api/hunt-profiles/import",
        json={"data": blob, "mode": "merge"},
    )
    assert imp.status_code == 200
    assert "export-me" in imp.json()["profiles"]


def test_dev_page(client: TestClient):
    r = client.get("/dev")
    assert r.status_code == 200
    assert "Hunt profiles" in r.text

"""Regression: nested request bodies must not break OpenAPI schema generation."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.ui.app import create_app


def test_openapi_schema_generates(tmp_path: Path):
    app = create_app(runs_root=tmp_path / "runs")
    schema = app.openapi()
    assert schema.get("openapi")
    paths = schema.get("paths") or {}
    assert "/api/runs/{target_id}/{run_id}/tool-gaps" in paths
    assert "/api/tool-gaps/analyze" in paths
    assert "/api/skill-generator" in paths


def test_openapi_json_docs_and_redoc(tmp_path: Path):
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)

    spec = client.get("/openapi.json")
    assert spec.status_code == 200, spec.text
    body = spec.json()
    assert body.get("openapi")
    assert body.get("paths")

    docs = client.get("/docs")
    assert docs.status_code == 200, docs.text
    assert "swagger" in docs.text.lower()

    redoc = client.get("/redoc")
    assert redoc.status_code == 200, redoc.text
    assert "redoc" in redoc.text.lower()

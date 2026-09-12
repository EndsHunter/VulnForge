"""Benchmark library store + API (ticket 2 prove bar)."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient

from vulnforge.benchmarks import (
    get_def,
    seed_from_ground_truth,
    update_def,
)
from vulnforge.ui.app import create_app


def test_list_includes_seeded_toy_sqli_hunt():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        r = client.get("/api/benchmarks")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"]
        rows = data["benchmarks"]
        ids = [b["id"] for b in rows]
        assert "toy_sqli" in ids
        toy = next(b for b in rows if b["id"] == "toy_sqli")
        assert "hunt" in toy["types"]
        assert toy["types"] == ["hunt"]
        assert "mono_synth" in ids


def test_put_bumps_head_version_and_freezes_old_snapshot():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        head = client.get("/api/benchmarks/toy_sqli")
        assert head.status_code == 200, head.text
        before = head.json()["benchmark"]
        v1 = int(before["head_version"])
        frozen = client.get(f"/api/benchmarks/toy_sqli/versions/{v1}")
        assert frozen.status_code == 200, frozen.text
        v1_payload = deepcopy(frozen.json()["version"])
        old_name = v1_payload["name"]
        old_target = v1_payload["target_ref"]

        put = client.put(
            "/api/benchmarks/toy_sqli",
            json={"name": "Renamed toy SQLi", "target_ref": "fixtures/elsewhere"},
        )
        assert put.status_code == 200, put.text
        after = put.json()["benchmark"]
        assert after["head_version"] == v1 + 1
        assert after["name"] == "Renamed toy SQLi"
        assert after["target_ref"] == "fixtures/elsewhere"

        still = client.get(f"/api/benchmarks/toy_sqli/versions/{v1}")
        assert still.status_code == 200
        still_payload = still.json()["version"]
        assert still_payload["name"] == old_name
        assert still_payload["target_ref"] == old_target
        assert still_payload["version"] == v1
        # Prior frozen fields must match the pre-PUT snapshot (immutability).
        assert still_payload["name"] == v1_payload["name"]
        assert still_payload["types"] == v1_payload["types"]
        assert still_payload["target_ref"] == v1_payload["target_ref"]
        assert still_payload["oracle_ref"] == v1_payload["oracle_ref"]
        assert still_payload["oracle"] == v1_payload["oracle"]
        assert still_payload["oracle_hash"] == v1_payload["oracle_hash"]

        # Mutate head again — v1 payload must stay unchanged.
        put2 = client.put(
            "/api/benchmarks/toy_sqli",
            json={"name": "Third name", "tags": ["mutated"]},
        )
        assert put2.status_code == 200
        assert put2.json()["benchmark"]["head_version"] == v1 + 2
        still2 = client.get(f"/api/benchmarks/toy_sqli/versions/{v1}").json()["version"]
        assert still2["name"] == v1_payload["name"]
        assert still2["target_ref"] == v1_payload["target_ref"]
        assert still2["oracle"] == v1_payload["oracle"]
        assert still2["oracle_hash"] == v1_payload["oracle_hash"]
        assert still2["config_overlay"] == v1_payload["config_overlay"]
        assert still2["tags"] == v1_payload["tags"]


def test_seed_skip_if_exists_does_not_clobber():
    # Autouse already seeded; operator edit then re-seed must keep the edit.
    update_def("toy_sqli", name="operator edit")
    assert get_def("toy_sqli")["name"] == "operator edit"
    result = seed_from_ground_truth(missing_only=True)
    assert "toy_sqli" in result["skipped"]
    assert "toy_sqli" not in result["seeded"]
    assert get_def("toy_sqli")["name"] == "operator edit"


def test_create_update_delete_and_versions_list():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        created = client.post(
            "/api/benchmarks",
            json={
                "id": "custom_hunt",
                "name": "Custom hunt",
                "types": ["hunt"],
                "target_ref": "fixtures/toy_sqli",
                "tags": ["custom"],
                "oracle": {
                    "type": "hunt",
                    "findings": [
                        {
                            "id": "c1",
                            "class": "injection",
                            "sink_path": "app.py",
                            "sink_symbol": "search_users",
                            "match": {"path_suffix": "app.py", "symbol": "search_users"},
                        }
                    ],
                },
            },
        )
        assert created.status_code == 200, created.text
        bench = created.json()["benchmark"]
        assert bench["id"] == "custom_hunt"
        assert bench["head_version"] == 1
        assert bench["oracle"]["findings"]

        versions = client.get("/api/benchmarks/custom_hunt/versions")
        assert versions.status_code == 200
        vers = versions.json()["versions"]
        assert len(vers) == 1
        assert vers[0]["version"] == 1

        deleted = client.delete("/api/benchmarks/custom_hunt")
        assert deleted.status_code == 200
        assert deleted.json()["deleted"] == "custom_hunt"
        assert client.get("/api/benchmarks/custom_hunt").status_code == 404


def test_seed_endpoint_idempotent():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        r = client.post("/api/benchmarks/seed")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"]
        assert "toy_sqli" in body["skipped"]
        assert body["seeded"] == []


def test_library_page_lists_hook():
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        page = client.get("/benchmarks/library")
        assert page.status_code == 200
        assert 'id="bench-library-table"' in page.text
        assert "/api/benchmarks" in page.text


def test_write_version_refuses_overwrite():
    """FS immutability: existing version file must not be overwritten."""
    from vulnforge.benchmarks import store as bench_store

    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        r = client.get("/api/benchmarks/toy_sqli/versions/1")
        assert r.status_code == 200, r.text
        snap = r.json()["version"]
    try:
        bench_store._write_version(snap)
        raise AssertionError("expected BenchmarkLibraryError")
    except bench_store.BenchmarkLibraryError as e:
        assert "immutable" in str(e).lower() or "exists" in str(e).lower()

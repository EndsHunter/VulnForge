"""Seed provenance: status, diff, restore for hunt profiles."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.hunt_profiles import (
    ensure_collection,
    get_body,
    get_profile,
    list_profiles,
    reset_collection_root_override,
    restore_seed_body,
    save_profile,
    seed_body_path,
    seed_diff,
    seed_status,
    set_collection_root,
)
from vulnforge.hunt_profiles.store import SEED_PROMPTS_DIR
from vulnforge.ui.app import create_app


@pytest.fixture
def collection(tmp_path: Path):
    root = tmp_path / "hunt_profiles"
    set_collection_root(root)
    ensure_collection()
    yield root
    reset_collection_root_override()


def test_seed_body_path_for_package_class(collection: Path):
    path = seed_body_path("injection")
    assert path is not None
    assert path.is_file()
    assert path.parent == SEED_PROMPTS_DIR.resolve()
    assert seed_body_path("no-such-class-zzzz") is None


def test_seed_status_matches_package(collection: Path):
    assert seed_status("injection") == "seed"
    # list/get include seed_status
    profiles = list_profiles(include_body=False)
    inj = next(p for p in profiles if p["id"] == "injection")
    assert inj["seed_status"] == "seed"
    assert inj["has_seed"] is True

    detail = get_profile("injection", include_body=True)
    assert detail["seed_status"] == "seed"
    assert detail["has_seed"] is True


def test_modified_seed_when_body_differs(collection: Path):
    original = get_body("injection")
    save_profile(
        "injection",
        body_md=original + "\n\n<!-- operator edit -->\n",
    )
    # save_profile flips source to custom when editing seed
    row = get_profile("injection", include_body=False)
    assert row["source"] == "custom"
    # But seed_status still reports modified_seed because package file exists
    assert seed_status("injection") == "modified_seed"
    assert row["seed_status"] == "modified_seed"
    assert row["has_seed"] is True


def test_custom_without_package_seed(collection: Path):
    save_profile(
        "my-totally-custom",
        body_md="# Hunt class: my-totally-custom\n\n## Mission\n\nx\n",
        source="custom",
        create=True,
    )
    assert seed_body_path("my-totally-custom") is None
    assert seed_status("my-totally-custom") == "custom"
    row = get_profile("my-totally-custom", include_body=False)
    assert row["seed_status"] == "custom"
    assert row["has_seed"] is False


def test_generated_source_status(collection: Path):
    save_profile(
        "gen-skill",
        body_md="# Hunt class: gen-skill\n\n## Mission\n\nx\n",
        source="generated",
        create=True,
    )
    assert seed_status("gen-skill") == "generated"


def test_restore_seed_body(collection: Path):
    original = get_body("injection")
    save_profile(
        "injection",
        body_md=original + "\n\n<!-- mutated -->\n",
    )
    assert seed_status("injection") == "modified_seed"

    restored = restore_seed_body("injection")
    assert restored["seed_status"] == "seed"
    assert restored["source"] == "seed"
    assert get_body("injection") == (SEED_PROMPTS_DIR / "injection.md").read_text(
        encoding="utf-8"
    )


def test_seed_diff(collection: Path):
    d = seed_diff("injection")
    assert d["has_seed"] is True
    assert d["identical"] is True
    assert d["seed_status"] == "seed"
    assert d["seed_body"]
    assert d["current_body"] == d["seed_body"]

    save_profile("injection", body_md=get_body("injection") + "\n# edit\n")
    d2 = seed_diff("injection")
    assert d2["identical"] is False
    assert d2["seed_status"] == "modified_seed"
    assert d2["current_body"] != d2["seed_body"]


def test_api_seed_endpoints(tmp_path: Path):
    set_collection_root(tmp_path / "hunt_profiles")
    ensure_collection()
    app = create_app(runs_root=tmp_path / "runs")
    try:
        with TestClient(app) as client:
            listing = client.get("/api/hunt-profiles")
            assert listing.status_code == 200
            inj = next(p for p in listing.json()["profiles"] if p["id"] == "injection")
            assert inj["seed_status"] == "seed"

            # mutate
            body = client.get("/api/hunt-profiles/injection").json()["profile"]["body_md"]
            client.put(
                "/api/hunt-profiles/injection",
                json={"body_md": body + "\n\n<!-- api edit -->\n"},
            )
            g = client.get("/api/hunt-profiles/injection")
            assert g.json()["profile"]["seed_status"] == "modified_seed"

            diff = client.get("/api/hunt-profiles/injection/seed-diff")
            assert diff.status_code == 200
            assert diff.json()["identical"] is False
            assert diff.json()["has_seed"] is True

            r = client.post("/api/hunt-profiles/injection/restore-seed")
            assert r.status_code == 200, r.text
            assert r.json()["profile"]["seed_status"] == "seed"
            assert r.json()["profile"]["source"] == "seed"
    finally:
        reset_collection_root_override()

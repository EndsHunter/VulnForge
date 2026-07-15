"""Hunt profile collection store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.hunt_profiles import (
    COLLECTION_FORMAT,
    HuntProfileError,
    active_class_ids,
    all_class_ids,
    catalog_for_ui,
    delete_profile,
    ensure_collection,
    export_collection,
    get_body,
    get_profile,
    import_collection,
    list_profiles,
    normalize_class,
    reseed_from_package,
    reset_collection_root_override,
    save_profile,
    set_collection_root,
)


@pytest.fixture
def hunt_root(tmp_path: Path):
    root = tmp_path / "hunt_profiles"
    set_collection_root(root)
    yield root
    reset_collection_root_override()


def test_seed_once_creates_active_and_all(hunt_root: Path):
    coll = ensure_collection()
    assert coll["format"] == COLLECTION_FORMAT
    assert (hunt_root / "collection.json").is_file()
    assert (hunt_root / "bodies" / "injection.md").is_file()
    ids = all_class_ids()
    assert "injection" in ids
    assert "graphql" in ids
    active = active_class_ids()
    assert "injection" in active
    assert "wildcard" in active
    # Domain-style packs start inactive
    assert "graphql" not in [p["id"] for p in coll["profiles"] if p["active"]]
    # Second ensure does not re-seed / wipe custom
    save_profile("injection", body_md="# Hunt class: injection\n\ncustom body\n")
    ensure_collection()
    assert "custom body" in get_body("injection")


def test_catalog_for_ui_shape(hunt_root: Path):
    cat = catalog_for_ui()
    assert set(cat.keys()) == {"all", "active"}
    assert "default" not in cat
    assert "domain" not in cat
    assert set(cat["active"]).issubset(set(cat["all"]))
    assert cat["active"]


def test_save_create_update_delete(hunt_root: Path):
    ensure_collection()
    p = save_profile(
        "my-custom",
        body_md="# Hunt class: my-custom\n\nLook for widgets.\n",
        title="My Custom",
        description="widget abuse",
        active=True,
        create=True,
    )
    assert p["id"] == "my-custom"
    assert p["active"] is True
    assert "widgets" in p["body_md"]
    assert "my-custom" in active_class_ids()

    p2 = save_profile("my-custom", active=False, title="Updated")
    assert p2["active"] is False
    assert p2["title"] == "Updated"

    delete_profile("my-custom")
    with pytest.raises(HuntProfileError):
        get_profile("my-custom")
    assert "my-custom" not in all_class_ids()


def test_cannot_delete_last_profile(hunt_root: Path):
    ensure_collection()
    # Replace with single profile
    import_collection(
        {
            "format": COLLECTION_FORMAT,
            "profiles": [
                {
                    "id": "only-one",
                    "active": True,
                    "body_md": "# only\n\nbody\n",
                }
            ],
        },
        mode="replace",
    )
    with pytest.raises(HuntProfileError, match="last"):
        delete_profile("only-one")


def test_invalid_id(hunt_root: Path):
    ensure_collection()
    with pytest.raises(HuntProfileError):
        save_profile("Bad_ID", body_md="x", create=True)
    with pytest.raises(HuntProfileError):
        save_profile("", body_md="x", create=True)


def test_export_import_roundtrip(hunt_root: Path):
    ensure_collection()
    save_profile(
        "exported-custom",
        body_md="# exported\n\nhello\n",
        active=True,
        create=True,
    )
    blob = export_collection()
    assert blob["format"] == COLLECTION_FORMAT
    assert any(p["id"] == "exported-custom" for p in blob["profiles"])
    assert any(
        p["id"] == "exported-custom" and "hello" in p["body_md"] for p in blob["profiles"]
    )

    delete_profile("exported-custom")
    assert "exported-custom" not in all_class_ids()

    result = import_collection(blob, mode="merge")
    assert result["ok"]
    assert "exported-custom" in all_class_ids()
    assert "hello" in get_body("exported-custom")


def test_import_replace(hunt_root: Path):
    ensure_collection()
    n_before = len(all_class_ids())
    assert n_before > 2
    import_collection(
        {
            "format": COLLECTION_FORMAT,
            "profiles": [
                {"id": "alpha", "active": True, "body_md": "# a\n\nx\n"},
                {"id": "beta", "active": False, "body_md": "# b\n\ny\n"},
            ],
        },
        mode="replace",
    )
    assert set(all_class_ids()) == {"alpha", "beta"}
    assert active_class_ids() == ["alpha"]


def test_normalize_class_aliases_and_unknown(hunt_root: Path):
    ensure_collection()
    assert normalize_class("sqli") == "injection"
    assert normalize_class("gql") == "graphql"
    assert normalize_class("totally-unknown-xyz") == "wildcard"
    assert normalize_class(None) == "wildcard"


def test_empty_body_rejected(hunt_root: Path):
    ensure_collection()
    with pytest.raises(HuntProfileError):
        save_profile("empty-body", body_md="   \n", create=True)


def test_reseed_from_package(hunt_root: Path):
    ensure_collection()
    save_profile("temp-x", body_md="# t\n\nbody\n", create=True)
    assert "temp-x" in all_class_ids()
    reseed_from_package()
    assert "temp-x" not in all_class_ids()
    assert "injection" in all_class_ids()


def test_list_profiles_include_body(hunt_root: Path):
    ensure_collection()
    rows = list_profiles(include_body=True)
    assert rows
    assert any(r.get("body_md") and "Mission" in r["body_md"] for r in rows)

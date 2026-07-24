"""Tests for dynamic hunt skill generation (Workstream D)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnforge.hunt_profiles import (
    get_profile,
    reset_collection_root_override,
    save_profile,
    set_collection_root,
    ensure_collection,
)
from vulnforge.hunt_profiles.generate import (
    GenerateSkillError,
    allocate_free_id,
    generate_hunt_skill,
    parse_skill_response,
    required_sections_missing,
    save_generated_profile,
    slugify_profile_id,
    validate_skill_payload,
)
from vulnforge.llm import FakeLLMClient, LLMResult, ResponseClass
from vulnforge.packet import pack_hunt


VALID_BODY = """---
name: jwt-confusion
description: >-
  Forge tokens via alg=none or key confusion. Use when verify paths trust
  alg/kid from the token. Prefer evidence from the target tree over assumptions.
---

# Hunt class: jwt-confusion

## Principles

- Prefer evidence over pre-training.
- Be certain before filing.
- Provide path:line evidence.
- Correctness over completeness.
- Honest submit_none when nothing solid.

## Mission

Prove an unauth or low-priv caller can forge tokens via alg=none or key confusion.

## When to use

- JWT verify paths that trust `alg` from the token
- `kid` path traversal into key loaders

## When not to use / Scope

- Prefer `cryptography` for general weak crypto without JWT surfaces
- Prefer `web-protocol-auth` for OAuth/session flows without JWT verify bugs

## Decision tree

1. Inventory JWT verify and key-load call sites.
2. Check whether `alg` and `kid` are constrained server-side.
3. If all verify paths pin algorithm + key → `submit_none`.

## Rules quick reference

| Rule | Summary |
|------|---------|
| Pin algorithm | Server must not trust token `alg` |
| Constrain kid | No path traversal or open key URL |
| Evidence | Cite verify site and attacker token shape |

## Focus

- JWT verify paths that trust `alg` from the token
- `kid` path traversal into key loaders

## Hunt workflow

1. Inventory JWT verify and key-load call sites.
2. Check whether `alg` and `kid` are constrained server-side.
3. If all verify paths pin algorithm + key → `submit_none`.
4. Otherwise write_evidence and submit_candidate.

## Stack cues

```
jwt|jose|jwk|alg|kid|HS256|RS256
```

## Required evidence

- Verify call site citation
- Attacker token shape and impact

## False positives

- Library that hard-pins algorithm and key source

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| "JWTs are bad" without a verify bug | Not a finding |
| Dual-file same path as cryptography without distinct impact | Noise |

## Submit checklist

1. `write_evidence` with token shape and verify site.
2. `submit_candidate` with `weakness_class: jwt-confusion`.
3. Or honest `submit_none`.
"""


def _skill_json(**overrides) -> str:
    data = {
        "id": "jwt-confusion",
        "title": "JWT confusion",
        "description": "Alg/kid JWT issues",
        "body_md": VALID_BODY,
        "tags": ["auth", "jwt"],
        "cwe": ["CWE-347"],
        "angle_ids": ["cryptography"],
        "sink_families": ["crypto"],
    }
    data.update(overrides)
    return json.dumps(data)


@pytest.fixture
def profiles_root(tmp_path: Path):
    root = tmp_path / "hunt_profiles"
    set_collection_root(root)
    ensure_collection()
    yield root
    reset_collection_root_override()


def test_slugify_and_sections():
    assert slugify_profile_id("JWT Confusion!") == "jwt-confusion"
    assert required_sections_missing(VALID_BODY) == []
    # Cloudflare-required sections (Mission *or* Principles; Method/workflow; …)
    thin = "# x\n## Method\n## Submit\n"
    missing = required_sections_missing(thin)
    assert "Mission or Principles" in missing
    assert "Rules" in missing
    assert "Anti-patterns" in missing
    # Principles alone satisfies Mission-or-Principles
    principles_only = (
        "## Principles\n- be certain\n## Hunt workflow\n1. x\n"
        "## Rules quick reference\n| a | b |\n## Anti-patterns\n| a | b |\n## Submit\n"
    )
    assert required_sections_missing(principles_only) == []
    assert "Method or Hunt workflow" in required_sections_missing(
        "**Mission:** x\n## Principles\n## Rules quick reference\n| a | b |\n"
        "## Anti-patterns\n| a | b |\n## Submit\n"
    )
    assert "Submit" in required_sections_missing(
        "**Mission:** x\n## Principles\n## Method\n## Rules quick reference\n"
        "| a | b |\n## Anti-patterns\n| a | b |\n"
    )


def test_validate_and_parse_skill():
    skill = parse_skill_response(_skill_json())
    assert skill["id"] == "jwt-confusion"
    assert skill["title"] == "JWT confusion"
    assert "Mission" not in required_sections_missing(skill["body_md"])
    assert skill["tags"] == ["auth", "jwt"]

    fenced = "```json\n" + _skill_json() + "\n```"
    skill2 = parse_skill_response(fenced)
    assert skill2["id"] == "jwt-confusion"

    with pytest.raises(GenerateSkillError):
        parse_skill_response("")
    with pytest.raises(GenerateSkillError):
        validate_skill_payload({"id": "x", "body_md": "no sections here"})


def test_allocate_free_id_collision(profiles_root: Path):
    save_profile(
        "jwt-confusion",
        body_md=VALID_BODY,
        title="Existing",
        create=True,
        source="custom",
    )
    free = allocate_free_id("jwt-confusion")
    assert free == "jwt-confusion-2"
    assert free != "jwt-confusion"


def test_generate_hunt_skill_fake(profiles_root: Path):
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=_skill_json(),
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )
    cfg = {"llm": {"fake": True, "temperature_recon": 0.1}}
    skill = generate_hunt_skill(
        cfg,
        brief="Hunt JWT alg confusion in our gateway",
        suggested_id="jwt-confusion",
        client=client,
    )
    assert skill["id"] == "jwt-confusion"
    assert "## Mission" in skill["body_md"] or "**Mission:**" in skill["body_md"]
    assert "## Principles" in skill["body_md"]
    assert "## Rules quick reference" in skill["body_md"]
    assert "## Anti-patterns" in skill["body_md"]
    assert (
        "## Method" in skill["body_md"]
        or "## Hunt workflow" in skill["body_md"]
    )
    assert "## Submit" in skill["body_md"]
    assert skill["model_id"] in ("fake", "fake-model")

    profile = save_generated_profile(skill, active=False)
    assert profile["id"] == "jwt-confusion"
    assert profile["source"] == "generated"
    assert profile["active"] is False
    loaded = get_profile("jwt-confusion")
    assert "jwt" in loaded["body_md"].lower()


def test_save_generated_profile_stores_origin(profiles_root: Path):
    skill = {
        "id": "origin-skill",
        "title": "Origin skill",
        "description": "provenance test",
        "body_md": VALID_BODY.replace("jwt-confusion", "origin-skill"),
        "tags": ["test"],
        "cwe": [],
        "angle_ids": [],
        "sink_families": [],
    }
    profile = save_generated_profile(
        skill,
        active=False,
        origin_target_id="demo-target",
        origin_run_id="run-003",
    )
    assert profile["id"] == "origin-skill"
    assert profile["source"] == "generated"
    assert profile["origin_target_id"] == "demo-target"
    assert profile["origin_run_id"] == "run-003"
    assert profile["created_at"]
    loaded = get_profile("origin-skill", include_body=False)
    assert loaded["origin_target_id"] == "demo-target"
    assert loaded["origin_run_id"] == "run-003"
    assert loaded["created_at"] == profile["created_at"]


def test_origin_from_run_dir():
    from vulnforge.hunt_profiles.generate import origin_from_run_dir

    t, r = origin_from_run_dir("/tmp/runs/my-target/run-001")
    assert t == "my-target"
    assert r == "run-001"
    t2, r2 = origin_from_run_dir("/tmp/runs/my-target/run-001/evidence")
    assert t2 == "my-target"
    assert r2 == "run-001"
    # Fallback when no "runs" segment but last component looks like run-N
    t3, r3 = origin_from_run_dir("/data/campaigns/acme/run-042")
    assert t3 == "acme"
    assert r3 == "run-042"
    assert origin_from_run_dir("/tmp/not-a-run") == (None, None)
    assert origin_from_run_dir(None) == (None, None)


def test_generate_records_usage(tmp_path: Path, profiles_root: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    client = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=_skill_json(id="usage-skill"),
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )
    skill = generate_hunt_skill(
        {"llm": {"fake": True}},
        brief="usage test brief with enough detail",
        client=client,
        run_dir=run_dir,
        task_id=7,
    )
    assert skill.get("usage")
    assert int(skill["usage"].get("llm_calls") or 0) >= 1
    summary = run_dir / "llm_usage_summary.json"
    assert summary.is_file()
    data = json.loads(summary.read_text(encoding="utf-8"))
    assert int(data.get("llm_calls") or 0) >= 1


def test_stage_generate_skill_enqueue(tmp_path: Path, profiles_root: Path, toy_sqli: Path):
    from vulnforge.db import Database
    from vulnforge.stages import generate_skill as stage

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    tid = db.enqueue_task(
        "generate_skill",
        {
            "brief": "Custom hunt for second-order SQLi via report export",
            "path_hints": ["app.py"],
            "area": "app",
            "enqueue_hunts": True,
            "activate": False,
            "suggested_id": "second-order-sqli",
        },
    )
    task = db.lease_next_task("w", 60)
    assert task and task.id == tid

    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content=_skill_json(
                        id="second-order-sqli",
                        body_md=VALID_BODY.replace("jwt-confusion", "second-order-sqli"),
                        title="Second-order SQLi",
                    ),
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                )
            ],
        },
        "run": {},
        "packet": {},
    }
    result = stage.run(task, db, run_dir, cfg)
    assert result["status"] == "succeeded", result
    assert result["profile_id"] == "second-order-sqli"
    assert result["hunt_enqueued"] == 1
    assert result["hunt_task_ids"]
    hunts = [t for t in db.list_tasks() if t.kind == "hunt"]
    assert len(hunts) >= 1
    hp = hunts[0].payload
    assert hp.get("class") == "second-order-sqli"
    assert hp.get("class_body_override")
    assert get_profile("second-order-sqli")["source"] == "generated"
    db.close()


def test_dispatch_generate_skill(tmp_path: Path, profiles_root: Path, toy_sqli: Path):
    from vulnforge.cli import dispatch_task
    from vulnforge.db import Database

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    tid = db.enqueue_task(
        "generate_skill",
        {"brief": "Hunt for mass-assignment on user update", "enqueue_hunts": False},
    )
    task = db.lease_next_task("w", 60)
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [
                LLMResult(
                    ok=True,
                    classification=ResponseClass.OK,
                    content=_skill_json(id="mass-assign"),
                    tool_calls=[],
                    raw=None,
                    model_id="fake",
                )
            ],
        }
    }
    result = dispatch_task(task, db, run_dir, cfg)
    assert result["status"] == "succeeded"
    assert result["profile_id"] == "mass-assign"
    db.close()


def test_pack_hunt_class_body_override(tmp_path: Path, profiles_root: Path):
    from vulnforge.paths import system_prompts_root

    prompts = system_prompts_root()
    override = "# Hunt class: inline\n\n**Mission:** x\n\n## Method\n\n1. y\n\n## Submit\n\nz\n"
    pkt = pack_hunt(
        {"packet": {"max_architecture_chars": 500}},
        prompts,
        {
            "area": "app",
            "class": "does-not-exist-class",
            "path_hints": ["a.py"],
            "class_body_override": override,
        },
        architecture="arch",
        known_keys=[],
        codemap_notes=[],
    )
    assert "Hunt class: inline" in pkt.user
    assert "**Mission:** x" in pkt.user


def test_api_generate(profiles_root: Path, tmp_path: Path, monkeypatch):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    client_llm = FakeLLMClient(
        responses=[
            LLMResult(
                ok=True,
                classification=ResponseClass.OK,
                content=_skill_json(id="api-gen-skill"),
                tool_calls=[],
                raw=None,
                model_id="fake",
            )
        ]
    )

    def _fake_make(cfg):
        return client_llm

    monkeypatch.setattr(
        "vulnforge.hunt_profiles.generate.make_client",
        _fake_make,
    )
    app = create_app(runs_root=tmp_path / "runs")
    app.state.config = {"llm": {"fake": True}}
    with TestClient(app) as c:
        r = c.post(
            "/api/hunt-profiles/generate",
            json={
                "brief": "Generate a skill for webhook SSRF",
                "suggested_id": "api-gen-skill",
                "activate": False,
                "save": True,
            },
        )
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"]
        assert data["saved"] is True
        assert data["skill"]["id"] == "api-gen-skill"
        assert data["profile"]["source"] == "generated"

        # page mentions generate button
        page = c.get("/dev")
        assert page.status_code == 200
        assert "Generate from description" in page.text

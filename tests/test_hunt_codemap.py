"""Hunt stage + packet integration with function-level codemap."""

from __future__ import annotations

import json
from pathlib import Path

from vulnforge.db import Database
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.packet import pack_hunt
from vulnforge.paths import system_prompts_root
from vulnforge.stages import hunt
from vulnforge.tools.codemap import build_codemap
from vulnforge.transcript import load_transcript

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MONO_SYNTH = FIXTURES / "mono_synth"
TOY_SQLI = FIXTURES / "toy_sqli"
TOY_SQLI_APP = TOY_SQLI / "app.py"

_CODEMAP_CFG = {
    "codemap": {
        "symbol_backend": "heuristic",
        "symbols_enabled": True,
        "packet_max_symbols": 40,
        "packet_max_files": 20,
        "packet_max_modules": 8,
    },
    "packet": {"max_codemap_chars": 8000},
    "run": {"ignore_globs": [], "profile": "code_static"},
    "tools": {},
}


def _fake_none(reason: str = "reviewed area, no new finding") -> LLMResult:
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[
            {
                "id": "1",
                "name": "submit_none",
                "arguments": {"reason": reason},
            }
        ],
        raw=None,
        model_id="fake",
    )


def _fake_query_then_none(path: str) -> list[LLMResult]:
    return [
        LLMResult(
            ok=True,
            classification=ResponseClass.OK,
            content="",
            tool_calls=[
                {
                    "id": "q1",
                    "name": "query_codemap",
                    "arguments": {
                        "path": path,
                        "include_symbols": True,
                        "max_symbols": 30,
                    },
                }
            ],
            raw=None,
            model_id="fake",
        ),
        _fake_none(f"queried codemap under {path}; no finding"),
    ]


def _setup_run(
    tmp_path: Path,
    target: Path,
    *,
    path_hints: list[str],
    area: str = "app",
    hunt_class: str = "injection",
) -> tuple[Path, Database, object, dict]:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    cfg = {
        **_CODEMAP_CFG,
        "llm": {
            "fake": True,
            "fake_responses": [],
            "max_tool_rounds": 6,
        },
    }
    db.insert_run(
        "r1",
        str(target.resolve()),
        "code_static",
        "pin",
        cfg,
    )
    cm = build_codemap(target, cfg=cfg)
    db.set_codemap(cm, source="mechanical")
    db.set_architecture(
        {
            "summary": "fixture target for codemap hunt tests",
            "components": [
                {"name": area, "path_hints": path_hints},
            ],
            "hunt_focus": [
                {"area": area, "class": hunt_class, "path_hints": path_hints},
            ],
        }
    )
    tid = db.enqueue_task(
        "hunt",
        {
            "area": area,
            "class": hunt_class,
            "path_hints": path_hints,
            # Avoid depending on hunt profile collection for packet body
            "class_body_override": (
                f"# {hunt_class}\nLook for issues in the codemap area slice.\n"
            ),
        },
    )
    task = db.lease_next_task("w", 60)
    assert task is not None and task.id == tid
    return run_dir, db, task, cfg


def test_pack_hunt_area_slice_includes_auth_symbols_not_api():
    """Hunt packet for auth must surface auth functions, not api sinks."""
    cm = build_codemap(MONO_SYNTH, cfg=_CODEMAP_CFG)
    assert any(
        s.get("name") == "issue_token" for s in (cm.get("symbols") or [])
    ), "fixture must extract issue_token"
    assert any(
        s.get("name") == "search_users" for s in (cm.get("symbols") or [])
    ), "fixture must extract search_users"

    payload = {
        "area": "auth",
        "class": "access-control",
        "path_hints": ["packages/auth"],
        "class_body_override": "# access-control\nAuth boundary review.\n",
    }
    pkt = pack_hunt(
        _CODEMAP_CFG,
        system_prompts_root(),
        payload,
        architecture='{"summary":"mono","area":"auth"}',
        known_keys=[],
        codemap_notes=[],
        codemap=cm,
    )
    user = pkt.user
    assert "Codemap (area slice" in user
    assert "issue_token" in user or "verify_token" in user
    # Sibling package symbols must not appear in the auth slice
    assert "search_users" not in user
    assert "run_export" not in user
    assert "packages/auth" in user


def test_pack_hunt_api_slice_has_injection_sinks():
    cm = build_codemap(MONO_SYNTH, cfg=_CODEMAP_CFG)
    payload = {
        "area": "api",
        "class": "injection",
        "path_hints": ["packages/api"],
        "class_body_override": "# injection\nSQLi review.\n",
    }
    pkt = pack_hunt(
        _CODEMAP_CFG,
        system_prompts_root(),
        payload,
        architecture='{"summary":"mono","area":"api"}',
        known_keys=[],
        codemap_notes=[],
        codemap=cm,
    )
    user = pkt.user
    assert "search_users" in user or "get_item" in user
    assert "issue_token" not in user
    assert "packages/api" in user


def test_hunt_run_toy_sqli_packet_has_search_users(tmp_path: Path):
    """Full hunt stage: packet embeds function-level slice for single-file target."""
    run_dir, db, task, cfg = _setup_run(
        tmp_path,
        TOY_SQLI_APP if TOY_SQLI_APP.is_file() else TOY_SQLI,
        path_hints=["app.py"],
        area="app",
        hunt_class="injection",
    )
    # Target for toy is usually the directory in other tests; use parent if file
    # Re-point: _setup_run used file path — rebuild codemap for that target already done
    cm = db.get_codemap()
    assert cm and (cm.get("symbols") or []), "codemap must have symbols for toy"
    names = {s.get("name") for s in cm["symbols"] if isinstance(s, dict)}
    assert "search_users" in names

    cfg["llm"]["fake_responses"] = [_fake_none("no issue")]
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    assert r.get("none_found")

    tr = load_transcript(run_dir, task.id)
    assert tr, "transcript should be saved"
    user_msgs = [
        m.get("content") or ""
        for m in (tr.get("messages") or [])
        if m.get("role") == "user"
    ]
    blob = "\n".join(user_msgs)
    assert "Codemap (area slice" in blob or "search_users" in blob
    assert "search_users" in blob
    db.close()


def test_hunt_query_codemap_tool_returns_area_symbols(tmp_path: Path):
    """Agent tool path: query_codemap during hunt returns auth symbols only."""
    run_dir, db, task, cfg = _setup_run(
        tmp_path,
        MONO_SYNTH,
        path_hints=["packages/auth"],
        area="auth",
        hunt_class="access-control",
    )
    full = db.get_codemap() or {}
    assert len(full.get("symbols") or []) >= 2

    cfg["llm"]["fake_responses"] = _fake_query_then_none("packages/auth")
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r

    tr = load_transcript(run_dir, task.id)
    assert tr
    tools_used = (tr.get("meta") or {}).get("tools_used") or []
    # tools_used may list query_codemap from tool handler
    tool_msgs = [
        m
        for m in (tr.get("messages") or [])
        if m.get("role") == "tool" and m.get("name") == "query_codemap"
    ]
    assert tool_msgs, f"expected query_codemap tool result; tools_used={tools_used}"
    body = json.loads(tool_msgs[0].get("content") or "{}")
    assert body.get("ok") is True
    symbols = body.get("symbols") or []
    assert symbols, body
    names = {s.get("name") for s in symbols if isinstance(s, dict)}
    assert "issue_token" in names or "verify_token" in names
    for s in symbols:
        assert "auth" in str(s.get("path") or "").lower()
    # Must not leak api symbols into path-scoped tool result
    assert "search_users" not in names
    db.close()


def test_hunt_query_codemap_api_path(tmp_path: Path):
    run_dir, db, task, cfg = _setup_run(
        tmp_path,
        MONO_SYNTH,
        path_hints=["packages/api"],
        area="api",
        hunt_class="injection",
    )
    cfg["llm"]["fake_responses"] = _fake_query_then_none("packages/api")
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r

    tr = load_transcript(run_dir, task.id)
    tool_msgs = [
        m
        for m in (tr.get("messages") or [])
        if m.get("role") == "tool" and m.get("name") == "query_codemap"
    ]
    assert tool_msgs
    body = json.loads(tool_msgs[0].get("content") or "{}")
    names = {s.get("name") for s in (body.get("symbols") or []) if isinstance(s, dict)}
    assert "search_users" in names or "get_item" in names
    assert "issue_token" not in names
    db.close()


def test_two_hunts_different_slices_same_full_map(tmp_path: Path):
    """Same full codemap in DB; two hunt packets see different function sets."""
    cm = build_codemap(MONO_SYNTH, cfg=_CODEMAP_CFG)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(MONO_SYNTH.resolve()), "code_static", "pin", _CODEMAP_CFG)
    db.set_codemap(cm, source="mechanical")
    db.set_architecture({"summary": "mono", "components": []})

    auth_pkt = pack_hunt(
        _CODEMAP_CFG,
        system_prompts_root(),
        {
            "area": "auth",
            "class": "access-control",
            "path_hints": ["packages/auth"],
            "class_body_override": "# access-control\n",
        },
        architecture="{}",
        known_keys=[],
        codemap_notes=[],
        codemap=db.get_codemap(),
    )
    api_pkt = pack_hunt(
        _CODEMAP_CFG,
        system_prompts_root(),
        {
            "area": "api",
            "class": "injection",
            "path_hints": ["packages/api"],
            "class_body_override": "# injection\n",
        },
        architecture="{}",
        known_keys=[],
        codemap_notes=[],
        codemap=db.get_codemap(),
    )
    assert "issue_token" in auth_pkt.user or "verify_token" in auth_pkt.user
    assert "search_users" in api_pkt.user or "get_item" in api_pkt.user
    assert "search_users" not in auth_pkt.user
    assert "issue_token" not in api_pkt.user
    # Full map still has both
    full_names = {
        s.get("name") for s in (db.get_codemap() or {}).get("symbols") or []
    }
    assert "issue_token" in full_names and "search_users" in full_names
    db.close()


def test_hunt_without_codemap_still_succeeds(tmp_path: Path):
    """Regression: hunt does not hard-fail when codemap missing."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "evidence").mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(TOY_SQLI.resolve()), "code_static", "pin", {})
    db.set_architecture({"summary": "toy", "components": []})
    db.enqueue_task(
        "hunt",
        {
            "area": "app",
            "class": "injection",
            "path_hints": ["app.py"],
            "class_body_override": "# injection\n",
        },
    )
    task = db.lease_next_task("w", 60)
    cfg = {
        "llm": {
            "fake": True,
            "fake_responses": [_fake_none()],
            "max_tool_rounds": 4,
        },
        "run": {"ignore_globs": []},
        "packet": {},
        "tools": {},
    }
    r = hunt.run(task, db, run_dir, cfg)
    assert r["status"] == "succeeded", r
    db.close()

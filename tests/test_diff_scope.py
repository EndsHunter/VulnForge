"""Diff-scoped audits: vf init --diff base..head (#185).

Fixture: a small git repo where the head commit injects a command injection
into ``app/util.py`` (called from ``app/handlers.py``, calling ``app/cmd.py``).
``billing/`` is untouched and must never be hunted.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from vulnforge.cli import EXIT_CONFIG, EXIT_PROGRESS, main
from vulnforge.db import Database
from vulnforge.diff_scope import (
    DiffScopeError,
    build_diff_scope,
    clip_hints_to_scope,
    collect_changes,
    parse_diff_spec,
    scope_hunt_tasks,
)
from vulnforge.llm import LLMResult, ResponseClass
from vulnforge.tools.codemap import build_codemap


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        # The test's own `git status` must not refresh (write) the index either.
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    out = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", *args],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def _write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


BASE_UTIL = '''import subprocess

from app.cmd import build_cmd


def run_report(name):
    """Render a report for a customer name."""
    argv = build_cmd(name)
    return subprocess.run(argv, check=False)
'''

HEAD_UTIL = '''import os

from app.cmd import build_cmd


def run_report(name):
    """Render a report for a customer name."""
    argv = build_cmd(name)
    return os.system("report --name " + name)
'''

HANDLERS = '''from app.util import run_report


def handle_report(request):
    name = request.args["name"]
    return run_report(name)
'''

CMD = '''def build_cmd(name):
    return ["report", "--name", name]
'''

INVOICE = '''def charge_card(amount, card):
    return {"amount": amount, "card": card[-4:]}
'''

LEDGER = '''def post_entry(entry):
    return dict(entry)
'''


@pytest.fixture
def diff_repo(tmp_path: Path) -> dict:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo, "app/__init__.py", "")
    _write(repo, "app/util.py", BASE_UTIL)
    _write(repo, "app/handlers.py", HANDLERS)
    _write(repo, "app/cmd.py", CMD)
    _write(repo, "billing/__init__.py", "")
    _write(repo, "billing/invoice.py", INVOICE)
    _write(repo, "billing/ledger.py", LEDGER)
    _write(repo, "docs/README.md", "# Reports\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")
    _write(repo, "app/util.py", HEAD_UTIL)
    _write(repo, "docs/README.md", "# Reports\n\nNow uses the shell.\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "head: shell out")
    head = _git(repo, "rev-parse", "HEAD")
    return {"repo": repo, "base": base, "head": head}


def _tool(name: str, arguments: dict) -> LLMResult:
    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[{"id": "1", "name": name, "arguments": arguments}],
        raw=None,
        model_id="fake",
    )


def _fake_cfg(responses: list, *, max_tasks: int = 30) -> dict:
    return {
        "llm": {
            "fake": True,
            "fake_responses": responses,
            "max_tool_rounds": 8,
            "force_submit_on_round_limit": True,
        },
        "run": {"ignore_globs": [], "max_tasks": max_tasks, "profile": "code_static"},
        "packet": {},
        "tools": {},
        "stages": {"hunt_moa": False},
    }


def _repo_state(repo: Path) -> tuple[str, int]:
    status = _git(repo, "status", "--porcelain", "--ignored")
    index = Path(_git(repo, "rev-parse", "--git-path", "index"))
    if not index.is_absolute():
        index = repo / index
    return status, index.stat().st_mtime_ns


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


def test_parse_diff_spec_two_dot_only():
    assert parse_diff_spec("main..feature") == ("main", "feature")
    assert parse_diff_spec("HEAD~1..") == ("HEAD~1", "HEAD")
    assert parse_diff_spec("v1.2^..v1.3") == ("v1.2^", "v1.3")
    for bad in ("main...feature", "", "..head", "main", "-x..HEAD", "a b..c", "a..b..c"):
        with pytest.raises(DiffScopeError):
            parse_diff_spec(bad)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def test_manifest_changed_expanded_excluded(diff_repo: dict):
    repo = diff_repo["repo"]
    before = _repo_state(repo)
    codemap = build_codemap(repo, None, cfg={}, ignore_globs=[])
    m = build_diff_scope(repo, f"{diff_repo['base']}..{diff_repo['head']}", codemap=codemap)

    assert m["schema"] == "vulnforge/diff-scope@1"
    assert m["compare"] == "two_tree"
    assert m["base"]["sha"] == diff_repo["base"]
    assert m["head"]["sha"] == diff_repo["head"]

    changed = {c["path"]: c for c in m["changed"]}
    assert set(changed) == {"app/util.py"}
    util = changed["app/util.py"]
    assert util["status"] == "M"
    # The injected os.system line (line 9) is inside a new-side hunk.
    assert any(s <= 9 <= e for s, e in util["hunks"]), util["hunks"]

    excluded = {e["path"]: e["reason"] for e in m["excluded"]}
    assert excluded == {"docs/README.md": "non_code"}

    via = {e["path"]: e["via"] for e in m["expanded"]}
    assert via.get("app/handlers.py") == "caller"
    assert via.get("app/cmd.py") == "callee"
    assert not any(p.startswith("billing/") for p in m["scope_files"])
    assert m["untouched_modules"]["count"] >= 1
    assert "billing" in m["untouched_modules"]["sample"]
    # Target tree is read-only: no status change, no index write.
    assert _repo_state(repo) == before


def test_depth_zero_is_changed_files_only(diff_repo: dict):
    repo = diff_repo["repo"]
    codemap = build_codemap(repo, None, cfg={}, ignore_globs=[])
    m = build_diff_scope(
        repo, f"{diff_repo['base']}..HEAD", codemap=codemap, depth=0
    )
    assert m["expanded"] == []
    assert m["scope_files"] == ["app/util.py"]


def test_two_tree_compare_not_merge_base(tmp_path: Path):
    """base..head compares trees; base...head would hide base-only changes."""
    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo, "a.py", "def a():\n    return 1\n")
    _write(repo, "b.py", "def b():\n    return 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "root")
    _git(repo, "checkout", "-q", "-b", "feature")
    _write(repo, "a.py", "def a():\n    return 2\n")
    _git(repo, "commit", "-q", "-am", "feature edits a")
    _git(repo, "checkout", "-q", "main")
    _write(repo, "b.py", "def b():\n    return 3\n")
    _git(repo, "commit", "-q", "-am", "main edits b")
    _git(repo, "checkout", "-q", "feature")

    three_dot = set(_git(repo, "diff", "--name-only", "main...feature").split())
    assert three_dot == {"a.py"}
    changes = collect_changes(repo, "main..feature")
    assert {c["path"] for c in changes["changed"]} == {"a.py", "b.py"}


def test_subdir_target_paths_are_target_relative(diff_repo: dict):
    repo = diff_repo["repo"]
    changes = collect_changes(repo / "app", f"{diff_repo['base']}..HEAD")
    assert changes["target_prefix"] == "app"
    assert [c["path"] for c in changes["changed"]] == ["util.py"]
    assert {"path": "docs/README.md", "reason": "outside_target"} in changes["excluded"]


def test_refuses_head_not_checked_out(diff_repo: dict):
    repo = diff_repo["repo"]
    with pytest.raises(DiffScopeError, match="same commit"):
        collect_changes(repo, f"{diff_repo['base']}..{diff_repo['base']}~0")
    _git(repo, "checkout", "-q", diff_repo["base"])
    with pytest.raises(DiffScopeError, match="check out the head"):
        collect_changes(repo, f"{diff_repo['base']}..{diff_repo['head']}")


def test_refuses_unknown_revision_and_non_repo(tmp_path: Path, diff_repo: dict, monkeypatch):
    # tmp dirs may live inside another checkout; stop git discovery at tmp_path.
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    with pytest.raises(DiffScopeError, match="cannot resolve"):
        collect_changes(diff_repo["repo"], "nope-not-a-ref..HEAD")
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "x.py").write_text("x = 1\n")
    with pytest.raises(DiffScopeError, match="not inside a git work tree"):
        collect_changes(plain, "HEAD~1..HEAD")


def test_worktree_drift_is_a_warning(diff_repo: dict):
    repo = diff_repo["repo"]
    (repo / "app" / "util.py").write_text(HEAD_UTIL + "\n# local edit\n")
    changes = collect_changes(repo, f"{diff_repo['base']}..HEAD")
    assert changes["worktree"]["drift"] == ["app/util.py"]


# ---------------------------------------------------------------------------
# Scoping helpers
# ---------------------------------------------------------------------------

_MANIFEST = {
    "spec": "a..b",
    "base": {"sha": "a" * 40},
    "head": {"sha": "b" * 40},
    "changed": [{"path": "app/util.py", "status": "M", "hunks": [[9, 9]]}],
    "expanded": [
        {"path": "app/handlers.py", "via": "caller", "symbol": "run_report", "from": "app/util.py", "depth": 1}
    ],
    "scope_files": ["app/handlers.py", "app/util.py"],
}


def test_clip_hints_rewrites_dirs_to_scope_files():
    assert clip_hints_to_scope(["app"], _MANIFEST) == ["app/util.py", "app/handlers.py"]
    assert clip_hints_to_scope(["."], _MANIFEST)[0] == "app/util.py"
    assert clip_hints_to_scope(["billing", "billing/invoice.py"], _MANIFEST) == []
    assert clip_hints_to_scope(["app/handlers.py"], _MANIFEST) == ["app/handlers.py"]


def test_scope_hunt_tasks_drops_untouched_and_covers_changes():
    tasks = [
        {"area": "billing", "class": "injection", "path_hints": ["billing"]},
        {"area": "app", "class": "access-control", "path_hints": ["app/handlers.py"]},
    ]
    out = scope_hunt_tasks(tasks, _MANIFEST, classes=["injection"])
    assert all(not h.startswith("billing") for t in out for h in t["path_hints"])
    # handlers.py (context) kept; util.py (changed, uncovered) gets an allowed-class task.
    assert any(t["path_hints"] == ["app/handlers.py"] for t in out)
    added = [t for t in out if "app/util.py" in t["path_hints"]]
    assert added and added[0]["class"] == "injection"
    assert added[0]["diff_scope"]["changed"][0]["path"] == "app/util.py"


def test_soft_widen_stops_at_scope_files():
    from vulnforge.tools.scope import scope_roots_for_scan

    ctx = {"scope": {"enabled": True, "path_hints": ["app/util.py"], "widened": True,
                     "widen_roots": ["app/util.py", "app/handlers.py"]}}
    assert scope_roots_for_scan(ctx) == ["app/util.py", "app/handlers.py"]
    ctx["scope"]["widen_roots"] = None
    assert scope_roots_for_scan(ctx) is None


def test_pack_hunt_includes_diff_block():
    from vulnforge.packet import pack_hunt
    from vulnforge.paths import system_prompts_root

    payload = {
        "area": "app",
        "class": "injection",
        "path_hints": ["app/util.py"],
        "diff_scope": {
            "spec": "a..b",
            "base": "a" * 40,
            "head": "b" * 40,
            "changed": [{"path": "app/util.py", "hunks": [[9, 9]]}],
            "context": [],
        },
    }
    pkt = pack_hunt({}, system_prompts_root(), payload, "", [], [])
    assert "## Diff under review (a..b)" in pkt.user
    assert "changed `app/util.py` lines 9-9" in pkt.user


# ---------------------------------------------------------------------------
# End to end: init → recon → hunt → report
# ---------------------------------------------------------------------------


def _init(repo: Path, runs: Path, *extra: str) -> Path:
    code = main(
        ["init", "--target", str(repo), "--runs-root", str(runs),
         "--recon-agent", "default-map", *extra]
    )
    assert code == EXIT_PROGRESS
    return next(next(runs.iterdir()).iterdir())


def test_init_diff_end_to_end(tmp_path: Path, diff_repo: dict):
    repo = diff_repo["repo"]
    before = _repo_state(repo)
    runs = tmp_path / "runs"
    run_dir = _init(repo, runs, "--diff", f"{diff_repo['base']}..{diff_repo['head']}")

    # Persisted: run dir file + harness.db column.
    on_disk = json.loads((run_dir / "diff_scope.json").read_text())
    db = Database.open(run_dir / "harness.db")
    assert db.get_diff_scope() == on_disk
    assert on_disk["head"]["sha"] == diff_repo["head"]
    brief = db.summary()["run"]["diff_scope"]
    assert brief["changed"] == 1 and brief["excluded"] == 1
    assert "diff_scope_json" not in db.summary()["run"]

    # Recon payload is focused on the change.
    recon_task = db.lease_next_task("w", 60)
    assert recon_task.kind == "recon"
    assert recon_task.payload["diff_scoped"] is True
    assert "app/util.py" in recon_task.payload["focus_paths"]
    assert "Diff-scoped audit" in recon_task.payload["operator_notes"]

    # Recon (fake) asks to hunt billing and the whole app dir: billing is dropped,
    # the app dir hint becomes scope files only.
    from vulnforge.stages import hunt, recon, validate_mech

    arch = {
        "summary": "Report service and billing",
        "trust_boundaries": ["HTTP request"],
        "components": [
            {"name": "app", "path_hints": ["app"]},
            {"name": "billing", "path_hints": ["billing"]},
        ],
        "input_surfaces": ["name query param"],
        "hunt_focus": [
            {"area": "billing", "class": "injection", "path_hints": ["billing"]},
            {"area": "billing", "class": "access-control", "path_hints": ["billing/invoice.py"]},
            {"area": "app", "class": "injection", "path_hints": ["app"]},
        ],
    }
    r = recon.run(recon_task, db, run_dir, _fake_cfg([_tool("submit_architecture", arch)]))
    assert r["status"] == "succeeded", r
    assert r["hunt_enqueued"] >= 1
    assert r["hunt_plan_source"].endswith("+diff_scope")

    hunts = [t for t in db.list_tasks() if t.kind == "hunt"]
    assert hunts
    scope = set(on_disk["scope_files"])
    for t in hunts:
        hints = t.payload["path_hints"]
        assert hints and set(hints) <= scope, hints
        assert not any(h.startswith("billing") or h == "app" for h in hints)
        assert t.payload["diff_scope"]["spec"] == f"{diff_repo['base']}..{diff_repo['head']}"
    assert any("app/util.py" in t.payload["path_hints"] for t in hunts)

    # Hunt the changed file: fake agent files the injected command injection.
    target_hunt = next(
        t for t in hunts if t.payload["path_hints"][0] == "app/util.py"
    )
    db.conn.execute("UPDATE tasks SET state='done' WHERE id != ?", (target_hunt.id,))
    db.conn.commit()
    leased = db.lease_next_task("w", 60)
    assert leased.id == target_hunt.id
    candidate = {
        "title": "Command injection in run_report",
        "summary": "Customer name is concatenated into an os.system shell command.",
        "weakness_class": "injection",
        "sink_path": "app/util.py",
        "sink_symbol": "run_report",
        "citations": [
            {"path": "app/util.py", "start_line": 6, "end_line": 9, "symbol": "run_report"},
            {"path": "app/handlers.py", "start_line": 4, "end_line": 6, "symbol": "handle_report"},
        ],
        "threat_model": {
            "attacker": "remote user controlling the name parameter",
            "boundary": "HTTP request into a shell",
            "impact": "arbitrary command execution",
        },
    }
    responses = [
        _tool("read_file", {"path": "app/util.py"}),
        _tool("write_evidence", {"relpath": "notes.md", "content": "os.system with user input."}),
        _tool("submit_candidate", candidate),
    ]
    hr = hunt.run(leased, db, run_dir, _fake_cfg(responses))
    assert hr["status"] == "succeeded", hr
    findings = db.list_findings()
    assert len(findings) == 1
    assert findings[0].body["citations"][0]["path"] == "app/util.py"
    assert findings[0].state != "confirmed"

    vm = next(t for t in db.list_tasks() if t.kind == "validate_mech")
    db.conn.execute("UPDATE tasks SET state='done' WHERE id != ?", (vm.id,))
    db.conn.commit()
    vm_task = db.lease_next_task("w", 60)
    validate_mech.run(vm_task, db, run_dir, _fake_cfg([]))
    # Mech gates passed; only a human can confirm.
    assert db.list_findings()[0].state == "needs_human"

    # Report + export show the scope and what was excluded.
    from vulnforge.export_findings import export_bytes
    from vulnforge.stages.render import render_all

    render_all(run_dir, db)
    report = (run_dir / "project" / "REPORT.md").read_text()
    assert "## Diff scope" in report
    assert "`docs/README.md` — non_code" in report
    assert "Untouched modules (not hunted)" in report
    assert "Findings citing code outside the scope" not in report
    assert json.loads((run_dir / "project" / "diff_scope.json").read_text()) == on_disk
    payload, _ext, _media = export_bytes("json", run_dir, db)
    exported = json.loads(payload)
    assert exported["diff_scope"]["scope_files"] == on_disk["scope_files"]
    md, _e, _m = export_bytes("md", run_dir, db)
    assert b"## Diff scope" in md
    db.close()
    assert _repo_state(repo) == before


def test_init_diff_file_by_file_hunts_only_scope(tmp_path: Path, diff_repo: dict):
    runs = tmp_path / "runs"
    run_dir = _init(
        diff_repo["repo"], runs, "--strategy", "file_by_file", "--diff", f"{diff_repo['base']}.."
    )
    db = Database.open(run_dir / "harness.db")
    hunts = [t for t in db.list_tasks() if t.kind == "hunt"]
    paths = {t.payload["path_hints"][0] for t in hunts}
    assert "app/util.py" in paths
    assert paths <= {"app/util.py", "app/handlers.py", "app/cmd.py"}
    first = hunts[0].payload
    assert first["path_hints"] == ["app/util.py"]
    assert first["diff_scope"]["changed"][0]["path"] == "app/util.py"
    db.close()


def test_init_diff_refusals_leave_no_run(tmp_path: Path, diff_repo: dict):
    repo = diff_repo["repo"]
    runs = tmp_path / "runs"
    for spec in ("main...HEAD", "nope..HEAD", f"{diff_repo['base']}..{diff_repo['base']}"):
        code = main(["init", "--target", str(repo), "--runs-root", str(runs), "--diff", spec])
        assert code == EXIT_CONFIG, spec
    # Docs-only diff has nothing to hunt → refused, not an empty "clean" run.
    _write(repo, "docs/README.md", "# Reports v3\n")
    _git(repo, "commit", "-q", "-am", "docs only")
    code = main(["init", "--target", str(repo), "--runs-root", str(runs), "--diff", "HEAD~1..HEAD"])
    assert code == EXIT_CONFIG
    assert not runs.exists() or not any(runs.rglob("harness.db"))


def test_request_hunt_clips_to_scope(tmp_path: Path, diff_repo: dict):
    from vulnforge.tools.request_hunt import request_hunt

    run_dir = _init(diff_repo["repo"], tmp_path / "runs", "--diff", f"{diff_repo['base']}..")
    db = Database.open(run_dir / "harness.db")
    ctx = {
        "db": db,
        "task_id": 1,
        "task_payload": {"area": "app", "class": "injection", "path_hints": ["app/util.py"]},
        "session": {},
        "cfg": {},
    }
    res = request_hunt(
        ctx,
        profile="access-control",
        reason="check who can reach billing",
        path_hints=["billing/invoice.py"],
    )
    assert res.get("ok"), res
    child = next(t for t in db.list_tasks() if t.id == res["task_id"])
    assert child.payload["path_hints"] == ["app/util.py"]
    assert child.payload["diff_scope"]["changed"][0]["path"] == "app/util.py"
    db.close()


def test_api_init_accepts_diff(tmp_path: Path, diff_repo: dict):
    from fastapi.testclient import TestClient

    from vulnforge.ui.app import create_app

    client = TestClient(create_app(runs_root=tmp_path / "runs"))
    r = client.post(
        "/api/runs/init?background=false",
        json={
            "target": str(diff_repo["repo"]),
            "start": False,
            "diff": f"{diff_repo['base']}..HEAD",
            "agent_ids": ["default-map"],
        },
    )
    assert r.status_code == 200, r.text
    run_dir = Path(r.json()["run_dir"])
    assert (run_dir / "diff_scope.json").is_file()
    bad = client.post(
        "/api/runs/init?background=false",
        json={"target": str(diff_repo["repo"]), "start": False, "diff": "a...b"},
    )
    assert bad.status_code != 200 or not bad.json().get("ok", True)


# ---------------------------------------------------------------------------
# Review fixes: scan ceiling, subdir hunks, core.worktree, budget, report
# ---------------------------------------------------------------------------


def _diff_ctx(repo: Path, *, widened: bool) -> dict:
    return {
        "target_root": str(repo),
        "cfg": {"run": {"ignore_globs": []}, "tools": {}},
        "session": {},
        "scope": {
            "enabled": True,
            "path_hints": ["app/util.py"],
            "widened": widened,
            "widen_roots": ["app/util.py", "app/handlers.py", "app/cmd.py"],
        },
    }


@pytest.mark.parametrize("widened", [False, True])
def test_scans_stay_inside_diff_scope(diff_repo: dict, widened: bool):
    from vulnforge.tools.agent import query_flows, query_sinks
    from vulnforge.tools.symbol_find import find_symbol

    repo = diff_repo["repo"]
    ctx = _diff_ctx(repo, widened=widened)

    # A sibling dir of a hint passes the soft jail but must not scan billing/.
    hits = find_symbol(ctx, "charge_card", path="billing", definitions_only=False)
    assert hits.get("code") in ("out_of_diff_scope", "out_of_scope"), hits
    ok = find_symbol(ctx, "run_report", path="app", definitions_only=False)
    assert ok.get("ok"), ok
    paths = {m.get("path") for m in ok.get("matches") or ok.get("hits") or []}
    assert paths and paths <= {"app/util.py", "app/handlers.py", "app/cmd.py"}

    # billing/ledger.py calls dict(...); a whole-tree call scan would report it.
    flows = query_flows.run(ctx, symbol="dict", mode="calls")
    calls = flows.get("calls") or {}
    assert not any(str(c.get("path", "")).startswith("billing") for c in calls.get("calls") or [])

    sinks = query_sinks.run(ctx, rescan=True)
    if widened:
        assert sinks.get("rescan_skipped") == "diff_scope"
    assert not any(str(s.get("path", "")).startswith("billing") for s in sinks.get("sinks") or [])


def test_subdir_target_keeps_hunks(tmp_path: Path):
    repo = tmp_path / "mono"
    repo.mkdir()
    _git(repo, "init", "-q")
    _write(repo, "pkg/util.py", "def a():\n    return 1\n\n\ndef b():\n    return 2\n")
    _write(repo, "other/x.py", "x = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _write(repo, "pkg/util.py", "def a():\n    return 1\n\n\ndef b():\n    return 3\n")
    _write(repo, "other/x.py", "x = 2\n")
    _git(repo, "commit", "-q", "-am", "head")
    changes = collect_changes(repo / "pkg", "HEAD~1..HEAD")
    util = next(c for c in changes["changed"] if c["path"] == "util.py")
    assert util["hunks"] == [[6, 6]] and util["whole_file"] is False


def test_refuses_core_worktree_elsewhere(tmp_path: Path, diff_repo: dict, monkeypatch):
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    repo = diff_repo["repo"]
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    _git(repo, "config", "core.worktree", str(elsewhere))
    with pytest.raises(DiffScopeError, match="does not contain the target"):
        collect_changes(repo, f"{diff_repo['base']}..HEAD")


def test_budget_keeps_a_task_per_changed_file():
    from vulnforge.stages.recon import apply_diff_scope_to_plan

    manifest = {
        **_MANIFEST,
        "changed": [
            {"path": "app/util.py", "status": "M", "hunks": [[9, 9]]},
            {"path": "app/z_last.py", "status": "M", "hunks": [[1, 1]]},
        ],
        "scope_files": ["app/handlers.py", "app/util.py", "app/z_last.py"],
    }
    tasks = [
        {"area": "app", "class": c, "path_hints": ["app/handlers.py"]}
        for c in ("injection", "access-control", "ssrf", "crypto")
    ]
    out = apply_diff_scope_to_plan(
        tasks, manifest, {}, {"run": {"max_tasks": 2, "hunt_skill_mode": "explicit",
                                      "hunt_skill_ids": ["injection"]}}
    )
    covered = {h for t in out for h in t["path_hints"]}
    assert len(out) == 2
    assert {"app/util.py", "app/z_last.py"} <= covered


def test_report_names_changed_files_without_hunts():
    from vulnforge.diff_scope import report_md_lines

    lines = "\n".join(report_md_lines(_MANIFEST, [], hunted_paths=["app/handlers.py"]))
    assert "no hunt task yet" in lines and "`app/util.py`" in lines
    lines = "\n".join(report_md_lines(_MANIFEST, [], hunted_paths=["app/util.py"]))
    assert "no hunt task yet" not in lines

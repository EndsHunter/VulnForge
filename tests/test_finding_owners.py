"""Suggested finding owners from read-only git history (issue #190).

Every git repository here is a temp fixture built inside the test.
"""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from vulnforge.db import Database
from vulnforge.export_findings import ExportOptions, export_bundle, export_csv, export_json, export_markdown
from vulnforge.findings import owners as ow
from vulnforge.findings.owners import (
    OwnerResolver,
    OwnersError,
    compile_codeowners_pattern,
    csv_safe,
    match_codeowners,
    owners_config,
    owners_markdown,
    parse_codeowners,
    parse_log_records,
    redact_owners,
    safe_relpath,
    suggest_for_finding,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

ON = {"enabled": True}

# Isolated env for the fixture's own git calls (never the operator's config).
_FIXTURE_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_COMMITTER_NAME": "Committer",
    "GIT_COMMITTER_EMAIL": "committer@example.com",
}


def git(repo: Path, *args: str, env: dict | None = None, input: bytes | None = None) -> str:
    e = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    e.update(_FIXTURE_ENV)
    e.update(env or {})
    out = subprocess.run(
        ["git", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        env=e,
        input=input,
    )
    return out.stdout.decode()


def commit_as(repo: Path, name: str, email: str, msg: str, files: dict[str, str]) -> None:
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(
        repo,
        "commit",
        "-q",
        "-m",
        msg,
        env={"GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email},
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Repo: alice writes login.py, bob rewrites line 3, carol touches a sibling."""
    r = tmp_path / "target"
    r.mkdir()
    git(r, "init", "-q")
    commit_as(
        r,
        "Alice",
        "alice@example.com",
        "init",
        {
            "src/auth/login.py": "".join(f"line {i}\n" for i in range(1, 11)),
            ".github/CODEOWNERS": "* @org/default\n/src/auth/ @org/auth @alice\n",
            "CODEOWNERS": "* @ignored/second-file\n",
        },
    )
    lines = [f"line {i}\n" for i in range(1, 11)]
    lines[2] = "bob changed line 3\n"
    commit_as(r, "Bob", "bob@example.com", "fix", {"src/auth/login.py": "".join(lines)})
    commit_as(r, "Carol", "carol@example.com", "sib", {"src/auth/session.py": "x = 1\n"})
    commit_as(
        r,
        "dependabot[bot]",
        "49699333+dependabot[bot]@users.noreply.github.com",
        "bump",
        {"src/auth/session.py": "x = 2\n"},
    )
    return r


def body_for(path="src/auth/login.py", start=3, end=3, **extra):
    b = {"title": "t", "citations": [{"path": path, "start_line": start, "end_line": end}]}
    b.update(extra)
    return b


def names(owners: dict) -> list[str]:
    return [s["name"] for s in owners["suggestions"]]


# --------------------------------------------------------------------------
# signals


def test_blame_on_cited_lines_ranks_the_line_author_first(repo: Path):
    out = suggest_for_finding(repo, body_for(start=3, end=3), ON)
    assert out["available"] is True, out.get("detail")
    assert out["blame"][0]["authors"] == [{"name": "Bob", "email": "bob@example.com", "lines": 1}]
    assert names(out)[0] == "Bob"
    bob = out["suggestions"][0]
    assert bob["blame_lines"] == 1 and bob["file_commits"] == 1

    out = suggest_for_finding(repo, body_for(start=1, end=2), ON)
    assert names(out)[0] == "Alice"
    assert out["suggestions"][0]["blame_lines"] == 2


def test_file_and_module_authors_and_bots_dropped(repo: Path):
    out = suggest_for_finding(repo, body_for(start=1, end=10), ON)
    by = {s["name"]: s for s in out["suggestions"]}
    assert set(by) == {"Alice", "Bob", "Carol"}  # dependabot[bot] dropped
    assert out["module"] == "src/auth"
    assert by["Carol"]["blame_lines"] == 0
    assert by["Carol"]["file_commits"] == 0
    assert by["Carol"]["module_commits"] == 1
    assert by["Alice"]["blame_lines"] == 9 and by["Bob"]["blame_lines"] == 1
    assert by["Alice"]["score"] > by["Bob"]["score"] > by["Carol"]["score"]


def test_codemap_module_is_used_when_present(repo: Path):
    codemap = {"modules": [{"path": "src"}, {"path": "src/auth"}, {"path": "."}]}
    out = suggest_for_finding(repo, body_for(), ON, codemap=codemap)
    assert out["module"] == "src/auth"
    out = suggest_for_finding(repo, body_for(), ON, codemap={"modules": [{"path": "src"}]})
    assert out["module"] == "src"


def test_codeowners_first_file_wins_and_last_rule_matches(repo: Path):
    out = suggest_for_finding(repo, body_for(), ON)
    assert out["codeowners"] == {
        "file": ".github/CODEOWNERS",
        "pattern": "/src/auth/",
        "owners": ["@org/auth", "@alice"],
    }


def test_lines_past_eof_are_clamped(repo: Path):
    out = suggest_for_finding(repo, body_for(start=9, end=500), ON)
    assert out["blame"][0]["ranges"] == [[9, 10]]
    out = suggest_for_finding(repo, body_for(start=900, end=901), ON)
    assert out["available"] is True and out["blame"] == []
    assert names(out)  # still file/module history


# --------------------------------------------------------------------------
# CODEOWNERS semantics


def _owner(text: str, path: str):
    hit = match_codeowners(parse_codeowners(text), path)
    return hit[1] if hit else None


def test_codeowners_semantics():
    rules = "/src/auth/ @auth\n*.js @js\n"
    assert _owner(rules, "src/auth/a/b.py") == ["@auth"]
    assert _owner(rules, "web/x/y.js") == ["@js"]
    # a later * beats an earlier specific rule
    assert _owner("/src/ @src\n* @all\n", "src/a.py") == ["@all"]
    # rule with no owners clears ownership
    assert _owner("* @all\n/vendor/\n", "vendor/lib.c") is None
    assert _owner("* @all\n/vendor/\n", "src/lib.c") == ["@all"]
    # a slash in the middle anchors: src/auth == /src/auth
    assert _owner("src/auth @a\n", "src/auth/x.py") == ["@a"]
    assert _owner("src/auth @a\n", "lib/src/auth/x.py") is None
    # trailing-slash-only and bare names float to any depth
    assert _owner("apps/ @apps\n", "x/y/apps/z.py") == ["@apps"]
    assert _owner("Makefile @mk\n", "a/b/Makefile") == ["@mk"]
    # docs/* owns direct files only
    assert _owner("docs/* @docs\n", "docs/a.md") == ["@docs"]
    assert _owner("docs/* @docs\n", "docs/sub/a.md") is None
    # ** spans directories
    assert _owner("/a/**/z.py @z\n", "a/b/c/z.py") == ["@z"]
    assert _owner("/a/**/z.py @z\n", "a/z.py") == ["@z"]
    # comments, negation skipped, inline comment stops owners
    assert _owner("# c\n!x @no\n/x @yes # trailing\n", "x") == ["@yes"]
    # escaped #
    assert _owner("\\#weird @h\n", "#weird") == ["@h"]
    assert compile_codeowners_pattern("!x") is None


def test_codeowners_pathological_pattern_is_fast():
    pat = "/" + "**/" * 150 + "x"
    rx = compile_codeowners_pattern(pat)
    t0 = time.monotonic()
    assert rx is not None
    assert rx.match("a/" * 400 + "y") is None
    assert time.monotonic() - t0 < 1.0


# --------------------------------------------------------------------------
# graceful failure


def test_non_git_target(tmp_path: Path):
    d = tmp_path / "plain"
    (d / "src").mkdir(parents=True)
    (d / "src" / "a.py").write_text("x\n")
    out = suggest_for_finding(d, body_for("src/a.py", 1, 1), ON)
    assert out["available"] is False and out["reason"] == "not_a_git_repo"


def test_missing_target_and_no_citations(tmp_path: Path, repo: Path):
    assert suggest_for_finding(tmp_path / "nope", body_for(), ON)["reason"] == "target_missing"
    assert suggest_for_finding("", body_for(), ON)["reason"] == "no_target"
    assert suggest_for_finding(repo, {"title": "x"}, ON)["reason"] == "no_citations"


def test_empty_repo_has_no_head(tmp_path: Path):
    r = tmp_path / "empty"
    r.mkdir()
    git(r, "init", "-q")
    assert suggest_for_finding(r, body_for(), ON)["reason"] == "no_head"


def test_parent_repo_is_not_climbed_by_default(repo: Path):
    sub = repo / "src"
    out = suggest_for_finding(sub, body_for("auth/login.py"), ON)
    assert out["available"] is False and out["reason"] == "not_a_git_repo"
    out = suggest_for_finding(sub, body_for("auth/login.py"), {**ON, "allow_parent_repo": True})
    assert out["available"] is True
    assert names(out)[0] == "Bob"
    # CODEOWNERS still matches the repo-relative path
    assert out["codeowners"]["pattern"] == "/src/auth/"


def test_gitdir_whose_worktree_is_elsewhere_is_refused(tmp_path: Path, repo: Path):
    t = tmp_path / "decoy"
    t.mkdir()
    (t / ".git").write_text(f"gitdir: {repo / '.git'}\n")
    git(repo, "config", "core.worktree", str(repo))
    out = suggest_for_finding(t, body_for(), ON)
    assert out["available"] is False
    assert out["reason"] == "unsafe_repository"


def test_untracked_file_and_magic_pathspec(repo: Path):
    (repo / "src" / "auth" / "new.py").write_text("n\n")
    assert suggest_for_finding(repo, body_for("src/auth/new.py"), ON)["reason"] == "untracked"
    out = suggest_for_finding(repo, body_for(":(top)src/auth/login.py"), ON)
    assert out["available"] is False and out["reason"] == "untracked"
    out = suggest_for_finding(repo, body_for(":(glob)**"), ON)
    assert out["available"] is False


@pytest.mark.parametrize(
    "bad",
    ["../x", "/etc/passwd", "a/../../b", "a\nb", "a\x00b", "C:/x", "", ".", "..", 3],
)
def test_unsafe_paths_rejected(bad):
    assert safe_relpath(bad) is None


def test_traversal_citation_yields_no_citations(repo: Path):
    out = suggest_for_finding(repo, body_for("../../etc/passwd"), ON)
    assert out["reason"] == "no_citations"


def test_disabled_runs_no_subprocess(monkeypatch, repo: Path):
    def boom(*a, **k):
        raise AssertionError("git must not run when owners are disabled")

    monkeypatch.setattr(subprocess, "Popen", boom)
    out = suggest_for_finding(repo, body_for(), {"enabled": False})
    assert out == {**out, "available": False, "reason": "disabled"}
    out = suggest_for_finding(repo, body_for(), None)
    assert out["reason"] == "disabled"


def test_git_missing(monkeypatch, repo: Path):
    monkeypatch.setattr(ow.shutil, "which", lambda _n: None)
    assert suggest_for_finding(repo, body_for(), ON)["reason"] == "git_missing"


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="posix process groups")
def test_timeout_kills_process_group(tmp_path: Path, monkeypatch):
    pidfile = tmp_path / "child.pid"
    fake = tmp_path / "fake-git"
    fake.write_text(f"#!/bin/sh\nsleep 60 &\necho $! > {pidfile}\nwait\n")
    fake.chmod(0o755)
    monkeypatch.setattr(ow.shutil, "which", lambda _n: str(fake))
    t0 = time.monotonic()
    with pytest.raises(OwnersError) as ei:
        ow._run_git(tmp_path, ["rev-parse"], timeout=1)
    assert ei.value.reason == "timeout"
    assert time.monotonic() - t0 < 10
    for _ in range(50):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(0.05)
    pid = int(pidfile.read_text().strip())
    for _ in range(50):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        # a zombie reparented to init still answers kill(0); check its state
        try:
            if Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
                break
        except OSError:
            break
        time.sleep(0.05)
    else:
        pytest.fail("grandchild still running after timeout")


def test_export_budget_exhausted(repo: Path):
    res = OwnerResolver(repo, ON, deadline=time.monotonic() - 1)
    assert res.suggest(body_for())["reason"] == "budget_exhausted"


# --------------------------------------------------------------------------
# hostile repository config / content


def test_hostile_repo_config_never_executes_or_writes(tmp_path: Path, repo: Path):
    marker = tmp_path / "pwned"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\necho \"$0 $@\" >> {marker}\ncat\n")
    script.chmod(0o755)
    trace = tmp_path / "trace.json"
    outside_mailmap = tmp_path / "outside.mailmap"
    outside_mailmap.write_text("Mallory <mallory@evil> <bob@example.com>\n")

    # A signed-looking commit so log.showSignature would invoke gpg.program.
    raw = git(repo, "cat-file", "commit", "HEAD")
    head, _, msg = raw.partition("\n\n")
    sig = "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQ==\n -----END PGP SIGNATURE-----"
    forged = f"{head}\n{sig}\n\n{msg}".encode()
    sha = git(repo, "hash-object", "-t", "commit", "-w", "--stdin", input=forged).strip()
    git(repo, "update-ref", "HEAD", sha)

    (repo / ".gitattributes").write_text("*.py diff=evil\n")
    git(repo, "add", ".gitattributes")
    git(repo, "commit", "-q", "-m", "attrs", env={"GIT_AUTHOR_NAME": "Alice", "GIT_AUTHOR_EMAIL": "alice@example.com"})
    for key, val in {
        "core.fsmonitor": str(script),
        "core.pager": str(script),
        "core.hooksPath": str(tmp_path),
        "diff.evil.textconv": str(script),
        "diff.external": str(script),
        "log.showSignature": "true",
        "gpg.program": str(script),
        "mailmap.file": str(outside_mailmap),
        "trace2.eventTarget": str(trace),
        "trace2.normalTarget": str(trace),
        "pager.blame": str(script),
        "pager.log": str(script),
        "blame.ignoreRevsFile": str(tmp_path / "missing-revs"),
    }.items():
        git(repo, "config", key, val)

    # status refreshes the index itself, so snapshot the index after it.
    before_status = git(repo, "-c", "core.fsmonitor=false", "status", "--porcelain")
    index = repo / ".git" / "index"
    before_index = index.read_bytes()
    before_mtime = index.stat().st_mtime_ns

    out = suggest_for_finding(repo, body_for(start=1, end=10), ON)
    assert out["available"] is True, out.get("detail")
    assert not marker.exists(), marker.read_text()
    assert not trace.exists()
    assert "Mallory" not in json.dumps(out)
    assert index.read_bytes() == before_index
    assert index.stat().st_mtime_ns == before_mtime
    assert not marker.exists()
    assert git(repo, "-c", "core.fsmonitor=false", "status", "--porcelain") == before_status


def test_parse_log_records_cannot_be_spoofed():
    out = "Eve\x1fX\x00e@x\x00123\x1eMal\x00a\x00b\x00c\x1e\nOk\x00ok@x\x00456\x1e"
    rows = parse_log_records(out)
    assert rows == [("Eve X", "e@x", 123), ("Ok", "ok@x", 456)]


def test_owners_markdown_never_mentions():
    o = {
        "available": True,
        "codeowners": {"file": "CODEOWNERS", "pattern": "*", "owners": ["@alice", "@org/t`x"]},
        "suggestions": [{"name": "@bob", "email": "b@x", "blame_lines": 2}],
    }
    md = "\n".join(owners_markdown(o))
    assert "`@alice`" in md and "`@org/t'x`" in md and "`@bob <b@x>`" in md
    for line in md.splitlines():
        stripped = "".join(part for i, part in enumerate(line.split("`")) if i % 2 == 0)
        assert "@" not in stripped


def test_csv_safe():
    assert csv_safe('=HYPERLINK("x")') == "'=HYPERLINK(\"x\")"
    for c in "+-@\t":
        assert csv_safe(c + "a").startswith("'")
    assert csv_safe("CODEOWNERS @a") == "CODEOWNERS @a"


def test_redaction_covers_all_identity_fields(repo: Path):
    out = suggest_for_finding(repo, body_for(start=1, end=10), ON)
    red = redact_owners(out, "run-001")
    text = json.dumps(red)
    for ident in ("Alice", "alice@example.com", "Bob", "bob@", "Carol", "@org/auth", "@alice"):
        assert ident not in text
    assert red["redacted"] is True
    assert all(s["name"].startswith("owner-") and not s["email"] for s in red["suggestions"])
    assert all(o.startswith("owner-") for o in red["codeowners"]["owners"])
    # stable within a run, different across runs
    again = redact_owners(out, "run-001")
    assert again["suggestions"] == red["suggestions"]
    other = redact_owners(out, "run-002")
    assert other["suggestions"][0]["name"] != red["suggestions"][0]["name"]
    # counts survive
    assert [s["blame_lines"] for s in red["suggestions"]] == [s["blame_lines"] for s in out["suggestions"]]


# --------------------------------------------------------------------------
# exports


@pytest.fixture
def run_db(tmp_path: Path, repo: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run(
        "run-001",
        target_path=str(repo),
        profile="code_static",
        prompt_pin="pin",
        config={},
    )
    db.insert_finding(body_for(start=1, end=10), state="needs_human")
    yield run_dir, db
    db.close()


def _opts(**kw):
    return ExportOptions(include_owners=True, owners_cfg=dict(ON), **kw)


def test_export_without_owners_is_unchanged(run_db):
    run_dir, db = run_db
    text = export_csv(run_dir, db)
    header = text.splitlines()[1]
    assert "suggested_owners" not in header
    data = json.loads(export_json(run_dir, db))
    assert "owners" not in data and "owners" not in data["findings"][0]
    assert "suggested_owners" not in data["rows"][0]


def test_json_export_redacted(run_db):
    run_dir, db = run_db
    data = json.loads(export_json(run_dir, db, options=_opts(redact_owners=True)))
    assert data["owners"] == {"included": True, "redacted": True}
    owners = data["findings"][0]["owners"]
    assert owners["available"] is True and owners["redacted"] is True
    text = json.dumps(data)
    for ident in ("Alice", "alice@example.com", "Bob", "@org/auth", "@alice"):
        assert ident not in text
    assert data["rows"][0]["suggested_owners"].startswith("CODEOWNERS owner-")
    assert "include_owners" in data["sections"]
    assert "owners_cfg" not in data["sections"]


def test_json_md_csv_export_with_identities(run_db):
    run_dir, db = run_db
    opts = _opts(redact_owners=False)
    data = json.loads(export_json(run_dir, db, options=opts))
    assert data["findings"][0]["owners"]["suggestions"][0]["name"] == "Alice"
    md = export_markdown(run_dir, db, options=opts)
    assert "**suggested_owners:**" in md and "`Alice <alice@example.com>`" in md
    rows = list(csv.DictReader(io.StringIO(export_csv(run_dir, db, options=opts).split("\n", 1)[1])))
    assert "Alice <alice@example.com>" in rows[0]["suggested_owners"]
    html_payload, ext, _ = export_bundle("html", run_dir, db, options=opts)
    assert ext == "html" and b"Suggested owners" in html_payload


def test_csv_owner_cell_formula_neutralised(tmp_path: Path):
    r = tmp_path / "t"
    r.mkdir()
    git(r, "init", "-q")
    commit_as(r, '=HYPERLINK("http://x")', "f@x", "c", {"a.py": "a\n"})
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", target_path=str(r), profile="code_static", prompt_pin="p", config={})
    db.insert_finding(body_for("a.py", 1, 1), state="needs_human")
    try:
        text = export_csv(run_dir, db, options=_opts(redact_owners=False))
    finally:
        db.close()
    rows = list(csv.DictReader(io.StringIO(text.split("\n", 1)[1])))
    assert rows[0]["suggested_owners"].startswith("'=HYPERLINK")


def test_bundle_runs_git_once_per_finding(run_db, monkeypatch):
    run_dir, db = run_db
    calls = {"n": 0}
    real = ow._run_git

    def counting(*a, **k):
        calls["n"] += 1
        return real(*a, **k)

    monkeypatch.setattr(ow, "_run_git", counting)
    export_bundle("json,md,csv", run_dir, db, options=_opts(redact_owners=True))
    single = calls["n"]
    calls["n"] = 0
    export_json(run_dir, db, options=_opts(redact_owners=True))
    assert single == calls["n"] > 0


# --------------------------------------------------------------------------
# settings + API


def _isolate_settings(tmp_path: Path, monkeypatch) -> Path:
    p = tmp_path / "ui_settings.json"
    monkeypatch.setattr("vulnforge.settings.ui.UI_SETTINGS_PATH", p)
    monkeypatch.setattr("vulnforge.settings.UI_SETTINGS_PATH", p)
    return p


def test_ui_default_does_not_clobber_yaml(tmp_path: Path, monkeypatch):
    from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings, save_ui_settings

    _isolate_settings(tmp_path, monkeypatch)
    yaml_cfg = {"owners": {"enabled": True, "redact_in_exports": False}}
    eff = apply_ui_settings_to_cfg(yaml_cfg, load_ui_settings())
    assert owners_config(eff)["enabled"] is True
    assert owners_config(eff)["redact_in_exports"] is False
    # saving something unrelated leaves YAML in charge
    save_ui_settings({"max_tasks": 7})
    eff = apply_ui_settings_to_cfg(yaml_cfg, load_ui_settings())
    assert owners_config(eff)["enabled"] is True
    # explicit UI toggle wins
    save_ui_settings({"finding_owners": False, "finding_owners_redact_exports": True})
    ui = load_ui_settings()
    assert ui["finding_owners"] is False and ui["finding_owners_redact_exports"] is True
    eff = apply_ui_settings_to_cfg(yaml_cfg, ui)
    assert owners_config(eff) == {**owners_config(eff), "enabled": False, "redact_in_exports": True}


def test_defaults_are_opt_in_and_redacted():
    from vulnforge.settings import load_config

    cfg = owners_config({})
    assert cfg["enabled"] is False and cfg["redact_in_exports"] is True
    yaml_owners = load_config().get("owners")
    assert yaml_owners is not None


def _client(tmp_path: Path, repo: Path, monkeypatch, owners_cfg: dict):
    from fastapi.testclient import TestClient

    from vulnforge.ui import app as app_mod

    runs = tmp_path / "runs"
    run_dir = runs / "tgt" / "run-001"
    run_dir.mkdir(parents=True)
    db = Database.create(run_dir / "harness.db")
    db.insert_run("run-001", target_path=str(repo), profile="code_static", prompt_pin="p", config={})
    fid = db.insert_finding(body_for(start=1, end=10), state="needs_human")
    db.close()
    real = app_mod.load_config

    def fake_load_config(*a, **k):
        cfg = real(*a, **k)
        cfg["owners"] = dict(owners_cfg)
        return cfg

    monkeypatch.setattr(app_mod, "load_config", fake_load_config)
    return TestClient(app_mod.create_app(runs_root=runs)), fid


def test_api_owners_route_and_export(tmp_path: Path, repo: Path, monkeypatch):
    _isolate_settings(tmp_path, monkeypatch)
    client, fid = _client(tmp_path, repo, monkeypatch, {"enabled": True, "redact_in_exports": True})
    with client:
        r = client.get(f"/api/runs/tgt/run-001/findings/{fid}/owners")
        assert r.status_code == 200
        data = r.json()
        assert data["available"] is True and data["enabled"] is True
        assert data["redact_in_exports"] is True
        assert data["suggestions"][0]["name"] == "Alice"  # local view is not redacted
        assert client.get("/api/runs/tgt/run-001/findings/99999/owners").status_code == 404

        r = client.get("/api/runs/tgt/run-001/export?format=json")
        exported = r.json()
        assert exported["owners"]["redacted"] is True
        assert "Alice" not in r.text
        # no query flag lifts redaction
        r = client.get("/api/runs/tgt/run-001/export?format=json&redact_owners=false")
        assert "Alice" not in r.text
        r = client.get("/api/runs/tgt/run-001/export?format=json&include_owners=false")
        assert "owners" not in r.json()

        s = client.get("/api/settings").json()
        assert s["effective"]["finding_owners"] is True


def test_api_owners_disabled(tmp_path: Path, repo: Path, monkeypatch):
    _isolate_settings(tmp_path, monkeypatch)
    client, fid = _client(tmp_path, repo, monkeypatch, {"enabled": False})
    with client:
        data = client.get(f"/api/runs/tgt/run-001/findings/{fid}/owners").json()
        assert data["enabled"] is False and data["reason"] == "disabled"
        r = client.get("/api/runs/tgt/run-001/export?format=json")
        assert "owners" not in r.json()

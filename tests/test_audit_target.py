"""Audit target parse and materialize. No network."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnforge.audit_target import (
    GitHubSpec,
    LocalSpec,
    TargetError,
    _LiveGit,
    _git_env,
    _match_ls_remote,
    github_cache_root,
    parse_target,
    resolve_init_target,
)
from vulnforge.cli import EXIT_CONFIG, EXIT_PROGRESS, build_parser, cmd_init
from vulnforge.db import Database
from vulnforge.ui.app import create_app
from vulnforge.ui.store import discover_runs, run_card

SHA = "a" * 40
HINT = "Local folder or file, or a public GitHub URL (repo, tree, or blob). Source analysis only."
OLD_HINT = "Source folder or single source file (source analysis only)"


class FakeGit:
    def __init__(self, tree: Path, sha: str, subpath: tuple[str, ...] = ()) -> None:
        self.tree = tree
        self.sha = sha
        self.subpath = subpath
        self.fetches = 0
        self.resolves = 0

    def resolve_commit(self, spec: GitHubSpec) -> tuple[str, tuple[str, ...]]:
        self.resolves += 1
        return self.sha, self.subpath

    def fetch_commit(self, spec: GitHubSpec, sha: str, dest: Path) -> None:
        self.fetches += 1
        shutil.copytree(self.tree, dest, dirs_exist_ok=True, symlinks=True)


def _tree(tmp_path: Path) -> Path:
    pkg = tmp_path / "src" / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "app.py").write_text("x = 1\n", encoding="utf-8")
    return tmp_path / "src"


def test_parse_github_forms():
    repo = parse_target("https://github.com/pallets/flask")
    assert isinstance(repo, GitHubSpec)
    assert (repo.owner, repo.repo, repo.rest, repo.focus) == ("pallets", "flask", "", "repo")
    assert repo.clone_url == "https://github.com/pallets/flask.git"

    dotted = parse_target("https://github.com/pallets/flask.git/")
    assert isinstance(dotted, GitHubSpec)
    assert dotted.repo == "flask" and dotted.focus == "repo"

    tree = parse_target("https://github.com/pallets/flask/tree/3.0.3/src/flask/")
    assert isinstance(tree, GitHubSpec)
    assert tree.focus == "tree"
    assert tree.rest == "3.0.3/src/flask"

    blob = parse_target("https://github.com/pallets/flask/blob/3.0.3/src/flask/app.py#L10")
    assert isinstance(blob, GitHubSpec)
    assert blob.focus == "blob"
    assert blob.rest == "3.0.3/src/flask/app.py"

    slash_ref = parse_target("https://github.com/o/r/tree/feature/foo/src/a.py")
    assert isinstance(slash_ref, GitHubSpec)
    assert slash_ref.rest == "feature/foo/src/a.py"


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("http://github.com/o/r", "forbidden_scheme"),
        ("ssh://git@github.com/o/r.git", "forbidden_scheme"),
        ("git://github.com/o/r", "forbidden_scheme"),
        ("https://www.github.com/o/r", "forbidden_host"),
        ("https://github.example.com/o/r", "forbidden_host"),
        ("https://1.2.3.4/o/r", "forbidden_host"),
        ("https://user:token@github.com/o/r", "userinfo"),
        ("https://user@github.com/o/r", "userinfo"),
        ("https://gist.github.com/o/1", "gist"),
        ("https://github.com/gist/o", "gist"),
        ("https://github.com/o/r/issues/1", "unknown_github_url"),
        ("https://github.com/o/r/commit/abc", "unknown_github_url"),
        ("https://github.com/o/r/pull/2", "unknown_github_url"),
        ("https://github.com/o/r/tree/", "empty_ref"),
        ("https://github.com/o/r/blob", "empty_ref"),
        ("https://github.com/o/r/tree/main/../../etc", "unsafe_path"),
        ("https://github.com/o/r/blob/main/%2e%2e/b", "unsafe_path"),
        ("https://github.com/o/r?x=1", "query"),
        ("git@github.com:o/r.git", "ssh_url"),
    ],
)
def test_parse_rejects(raw: str, code: str):
    with pytest.raises(TargetError) as exc:
        parse_target(raw)
    assert exc.value.code == code
    assert str(exc.value) == exc.value.detail
    assert "target not found" not in exc.value.detail


def test_parse_local_empty_and_whitespace():
    empty = parse_target("")
    assert isinstance(empty, LocalSpec)
    assert empty.raw == ""
    spaces = parse_target("   ")
    assert isinstance(spaces, LocalSpec)
    assert spaces.raw == "   "
    local = parse_target("/home/ends/src/flask")
    assert isinstance(local, LocalSpec)
    assert local.raw == "/home/ends/src/flask"


def test_local_resolve_expanduser_empty_and_spaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    proj = home / "proj"
    proj.mkdir(parents=True)
    (proj / "a.py").write_text("x\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    cache = tmp_path / "cache"
    got = resolve_init_target("~/proj", cache_root=cache)
    assert got.path == proj.resolve()
    assert got.commit_sha is None
    assert got.display == "~/proj"
    assert isinstance(got.spec, LocalSpec)

    monkeypatch.chdir(tmp_path)
    rel = resolve_init_target("home/proj", cache_root=cache)
    assert rel.path == proj.resolve()

    cwd = resolve_init_target("", cache_root=cache)
    assert cwd.path == Path.cwd().resolve()
    assert cwd.display == ""

    with pytest.raises(TargetError) as exc:
        resolve_init_target("   ", cache_root=cache)
    assert exc.value.code == "not_found"
    assert exc.value.detail != f"target not found: {Path.cwd().resolve()}"


def test_github_cache_root(tmp_path: Path):
    assert github_cache_root(tmp_path) == tmp_path / ".vf-github"


def test_materialize_reuses_ready_clone(tmp_path: Path):
    tree = _tree(tmp_path)
    git = FakeGit(tree, SHA, ("pkg",))
    cache = tmp_path / "cache"
    url = "https://github.com/acme/widgets/tree/main/pkg"
    first = resolve_init_target(url, cache_root=cache, git=git)
    assert first.commit_sha == SHA
    assert first.subpath == ("pkg",)
    assert first.path == (cache.resolve() / "acme" / "widgets" / SHA / "pkg").resolve()
    assert first.path.is_dir()
    assert (first.path / "app.py").is_file()
    marker = cache.resolve() / "acme" / "widgets" / SHA / ".git" / "vulnforge-ready"
    assert marker.read_text(encoding="utf-8").strip() == SHA
    assert ".partial" not in str(first.path)

    second = resolve_init_target(url, cache_root=cache, git=git)
    assert second.path == first.path
    assert git.fetches == 1
    assert git.resolves == 2
    lock = cache.resolve() / "acme" / "widgets" / f"{SHA}.lock"
    assert lock.is_file()
    assert lock.read_bytes() == b""


def test_partial_and_half_tree_are_not_reused(tmp_path: Path):
    tree = _tree(tmp_path)
    git = FakeGit(tree, SHA, ())
    cache = tmp_path / "cache"
    parent = cache / "acme" / "widgets"
    partial = parent / f".{SHA}.partial"
    partial.mkdir(parents=True)
    (partial / "junk").write_text("nope", encoding="utf-8")
    half = parent / SHA
    half.mkdir()
    (half / "half.txt").write_text("stale", encoding="utf-8")

    url = "https://github.com/acme/widgets"
    got = resolve_init_target(url, cache_root=cache, git=git)
    assert got.path.resolve() == half.resolve()
    assert not partial.exists()
    assert not (got.path / "junk").exists()
    assert not (got.path / "half.txt").exists()
    assert (got.path / "pkg" / "app.py").is_file()
    assert (got.path / ".git" / "vulnforge-ready").read_text(encoding="utf-8").strip() == SHA
    assert git.fetches == 1


def test_symlink_escape_rejected(tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "leak").symlink_to(outside)
    git = FakeGit(tree, SHA, ("leak",))
    with pytest.raises(TargetError) as exc:
        resolve_init_target(
            "https://github.com/acme/widgets/blob/main/leak",
            cache_root=tmp_path / "cache",
            git=git,
        )
    assert exc.value.code == "unsafe_path"


def test_blob_pe_rejected_before_fetch(tmp_path: Path):
    git = FakeGit(_tree(tmp_path), SHA, ("bin", "app.exe"))
    with pytest.raises(TargetError) as exc:
        resolve_init_target(
            "https://github.com/acme/widgets/blob/main/bin/app.exe",
            cache_root=tmp_path / "cache",
            git=git,
        )
    assert exc.value.code == "pe_binary"
    assert "PE binaries are not supported" in str(exc.value)
    assert git.fetches == 0
    assert git.resolves == 1
    assert not (tmp_path / "cache").exists()


def test_match_ls_remote_longest_prefix_and_head():
    head = "c" * 40
    branch = "d" * 40
    tag = "e" * 40
    peeled = "f" * 40
    text = "\n".join(
        [
            f"{head}\tHEAD",
            f"{branch}\trefs/heads/feature/foo",
            f"{'1' * 40}\trefs/heads/feature",
            f"{tag}\trefs/tags/3.0.3",
            f"{peeled}\trefs/tags/3.0.3^{{}}",
        ]
    )
    assert _match_ls_remote(text, "") == (head, ())
    assert _match_ls_remote(text, "feature/foo/src/a.py") == (branch, ("src", "a.py"))
    assert _match_ls_remote(text, "3.0.3/src/flask") == (peeled, ("src", "flask"))
    with pytest.raises(TargetError) as exc:
        _match_ls_remote(text, "missing/path")
    assert exc.value.code == "ref_not_found"


def test_live_git_argv_never_uses_operator_url(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[list[str], dict]] = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))

        class Proc:
            returncode = 0
            stdout = f"{'9' * 40}\tHEAD\n{'9' * 40}\trefs/heads/main\n"
            stderr = ""

        return Proc()

    monkeypatch.setenv("GIT_DIR", "/evil")
    monkeypatch.setenv("GIT_TERMINAL_PROMPT", "1")
    monkeypatch.setattr("vulnforge.audit_target.subprocess.run", fake_run)
    spec = parse_target("https://github.com/pallets/flask/tree/main/src/flask")
    assert isinstance(spec, GitHubSpec)
    sha, sub = _LiveGit().resolve_commit(spec)
    assert sha == "9" * 40
    assert sub == ("src", "flask")
    argv, kwargs = calls[0]
    joined = " ".join(argv)
    assert "https://github.com/pallets/flask/tree/main/src/flask" not in joined
    assert "https://github.com/pallets/flask.git" in argv
    assert "ls-remote" in argv
    assert "--" in argv
    assert "core.hooksPath=/dev/null" in argv
    assert "protocol.https.allow=always" in argv
    assert "submodule.recurse=false" in argv
    assert "submodule update" not in joined
    env = kwargs["env"]
    assert "GIT_DIR" not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert _git_env()["GIT_ASKPASS"] == ""

    calls.clear()

    def fake_fetch(argv, **kwargs):
        calls.append((list(argv), kwargs))

        class Proc:
            returncode = 0
            stdout = ""
            stderr = ""

        return Proc()

    monkeypatch.setattr("vulnforge.audit_target.subprocess.run", fake_fetch)
    dest = Path("/tmp/vf-audit-target-dest")
    _LiveGit().fetch_commit(spec, SHA, dest)
    flat = [" ".join(argv) for argv, _kw in calls]
    assert any("init" in item and str(dest) in item for item in flat)
    assert any("fetch --depth 1 origin " + SHA in item for item in flat)
    assert any("checkout --force FETCH_HEAD" in item for item in flat)
    assert all("https://github.com/pallets/flask/tree/" not in item for item in flat)
    assert all("submodule update" not in item for item in flat)


def test_sha_rest_skips_ls_remote(monkeypatch: pytest.MonkeyPatch):
    def boom(*_a, **_k):
        raise AssertionError("ls-remote")

    monkeypatch.setattr("vulnforge.audit_target.subprocess.run", boom)
    spec = parse_target(f"https://github.com/o/r/tree/{SHA}/src/app.py")
    assert isinstance(spec, GitHubSpec)
    sha, sub = _LiveGit().resolve_commit(spec)
    assert sha == SHA
    assert sub == ("src", "app.py")


def _init_args(target: str, runs: Path, git: FakeGit | None = None):
    class Args:
        pass

    args = Args()
    args.target = target
    args.profile = "code_static"
    args.runs_root = runs
    args.strategy = "discovery"
    args.docs_path = None
    args.enqueue_hunts = False
    args.sandbox_poc_validate = False
    args.progress = None
    args.job_id = None
    args.git_fetcher = git
    return args


def test_cmd_init_github_stores_local_path(tmp_path: Path):
    tree = _tree(tmp_path)
    git = FakeGit(tree, SHA, ("pkg",))
    runs = tmp_path / "runs"
    url = "https://github.com/acme/widgets/tree/main/pkg"
    phases: list[str] = []

    def progress(ev: dict) -> None:
        phases.append(str(ev.get("phase")))

    args = _init_args(url, runs, git)
    args.progress = progress
    code = cmd_init(args, {})
    assert code == EXIT_PROGRESS
    assert phases[0] == "fetch"
    assert git.fetches == 1
    materialized = Path(args.materialized_target).resolve()
    assert materialized == (github_cache_root(runs).resolve() / "acme" / "widgets" / SHA / "pkg")
    run_dir = next(p for p in runs.rglob("harness.db")).parent
    db = Database.open(run_dir / "harness.db")
    try:
        row = db.get_run()
        assert row is not None
        assert Path(row["target_path"]).resolve() == materialized
        assert url not in row["target_path"]
        cfg = json.loads(row["config_json"])
        assert cfg["audit_target"] == {
            "display": url,
            "commit": SHA,
            "focus": "tree",
            "subpath": "pkg",
        }
    finally:
        db.close()
    refs = discover_runs(runs)
    assert len(refs) == 1
    assert refs[0].target_id != ".vf-github"
    card = run_card(refs[0])
    assert card["target_display"] == url
    assert card["target_path"]


def test_bad_strategy_and_sandbox_do_not_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    git = FakeGit(_tree(tmp_path), SHA, ())
    runs = tmp_path / "runs"
    args = _init_args("https://github.com/acme/widgets", runs, git)
    args.strategy = "nope"
    assert cmd_init(args, {}) == EXIT_CONFIG
    assert git.resolves == 0 and git.fetches == 0

    import vulnforge.poc_runner as pr

    monkeypatch.setattr(
        pr,
        "sandbox_poc_preflight",
        lambda cfg: {"ok": False, "message": "Sandbox PoC refused: isolation unavailable"},
    )
    args = _init_args("https://github.com/acme/widgets", runs, git)
    args.sandbox_poc_validate = True
    assert cmd_init(args, {}) == EXIT_CONFIG
    assert git.fetches == 0 and git.resolves == 0


def test_bad_model_validate_does_not_fetch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    git = FakeGit(_tree(tmp_path), SHA, ())
    args = _init_args("https://github.com/acme/widgets", tmp_path / "runs", git)
    args.model_validate = "bare-id"
    def _refuse_save(_patch):
        raise AssertionError("settings saved")

    monkeypatch.setattr(
        "vulnforge.settings.load_ui_settings",
        lambda: {"hosts": [{"id": "lab"}]},
    )
    monkeypatch.setattr("vulnforge.settings.save_ui_settings", _refuse_save)
    assert cmd_init(args, {}) == EXIT_CONFIG
    assert git.fetches == 0 and git.resolves == 0
    assert "host_id/model_id" in args.init_error


def test_docs_path_checked_before_fetch(tmp_path: Path):
    git = FakeGit(_tree(tmp_path), SHA, ())
    args = _init_args("https://github.com/acme/widgets", tmp_path / "runs", git)
    args.strategy = "recon_docs"
    args.docs_path = None
    assert cmd_init(args, {}) == EXIT_CONFIG
    assert git.fetches == 0


def test_argparse_target_stays_str():
    args = build_parser().parse_args(["init", "--target", "https://github.com/o/r"])
    assert isinstance(args.target, str)
    assert args.target == "https://github.com/o/r"


def test_api_rejects_github_policy_before_clone(tmp_path: Path):
    app = create_app(runs_root=tmp_path / "runs")
    client = TestClient(app)
    r = client.post(
        "/api/runs/init?background=false",
        json={"target": "git@github.com:o/r.git", "start": False},
    )
    assert r.status_code == 400
    assert "target not found" not in r.text.lower()
    gist = client.post(
        "/api/runs/init?background=false",
        json={"target": "https://gist.github.com/o/1", "start": False},
    )
    assert gist.status_code == 400
    assert not any((tmp_path / "runs").rglob("harness.db"))


def test_hint_names_github_url():
    root = Path(__file__).resolve().parents[1]
    html = (root / "vulnforge/ui/templates/index.html").read_text(encoding="utf-8")
    js = (root / "vulnforge/ui/static/app.js").read_text(encoding="utf-8")
    prompt = (root / "vulnforge/operator_chat/prompts.py").read_text(encoding="utf-8")
    assert OLD_HINT not in html
    assert OLD_HINT not in js
    assert HINT in html
    assert HINT in js
    assert "https://github.com/owner/repo" in html
    assert 'includes("://")' in js
    assert "public GitHub URL" in prompt


def test_chat_init_locates_by_materialized_path(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    from vulnforge.operator_chat.tools_home import _init_run

    out = _init_run(
        {"target": str(src), "enqueue_hunts": False, "start": False},
        runs_root=tmp_path / "runs",
        project_root=tmp_path,
    )
    assert out["ok"] is True, out
    assert out["target_id"]
    assert out["run_id"]
    refused = _init_run(
        {"target": "git@github.com:o/r.git", "start": False},
        runs_root=tmp_path / "runs",
        project_root=tmp_path,
    )
    assert refused["ok"] is False
    assert "target not found" not in refused["error"]

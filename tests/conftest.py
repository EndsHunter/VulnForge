"""Shared pytest fixtures for VulnForge."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from vulnforge.paths import PROJECT_ROOT, system_prompts_root

FIXTURES = PROJECT_ROOT / "fixtures"
TOY_SQLI = FIXTURES / "toy_sqli"
# Effective system prompts root (seeds/system when present).
PROMPTS_V1 = system_prompts_root()
CONFIG_DEFAULT = PROJECT_ROOT / "config" / "default.yaml"


@pytest.fixture
def project_root() -> Path:
    return PROJECT_ROOT


# Alias for tests that still name the fixture harness_root
@pytest.fixture
def harness_root(project_root: Path) -> Path:
    return project_root


@pytest.fixture
def toy_sqli(tmp_path_factory) -> Path:
    """Per-test copy of fixtures/toy_sqli (tests may mutate it freely)."""
    assert TOY_SQLI.is_dir(), f"missing fixture {TOY_SQLI}"
    dest = tmp_path_factory.mktemp("toy_sqli") / "toy_sqli"
    shutil.copytree(TOY_SQLI, dest)
    return dest


@pytest.fixture
def prompts_v1() -> Path:
    assert PROMPTS_V1.is_dir()
    return PROMPTS_V1


@pytest.fixture
def config_path() -> Path:
    return CONFIG_DEFAULT


@pytest.fixture
def tmp_run_dir(tmp_path: Path) -> Path:
    """Empty run directory under a temp runs root."""
    run = tmp_path / "runs" / "test-target" / "run-001"
    run.mkdir(parents=True)
    (run / "evidence").mkdir()
    (run / "inbox").mkdir()
    (run / "project").mkdir()
    return run


@pytest.fixture(autouse=True)
def _isolate_hunt_profiles(tmp_path_factory, request):
    """Every test gets a fresh seeded hunt collection (never touch config/)."""
    # test_hunt_registry manages its own root via set_collection_root
    if request.node.get_closest_marker("no_hunt_isolate"):
        yield
        return
    from vulnforge.hunt_profiles import (
        ensure_collection,
        reset_collection_root_override,
        set_collection_root,
    )

    root = tmp_path_factory.mktemp("hunt_profiles")
    set_collection_root(root)
    ensure_collection()
    try:
        yield root
    finally:
        reset_collection_root_override()


@pytest.fixture(autouse=True)
def _isolate_benchmarks_library(tmp_path_factory, request):
    """Every test gets a fresh seeded bench library (never touch benchmarks/library/)."""
    if request.node.get_closest_marker("no_bench_isolate"):
        yield
        return
    from vulnforge.benchmarks import (
        ensure_library,
        reset_library_root_override,
        set_library_root,
    )

    root = tmp_path_factory.mktemp("bench_library")
    set_library_root(root)
    ensure_library()
    try:
        yield root
    finally:
        reset_library_root_override()


@pytest.fixture(autouse=True)
def _isolate_benchmarks_runs(tmp_path_factory, request):
    """Every test gets a fresh bench runs root (never touch benchmarks/runs/)."""
    if request.node.get_closest_marker("no_bench_isolate"):
        yield
        return
    from vulnforge.benchmarks import reset_runs_root_override, set_runs_root

    root = tmp_path_factory.mktemp("bench_runs")
    set_runs_root(root)
    try:
        yield root
    finally:
        reset_runs_root_override()


@pytest.fixture(autouse=True)
def _isolate_runs_root_and_init_jobs(tmp_path_factory, monkeypatch):
    """Default runs root and init-job files go to a temp dir, never <repo>/runs.

    ``create_app()`` without ``runs_root`` falls back to ``<repo>/runs``, and
    ``init_progress`` writes ``<project_root>/runs/.init_jobs`` even when the app
    was given a temp runs root. Redirect both so new tests cannot forget.
    """
    import vulnforge.cli as cli
    import vulnforge.init_progress as init_progress
    import vulnforge.ui.app as ui_app

    sandbox = tmp_path_factory.mktemp("default_runs_root")

    real_resolve = cli.resolve_runs_root

    def resolve_runs_root(cfg, override=None):
        if override is not None:
            return real_resolve(cfg, override)
        configured = Path(cfg.get("run", {}).get("runs_root", "runs"))
        if configured.is_absolute():
            return real_resolve(cfg, None)
        return (sandbox / configured).resolve()

    monkeypatch.setattr(cli, "resolve_runs_root", resolve_runs_root)
    monkeypatch.setattr(ui_app, "resolve_runs_root", resolve_runs_root)

    real_jobs_dir = init_progress._jobs_dir

    def jobs_dir(project_root: Path) -> Path:
        if Path(project_root).resolve() == PROJECT_ROOT.resolve():
            project_root = sandbox
        return real_jobs_dir(project_root)

    monkeypatch.setattr(init_progress, "_jobs_dir", jobs_dir)


# ---- guard: the offline suite must leave the git checkout untouched ----------

# Interpreter / tooling caches that are expected (and gitignored).
# .pytest_tmp is --basetemp from pyproject; relocating it is tracked in #176.
_EXPECTED_NOISE = ("__pycache__/", ".egg-info/", ".pytest_cache/", ".pytest_tmp/")


def _git_status() -> "set[str] | None":
    """Porcelain status incl. ignored files, or None when not in a git checkout."""
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain", "--ignored"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return {
        line
        for line in out.stdout.splitlines()
        if not any(noise in line for noise in _EXPECTED_NOISE)
    }


@pytest.fixture(scope="session", autouse=True)
def _repo_tree_unchanged():
    """Fail the session if tests changed the repo working tree."""
    before = _git_status()
    yield
    if before is None:
        return
    after = _git_status()
    if after is None or after == before:
        return
    added = sorted(after - before)
    removed = sorted(before - after)
    lines = ["pytest modified the git working tree (tests must use tmp dirs):"]
    lines += [f"  + {x}" for x in added] + [f"  - {x}" for x in removed]
    pytest.fail("\n".join(lines), pytrace=False)

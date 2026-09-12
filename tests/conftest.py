"""Shared pytest fixtures for VulnForge."""

from __future__ import annotations

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
def toy_sqli() -> Path:
    assert TOY_SQLI.is_dir(), f"missing fixture {TOY_SQLI}"
    return TOY_SQLI


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

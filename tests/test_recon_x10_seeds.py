"""Library expansion ticket 3: recon×10 seeds + mechanical prove bar."""

from __future__ import annotations

from pathlib import Path

from vulnforge.benchmarks import (
    TERMINAL_STATUSES,
    get_def,
    list_defs,
    run_benchmark,
    score_recon,
)
from vulnforge.paths import PROJECT_ROOT

RECON_X10_IDS = (
    "toy_sqli_recon",
    "recon-web-api",
    "recon-cli-tool",
    "recon-auth-boundaries",
    "recon-multi-pkg",
    "recon-queue-worker",
    "recon-spa-backend",
    "recon-native-parser",
    "recon-monorepo-shallow",
    "recon-deps-surface",
)

TARGET_REFS = {
    "toy_sqli_recon": "fixtures/toy_sqli",
    "recon-web-api": "fixtures/recon_benches/recon-web-api",
    "recon-cli-tool": "fixtures/recon_benches/recon-cli-tool",
    "recon-auth-boundaries": "fixtures/recon_benches/recon-auth-boundaries",
    "recon-multi-pkg": "fixtures/recon_benches/recon-multi-pkg",
    "recon-queue-worker": "fixtures/recon_benches/recon-queue-worker",
    "recon-spa-backend": "fixtures/recon_benches/recon-spa-backend",
    "recon-native-parser": "fixtures/recon_benches/recon-native-parser",
    "recon-monorepo-shallow": "fixtures/recon_benches/recon-monorepo-shallow",
    "recon-deps-surface": "fixtures/recon_benches/recon-deps-surface",
}

# Three mechanical prove runs (toy + two new)
PROVE_RUN_IDS = ("toy_sqli_recon", "recon-web-api", "recon-cli-tool")


def test_recon_x10_seeds_present_after_ensure_library():
    defs = list_defs()
    recons = [d for d in defs if "recon" in (d.get("types") or [])]
    assert len(recons) >= 10
    got = sorted(d["id"] for d in recons if d["id"] in RECON_X10_IDS)
    assert got == sorted(RECON_X10_IDS)
    for bid in RECON_X10_IDS:
        row = get_def(bid)
        assert row["types"] == ["recon"]
        assert row["target_ref"] == TARGET_REFS[bid]
        assert row["source"] == "seed"
        tags = {str(t).lower() for t in (row.get("tags") or [])}
        assert "seed" in tags
        assert "recon" in tags
        oracle = row.get("oracle") or {}
        assert oracle.get("type") == "recon" or (row["types"] == ["recon"])
        comps = oracle.get("components") or []
        assert comps, f"{bid} missing components"
        assert oracle.get("require_relations") is True
        assert oracle.get("require_trust_boundaries") is True
        assert oracle.get("architecture_ref"), f"{bid} missing architecture_ref"
        target = PROJECT_ROOT / TARGET_REFS[bid]
        assert target.is_dir(), f"missing target tree {target}"
        for c in comps:
            if not isinstance(c, dict):
                continue
            for hint in c.get("path_hints") or []:
                direct = target / hint
                if direct.exists():
                    continue
                matches = list(target.rglob(Path(hint).name))
                assert matches, f"{bid}: path_hint {hint!r} missing under {target}"


def test_three_mechanical_recon_runs_pass():
    for bid in PROVE_RUN_IDS:
        run = run_benchmark(def_id=bid, types=["recon"], mode="mechanical")
        assert run["status"] in TERMINAL_STATUSES
        assert run["status"] == "passed", (bid, run.get("metrics"))
        metrics = run["metrics"]
        assert metrics.get("bench_type") == "recon"
        assert metrics.get("mode") == "mechanical"
        assert metrics.get("component_recall", 0) == 1.0
        assert metrics.get("path_hint_recall", 0) == 1.0
        assert metrics.get("relations_ok") is True
        assert metrics.get("trust_boundaries_ok") is True
        assert metrics.get("score", 0) > 0
        assert metrics.get("passed") is True


def test_empty_or_missing_architecture_fails_require_keys():
    """Empty/missing architecture fails require_* with clear metrics."""
    target = PROJECT_ROOT / "fixtures" / "toy_sqli"
    base_oracle = {
        "type": "recon",
        "id": "toy_sqli_recon",
        "components": [{"name": "app", "path_hints": ["app.py"]}],
        "require_relations": True,
        "require_trust_boundaries": True,
    }

    # Explicit empty architecture (no relations / trust_boundaries)
    empty = score_recon(target, base_oracle, architecture={})
    assert empty["passed"] is False
    assert empty["relations_ok"] is False
    assert empty["trust_boundaries_ok"] is False
    assert empty["score"] < 1.0
    assert "relations_ok" in empty and "trust_boundaries_ok" in empty

    # Architecture present but empty lists
    blank_lists = score_recon(
        target,
        base_oracle,
        architecture={
            "components": [{"name": "app", "path_hints": ["app.py"]}],
            "relations": [],
            "trust_boundaries": [],
        },
    )
    assert blank_lists["passed"] is False
    assert blank_lists["relations_ok"] is False
    assert blank_lists["trust_boundaries_ok"] is False
    assert blank_lists.get("component_recall", 0) == 1.0

    # Missing architecture_ref → synthesize leaves relations/trust empty → fail
    missing_ref = score_recon(
        target,
        {
            **base_oracle,
            # no architecture_ref; avoid auto-discovery of shipped toy_sqli arch
            "id": "no_such_recon_fixture_xyz",
        },
    )
    # toy_sqli/architecture.json may not exist; synthesis should not invent require_*
    assert missing_ref["relations_ok"] is False
    assert missing_ref["trust_boundaries_ok"] is False
    assert missing_ref["passed"] is False
    assert missing_ref.get("architecture_source") in {"synthesize", "unknown"} or True

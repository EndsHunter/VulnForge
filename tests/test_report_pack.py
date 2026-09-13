"""Library expansion ticket 4: report-writing pack (gold/overclaim/vacuous)."""

from __future__ import annotations

from pathlib import Path

from vulnforge.benchmarks import (
    TERMINAL_STATUSES,
    get_def,
    list_defs,
    run_benchmark,
    score_finding_report,
    seed_from_ground_truth,
)
from vulnforge.paths import PROJECT_ROOT

REPORT_PACK_IDS = (
    "report-toy_sqli-gold",
    "report-toy_sqli-overclaim",
    "report-toy_sqli-vacuous",
    "report-pe-sql-gold",
    "report-pe-jwt-gold",
    "report-pe-sql-overclaim",
    "report-vg-00319-gold",
    "report-vg-00080-gold",
    "report-vg-00447-gold",
    "report-vg-00319-vacuous",
)

EXPECT = {
    "report-toy_sqli-gold": (True, "gold"),
    "report-toy_sqli-overclaim": (False, "overclaim"),
    "report-toy_sqli-vacuous": (False, "vacuous_tm"),
    "report-pe-sql-gold": (True, "gold"),
    "report-pe-jwt-gold": (True, "gold"),
    "report-pe-sql-overclaim": (False, "overclaim"),
    "report-vg-00319-gold": (True, "gold"),
    "report-vg-00080-gold": (True, "gold"),
    "report-vg-00447-gold": (True, "gold"),
    "report-vg-00319-vacuous": (False, "vacuous_tm"),
}

TARGET_REFS = {
    "report-toy_sqli-gold": "fixtures/toy_sqli",
    "report-toy_sqli-overclaim": "fixtures/toy_sqli",
    "report-toy_sqli-vacuous": "fixtures/toy_sqli",
    "report-pe-sql-gold": "fixtures/profile_eval/tree",
    "report-pe-jwt-gold": "fixtures/profile_eval/tree",
    "report-pe-sql-overclaim": "fixtures/profile_eval/tree",
    "report-vg-00319-gold": "fixtures/report_benches/vg-00319",
    "report-vg-00080-gold": "fixtures/report_benches/vg-00080",
    "report-vg-00447-gold": "fixtures/report_benches/vg-00447",
    "report-vg-00319-vacuous": "fixtures/report_benches/vg-00319",
}


def test_report_pack_seeds_present():
    seed_from_ground_truth(missing_only=True)
    ids = {d["id"] for d in list_defs()}
    for bid in REPORT_PACK_IDS:
        assert bid in ids, bid
    variants = {EXPECT[b][1] for b in REPORT_PACK_IDS}
    assert variants == {"gold", "overclaim", "vacuous_tm"}
    for bid in REPORT_PACK_IDS:
        row = get_def(bid, include_oracle=True)
        assert row["types"] == ["finding_report"]
        assert row["target_ref"] == TARGET_REFS[bid]
        assert row["source"] == "seed"
        tags = {str(t).lower() for t in (row.get("tags") or [])}
        expect_pass, variant = EXPECT[bid]
        assert "seed" in tags
        assert "finding_report" in tags
        assert "report-pack" in tags
        assert variant in tags
        oracle = row.get("oracle") or {}
        assert oracle.get("type") == "finding_report"
        assert oracle.get("variant") == variant
        assert bool(oracle.get("expect_pass")) is expect_pass
        assert oracle.get("fixture_report_ref")
        ref = PROJECT_ROOT / str(oracle["fixture_report_ref"])
        assert ref.is_file(), ref
        assert (PROJECT_ROOT / TARGET_REFS[bid]).is_dir()


def test_report_pack_mechanical_runs_align_expect_pass():
    """All 10 runs terminal passed when accepted == expect_pass."""
    seed_from_ground_truth(missing_only=True)
    for bid in REPORT_PACK_IDS:
        expect_pass, variant = EXPECT[bid]
        run = run_benchmark(
            def_id=bid, types=["finding_report"], mode="mechanical"
        )
        assert run["status"] in TERMINAL_STATUSES
        metrics = run["metrics"]
        assert metrics.get("bench_type") == "finding_report"
        assert metrics.get("variant") == variant
        assert bool(metrics.get("expect_pass")) is expect_pass
        accepted = bool(metrics.get("accepted"))
        assert accepted is expect_pass, (bid, metrics)
        assert bool(metrics.get("passed")) is True
        assert run["status"] == "passed", (bid, metrics)
        if variant == "gold":
            assert accepted is True
            assert metrics.get("threat_model_ok") is True
            assert metrics.get("overclaim_ok") is True
        elif variant == "overclaim":
            assert accepted is False
            assert metrics.get("overclaim_ok") is False or metrics.get(
                "honesty_labels_recall", 1
            ) < 1
            flags = metrics.get("overclaim_flags") or []
            assert flags, (bid, metrics)
        elif variant == "vacuous_tm":
            assert accepted is False
            assert metrics.get("threat_model_ok") is False


def test_score_finding_report_variant_semantics_unit():
    gold = score_finding_report(
        None,
        {
            "type": "finding_report",
            "variant": "gold",
            "expect_pass": True,
            "required_fields": [
                "title",
                "summary",
                "weakness_class",
                "threat_model",
                "citations",
                "severity_claim",
            ],
            "min_citation_density": 1.0,
            "honesty_labels": ["severity_claim", "needs_human"],
            "fixture_report_ref": "fixtures/benchmarks/reports/report-toy_sqli-gold.json",
            "target": "fixtures/toy_sqli",
        },
        target=PROJECT_ROOT / "fixtures" / "toy_sqli",
    )
    assert gold["accepted"] is True
    assert gold["expect_pass"] is True
    assert gold["passed"] is True

    over = score_finding_report(
        None,
        {
            "type": "finding_report",
            "variant": "overclaim",
            "expect_pass": False,
            "required_fields": [
                "title",
                "summary",
                "weakness_class",
                "threat_model",
                "citations",
                "severity_claim",
            ],
            "min_citation_density": 1.0,
            "honesty_labels": ["severity_claim", "needs_human"],
            "fixture_report_ref": "fixtures/benchmarks/reports/report-toy_sqli-overclaim.json",
            "target": "fixtures/toy_sqli",
        },
        target=PROJECT_ROOT / "fixtures" / "toy_sqli",
    )
    assert over["accepted"] is False
    assert over["expect_pass"] is False
    assert over["passed"] is True
    assert over["overclaim_flags"]

    vac = score_finding_report(
        None,
        {
            "type": "finding_report",
            "variant": "vacuous_tm",
            "expect_pass": False,
            "required_fields": [
                "title",
                "summary",
                "weakness_class",
                "threat_model",
                "citations",
                "severity_claim",
            ],
            "min_citation_density": 1.0,
            "honesty_labels": ["severity_claim", "needs_human"],
            "fixture_report_ref": "fixtures/benchmarks/reports/report-toy_sqli-vacuous.json",
            "target": "fixtures/toy_sqli",
        },
        target=PROJECT_ROOT / "fixtures" / "toy_sqli",
    )
    assert vac["accepted"] is False
    assert vac["threat_model_ok"] is False
    assert vac["passed"] is True


def test_legacy_toy_sqli_finding_report_still_passes():
    run = run_benchmark(
        def_id="toy_sqli_finding_report",
        types=["finding_report"],
        mode="mechanical",
    )
    assert run["status"] == "passed"
    assert run["metrics"].get("accepted") is True
    assert run["metrics"].get("expect_pass") is True

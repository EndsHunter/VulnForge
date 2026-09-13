"""profile_eval pe-* hunt seeds (library expansion ticket 2)."""

from __future__ import annotations

from vulnforge.benchmarks import TERMINAL_STATUSES, get_def, list_defs, run_benchmark

PE_IDS = (
    "pe-jwt",
    "pe-cmd",
    "pe-crypto",
    "pe-upload",
    "pe-path",
    "pe-sql",
    "pe-sql-err",
    "pe-sql-union",
    "pe-xss",
    "pe-xss-store",
    "pe-ssrf",
    "pe-xxe",
)

PE_PATH_SUFFIX = {
    "pe-jwt": "unit_01.py",
    "pe-cmd": "unit_02.php",
    "pe-crypto": "unit_03.py",
    "pe-upload": "unit_04.php",
    "pe-path": "unit_05.php",
    "pe-sql": "unit_06.py",
    "pe-sql-err": "unit_07.php",
    "pe-sql-union": "unit_08.php",
    "pe-xss": "unit_10.php",
    "pe-xss-store": "unit_11.php",
    "pe-ssrf": "unit_16.js",
    "pe-xxe": "unit_13.php",
}

PE_DIFFICULTY = {
    "pe-jwt": "easy",
    "pe-sql": "easy",
    "pe-cmd": "medium",
    "pe-crypto": "medium",
    "pe-upload": "medium",
    "pe-path": "medium",
    "pe-sql-err": "medium",
    "pe-sql-union": "medium",
    "pe-xss": "medium",
    "pe-xss-store": "hard",
    "pe-ssrf": "hard",
    "pe-xxe": "hard",
}


def test_pe_hunt_seeds_present_after_ensure_library():
    defs = list_defs()
    hunts = [d for d in defs if "hunt" in (d.get("types") or [])]
    assert len(hunts) >= 18
    pe = sorted(d["id"] for d in hunts if str(d["id"]).startswith("pe-"))
    assert pe == sorted(PE_IDS)
    for bid in PE_IDS:
        row = get_def(bid)
        assert row["types"] == ["hunt"]
        assert row["target_ref"] == "fixtures/profile_eval/tree"
        assert row["source"] == "seed"
        findings = (row.get("oracle") or {}).get("findings") or []
        assert len(findings) == 1
        finding = findings[0]
        assert finding.get("id") == bid.removeprefix("pe-")
        match = finding.get("match") if isinstance(finding.get("match"), dict) else {}
        assert match.get("path_suffix") == PE_PATH_SUFFIX[bid]
        tags = {str(t).lower() for t in (row.get("tags") or [])}
        assert "profile_eval" in tags
        assert "seed" in tags
        overlay = row.get("config_overlay") or {}
        diff = overlay.get("difficulty")
        assert diff in {"easy", "medium", "hard"}
        assert diff == PE_DIFFICULTY[bid]


def test_toy_gt_seed_unchanged_without_difficulty_or_tags():
    """toy_sqli / mono_synth stay tags=['seed'] and empty overlay."""
    for bid in ("toy_sqli", "mono_synth"):
        row = get_def(bid)
        assert row["types"] == ["hunt"]
        assert row["source"] == "seed"
        assert row.get("config_overlay") == {}
        assert row.get("tags") == ["seed"]


def test_pe_sql_and_pe_jwt_mechanical_runs():
    for bid in ("pe-sql", "pe-jwt"):
        run = run_benchmark(def_id=bid, types=["hunt"], mode="mechanical")
        assert run["status"] in TERMINAL_STATUSES
        metrics = run["metrics"]
        assert isinstance(metrics, dict)
        assert "recall" in metrics
        assert "hit_count" in metrics
        assert "oracle_count" in metrics
        assert metrics["oracle_count"] >= 1
        assert run["status"] == "passed"
        assert metrics["recall"] > 0
        assert metrics.get("passed") is True

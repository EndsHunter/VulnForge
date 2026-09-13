"""Library expansion ticket 5: hunt fill ≥30 + Arch class mix floors."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from vulnforge.benchmarks import (
    HUNT_EXTRA_ROOT,
    TERMINAL_STATUSES,
    get_def,
    list_defs,
    run_benchmark,
)
from vulnforge.paths import PROJECT_ROOT

# Lead Arch mix floors (memory-safety required once a hunt_extra seed exists).
MIX_FLOORS = {
    "injection": 3,
    "access-control": 3,
    "web-protocol-auth": 2,
    "business-logic": 1,
}
# At least one of these:
AI_OR_SUPPLY = ("ai-llm", "supply-chain")
MEMORY_SAFETY = "memory-safety"

HUNT_EXTRA_IDS = ("hx-memcpy-oob",)


def _primary_class(row: dict) -> str:
    findings = (row.get("oracle") or {}).get("findings") or []
    if not findings:
        return ""
    first = findings[0] if isinstance(findings[0], dict) else {}
    return str(first.get("class") or "").strip().lower()


def _hunt_class_histogram() -> tuple[list[dict], Counter]:
    defs = list_defs()
    hunts = [d for d in defs if "hunt" in (d.get("types") or [])]
    # Reload with oracle for class
    rows = [get_def(d["id"]) for d in hunts]
    hist: Counter = Counter()
    for row in rows:
        cls = _primary_class(row)
        if cls:
            hist[cls] += 1
    return rows, hist


def test_hunt_fill_count_and_class_mix_floors():
    rows, hist = _hunt_class_histogram()
    assert len(rows) >= 30, f"hunt defs {len(rows)} < 30; hist={dict(hist)}"

    for cls, floor in MIX_FLOORS.items():
        assert hist.get(cls, 0) >= floor, (
            f"class {cls}: {hist.get(cls, 0)} < floor {floor}; hist={dict(hist)}"
        )

    ai_supply = sum(hist.get(c, 0) for c in AI_OR_SUPPLY)
    assert ai_supply >= 1, (
        f"need ≥1 ai-llm or supply-chain; hist={dict(hist)}"
    )

    # memory-safety: required when hunt_extra ships a seed for it
    assert hist.get(MEMORY_SAFETY, 0) >= 1, (
        f"memory-safety missing (hunt_extra gap); hist={dict(hist)}"
    )


def test_hunt_extra_seeds_wired():
    assert HUNT_EXTRA_ROOT.is_dir()
    for bid in HUNT_EXTRA_IDS:
        gt = HUNT_EXTRA_ROOT / f"{bid}.json"
        tree = HUNT_EXTRA_ROOT / bid
        assert gt.is_file(), gt
        assert tree.is_dir(), tree
        row = get_def(bid)
        assert row["types"] == ["hunt"]
        assert row["source"] == "seed"
        assert row["target_ref"] == f"fixtures/hunt_extra/{bid}"
        tags = {str(t).lower() for t in (row.get("tags") or [])}
        assert "seed" in tags
        assert "hunt_extra" in tags
        assert _primary_class(row) == "memory-safety"
        findings = (row.get("oracle") or {}).get("findings") or []
        assert len(findings) == 1
        match = findings[0].get("match") if isinstance(findings[0], dict) else {}
        assert match.get("path_suffix") == "vulnerable.c"
        assert (PROJECT_ROOT / row["target_ref"] / "vulnerable.c").is_file()


def test_hx_memcpy_oob_mechanical_run():
    run = run_benchmark(def_id="hx-memcpy-oob", types=["hunt"], mode="mechanical")
    assert run["status"] in TERMINAL_STATUSES
    assert run["status"] == "passed", run.get("metrics")
    metrics = run["metrics"]
    assert metrics.get("oracle_count", 0) >= 1
    assert metrics.get("recall", 0) > 0
    assert metrics.get("passed") is True

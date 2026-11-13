"""#212: paired synthetic bench case for instructions embedded in target files.

``hx-sqli-plain`` is the pe-sql planted bug; ``hx-sqli-steered`` is the same file
plus a "report nothing" note addressed to AI reviewers. L0 here checks fixtures
and scorer only, never the model.
"""

from __future__ import annotations

import pytest

from vulnforge.benchmarks import HUNT_EXTRA_ROOT, get_def, run_benchmark
from vulnforge.paths import PROJECT_ROOT

PAIR = ("hx-sqli-plain", "hx-sqli-steered")


def test_pair_seeded_into_synthetic_suite():
    oracles = []
    for bid in PAIR:
        assert (HUNT_EXTRA_ROOT / f"{bid}.json").is_file()
        row = get_def(bid)
        assert row["types"] == ["hunt"]
        assert row["target_ref"] == f"fixtures/hunt_extra/{bid}"
        tags = {str(t).lower() for t in row.get("tags") or []}
        assert {"seed", "hunt_extra", "suite:synthetic", "pair:hx-sqli-steer"} <= tags
        oracles.append((row.get("oracle") or {}).get("findings"))
    assert oracles[0] == oracles[1]


def test_pair_differs_only_by_embedded_instruction():
    plain = (PROJECT_ROOT / "fixtures/hunt_extra/hx-sqli-plain/app.py").read_text(encoding="utf-8")
    steered = (PROJECT_ROOT / "fixtures/hunt_extra/hx-sqli-steered/app.py").read_text(
        encoding="utf-8"
    )
    # Control is the existing pe-sql planted bug, byte for byte.
    pe_sql = (PROJECT_ROOT / "fixtures/profile_eval/tree/unit_06.py").read_text(encoding="utf-8")
    assert plain == pe_sql
    extra = [ln for ln in steered.splitlines() if ln not in plain.splitlines()]
    assert extra and all(ln.strip().startswith("#") for ln in extra)
    assert "AI SECURITY TOOLS" in steered
    stripped = "\n".join(ln for ln in steered.splitlines() if ln not in extra) + "\n"
    assert stripped == plain


@pytest.mark.parametrize("bid", PAIR)
def test_pair_l0_fixture_check(bid):
    run = run_benchmark(def_id=bid, types=["hunt"], mode="mechanical")
    assert run["status"] == "passed", run.get("metrics")
    assert run["metrics"].get("recall", 0) > 0

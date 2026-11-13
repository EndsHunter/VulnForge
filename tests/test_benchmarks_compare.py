"""State-aware live scoring, suite aggregates, run-vs-baseline compare, fingerprints.

Replaces test_benchmarks_series.py (the def-version compare and the
speed/accuracy scatter were removed in #204).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from vulnforge.benchmarks import (
    aggregate,
    compare_runs,
    create_run,
    fingerprint_diff,
    score_case,
    set_baseline,
    summarize_repeats,
    update_run,
)
from vulnforge.benchmarks.fingerprint import capture_fingerprint, endpoint_host, hash_tree
from vulnforge.ui.app import create_app

ORACLE = {
    "id": "o1",
    "sink_path": "app.py",
    "sink_symbol": "search_users",
    "match": {"path_suffix": "app.py", "symbol": "search_users"},
}
HIT_BODY = {
    "sink_path": "app.py",
    "sink_symbol": "search_users",
    "citations": [{"path": "app.py", "start_line": 12, "symbol": "search_users"}],
}
OTHER_BODY = {
    "sink_path": "other.py",
    "sink_symbol": "x",
    "citations": [{"path": "other.py", "start_line": 1, "symbol": "x"}],
}


def _f(fid, state, body):
    return SimpleNamespace(id=fid, state=state, body=body)


# ---------------------------------------------------------------- score_case


def test_score_case_gated_vs_raw_and_unmatched():
    sc = score_case(
        [_f(1, "needs_human", HIT_BODY), _f(2, "needs_human", OTHER_BODY), _f(3, "candidate", OTHER_BODY)],
        [ORACLE],
        usage={"total_tokens": 9000, "prompt_tokens": 8000, "completion_tokens": 1000, "llm_calls": 4},
    )
    assert sc["recall"] == 1.0 and sc["recall_raw"] == 1.0
    assert sc["hits"] == ["o1"] and sc["misses"] == []
    assert sc["matches"] == [{"oracle_id": "o1", "finding_id": 1, "state": "needs_human", "gated": True}]
    assert sc["unmatched"] == 1  # gated #2 only; candidate #3 never reached the gates
    assert sc["ungated_count"] == 1
    assert sc["extras"] == 2
    assert sc["tokens"]["total_tokens"] == 9000
    assert sc["confirmed"] is False
    assert sc["passed"] is True


def test_score_case_gate_loss_and_miss():
    lost = score_case([_f(1, "rejected_llm", HIT_BODY)], [ORACLE])
    assert lost["recall"] == 0.0 and lost["recall_raw"] == 1.0
    assert lost["raw_only"] == ["o1"]
    assert lost["matches"][0]["gated"] is False
    assert lost["unmatched"] == 0
    assert lost["passed"] is False
    miss = score_case([], [ORACLE])
    assert miss["misses"] == ["o1"] and miss["tokens"]["total_tokens"] == 0
    # Confirmed (human) counts as gated too, but the bench never sets it.
    assert score_case([_f(1, "confirmed", HIT_BODY)], [ORACLE])["hit_count"] == 1


# ------------------------------------------------------------- aggregates


def _member(def_id, repeat, hits, oracles, *, status="passed", unmatched=0, tokens=1000, wall=10.0, oh="h1"):
    return {
        "def_id": def_id,
        "run_id": f"br-{def_id}{repeat}",
        "repeat": repeat,
        "status": status,
        "oracle_hash": oh,
        "oracle_count": oracles,
        "hit_count": hits,
        "raw_hit_count": hits,
        "unmatched": unmatched,
        "tokens_total": tokens,
        "wall_s": wall,
        "hits": ["o1"] if hits else [],
        "raw_only": [],
        "misses": [] if hits else ["o1"],
    }


def test_aggregate_headline_and_errors_excluded():
    agg = aggregate(
        [
            _member("a", 0, 1, 1, unmatched=2, tokens=3000),
            _member("b", 0, 0, 1, tokens=1000),
            _member("c", 0, 0, 0, status="error", tokens=None),
        ]
    )
    assert agg["cases"] == 2 and agg["errors"] == 1
    assert agg["recall"] == 0.5
    assert agg["unmatched_per_target"] == 1.0
    assert agg["tokens_total"] == 4000
    assert agg["tokens_per_hit"] == 4000
    assert agg["wall_s"] == 20.0


def test_aggregate_without_tokens_is_none_not_zero():
    agg = aggregate([_member("a", 0, 0, 1, tokens=None)])
    assert agg["tokens_total"] is None and agg["tokens_per_hit"] is None


def test_summarize_repeats_spread():
    rows = [_member("a", 0, 1, 1), _member("b", 0, 1, 1), _member("a", 1, 1, 1), _member("b", 1, 0, 1)]
    s = summarize_repeats(rows)
    assert s["n_repeats"] == 2
    assert s["spread"]["recall"] == {"mean": 0.75, "min": 0.5, "max": 1.0}
    assert s["headline"]["recall"] == 0.75
    assert s["totals"]["oracle_count"] == 4


# ---------------------------------------------------------------- compare


def _suite_run(rid, members, *, fp=None, tier="directed", suite_id="synthetic"):
    return {
        "id": rid,
        "def_id": f"suite-{suite_id}",
        "suite_id": suite_id,
        "tier": tier,
        "fingerprint": fp or {},
        "metrics": {"suite": True, "members": members},
    }


def test_compare_flips_deltas_and_fingerprint_diff():
    a = _suite_run("br-a", [_member("a", 0, 1, 1), _member("b", 0, 0, 1)], fp={"model": "m1", "git_sha": "aaa"})
    b = _suite_run("br-b", [_member("a", 0, 0, 1), _member("b", 0, 1, 1, tokens=500)], fp={"model": "m2", "git_sha": "aaa"})
    out = compare_runs(a, b)
    assert out["comparable"] is True
    assert out["fingerprint_diff"] == [{"key": "model", "a": "m1", "b": "m2"}]
    assert out["counts"] == {"regression": 1, "gain": 1}
    flips = {f["def_id"]: f["change"] for f in out["flips"]}
    assert flips == {"a": "regression", "b": "gain"}
    assert out["flips"][0]["change"] == "regression"  # regressions sort first
    assert out["deltas"]["recall"] == 0.0
    assert out["deltas"]["tokens_per_hit"] == -500
    assert any("single run" in w for w in out["warnings"])


def test_compare_refuses_changed_oracle_tier_and_suite():
    a = _suite_run("br-a", [_member("a", 0, 1, 1, oh="h1")])
    b = _suite_run("br-b", [_member("a", 0, 1, 1, oh="h2")])
    out = compare_runs(a, b)
    assert out["comparable"] is False and "oracle changed" in out["refusal"]
    assert out["flips"] == [] and out["deltas"] == {}
    tier = compare_runs(a, _suite_run("br-c", [_member("a", 0, 1, 1)], tier="l0"))
    assert tier["comparable"] is False and "tier" in tier["refusal"]
    suite = compare_runs(a, _suite_run("br-d", [_member("a", 0, 1, 1)], suite_id="realworld"))
    assert suite["comparable"] is False


def test_compare_warns_on_case_set_difference():
    a = _suite_run("br-a", [_member("a", 0, 1, 1), _member("a", 1, 1, 1)])
    b = _suite_run("br-b", [_member("a", 0, 1, 1), _member("a", 1, 1, 1), _member("z", 0, 0, 1), _member("z", 1, 0, 1)])
    out = compare_runs(a, b)
    assert out["comparable"] is True
    assert any("case sets differ" in w for w in out["warnings"])
    assert not any("single run" in w for w in out["warnings"])
    assert {f["def_id"] for f in out["flips"]} == {"a"}


# ------------------------------------------------------------ fingerprint


def test_fingerprint_never_holds_keys_and_diffs(tmp_path):
    cfg = {"llm": {"base_url": "https://user:secret@api.example.com:8443/v1?x=1", "model": "m", "api_key": "sk-x"}}
    fp = capture_fingerprint(cfg, validate_llm=False)
    assert fp["endpoint_host"] == "api.example.com:8443"
    assert "secret" not in str(fp) and "sk-x" not in str(fp)
    assert fp["validate_llm"] is False
    assert fp["model"] == "m"
    assert endpoint_host("") == ""
    assert endpoint_host("127.0.0.1:11434") == "127.0.0.1:11434"
    assert fingerprint_diff(fp, dict(fp)) == []
    assert [d["key"] for d in fingerprint_diff(fp, {**fp, "validate_llm": True})] == ["validate_llm"]
    (tmp_path / "a.md").write_text("one", encoding="utf-8")
    h1 = hash_tree(tmp_path)
    (tmp_path / "a.md").write_text("two", encoding="utf-8")
    assert hash_tree(tmp_path) != h1
    assert hash_tree(tmp_path / "missing") == ""


# --------------------------------------------------------------- baselines


def _finished_suite(note=""):
    run = create_run(
        def_id="suite-synthetic",
        version=1,
        types_run=["hunt"],
        mode="live",
        status="running",
        suite_id="synthetic",
        tier="directed",
        fingerprint={"model": "m1"},
        note=note,
    )
    return update_run(
        run["id"],
        status="passed",
        metrics={"suite": True, "members": [_member("toy_sqli", 0, 1, 1)], "summary": summarize_repeats([_member("toy_sqli", 0, 1, 1)])},
    )


def test_baseline_api_and_scoreboard_cards(monkeypatch):
    clock = iter(f"2026-11-12T10:00:{i:02d}Z" for i in range(60))
    monkeypatch.setattr("vulnforge.benchmarks.runs.utc_now_iso", lambda: next(clock))
    base = _finished_suite("baseline")
    newer = _finished_suite("new prompt")
    app = create_app(runs_root=Path("/tmp/vf-bench-runs-unused"))
    with TestClient(app) as client:
        pinned = client.post(f"/api/benchmarks/runs/{base['id']}/baseline")
        assert pinned.status_code == 200, pinned.text
        assert pinned.json()["key"] == "synthetic:directed"
        detail = client.get(f"/api/benchmarks/runs/{newer['id']}").json()
        assert detail["baseline_id"] == base["id"]

        suites = client.get("/api/benchmarks/suites").json()
        syn = next(s for s in suites["suites"] if s["id"] == "synthetic")
        card = syn["runs"]["directed"]
        assert card["baseline_id"] == base["id"]
        assert card["latest"]["id"] == newer["id"]
        assert card["latest"]["headline"]["recall"] == 1.0
        assert [p["id"] for p in card["trend"]] == [base["id"], newer["id"]]
        assert {t["id"] for t in suites["tiers"]} == {"l0", "directed"}

        cmp = client.get("/api/benchmarks/compare", params={"a": base["id"], "b": newer["id"]})
        assert cmp.status_code == 200, cmp.text
        assert cmp.json()["comparable"] is True
        assert client.get("/api/benchmarks/compare").status_code == 400


def test_baseline_refuses_unfinished_and_single_case_runs():
    import pytest

    from vulnforge.benchmarks import BenchmarkRunError

    running = create_run(
        def_id="suite-synthetic", version=1, mode="live", status="running", suite_id="synthetic", tier="directed"
    )
    with pytest.raises(BenchmarkRunError, match="finished"):
        set_baseline(running["id"])
    single = create_run(def_id="toy_sqli", version=1, status="passed")
    with pytest.raises(BenchmarkRunError, match="suite"):
        set_baseline(single["id"])

"""Stage model routing + multi-model consensus helpers."""

from __future__ import annotations

from vulnforge.llm_models import (
    consensus_positive,
    consensus_referee_slots,
    multi_model_disprove_meta,
    normalize_model_list,
    resolve_stage_model,
    resolve_validate_models,
)


def test_normalize_model_list():
    assert normalize_model_list("a\nb, c\n") == ["a", "b", "c"]
    assert normalize_model_list(["x", "x", " y "]) == ["x", "y"]
    assert normalize_model_list(None) == []


def test_resolve_stage_and_validate_models():
    cfg = {
        "llm": {
            "model": "default-m",
            "model_recon": "recon-m",
            "model_hunt": "",
            "validate_models": ["v1", "v2"],
        }
    }
    assert resolve_stage_model(cfg, "recon") == "recon-m"
    assert resolve_stage_model(cfg, "hunt") == "default-m"
    assert resolve_stage_model(cfg, "develop_poc") == "default-m"
    assert resolve_validate_models(cfg) == ["v1", "v2"]
    assert resolve_validate_models({"llm": {"model": "only"}}) == ["only"]


def test_consensus_positive_majority_and_all():
    votes = ["signal_observed", "signal_observed", "signal_absent"]
    m = consensus_positive(votes, positive="signal_observed", mode="majority")
    assert m["agreed"] is True
    a = consensus_positive(votes, positive="signal_observed", mode="all")
    assert a["agreed"] is False


def test_consensus_referee_requires_agreement_for_observed():
    slots = [
        {"ok": True, "verdict": "signal_observed", "model_id": "a"},
        {"ok": True, "verdict": "signal_absent", "model_id": "b"},
    ]
    r = consensus_referee_slots(slots, mode="all")
    assert r["verdict"] != "signal_observed"
    slots2 = [
        {"ok": True, "verdict": "signal_observed", "model_id": "a"},
        {"ok": True, "verdict": "signal_observed", "model_id": "b"},
    ]
    r2 = consensus_referee_slots(slots2, mode="majority")
    assert r2["verdict"] == "signal_observed"
    assert r2["confidence"] in ("high", "medium")


def test_multi_model_disprove_meta():
    results = [
        {"model_id": "a", "verdict": "stand"},
        {"model_id": "a", "verdict": "stand"},
        {"model_id": "b", "verdict": "reject"},
        {"model_id": "b", "verdict": "reject"},
    ]
    meta = multi_model_disprove_meta(results, mode="majority")
    assert meta["models_total"] == 2
    assert meta["models_stand"] == 1
    assert meta["models_reject"] == 1
    assert "1/2" in meta["multi_model_label"]

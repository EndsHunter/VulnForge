"""Per-stage model routing and multi-model validation consensus.

Default model: ``llm.model``. Optional overrides:
  - ``llm.model_recon`` / ``model_hunt`` / ``model_develop_poc``
  - ``llm.validate_models`` — list of 1+ models for disprove / PoC referee

Consensus (for positive “valid” agreement — reduce false positives):
  - ``all`` — every model must agree on the positive verdict
  - ``majority`` — more than half must agree (default)

Rejection of a finding still requires unanimous reject across validation slots
(existing validate_llm behavior extended across models).
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional


STAGE_MODEL_KEYS: dict[str, str] = {
    "recon": "model_recon",
    "hunt": "model_hunt",
    "develop_poc": "model_develop_poc",
    # validation stages use validate_models list
    "validate_llm": "validate_models",
    "validate_poc": "validate_models",
    "poc_referee": "validate_models",
}

CONSENSUS_MODES = frozenset({"all", "majority"})


def normalize_model_list(raw: Any) -> list[str]:
    """Parse validate_models from list, comma/newline string, or empty."""
    out: list[str] = []
    if raw is None:
        return out
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, str):
        text = raw.replace(",", "\n")
        items = text.splitlines()
    else:
        return out
    seen: set[str] = set()
    for x in items:
        s = str(x).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def normalize_consensus(raw: Any) -> str:
    s = str(raw or "majority").strip().lower()
    return s if s in CONSENSUS_MODES else "majority"


def resolve_stage_model(cfg: dict | None, stage: str) -> str:
    """Single model id for recon/hunt/develop_poc (falls back to llm.model)."""
    llm = (cfg or {}).get("llm") or {}
    key = STAGE_MODEL_KEYS.get(stage or "")
    if key and key != "validate_models":
        override = str(llm.get(key) or "").strip()
        if override:
            return override
    return str(llm.get("model") or "").strip()


def resolve_validate_models(cfg: dict | None) -> list[str]:
    """1+ models for multi-LLM validation (disprove + PoC referee)."""
    llm = (cfg or {}).get("llm") or {}
    models = normalize_model_list(llm.get("validate_models"))
    if not models:
        default = str(llm.get("model") or "").strip()
        if default:
            models = [default]
    return models


def resolve_validate_consensus(cfg: dict | None) -> str:
    llm = (cfg or {}).get("llm") or {}
    return normalize_consensus(llm.get("validate_consensus"))


def cfg_with_model(cfg: dict, model: str | None) -> dict:
    """Shallow-deep copy of cfg with llm.model set (for make_client)."""
    if not model:
        return cfg
    out = deepcopy(cfg)
    out.setdefault("llm", {})["model"] = str(model).strip()
    return out


def make_client_for_stage(cfg: dict, stage: str):
    """LLM client bound to the stage's configured model."""
    from vulnforge.llm import make_client

    model = resolve_stage_model(cfg, stage)
    return make_client(cfg_with_model(cfg, model) if model else cfg)


def make_client_for_model(cfg: dict, model: str | None):
    """LLM client for an explicit model id (validate multi-model loops)."""
    from vulnforge.llm import make_client

    if model:
        return make_client(cfg_with_model(cfg, model))
    return make_client(cfg)


def consensus_positive(
    votes: list[str],
    *,
    positive: str,
    mode: str = "majority",
) -> dict[str, Any]:
    """Whether positive label wins under consensus rules.

    Used for signal_observed / stand-style agreement across models.
    Empty votes → not agreed.
    """
    mode = normalize_consensus(mode)
    cleaned = [str(v or "").strip().lower() for v in votes if v is not None]
    total = len(cleaned)
    if total == 0:
        return {
            "agreed": False,
            "positive_count": 0,
            "total": 0,
            "ratio": 0.0,
            "mode": mode,
            "label": "0/0",
        }
    pos = sum(1 for v in cleaned if v == positive)
    if mode == "all":
        agreed = pos == total
    else:
        agreed = pos > (total / 2.0)
    return {
        "agreed": agreed,
        "positive_count": pos,
        "total": total,
        "ratio": pos / total if total else 0.0,
        "mode": mode,
        "label": f"{pos}/{total}",
    }


def consensus_referee_slots(
    slots: list[dict[str, Any]],
    *,
    mode: str = "majority",
) -> dict[str, Any]:
    """Aggregate multi-model PoC referee slots into one verdict.

    False-positive-aware:
      - signal_observed only if consensus agrees on signal_observed
      - else if any signal_absent with no consensus observed → signal_absent
      - else if all poc_broken → poc_broken
      - else inconclusive
    """
    mode = normalize_consensus(mode)
    ok_slots = [s for s in slots if s.get("ok")]
    votes = [str(s.get("verdict") or "inconclusive").lower() for s in ok_slots]
    if not votes:
        return {
            "verdict": "inconclusive",
            "confidence": "low",
            "consensus": consensus_positive([], positive="signal_observed", mode=mode),
            "slots": slots,
            "reason": "no_successful_referees",
        }

    obs = consensus_positive(votes, positive="signal_observed", mode=mode)
    if obs["agreed"]:
        return {
            "verdict": "signal_observed",
            "confidence": "high" if obs["ratio"] >= 1.0 else "medium",
            "consensus": obs,
            "slots": slots,
            "reason": "consensus_signal_observed",
        }

    absent = consensus_positive(votes, positive="signal_absent", mode=mode)
    if absent["agreed"]:
        return {
            "verdict": "signal_absent",
            "confidence": "high" if absent["ratio"] >= 1.0 else "medium",
            "consensus": absent,
            "slots": slots,
            "reason": "consensus_signal_absent",
        }

    broken = sum(1 for v in votes if v == "poc_broken")
    if broken == len(votes):
        return {
            "verdict": "poc_broken",
            "confidence": "medium",
            "consensus": consensus_positive(votes, positive="poc_broken", mode=mode),
            "slots": slots,
            "reason": "all_poc_broken",
        }

    # Mixed / no clear consensus → inconclusive (do not claim observed)
    return {
        "verdict": "inconclusive",
        "confidence": "low",
        "consensus": obs,
        "slots": slots,
        "reason": "no_consensus",
        "vote_counts": {
            "signal_observed": sum(1 for v in votes if v == "signal_observed"),
            "signal_absent": sum(1 for v in votes if v == "signal_absent"),
            "poc_broken": broken,
            "inconclusive": sum(1 for v in votes if v == "inconclusive"),
            "unsafe_skipped": sum(1 for v in votes if v == "unsafe_skipped"),
        },
    }


def multi_model_disprove_meta(
    verifier_results: list[dict[str, Any]],
    *,
    mode: str = "majority",
) -> dict[str, Any]:
    """Extra multi-model stats for validate_llm body / Report.

    Groups by model_id; a model “stands” if any of its slots stood (could not kill).
    A model “rejects” only if all of its slots reject.
    """
    mode = normalize_consensus(mode)
    by_model: dict[str, list[str]] = {}
    for vr in verifier_results:
        mid = str(vr.get("model_id") or "unknown")
        v = str(vr.get("verdict") or "needs_human").lower()
        by_model.setdefault(mid, []).append(v)

    model_summaries: list[dict[str, Any]] = []
    stand_models = 0
    reject_models = 0
    for mid, verdicts in by_model.items():
        all_reject = all(v == "reject" for v in verdicts) and bool(verdicts)
        any_stand = any(v == "stand" for v in verdicts)
        if all_reject:
            reject_models += 1
            label = "reject"
        elif any_stand:
            stand_models += 1
            label = "stand"
        else:
            label = "needs_human"
        model_summaries.append(
            {
                "model_id": mid,
                "label": label,
                "slots": len(verdicts),
                "verdicts": verdicts,
            }
        )

    total_models = len(by_model)
    stand_cons = consensus_positive(
        ["stand" if m["label"] == "stand" else "other" for m in model_summaries],
        positive="stand",
        mode=mode,
    )
    return {
        "models": model_summaries,
        "models_total": total_models,
        "models_stand": stand_models,
        "models_reject": reject_models,
        "stand_consensus": stand_cons,
        "multi_model_label": f"{stand_models}/{total_models} models stand",
        "consensus_mode": mode,
    }

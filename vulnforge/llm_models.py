"""Per-stage model routing and multi-model validation consensus.

Default model: ``llm.model``. Optional overrides:
  - ``llm.model_recon`` / ``model_hunt`` / ``model_develop_poc``
  - ``llm.model_validate`` — dedicated validate_llm / PoC referee role
  - ``llm.validate_models`` — list of 1+ models for disprove / PoC referee

Validate slot rule (also :func:`resolve_validate_targets`): a non-empty
``validate_models`` list is the complete slot set. Otherwise ``model_validate``
when set. Otherwise the hunt role (``model_hunt``, else the default role).

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
    # Single-client binding uses the first resolved validate slot.
    "validate_llm": "model_validate",
    "validate_poc": "model_validate",
    "poc_referee": "model_validate",
}

# Stages whose client is the validate slot list, not a lone role key.
_VALIDATE_STAGES = frozenset({"validate_llm", "validate_poc", "poc_referee"})

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


def resolve_validate_consensus(cfg: dict | None) -> str:
    llm = (cfg or {}).get("llm") or {}
    return normalize_consensus(llm.get("validate_consensus"))


def cfg_with_model(cfg: dict, model: str | None) -> dict:
    """Deep copy of cfg with llm.model set (single-endpoint / no host list)."""
    if not model:
        return cfg
    out = deepcopy(cfg)
    out.setdefault("llm", {})["model"] = str(model).strip()
    return out


def _explicit_role(llm: dict, key: str) -> Any:
    """Host ref or legacy model id when ``llm[key]`` is set, else None."""
    from vulnforge.settings.catalog import is_model_ref

    raw = llm.get(key)
    if is_model_ref(raw):
        return {"host_id": str(raw["host_id"]).strip(), "model_id": str(raw["model_id"]).strip()}
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


def _default_role(llm: dict) -> Any:
    """Default role ref, else ``llm.model`` (may be empty)."""
    from vulnforge.settings.catalog import is_model_ref

    if is_model_ref(llm.get("model_ref")):
        ref = llm["model_ref"]
        return {"host_id": str(ref["host_id"]).strip(), "model_id": str(ref["model_id"]).strip()}
    return str(llm.get("model") or "").strip()


def resolve_stage_ref(cfg: dict | None, stage: str) -> Any:
    """Stage role value: a host ref, a legacy model id, or "" when unset.

    Recon, hunt, and develop PoC: an empty override falls back to the default
    role ref, then ``llm.model``. Validate stages return the first slot from
    :func:`resolve_validate_targets` (list, else dedicated role, else hunt).
    """
    llm = (cfg or {}).get("llm") or {}
    if (stage or "") in _VALIDATE_STAGES:
        targets = resolve_validate_targets(cfg)
        return targets[0] if targets else ""
    key = STAGE_MODEL_KEYS.get(stage or "")
    explicit = _explicit_role(llm, key) if key else None
    if explicit:
        return explicit
    return _default_role(llm)


def resolve_stage_model(cfg: dict | None, stage: str) -> str:
    """Single model id for recon/hunt/develop_poc (falls back to llm.model)."""
    from vulnforge.settings.catalog import model_id_of

    return model_id_of(resolve_stage_ref(cfg, stage))


# Kinds that call the validation list. One lease is one agent; the first
# validate target is the model id that lease counts against.
_VALIDATE_LEASE_KINDS = frozenset({"validate_llm", "validate_poc", "validate_poc_referee", "poc_referee"})
_KIND_LEASE_STAGE = {
    "recon": "recon",
    "hunt": "hunt",
    "develop_poc": "develop_poc",
    "validate_llm": "validate_llm",
    "validate_poc": "validate_poc",
    "validate_poc_referee": "poc_referee",
    "poc_referee": "poc_referee",
    # Rewrite cycles use the Develop PoC role. The session never confirms.
    "iterate_poc": "develop_poc",
}


def lease_pair(cfg: dict | None, kind: str, payload: dict | None = None) -> tuple[str, str]:
    """``(host_id, model_id)`` an in-flight lease counts against.

    Validation kinds use the first validate target. Other kinds use the stage
    role, then the default model. A legacy bare model id uses host ``""``.
    ``payload`` is accepted so the lease loop can pass the task body; the pair
    comes from the role, not the payload.
    """
    del payload
    from vulnforge.settings.catalog import host_id_of, is_model_ref, model_id_of

    if kind in _VALIDATE_LEASE_KINDS:
        targets = resolve_validate_targets(cfg)
        ref: Any = targets[0] if targets else ""
    else:
        ref = resolve_stage_ref(cfg, _KIND_LEASE_STAGE.get(kind or "", ""))
    if is_model_ref(ref):
        return host_id_of(ref), model_id_of(ref)
    return "", model_id_of(ref)


def lease_model_id(cfg: dict | None, kind: str, payload: dict | None = None) -> str:
    """Model id half of :func:`lease_pair`."""
    return lease_pair(cfg, kind, payload)[1]


def resolve_validate_targets(cfg: dict | None) -> list[Any]:
    """Validate / PoC referee slots. One rule:

    1. Non-empty ``llm.validate_models`` (host refs, or legacy ids) is the
       complete slot list. A set ``model_validate`` is not prepended.
    2. Else ``llm.model_validate`` when set — the dedicated referee role.
    3. Else the hunt role (``model_hunt``, else the default role / ``llm.model``).

    Blank dedicated role and an empty list keep campaigns on the hunt model
    (the default role when hunt is also blank). Each ref still binds through
    :func:`bind_role_cfg`; a bare id is not searched on another host.
    """
    from vulnforge.settings.catalog import is_model_ref

    llm = (cfg or {}).get("llm") or {}
    raw = llm.get("validate_models")
    items = raw if isinstance(raw, list) else []
    refs = [
        {"host_id": str(item["host_id"]).strip(), "model_id": str(item["model_id"]).strip()}
        for item in items
        if is_model_ref(item)
    ]
    if refs:
        return refs
    models = normalize_model_list(raw)
    if models:
        return models
    dedicated = _explicit_role(llm, "model_validate")
    if dedicated:
        return [dedicated]
    hunt = _explicit_role(llm, "model_hunt")
    if hunt:
        return [hunt]
    default = _default_role(llm)
    return [default] if default else []


def _role_pair(ref: Any) -> tuple[str, str]:
    from vulnforge.settings.catalog import host_id_of, is_model_ref, model_id_of

    if is_model_ref(ref):
        return host_id_of(ref), model_id_of(ref)
    return "", model_id_of(ref)


def format_model_ref(ref: Any) -> str:
    """``host/model`` when the ref names a host, else the model id."""
    host_id, model_id = _role_pair(ref)
    if not model_id:
        return "(unset)"
    if host_id:
        return f"{host_id}/{model_id}"
    return model_id


def validate_same_as_hunt(cfg: dict | None) -> bool:
    """True when every resolved validate slot is the hunt role."""
    targets = resolve_validate_targets(cfg)
    hunt = _role_pair(resolve_stage_ref(cfg, "hunt"))
    if not targets:
        return not hunt[1]
    return all(_role_pair(item) == hunt for item in targets)


def status_model_summary(cfg: dict | None) -> str:
    """One status line: resolved hunt model and validate slot(s)."""
    hunt = format_model_ref(resolve_stage_ref(cfg, "hunt"))
    targets = resolve_validate_targets(cfg)
    validate = ", ".join(format_model_ref(item) for item in targets) or "(unset)"
    return f"hunt={hunt} validate={validate}"


def resolve_validate_models(cfg: dict | None) -> list[str]:
    """1+ model ids for multi-LLM validation (disprove + PoC referee)."""
    from vulnforge.settings.catalog import model_id_of

    return [model_id_of(item) for item in resolve_validate_targets(cfg) if model_id_of(item)]


def bind_role_cfg(cfg: dict, ref: Any) -> dict:
    """Copy cfg so llm base_url, api_mode, api_key, and model come from one ref.

    No host list: a string model id only swaps ``llm.model`` (YAML single endpoint).
    Host list present: the ref must name that host and an available pair.
    A bare model id is refused — the same id on another host is not a fallback.
    """
    from vulnforge.llm import ConfigError
    from vulnforge.settings.catalog import (
        find_host,
        host_id_of,
        is_model_ref,
        model_id_of,
        pair_available,
    )

    llm = (cfg or {}).get("llm") or {}
    hosts = llm.get("hosts") or []
    if not hosts:
        return cfg_with_model(cfg, model_id_of(ref))

    model_id = model_id_of(ref)
    host_id = host_id_of(ref)
    if not model_id:
        raise ConfigError("model ref is empty")
    if not is_model_ref(ref):
        raise ConfigError(
            f"model {model_id!r} is not a host ref; refusing cross-host fallback"
        )
    host = find_host(hosts, host_id)
    if host is None:
        raise ConfigError(f"host {host_id!r} is not configured")
    if not pair_available(llm.get("available"), host_id, model_id):
        raise ConfigError(
            f"{model_id!r} on host {host_id!r} is not available"
        )
    out = deepcopy(cfg)
    bound = out.setdefault("llm", {})
    bound["base_url"] = str(host.get("base_url") or "").rstrip("/")
    bound["api_mode"] = host.get("api_mode") or "chat_completions"
    bound["api_key"] = host.get("api_key") if host.get("api_key") is not None else ""
    bound["model"] = model_id
    bound["model_ref"] = {"host_id": host_id, "model_id": model_id}
    bound["model_unbound"] = False
    from vulnforge.settings.catalog import resolve_pair_budgets

    budgets = resolve_pair_budgets(bound, host_id, model_id)
    bound["max_tokens"] = budgets["max_tokens"]
    bound["context_tokens"] = budgets["context_tokens"]
    return out


def cfg_for_stage(cfg: dict, stage: str) -> dict:
    """Cfg bound to the stage role, including that pair's token budgets.

    No host list: ``cfg`` unchanged (single endpoint; globals are the seed).
    Host list: ``bind_role_cfg``. An unavailable pair raises ``ConfigError``.
    """
    ref = resolve_stage_ref(cfg, stage)
    llm = (cfg or {}).get("llm") or {}
    if not llm.get("hosts") or not ref:
        return cfg
    return bind_role_cfg(cfg, ref)


def make_client_for_stage(cfg: dict, stage: str):
    """LLM client bound to the stage role's host, key, model, and budgets."""
    from vulnforge.llm import make_client

    ref = resolve_stage_ref(cfg, stage)
    if not ref:
        return make_client(cfg)
    return make_client(cfg, ref)


def make_client_for_model(cfg: dict, model: Any | None):
    """LLM client for an explicit role ref or legacy model id."""
    from vulnforge.llm import make_client

    if model:
        return make_client(cfg, model)
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

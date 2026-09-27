"""Multi-host catalog: hosts, discovered models, verified available pairs.

Role assignments are ``{host_id, model_id}`` refs. A bare model id is not a
ref. Resolution never searches another host for the same model id.

Per-pair agent budgets (``max_tokens``, ``context_tokens``) and the
concurrent-agent cap (``max_concurrent_agents``) live on the available row.
The cap key is ``(host_id, model_id)``: the same model id on two hosts can
differ. A missing knob is not written back. Token knobs fall back to the
global ui_settings seed at resolve time. A missing concurrent number falls
back to global ``max_concurrent_agents`` only — there is no separate
default-override map. An override on one pair never copies onto another
pair, another host, or back onto the globals.
``max_context_fraction`` stays global.
"""

from __future__ import annotations

import secrets
from typing import Any

from vulnforge.util import utc_now_iso

# Flat keys that mean "single endpoint" in ui_settings written before hosts.
FLAT_CONNECTION_KEYS = (
    "host",
    "port",
    "api_key",
    "api_mode",
    "model",
    "model_recon",
    "model_hunt",
    "model_develop_poc",
)

MIGRATED_HOST_ID = "default"

# Integers stored on an available row. Token knobs seed from the globals.
# ``max_concurrent_agents`` is the (host, model) lease cap; blank uses the global cap.
_PAIR_INT_KNOBS = ("max_tokens", "context_tokens", "max_concurrent_agents")
_TOKEN_BUDGET_KNOBS = ("max_tokens", "context_tokens")

# Used only when a legacy save names a connection field and omits the rest.
LEGACY_DEFAULT_HOST = "127.0.0.1"
LEGACY_DEFAULT_PORT = 1234
LEGACY_DEFAULT_MODEL = "ornith-1.0-35b"


def is_model_ref(value: Any) -> bool:
    """True for a non-empty ``{host_id, model_id}`` pair."""
    return (
        isinstance(value, dict)
        and bool(str(value.get("host_id") or "").strip())
        and bool(str(value.get("model_id") or "").strip())
    )


def model_ref(host_id: str, model_id: str) -> dict[str, str]:
    return {"host_id": str(host_id).strip(), "model_id": str(model_id).strip()}


def model_id_of(value: Any) -> str:
    """Model id string from a ref, a legacy string, or empty."""
    if isinstance(value, dict):
        return str(value.get("model_id") or "").strip()
    return str(value or "").strip()


def host_id_of(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("host_id") or "").strip()
    return ""


def coerce_role_ref(value: Any) -> Any:
    """Normalize one role field.

    Ref dict → ``{host_id, model_id}``. Non-empty string → legacy bare id.
    Empty → None.
    """
    if isinstance(value, dict):
        hid = str(value.get("host_id") or "").strip()
        mid = str(value.get("model_id") or "").strip()
        if hid and mid:
            return model_ref(hid, mid)
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    return None


def normalize_validate_entries(value: Any) -> list[Any]:
    """Validate-model list: refs and/or legacy bare strings. Deduped, order kept."""
    from vulnforge.llm_models import normalize_model_list

    if isinstance(value, str):
        return normalize_model_list(value)
    if not isinstance(value, list):
        return []
    out: list[Any] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if isinstance(item, dict):
            hid = str(item.get("host_id") or "").strip()
            mid = str(item.get("model_id") or "").strip()
            if not hid or not mid:
                continue
            key = ("ref", hid, mid)
            if key in seen:
                continue
            seen.add(key)
            out.append(model_ref(hid, mid))
            continue
        text = str(item or "").strip()
        if not text:
            continue
        key = ("str", "", text)
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _new_host_id(existing: set[str]) -> str:
    while True:
        hid = "h_" + secrets.token_hex(4)
        if hid not in existing:
            return hid


def normalize_host(raw: Any, *, existing_ids: set[str]) -> dict[str, Any]:
    """One host record. ``base_url`` or ``host``+``port``. API key stays on this host."""
    from vulnforge.settings.ui import (
        build_llm_base_url,
        normalize_api_key,
        normalize_api_mode,
    )

    if not isinstance(raw, dict):
        raise ValueError("host must be an object")
    hid = str(raw.get("id") or "").strip()
    if not hid:
        hid = _new_host_id(existing_ids)
    if hid in existing_ids:
        raise ValueError(f"duplicate host id {hid!r}")
    base = str(raw.get("base_url") or "").strip()
    host = str(raw.get("host") or "").strip()
    port = raw.get("port")
    if base:
        base_url = build_llm_base_url(base, port)
    elif host:
        base_url = build_llm_base_url(host, port)
    else:
        raise ValueError("host needs a base URL")
    existing_ids.add(hid)
    return {
        "id": hid,
        "base_url": base_url,
        "api_mode": normalize_api_mode(raw.get("api_mode")),
        "api_key": normalize_api_key(raw.get("api_key")),
    }


def normalize_hosts(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("hosts must be a list")
    existing: set[str] = set()
    return [normalize_host(item, existing_ids=existing) for item in value]


def normalize_catalog(value: Any) -> list[dict[str, str]]:
    """Discovered ``(host_id, model_id)`` pairs. Verification lives in available."""
    if not isinstance(value, list):
        return []
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        hid = str(item.get("host_id") or "").strip()
        mid = str(item.get("model_id") or "").strip()
        if not hid or not mid:
            continue
        key = (hid, mid)
        if key in seen:
            continue
        seen.add(key)
        out.append({"host_id": hid, "model_id": mid})
    return out


def normalize_model_concurrent_caps(value: Any) -> dict[str, dict[str, int]]:
    """Optional concurrent caps keyed by ``(host_id, model_id)``.

    Accepted shape: ``{host_id: {model_id: n}}``. A flat ``{model_id: n}``
    map is rejected (those values are not host maps). A blank, zero, or
    non-int inner value drops that pair so the global cap applies.
    """
    if not isinstance(value, dict):
        return {}
    out: dict[str, dict[str, int]] = {}
    for host_key, raw_models in value.items():
        if not isinstance(raw_models, dict):
            continue
        hid = str(host_key or "").strip()
        if not hid:
            continue
        inner: dict[str, int] = {}
        for model_key, raw in raw_models.items():
            mid = str(model_key or "").strip()
            if not mid:
                continue
            n = _budget_int(raw)
            if n is None:
                continue
            inner[mid] = n
        if inner:
            out[hid] = inner
    return out


def caps_from_available(available: Any) -> dict[str, dict[str, int]]:
    """Nested cap map from available rows that store a concurrent number."""
    out: dict[str, dict[str, int]] = {}
    if not isinstance(available, list):
        return out
    for item in available:
        if not isinstance(item, dict) or "max_concurrent_agents" not in item:
            continue
        hid = str(item.get("host_id") or "").strip()
        mid = str(item.get("model_id") or "").strip()
        n = _budget_int(item.get("max_concurrent_agents"))
        if not hid or not mid or n is None:
            continue
        out.setdefault(hid, {})[mid] = n
    return out


def merge_pair_caps(available: Any, caps: Any) -> dict[str, dict[str, int]]:
    """Row numbers win. A nested map fills pairs the rows do not name.

    A flat model-id map contributes nothing.
    """
    merged = normalize_model_concurrent_caps(caps)
    for hid, models in caps_from_available(available).items():
        bucket = merged.setdefault(hid, {})
        bucket.update(models)
    return merged


def apply_explicit_cap_map(available: list[dict[str, Any]], caps: Any) -> list[dict[str, Any]]:
    """Write a nested host→model map onto existing rows.

    A flat model-id map is rejected and leaves rows unchanged. A null or
    invalid inner value clears that pair. Pairs that are not available are
    not invented.
    """
    rows = [dict(row) for row in available if isinstance(row, dict)]
    if not isinstance(caps, dict) or not any(isinstance(v, dict) for v in caps.values()):
        return rows
    index = {
        (str(row.get("host_id") or "").strip(), str(row.get("model_id") or "").strip()): row
        for row in rows
    }
    for host_key, raw_models in caps.items():
        if not isinstance(raw_models, dict):
            continue
        hid = str(host_key or "").strip()
        if not hid:
            continue
        for model_key, raw in raw_models.items():
            mid = str(model_key or "").strip()
            row = index.get((hid, mid))
            if row is None:
                continue
            n = _budget_int(raw)
            if n is None:
                row.pop("max_concurrent_agents", None)
            else:
                row["max_concurrent_agents"] = n
    return rows


def absorb_missing_caps(available: list[dict[str, Any]], caps: Any) -> list[dict[str, Any]]:
    """Copy nested caps onto rows that have no concurrent number yet.

    Does not clear a stored number and does not add pairs. A flat map is ignored.
    """
    nested = normalize_model_concurrent_caps(caps)
    if not nested:
        return available
    out: list[dict[str, Any]] = []
    for row in available:
        updated = dict(row)
        if "max_concurrent_agents" not in updated:
            hid = str(updated.get("host_id") or "").strip()
            mid = str(updated.get("model_id") or "").strip()
            n = (nested.get(hid) or {}).get(mid)
            if n is not None:
                updated["max_concurrent_agents"] = n
        out.append(updated)
    return out


def effective_pair_cap(caps: Any, host_id: str, model_id: str, default: int) -> int:
    """Cap for one ``(host_id, model_id)``. No row → ``default`` (the global cap).

    A flat model-id map does not match. The same model id on another host
    does not match.
    """
    try:
        fallback = max(1, int(default or 1))
    except (TypeError, ValueError):
        fallback = 1
    hid = str(host_id or "").strip()
    mid = str(model_id or "").strip()
    table = normalize_model_concurrent_caps(caps)
    host_map = table.get(hid) or {}
    if not mid or mid not in host_map:
        return fallback
    return host_map[mid]


def configured_lease_pairs(source: Any) -> list[tuple[str, str]]:
    """Role ``(host_id, model_id)`` pairs in first-seen order.

    The same pair counts once. A bare model id uses host ``""``.
    """
    if not isinstance(source, dict):
        return []
    found: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(value: Any) -> None:
        if is_model_ref(value):
            pair = (
                str(value.get("host_id") or "").strip(),
                str(value.get("model_id") or "").strip(),
            )
        else:
            mid = model_id_of(value)
            if not mid:
                return
            pair = ("", mid)
        if not pair[1] or pair in seen:
            return
        seen.add(pair)
        found.append(pair)

    ref = source.get("model_ref")
    add(ref if is_model_ref(ref) else source.get("model"))
    for key in ("model_recon", "model_hunt", "model_develop_poc"):
        add(source.get(key))
    raw_validate = source.get("validate_models")
    if isinstance(raw_validate, list):
        for item in raw_validate:
            add(item)
    slots = source.get("hunt_perspectives")
    if isinstance(slots, list):
        for slot in slots:
            if isinstance(slot, dict):
                add(slot.get("model"))
    return found


def parallel_lease_ceiling(
    default_cap: int,
    caps: Any,
    pairs: list[tuple[str, str]],
) -> int:
    """How many leases can be in flight if every configured pair is at its cap.

    No configured pairs → ``default_cap`` (single pool). Each distinct
    ``(host, model)`` contributes its row cap or the global default once.
    """
    try:
        default_n = max(1, int(default_cap or 1))
    except (TypeError, ValueError):
        default_n = 1
    table = normalize_model_concurrent_caps(caps)
    total = 0
    seen: set[tuple[str, str]] = set()
    for hid, mid in pairs or []:
        pair = (str(hid or "").strip(), str(mid or "").strip())
        if not pair[1] or pair in seen:
            continue
        seen.add(pair)
        total += effective_pair_cap(table, pair[0], pair[1], default_n)
    if not seen:
        return default_n
    return max(1, total)


def ui_lease_ceiling(ui: Any) -> int:
    """Ralph worker ceiling from UI settings."""
    src = ui if isinstance(ui, dict) else {}
    return parallel_lease_ceiling(
        src.get("max_concurrent_agents") or 1,
        merge_pair_caps(src.get("available"), src.get("model_concurrent_caps")),
        configured_lease_pairs(src),
    )


def cfg_lease_ceiling(cfg: Any) -> int:
    """Ralph worker ceiling from a merged harness config."""
    src = cfg if isinstance(cfg, dict) else {}
    run = src.get("run") if isinstance(src.get("run"), dict) else {}
    llm = src.get("llm") if isinstance(src.get("llm"), dict) else {}
    return parallel_lease_ceiling(
        run.get("max_leases_parallel") or 1,
        merge_pair_caps(llm.get("available"), run.get("model_concurrent_caps")),
        configured_lease_pairs(llm),
    )


def _budget_int(value: Any) -> int | None:
    """Positive int, or None when the knob is blank / invalid (use the global seed)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        value = text
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n < 1:
        return None
    return n


def normalize_available(value: Any) -> list[dict[str, Any]]:
    """Verified pairs. Optional token budgets and a per-pair concurrent cap.

    Absent keys are not filled from the globals. Token seeds are applied in
    ``resolve_pair_budgets``. A missing concurrent number stays missing so
    the lease path can fall back to ``max_concurrent_agents``. Pair A cannot
    bleed onto pair B.
    """
    if not isinstance(value, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        hid = str(item.get("host_id") or "").strip()
        mid = str(item.get("model_id") or "").strip()
        if not hid or not mid:
            continue
        key = (hid, mid)
        if key in seen:
            continue
        seen.add(key)
        row: dict[str, Any] = {"host_id": hid, "model_id": mid}
        stamp = str(item.get("verified_at") or "").strip()
        if stamp:
            row["verified_at"] = stamp
        for knob in _PAIR_INT_KNOBS:
            n = _budget_int(item.get(knob)) if knob in item else None
            if n is not None:
                row[knob] = n
        out.append(row)
    return out


def apply_submitted_budgets(available: list[dict[str, Any]], submitted: Any) -> list[dict[str, Any]]:
    """Copy per-pair budget knobs onto pairs that already exist.

    Does not add or remove pairs (verification stays on the refresh/verify
    routes). A present null clears that knob back to the global seed. A
    missing key leaves the stored override alone. No pair's numbers are
    written onto a different ``(host_id, model_id)``.
    """
    if not isinstance(submitted, list):
        return list(available)
    incoming: dict[tuple[str, str], dict[str, Any]] = {}
    for item in submitted:
        if not isinstance(item, dict):
            continue
        hid = str(item.get("host_id") or "").strip()
        mid = str(item.get("model_id") or "").strip()
        if not hid or not mid:
            continue
        incoming[(hid, mid)] = item
    out: list[dict[str, Any]] = []
    for row in available:
        if not isinstance(row, dict):
            continue
        key = (str(row.get("host_id") or "").strip(), str(row.get("model_id") or "").strip())
        src = incoming.get(key)
        if src is None:
            out.append(dict(row))
            continue
        updated = dict(row)
        for knob in _PAIR_INT_KNOBS:
            if knob not in src:
                continue
            n = _budget_int(src.get(knob))
            if n is None:
                updated.pop(knob, None)
            else:
                updated[knob] = n
        out.append(updated)
    return out


def pair_budget_overrides(available: Any, host_id: str, model_id: str) -> dict[str, int]:
    """Stored overrides for this pair only. Empty when the pair has no knobs."""
    hid = str(host_id or "").strip()
    mid = str(model_id or "").strip()
    if not hid or not mid or not isinstance(available, list):
        return {}
    for item in available:
        if not isinstance(item, dict):
            continue
        if str(item.get("host_id") or "").strip() != hid:
            continue
        if str(item.get("model_id") or "").strip() != mid:
            continue
        out: dict[str, int] = {}
        for knob in _TOKEN_BUDGET_KNOBS:
            n = _budget_int(item.get(knob)) if knob in item else None
            if n is not None:
                out[knob] = n
        return out
    return {}


def resolve_pair_budgets(llm: dict[str, Any] | None, host_id: str, model_id: str) -> dict[str, int]:
    """``max_tokens`` and ``context_tokens`` for one verified pair.

    One-way rule: the available-row override wins per key. A missing key
    uses the global value already on ``llm`` (the seed from ui_settings).
    The seed is not written onto the pair. Pair A does not affect pair B.
    ``max_context_fraction`` is not resolved here; it stays on ``llm``.
    """
    src = llm if isinstance(llm, dict) else {}
    overrides = pair_budget_overrides(src.get("available"), host_id, model_id)

    def pick(key: str, default: int) -> int:
        if key in overrides:
            return overrides[key]
        try:
            n = int(src.get(key) or default)
        except (TypeError, ValueError):
            n = default
        return max(1, n)

    return {
        "max_tokens": pick("max_tokens", 4096),
        "context_tokens": pick("context_tokens", 32768),
    }


def pair_available(available: Any, host_id: str, model_id: str) -> bool:
    hid = str(host_id or "").strip()
    mid = str(model_id or "").strip()
    if not hid or not mid or not isinstance(available, list):
        return False
    for item in available:
        if not isinstance(item, dict):
            continue
        if str(item.get("host_id") or "").strip() == hid and str(item.get("model_id") or "").strip() == mid:
            return True
    return False


def find_host(hosts: Any, host_id: str) -> dict[str, Any] | None:
    hid = str(host_id or "").strip()
    if not hid or not isinstance(hosts, list):
        return None
    for host in hosts:
        if isinstance(host, dict) and str(host.get("id") or "").strip() == hid:
            return host
    return None


def is_flat_document(raw: Any) -> bool:
    """True when a saved file is the pre-hosts single endpoint and has no host list."""
    if not isinstance(raw, dict):
        return False
    hosts = raw.get("hosts")
    if isinstance(hosts, list) and hosts:
        return False
    if isinstance(raw.get("model"), dict):
        return False
    if "hosts" in raw and not any(k in raw for k in ("host", "port", "api_key", "api_mode")):
        # New shape, including an empty host list. A string model here is legacy residue.
        if isinstance(raw.get("model"), str) and str(raw.get("model") or "").strip():
            return True
        return False
    return any(k in raw for k in FLAT_CONNECTION_KEYS)


def _collect_flat_model_ids(raw: dict[str, Any]) -> list[str]:
    """Model ids the flat file actually named, in stable order."""
    from vulnforge.llm_models import normalize_model_list
    from vulnforge.settings.ui import normalize_hunt_perspectives

    out: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        text = str(value or "").strip()
        if not text or text in seen:
            return
        seen.add(text)
        out.append(text)

    add(raw.get("model"))
    for key in ("model_recon", "model_hunt", "model_develop_poc"):
        add(raw.get(key))
    for mid in normalize_model_list(raw.get("validate_models")):
        add(mid)
    for slot in normalize_hunt_perspectives(raw.get("hunt_perspectives")):
        add(slot.get("model"))
    return out


def _ref_or_none(host_id: str, value: Any) -> Any:
    text = str(value or "").strip()
    if not text:
        return None
    return model_ref(host_id, text)


def migrate_flat_settings(raw: dict[str, Any], *, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """One-way: one host, verified role models, role fields rewritten to refs.

    Models named in the flat file are marked verified so an existing hunt lease
    still resolves. Other discovered models are not invented.
    """
    from vulnforge.settings.ui import (
        build_llm_base_url,
        normalize_api_key,
        normalize_api_mode,
        normalize_hunt_perspectives,
    )

    src = dict(raw or {})
    host_field = str(src.get("host") or LEGACY_DEFAULT_HOST).strip() or LEGACY_DEFAULT_HOST
    port = src.get("port", LEGACY_DEFAULT_PORT)
    model = str(src.get("model") or "").strip()
    if "model" not in src:
        model = LEGACY_DEFAULT_MODEL
    host = {
        "id": MIGRATED_HOST_ID,
        "base_url": build_llm_base_url(host_field, port),
        "api_mode": normalize_api_mode(src.get("api_mode")),
        "api_key": normalize_api_key(src.get("api_key")),
    }
    src = dict(src)
    src["model"] = model
    ids = _collect_flat_model_ids(src)
    stamp = utc_now_iso()
    catalog = [{"host_id": host["id"], "model_id": mid} for mid in ids]
    available = [
        {"host_id": host["id"], "model_id": mid, "verified_at": stamp} for mid in ids
    ]
    perspectives = []
    for slot in normalize_hunt_perspectives(src.get("hunt_perspectives")):
        item = {"id": slot["id"], "prompt": slot["prompt"], "model": ""}
        ref = _ref_or_none(host["id"], slot.get("model"))
        if ref:
            item["model"] = ref
        perspectives.append(item)

    from vulnforge.llm_models import normalize_model_list

    validate_refs = [
        model_ref(host["id"], mid) for mid in normalize_model_list(src.get("validate_models"))
    ]
    out = dict(base or {})
    out.update(
        {
            "hosts": [host],
            "catalog": catalog,
            "available": available,
            "model": _ref_or_none(host["id"], model),
            "model_recon": _ref_or_none(host["id"], src.get("model_recon")),
            "model_hunt": _ref_or_none(host["id"], src.get("model_hunt")),
            "model_develop_poc": _ref_or_none(host["id"], src.get("model_develop_poc")),
            "validate_models": validate_refs,
            "hunt_perspectives": perspectives,
        }
    )
    return out


def merge_refresh(
    catalog: list[dict[str, str]],
    available: list[dict[str, str]],
    host_id: str,
    listed_ids: list[str],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Replace one host's discovered ids. Keep verified only if the id is still listed."""
    listed: list[str] = []
    seen: set[str] = set()
    for raw in listed_ids:
        mid = str(raw or "").strip()
        if not mid or mid in seen:
            continue
        seen.add(mid)
        listed.append(mid)
    hid = str(host_id).strip()
    kept_catalog = [c for c in catalog if c.get("host_id") != hid]
    kept_available = [a for a in available if a.get("host_id") != hid]
    prev = {
        str(a.get("model_id") or ""): a
        for a in available
        if a.get("host_id") == hid
    }
    new_catalog = kept_catalog + [{"host_id": hid, "model_id": mid} for mid in listed]
    new_available = list(kept_available)
    for mid in listed:
        old = prev.get(mid)
        if old:
            new_available.append(dict(old))
    return new_catalog, new_available


def mark_available(
    available: list[dict[str, Any]],
    host_id: str,
    model_id: str,
    *,
    when: str | None = None,
) -> list[dict[str, Any]]:
    hid = str(host_id).strip()
    mid = str(model_id).strip()
    old: dict[str, Any] | None = None
    kept: list[dict[str, Any]] = []
    for row in available:
        if row.get("host_id") == hid and row.get("model_id") == mid:
            old = row
            continue
        kept.append(row)
    fresh: dict[str, Any] = {"host_id": hid, "model_id": mid, "verified_at": when or utc_now_iso()}
    if isinstance(old, dict):
        for knob in _PAIR_INT_KNOBS:
            if knob in old:
                fresh[knob] = old[knob]
    kept.append(fresh)
    return kept


def drop_host_records(
    catalog: list[dict[str, str]],
    available: list[dict[str, str]],
    host_id: str,
    *,
    drop_catalog: bool,
    drop_available: bool,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    hid = str(host_id).strip()
    if drop_catalog:
        catalog = [c for c in catalog if c.get("host_id") != hid]
    if drop_available:
        available = [a for a in available if a.get("host_id") != hid]
    return catalog, available


def sync_catalog_for_host_edit(
    old_hosts: list[dict[str, Any]],
    new_hosts: list[dict[str, Any]],
    catalog: list[dict[str, str]],
    available: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Drop pairs whose host disappeared, changed URL, or changed key/mode.

    A URL change drops discovery and verification. A key or mode change drops
    verification only (the model list may still be right; it must be verified again).
    """
    old_by = {str(h.get("id") or ""): h for h in old_hosts if isinstance(h, dict)}
    new_ids = {str(h.get("id") or "") for h in new_hosts}
    for hid in list(old_by):
        if hid not in new_ids:
            catalog, available = drop_host_records(
                catalog, available, hid, drop_catalog=True, drop_available=True
            )
    for host in new_hosts:
        hid = str(host.get("id") or "")
        old = old_by.get(hid)
        if not old:
            continue
        if str(old.get("base_url") or "") != str(host.get("base_url") or ""):
            catalog, available = drop_host_records(
                catalog, available, hid, drop_catalog=True, drop_available=True
            )
        elif (
            str(old.get("api_key") or "") != str(host.get("api_key") or "")
            or str(old.get("api_mode") or "") != str(host.get("api_mode") or "")
        ):
            catalog, available = drop_host_records(
                catalog, available, hid, drop_catalog=False, drop_available=True
            )
    return catalog, available


def require_available_ref(value: Any, available: list[dict[str, str]], *, label: str) -> Any:
    """Role value once hosts exist. Empty is allowed. Bare strings are not."""
    if value in (None, "", {}):
        return None
    if isinstance(value, str):
        if value.strip():
            raise ValueError(f"{label} must be a verified host model, not a free-text id")
        return None
    ref = coerce_role_ref(value)
    if ref is None:
        return None
    if not isinstance(ref, dict):
        raise ValueError(f"{label} must be a verified host model, not a free-text id")
    if not pair_available(available, ref["host_id"], ref["model_id"]):
        raise ValueError(
            f"{label} {ref['model_id']!r} on host {ref['host_id']!r} is not available"
        )
    return ref


def clear_unavailable_perspective_models(
    slots: list[dict[str, Any]],
    available: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Keep perspective ids. A model ref that is not available is an error."""
    out: list[dict[str, Any]] = []
    for slot in slots:
        item = dict(slot)
        model = item.get("model")
        if model in (None, "", {}):
            item["model"] = ""
        else:
            item["model"] = require_available_ref(
                model, available, label=f"hunt perspective {item.get('id')!r}"
            ) or ""
        out.append(item)
    return out

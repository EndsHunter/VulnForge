"""
Runtime LLM / agent settings (GUI + env overrides).

Stored at: <PROJECT_ROOT>/config/ui_settings.json
Merged on top of config/default.yaml by ``vulnforge.settings.load.load_config``.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from vulnforge.paths import CONFIG_ROOT, PROJECT_ROOT
from vulnforge.util import utc_now_iso

UI_SETTINGS_PATH = CONFIG_ROOT / "ui_settings.json"

# LLM HTTP API surface (OpenAI chat.completions / responses / Anthropic messages)
API_MODES = frozenset({"chat_completions", "responses", "messages"})
DEFAULT_API_MODE = "chat_completions"

# Sentinel strings operators may type when no key is needed (local LM Studio, etc.)
_NO_API_KEY = frozenset({"", "none", "null", "n/a", "na", "blank", "-"})

# Fields the dashboard may edit.
# Connection identity lives on ``hosts`` (per-host URL, api_mode, api_key).
# Role fields are ``{host_id, model_id}`` refs or null. Empty stage refs mean
# "use the default role". ``catalog`` is discovered ids; ``available`` is verified.
DEFAULT_UI_SETTINGS: dict[str, Any] = {
    "hosts": [],
    "catalog": [],
    "available": [],
    "model": None,
    "model_recon": None,
    "model_hunt": None,
    "model_develop_poc": None,
    # Refs once hosts exist; legacy bare strings only when hosts is empty.
    "validate_models": [],
    # all | majority — required agreement for positive “valid” signals
    "validate_consensus": "majority",
    # Run multi-model PoC referee after harness execution (default on)
    "validate_poc_referee": True,
    # Dual-LLM disprove after mech pass (default on — multi-model FP reduction)
    "validate_llm": True,
    # Hunt MoA (issue #72). Default off. Empty perspectives → keep YAML /
    # built-in slots; a non-empty list replaces llm.hunt_perspectives.
    # Per-slot model is a role ref (or blank). It is not copied from validate_models.
    "hunt_moa": False,
    "hunt_perspectives": [],
    "max_concurrent_agents": 1,
    # Seed for a verified pair with no max_tokens / context_tokens override.
    # Fraction stays global. See vulnforge.settings.catalog.resolve_pair_budgets.
    "context_tokens": 32768,
    "max_context_fraction": 0.25,
    "max_tokens": 4096,
    "max_tool_rounds": 12,
    "timeout_seconds": 600,
    "max_tasks": 50,
}

_ROLE_KEYS = ("model", "model_recon", "model_hunt", "model_develop_poc")
_GLOBAL_KEYS = (
    "validate_consensus",
    "validate_poc_referee",
    "validate_llm",
    "hunt_moa",
    "max_concurrent_agents",
    "context_tokens",
    "max_context_fraction",
    "max_tokens",
    "max_tool_rounds",
    "timeout_seconds",
    "max_tasks",
)


def normalize_api_mode(value: Any) -> str:
    """Map UI / config aliases to a canonical api_mode string."""
    raw = str(value or DEFAULT_API_MODE).strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "chat_completions": "chat_completions",
        "chat_completion": "chat_completions",
        "chatcompletions": "chat_completions",
        "completions": "chat_completions",
        "openai": "chat_completions",
        "responses": "responses",
        "response": "responses",
        "messages": "messages",
        "message": "messages",
        "anthropic": "messages",
    }
    mode = aliases.get(raw, raw)
    if mode not in API_MODES:
        return DEFAULT_API_MODE
    return mode


def normalize_api_key(value: Any) -> str:
    """Return a usable API key string, or \"\" when blank/none is intended.

    Empty, None, and common placeholders (none, null, n/a, blank) mean no key.
    """
    if value is None:
        return ""
    s = str(value).strip()
    if s.lower() in _NO_API_KEY:
        return ""
    return s


def build_llm_base_url(host: Any, port: Any = None) -> str:
    """Build an OpenAI-compatible base URL from UI host + port.

    Accepts either classic local settings::

        host=10.0.0.232, port=1234  →  http://10.0.0.232:1234/v1

    or a full endpoint (http or https), hostname or IP::

        https://random.something           →  https://random.something/v1
        https://random.something/v1        →  https://random.something/v1
        https://api.example.com/openai/v1  →  https://api.example.com/openai/v1
        http://10.0.0.5:8080             →  http://10.0.0.5:8080/v1

    When the host field includes a scheme (``http://`` / ``https://``), the
    separate port field is ignored (use ``:port`` in the URL if needed).
    Empty path gets ``/v1``; any non-empty path is kept as the API root.
    """
    raw = (str(host).strip() if host is not None else "") or "127.0.0.1"

    if "://" in raw:
        u = urlparse(raw)
        scheme = (u.scheme or "https").lower()
        if scheme not in ("http", "https"):
            scheme = "https"
        netloc = u.netloc
        path = (u.path or "").rstrip("/")
        # urlparse("https://host") → path ""; ("https://host/") → "/"
        if not path:
            path = "/v1"
        # Preserve query/fragment? Not meaningful for base_url — drop them.
        return urlunparse((scheme, netloc, path, "", "", "")).rstrip("/")

    # Bare host or host:port (no scheme) → http://host:port/v1
    host_only = raw
    try:
        p = int(port) if port is not None and str(port).strip() != "" else 1234
    except (TypeError, ValueError):
        p = 1234
    p = max(1, min(65535, p))

    # Allow "host:port" embedded in the host field (IPv4 / hostname only).
    # IPv6 literals use [addr]:port — leave those alone unless bracketed.
    if host_only.startswith("[") and "]" in host_only:
        # [2001:db8::1] or [2001:db8::1]:1234
        bracket_end = host_only.find("]")
        rest = host_only[bracket_end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            p = int(rest[1:])
            host_only = host_only[: bracket_end + 1]
    elif host_only.count(":") == 1:
        left, right = host_only.rsplit(":", 1)
        if left and right.isdigit():
            host_only = left
            p = int(right)

    host_only = host_only.strip() or "127.0.0.1"
    return f"http://{host_only}:{p}/v1"


def settings_path() -> Path:
    return UI_SETTINGS_PATH


def _coerce_bool(value: Any, default: bool) -> bool:
    """Parse a settings flag. The string ``\"false\"`` is false, not true."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off", ""}:
        return False
    return default


def normalize_hunt_perspectives(value: Any) -> list[dict[str, str]]:
    """Normalize Settings slots to ``{id, prompt, model}``.

    Mirrors ``llm.hunt_perspectives`` (id, prompt, optional model). Blank model
    is stored as ``\"\"`` and omitted when applied onto config. Rows without an
    id are dropped. Duplicate ids keep the first row. Empty input is ``[]``,
    which means "do not override YAML". This does not read ``validate_models``.
    """
    from vulnforge.stages.hunt_moa import default_hunt_perspective_prompt

    raw = value
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return []
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        pid = str(item.get("id") or "").strip()
        if not pid or pid in seen:
            continue
        seen.add(pid)
        prompt = str(item.get("prompt") or "").strip()
        if not prompt:
            prompt = default_hunt_perspective_prompt(pid)
        model = _coerce_perspective_model(item.get("model"))
        out.append({"id": pid, "prompt": prompt, "model": model})
    return out


def _coerce_perspective_model(value: Any) -> Any:
    """Blank, a legacy model id string, or a ``{host_id, model_id}`` ref."""
    from vulnforge.settings.catalog import is_model_ref, model_ref

    if isinstance(value, dict):
        if is_model_ref(value):
            return model_ref(str(value.get("host_id") or ""), str(value.get("model_id") or ""))
        return ""
    return str(value or "").strip()


def _hunt_perspectives_for_cfg(slots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop blank per-slot models so resolve treats them as unset."""
    cleaned: list[dict[str, Any]] = []
    for slot in slots:
        item: dict[str, Any] = {"id": slot["id"], "prompt": slot["prompt"]}
        model = _coerce_perspective_model(slot.get("model"))
        if model:
            item["model"] = model
        cleaned.append(item)
    return cleaned


def _blank_settings() -> dict[str, Any]:
    data = dict(DEFAULT_UI_SETTINGS)
    data["hosts"] = []
    data["catalog"] = []
    data["available"] = []
    data["validate_models"] = []
    data["hunt_perspectives"] = []
    return data


def _read_settings_file() -> dict[str, Any] | None:
    p = settings_path()
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return raw if isinstance(raw, dict) else None


def _write_settings(current: dict[str, Any]) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    persist = {k: current[k] for k in DEFAULT_UI_SETTINGS}
    persist["updated_at"] = current.get("updated_at") or utc_now_iso()
    path.write_text(json.dumps(persist, indent=2) + "\n", encoding="utf-8")


def load_ui_settings() -> dict[str, Any]:
    data = _blank_settings()
    raw = _read_settings_file()
    if raw is None:
        return _normalize_ui_settings(data)
    from vulnforge.settings.catalog import is_flat_document, migrate_flat_settings

    if is_flat_document(raw):
        merged = dict(raw)
        for key in _GLOBAL_KEYS:
            if key not in merged and key in data:
                merged[key] = data[key]
        data = migrate_flat_settings(merged, base=data)
        for key in _GLOBAL_KEYS:
            if key in raw:
                data[key] = raw[key]
        data = _normalize_ui_settings(data)
        data["updated_at"] = utc_now_iso()
        _write_settings(data)
        return data
    data.update({k: raw[k] for k in DEFAULT_UI_SETTINGS if k in raw})
    return _normalize_ui_settings(data)


def _normalize_ui_settings(current: dict[str, Any]) -> dict[str, Any]:
    """Coerce types for UI settings (shared by load + save)."""
    from vulnforge.llm_models import normalize_consensus
    from vulnforge.settings.catalog import (
        coerce_role_ref,
        normalize_available,
        normalize_catalog,
        normalize_hosts,
        normalize_validate_entries,
    )

    current["max_concurrent_agents"] = max(1, int(current.get("max_concurrent_agents") or 1))
    current["context_tokens"] = max(1, int(current.get("context_tokens") or 32768))
    frac = float(current.get("max_context_fraction") if current.get("max_context_fraction") is not None else 0.25)
    if frac <= 0:
        frac = 0.01
    if frac > 1:
        frac = 1.0
    current["max_context_fraction"] = frac
    current["max_tokens"] = max(1, int(current.get("max_tokens") or 4096))
    current["max_tool_rounds"] = max(1, int(current.get("max_tool_rounds") or 12))
    current["timeout_seconds"] = max(1, int(current.get("timeout_seconds") or 600))
    current["max_tasks"] = max(1, int(current.get("max_tasks") or 50))
    try:
        current["hosts"] = normalize_hosts(current.get("hosts") or [])
    except ValueError:
        current["hosts"] = []
    current["catalog"] = normalize_catalog(current.get("catalog"))
    current["available"] = normalize_available(current.get("available"))
    for key in _ROLE_KEYS:
        current[key] = coerce_role_ref(current.get(key))
    current["validate_models"] = normalize_validate_entries(current.get("validate_models"))
    current["validate_consensus"] = normalize_consensus(current.get("validate_consensus"))
    current["validate_poc_referee"] = bool(current.get("validate_poc_referee", True))
    current["validate_llm"] = bool(current.get("validate_llm", True))
    current["hunt_moa"] = _coerce_bool(current.get("hunt_moa"), False)
    current["hunt_perspectives"] = normalize_hunt_perspectives(current.get("hunt_perspectives"))
    return current


def _legacy_connection_update(updates: dict[str, Any]) -> bool:
    return "hosts" not in updates and any(
        k in updates for k in ("host", "port", "model", "api_mode", "api_key")
    )


def _apply_legacy_connection(current: dict[str, Any], updates: dict[str, Any]) -> None:
    """Fold a pre-hosts save into the host list.

    No hosts yet → one-way migrate (default model verified when a model id is present).
    Hosts already saved → update that host's URL / mode / key. Do not invent a role
    from a free-text model id.
    """
    from vulnforge.settings.catalog import (
        LEGACY_DEFAULT_HOST,
        LEGACY_DEFAULT_MODEL,
        LEGACY_DEFAULT_PORT,
        find_host,
        migrate_flat_settings,
    )

    if not current.get("hosts"):
        flat = {
            "host": updates.get("host", LEGACY_DEFAULT_HOST),
            "port": updates.get("port", LEGACY_DEFAULT_PORT),
            "api_mode": updates.get("api_mode", DEFAULT_API_MODE),
            "api_key": updates.get("api_key", ""),
            "model": updates.get("model", LEGACY_DEFAULT_MODEL),
            "model_recon": updates.get("model_recon", current.get("model_recon") or ""),
            "model_hunt": updates.get("model_hunt", current.get("model_hunt") or ""),
            "model_develop_poc": updates.get(
                "model_develop_poc", current.get("model_develop_poc") or ""
            ),
            "validate_models": updates.get("validate_models", current.get("validate_models") or []),
            "hunt_perspectives": updates.get(
                "hunt_perspectives", current.get("hunt_perspectives") or []
            ),
        }
        if "model" in updates:
            flat["model"] = str(updates.get("model") or "").strip()
        migrated = migrate_flat_settings(flat, base=current)
        current["hosts"] = migrated["hosts"]
        current["catalog"] = migrated["catalog"]
        current["available"] = migrated["available"]
        current["model"] = migrated["model"]
        current["model_recon"] = migrated["model_recon"]
        current["model_hunt"] = migrated["model_hunt"]
        current["model_develop_poc"] = migrated["model_develop_poc"]
        current["validate_models"] = migrated["validate_models"]
        current["hunt_perspectives"] = migrated["hunt_perspectives"]
        return

    from vulnforge.settings.catalog import drop_host_records

    ref = current.get("model") if isinstance(current.get("model"), dict) else None
    host = find_host(current.get("hosts"), ref.get("host_id")) if ref else None
    if host is None:
        hosts = current.get("hosts") or []
        host = hosts[0] if len(hosts) == 1 else None
    if host is None:
        return
    url_changed = False
    if any(k in updates for k in ("host", "port")):
        host_field = updates.get("host", host.get("base_url"))
        port = updates.get("port")
        new_url = build_llm_base_url(host_field, port)
        url_changed = new_url != host.get("base_url")
        host["base_url"] = new_url
    mode_changed = False
    if "api_mode" in updates:
        mode = normalize_api_mode(updates.get("api_mode"))
        mode_changed = mode != host.get("api_mode")
        host["api_mode"] = mode
    if "api_key" in updates:
        host["api_key"] = normalize_api_key(updates.get("api_key"))
    # Key-only edits keep verification so an existing lease still resolves.
    # A different URL or API mode must be verified again.
    if url_changed or mode_changed:
        catalog, available = drop_host_records(
            list(current.get("catalog") or []),
            list(current.get("available") or []),
            str(host.get("id") or ""),
            drop_catalog=url_changed,
            drop_available=True,
        )
        current["catalog"] = catalog
        current["available"] = available
        _clear_dangling_roles(current)


def _invalidate_dropped_roles(current: dict[str, Any], previous_available: list[dict[str, Any]]) -> None:
    """Clear refs that this save just unverified. Other missing refs still error."""
    prev = {
        (str(a.get("host_id") or ""), str(a.get("model_id") or ""))
        for a in previous_available
        if isinstance(a, dict)
    }
    now = {
        (str(a.get("host_id") or ""), str(a.get("model_id") or ""))
        for a in (current.get("available") or [])
        if isinstance(a, dict)
    }
    dropped = prev - now
    if not dropped:
        return

    def dropped_ref(ref: Any) -> bool:
        from vulnforge.settings.catalog import is_model_ref

        return (
            is_model_ref(ref)
            and (str(ref.get("host_id") or ""), str(ref.get("model_id") or "")) in dropped
        )

    for key in _ROLE_KEYS:
        if dropped_ref(current.get(key)):
            current[key] = None
    current["validate_models"] = [
        item for item in (current.get("validate_models") or []) if not dropped_ref(item)
    ]
    for slot in current.get("hunt_perspectives") or []:
        if dropped_ref(slot.get("model")):
            slot["model"] = ""


def _clear_dangling_roles(current: dict[str, Any]) -> None:
    """Drop role refs whose pair is no longer available. Blank means use default / YAML."""
    from vulnforge.settings.catalog import is_model_ref, pair_available

    available = current.get("available") or []

    def live(ref: Any) -> bool:
        return is_model_ref(ref) and pair_available(available, ref["host_id"], ref["model_id"])

    for key in _ROLE_KEYS:
        ref = current.get(key)
        if is_model_ref(ref) and not live(ref):
            current[key] = None
    kept = []
    for item in current.get("validate_models") or []:
        if is_model_ref(item) and live(item):
            kept.append(item)
        elif isinstance(item, str) and item.strip() and not current.get("hosts"):
            kept.append(item.strip())
    current["validate_models"] = kept
    for slot in current.get("hunt_perspectives") or []:
        model = slot.get("model")
        if is_model_ref(model) and not live(model):
            slot["model"] = ""


def _validate_roles_against_available(current: dict[str, Any]) -> None:
    """Once hosts exist, every non-empty role must be an available pair."""
    from vulnforge.settings.catalog import (
        clear_unavailable_perspective_models,
        require_available_ref,
    )

    if not current.get("hosts"):
        return
    available = current.get("available") or []
    for key, label in (
        ("model", "default model"),
        ("model_recon", "recon model"),
        ("model_hunt", "hunt model"),
        ("model_develop_poc", "develop PoC model"),
    ):
        current[key] = require_available_ref(current.get(key), available, label=label)
    refs = []
    for item in current.get("validate_models") or []:
        ref = require_available_ref(item, available, label="validation model")
        if ref:
            refs.append(ref)
    current["validate_models"] = refs
    current["hunt_perspectives"] = clear_unavailable_perspective_models(
        current.get("hunt_perspectives") or [], available
    )


def save_ui_settings(updates: dict[str, Any]) -> dict[str, Any]:
    from vulnforge.settings.catalog import (
        apply_submitted_budgets,
        coerce_role_ref,
        normalize_available,
        normalize_catalog,
        normalize_hosts,
        normalize_validate_entries,
        sync_catalog_for_host_edit,
    )

    current = load_ui_settings()
    if not isinstance(updates, dict):
        updates = {}
    legacy = _legacy_connection_update(updates)
    apply_roles = True
    previous_available = list(current.get("available") or [])

    if "hosts" in updates and updates.get("hosts") is not None:
        old_hosts = list(current.get("hosts") or [])
        new_hosts = normalize_hosts(updates.get("hosts") or [])
        catalog, available = sync_catalog_for_host_edit(
            old_hosts,
            new_hosts,
            list(current.get("catalog") or []),
            list(current.get("available") or []),
        )
        current["hosts"] = new_hosts
        current["catalog"] = catalog
        current["available"] = available
        if not new_hosts:
            current["catalog"] = []
            current["available"] = []
            for key in _ROLE_KEYS:
                current[key] = None
            current["validate_models"] = []
            for slot in current.get("hunt_perspectives") or []:
                slot["model"] = ""
    elif legacy:
        _apply_legacy_connection(current, updates)
        # Migration already rewrote role strings into refs for this payload.
        apply_roles = False

    if "catalog" in updates and "hosts" not in updates:
        current["catalog"] = normalize_catalog(updates.get("catalog"))
    if "available" in updates and "hosts" not in updates:
        current["available"] = normalize_available(updates.get("available"))
    elif "available" in updates:
        # Hosts were saved in this request, so the verified set came from
        # sync above. Only the per-pair budget knobs travel with the form.
        current["available"] = normalize_available(
            apply_submitted_budgets(list(current.get("available") or []), updates.get("available"))
        )

    if apply_roles:
        for key in _ROLE_KEYS:
            if key in updates:
                current[key] = coerce_role_ref(updates.get(key))
        if "validate_models" in updates:
            current["validate_models"] = normalize_validate_entries(updates.get("validate_models"))
        if "hunt_perspectives" in updates:
            current["hunt_perspectives"] = normalize_hunt_perspectives(
                updates.get("hunt_perspectives")
            )
    if "hunt_moa" in updates:
        current["hunt_moa"] = _coerce_bool(updates.get("hunt_moa"), False)
    for key in ("validate_poc_referee", "validate_llm"):
        if key in updates:
            current[key] = bool(updates.get(key))
    for key in (
        "validate_consensus",
        "max_concurrent_agents",
        "context_tokens",
        "max_context_fraction",
        "max_tokens",
        "max_tool_rounds",
        "timeout_seconds",
        "max_tasks",
    ):
        if key in updates and updates[key] is not None:
            current[key] = updates[key]

    current = _normalize_ui_settings(current)
    if "hosts" in updates:
        _invalidate_dropped_roles(current, previous_available)
    _validate_roles_against_available(current)
    current["updated_at"] = utc_now_iso()
    _write_settings(current)
    return current


def _apply_globals(out: dict, ui: dict[str, Any]) -> None:
    llm = out.setdefault("llm", {})
    llm["context_tokens"] = int(ui.get("context_tokens") or llm.get("context_tokens") or 32768)
    llm["max_context_fraction"] = float(
        ui.get("max_context_fraction")
        if ui.get("max_context_fraction") is not None
        else llm.get("max_context_fraction") or 0.25
    )
    llm["max_tokens"] = int(ui.get("max_tokens") or llm.get("max_tokens") or 4096)
    llm["max_tool_rounds"] = int(ui.get("max_tool_rounds") or llm.get("max_tool_rounds") or 12)
    llm["timeout_seconds"] = int(ui.get("timeout_seconds") or llm.get("timeout_seconds") or 600)
    from vulnforge.llm_models import normalize_consensus

    llm["validate_consensus"] = normalize_consensus(ui.get("validate_consensus"))
    stages = out.setdefault("stages", {})
    stages["validate_poc_referee"] = bool(ui.get("validate_poc_referee", True))
    stages["validate_llm"] = bool(ui.get("validate_llm", True))
    stages["hunt_moa"] = _coerce_bool(ui.get("hunt_moa"), False)
    run = out.setdefault("run", {})
    run["max_leases_parallel"] = max(1, int(ui.get("max_concurrent_agents") or 1))
    run["max_tasks"] = int(ui.get("max_tasks") or run.get("max_tasks") or 50)


def _bind_default_host(llm: dict, ui: dict[str, Any]) -> None:
    """Point llm.base_url/api_key/api_mode/model at the default role's host.

    A missing host or a pair that is not available does not borrow another host.
    """
    from vulnforge.settings.catalog import find_host, is_model_ref, pair_available

    hosts = ui.get("hosts") or []
    llm["hosts"] = hosts
    llm["available"] = list(ui.get("available") or [])
    llm["catalog"] = list(ui.get("catalog") or [])
    ref = ui.get("model") if is_model_ref(ui.get("model")) else None
    llm["model_ref"] = ref
    if ref is None:
        llm["model_unbound"] = True
        return
    host = find_host(hosts, ref["host_id"])
    if host is None or not pair_available(ui.get("available"), ref["host_id"], ref["model_id"]):
        llm["model"] = ref["model_id"]
        llm["model_unbound"] = True
        return
    llm["base_url"] = host["base_url"]
    llm["api_mode"] = host.get("api_mode") or DEFAULT_API_MODE
    llm["api_key"] = host.get("api_key") or ""
    llm["model"] = ref["model_id"]
    llm["model_unbound"] = False


def apply_ui_settings_to_cfg(cfg: dict, ui: Optional[dict] = None) -> dict:
    """Deep-merge UI settings into a harness config dict (returns new dict).

    No hosts (UI never saved a connection) → YAML ``llm`` URL / model / key stay.
    Hosts present → the default role binds that host's URL, mode, and key.
    """
    out = deepcopy(cfg)
    ui = ui if ui is not None else load_ui_settings()
    llm = out.setdefault("llm", {})
    hosts = ui.get("hosts") or []
    if hosts:
        _bind_default_host(llm, ui)
        for key in ("model_recon", "model_hunt", "model_develop_poc"):
            ref = ui.get(key)
            llm[key] = ref if isinstance(ref, dict) else ""
        llm["validate_models"] = list(ui.get("validate_models") or [])
    else:
        # Legacy string roles (no host list). Empty lists do not wipe YAML.
        from vulnforge.llm_models import normalize_model_list

        for key in ("model_recon", "model_hunt", "model_develop_poc"):
            raw = ui.get(key)
            if isinstance(raw, str) and raw.strip():
                llm[key] = raw.strip()
        validate = ui.get("validate_models") or []
        if validate:
            llm["validate_models"] = normalize_model_list(validate)
    hunt_slots = normalize_hunt_perspectives(ui.get("hunt_perspectives"))
    if hunt_slots:
        llm["hunt_perspectives"] = _hunt_perspectives_for_cfg(hunt_slots)
    _apply_globals(out, ui)
    out["_ui_settings"] = ui
    return out

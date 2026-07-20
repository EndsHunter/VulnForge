"""
Runtime LLM / agent settings (GUI + env overrides).

Stored at: <PROJECT_ROOT>/config/ui_settings.json
Merged on top of config/default.yaml by load_runtime_config().
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

from vulnforge.util import utc_now_iso

PROJECT_ROOT = Path(__file__).resolve().parents[1]
UI_SETTINGS_PATH = PROJECT_ROOT / "config" / "ui_settings.json"

# LLM HTTP API surface (OpenAI chat.completions / responses / Anthropic messages)
API_MODES = frozenset({"chat_completions", "responses", "messages"})
DEFAULT_API_MODE = "chat_completions"

# Sentinel strings operators may type when no key is needed (local LM Studio, etc.)
_NO_API_KEY = frozenset({"", "none", "null", "n/a", "na", "blank", "-"})

# Fields the dashboard may edit
DEFAULT_UI_SETTINGS: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 1234,
    "model": "ornith-1.0-35b@4bit",
    "api_mode": DEFAULT_API_MODE,
    # Optional; blank / none / null → no Authorization header (local servers).
    "api_key": "",
    "max_concurrent_agents": 1,
    "context_tokens": 32768,
    "max_context_fraction": 0.25,
    "max_tokens": 4096,
    "max_tool_rounds": 12,
    "timeout_seconds": 600,
    "max_tasks": 50,
}


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


def load_ui_settings() -> dict[str, Any]:
    data = dict(DEFAULT_UI_SETTINGS)
    p = settings_path()
    if p.is_file():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                data.update({k: raw[k] for k in DEFAULT_UI_SETTINGS if k in raw})
        except (OSError, json.JSONDecodeError):
            pass
    return data


def save_ui_settings(updates: dict[str, Any]) -> dict[str, Any]:
    current = load_ui_settings()
    for k in DEFAULT_UI_SETTINGS:
        if k not in updates:
            continue
        # api_key may be cleared with "" / "none"; other fields ignore null only
        if k == "api_key":
            current[k] = normalize_api_key(updates[k])
        elif updates[k] is not None:
            current[k] = updates[k]
    # normalize types — only floor invalid/zero values; no artificial ceilings
    current["port"] = max(1, min(65535, int(current["port"])))
    current["max_concurrent_agents"] = max(1, int(current["max_concurrent_agents"]))
    current["context_tokens"] = max(1, int(current["context_tokens"]))
    frac = float(current["max_context_fraction"])
    # Allow full context use; clamp only out-of-range floats
    if frac <= 0:
        frac = 0.01
    if frac > 1:
        frac = 1.0
    current["max_context_fraction"] = frac
    current["max_tokens"] = max(1, int(current["max_tokens"]))
    current["max_tool_rounds"] = max(1, int(current["max_tool_rounds"]))
    current["timeout_seconds"] = max(1, int(current["timeout_seconds"]))
    current["max_tasks"] = max(1, int(current["max_tasks"]))
    current["host"] = str(current["host"]).strip().rstrip("/")
    current["model"] = str(current["model"]).strip()
    current["api_mode"] = normalize_api_mode(current.get("api_mode"))
    current["api_key"] = normalize_api_key(current.get("api_key"))
    current["updated_at"] = utc_now_iso()
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    return current


def apply_ui_settings_to_cfg(cfg: dict, ui: Optional[dict] = None) -> dict:
    """Deep-merge UI settings into a harness config dict (returns new dict)."""
    out = deepcopy(cfg)
    ui = ui if ui is not None else load_ui_settings()
    host = ui.get("host") or "127.0.0.1"
    port = ui.get("port") or 1234
    base = build_llm_base_url(host, port)
    llm = out.setdefault("llm", {})
    llm["base_url"] = base
    llm["model"] = ui.get("model") or llm.get("model")
    llm["api_mode"] = normalize_api_mode(
        ui.get("api_mode") if ui.get("api_mode") is not None else llm.get("api_mode")
    )
    # UI always owns api_key when settings are applied (blank/none → empty string).
    if "api_key" in ui:
        llm["api_key"] = normalize_api_key(ui.get("api_key"))
    llm["context_tokens"] = int(ui.get("context_tokens") or llm.get("context_tokens") or 32768)
    llm["max_context_fraction"] = float(
        ui.get("max_context_fraction")
        if ui.get("max_context_fraction") is not None
        else llm.get("max_context_fraction") or 0.25
    )
    llm["max_tokens"] = int(ui.get("max_tokens") or llm.get("max_tokens") or 4096)
    llm["max_tool_rounds"] = int(ui.get("max_tool_rounds") or llm.get("max_tool_rounds") or 12)
    llm["timeout_seconds"] = int(ui.get("timeout_seconds") or llm.get("timeout_seconds") or 600)
    run = out.setdefault("run", {})
    run["max_leases_parallel"] = max(1, int(ui.get("max_concurrent_agents") or 1))
    run["max_tasks"] = int(ui.get("max_tasks") or run.get("max_tasks") or 50)
    out["_ui_settings"] = ui
    return out

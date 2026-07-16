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

from vulnforge.util import utc_now_iso

PROJECT_ROOT = Path(__file__).resolve().parents[1]
UI_SETTINGS_PATH = PROJECT_ROOT / "config" / "ui_settings.json"

# LLM HTTP API surface (OpenAI chat.completions / responses / Anthropic messages)
API_MODES = frozenset({"chat_completions", "responses", "messages"})
DEFAULT_API_MODE = "chat_completions"

# Fields the dashboard may edit
DEFAULT_UI_SETTINGS: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 1234,
    "model": "ornith-1.0-35b@4bit",
    "api_mode": DEFAULT_API_MODE,
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
        if k in updates and updates[k] is not None:
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
    current["host"] = str(current["host"]).strip()
    current["model"] = str(current["model"]).strip()
    current["api_mode"] = normalize_api_mode(current.get("api_mode"))
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
    port = int(ui.get("port") or 1234)
    base = f"http://{host}:{port}/v1"
    llm = out.setdefault("llm", {})
    llm["base_url"] = base
    llm["model"] = ui.get("model") or llm.get("model")
    llm["api_mode"] = normalize_api_mode(
        ui.get("api_mode") if ui.get("api_mode") is not None else llm.get("api_mode")
    )
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

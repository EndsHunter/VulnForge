"""Load harness runtime config (yaml + UI + env).

Precedence (later wins)::

    config/default.yaml
      < config/ui_settings.json
        < env VF_*
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from vulnforge.paths import CONFIG_ROOT, PROJECT_ROOT


def load_config(path: Optional[Path] = None) -> dict[str, Any]:
    """Load YAML config, merge UI settings, then apply VF_* env overrides."""
    cfg_path = path or (CONFIG_ROOT / "default.yaml")
    cfg_path = Path(cfg_path)
    if not cfg_path.is_file():
        raise FileNotFoundError(f"config not found: {cfg_path}")
    with cfg_path.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    try:
        from vulnforge.settings import apply_ui_settings_to_cfg, load_ui_settings

        cfg = apply_ui_settings_to_cfg(cfg, load_ui_settings())
    except Exception:
        pass
    if os.environ.get("VF_BASE_URL"):
        cfg.setdefault("llm", {})["base_url"] = os.environ["VF_BASE_URL"]
    if os.environ.get("VF_MODEL"):
        cfg.setdefault("llm", {})["model"] = os.environ["VF_MODEL"]
    if os.environ.get("VF_HOST") and os.environ.get("VF_PORT"):
        cfg.setdefault("llm", {})["base_url"] = (
            f"http://{os.environ['VF_HOST']}:{os.environ['VF_PORT']}/v1"
        )
    cfg["_config_path"] = str(cfg_path.resolve())
    return cfg


def default_config_path() -> Path:
    return CONFIG_ROOT / "default.yaml"


__all__ = ["PROJECT_ROOT", "load_config", "default_config_path"]

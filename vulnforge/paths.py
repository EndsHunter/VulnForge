"""Single source of truth for project filesystem roots.

Import from here instead of re-declaring ``Path(__file__).resolve().parents[N]``.
"""

from __future__ import annotations

from pathlib import Path

# Package lives at <root>/vulnforge/paths.py → parents[1] is the project root.
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]
CONFIG_ROOT: Path = PROJECT_ROOT / "config"
# Package seed library (reseed source). Runtime authority is seeds/.
SEEDS_ROOT: Path = PROJECT_ROOT / "seeds"


def system_prompts_root() -> Path:
    """Directory of stage/system markdown (preamble, PRINCIPLES, disprove*, …)."""
    return SEEDS_ROOT / "system"


def hunt_class_seeds_root() -> Path:
    """Package seed bodies for hunt skills (reseed source only)."""
    return SEEDS_ROOT / "hunt_classes"


def recon_agent_seeds_root() -> Path:
    """Package seed bodies for recon agents (reseed source only)."""
    return SEEDS_ROOT / "recon_agents"


def prompt_overrides_root() -> Path:
    """Optional operator overrides for system prompts (basename.md)."""
    return CONFIG_ROOT / "prompts" / "overrides"


def effective_prompt_pin_root() -> Path:
    """Root hashed at ``vf init`` for prompt_pin."""
    return SEEDS_ROOT

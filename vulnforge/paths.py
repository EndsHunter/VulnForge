"""Single source of truth for project filesystem roots.

Import from here instead of re-declaring ``Path(__file__).resolve().parents[N]``.
"""

from __future__ import annotations

from pathlib import Path

# Package lives at <root>/vulnforge/paths.py → parents[1] is the project root.
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]
CONFIG_ROOT: Path = PROJECT_ROOT / "config"
# Package seed library (reseed source). Prefer seeds/; fall back to prompts/v1.
SEEDS_ROOT: Path = PROJECT_ROOT / "seeds"
# Historical path; only used when seeds/ is not populated.
LEGACY_PROMPTS_V1: Path = PROJECT_ROOT / "prompts" / "v1"


def system_prompts_root() -> Path:
    """Directory of stage/system markdown (preamble, PRINCIPLES, disprove*, …).

    Prefer ``seeds/system`` when present; otherwise ``prompts/v1`` (legacy layout).
    """
    seeds_sys = SEEDS_ROOT / "system"
    if seeds_sys.is_dir() and any(seeds_sys.glob("*.md")):
        return seeds_sys
    return LEGACY_PROMPTS_V1


def hunt_class_seeds_root() -> Path:
    """Package seed bodies for hunt skills (reseed source only)."""
    seeds = SEEDS_ROOT / "hunt_classes"
    if seeds.is_dir() and any(seeds.glob("*.md")):
        return seeds
    return LEGACY_PROMPTS_V1 / "hunt_classes"


def recon_agent_seeds_root() -> Path:
    """Package seed bodies for recon agents (reseed source only)."""
    seeds = SEEDS_ROOT / "recon_agents"
    if seeds.is_dir() and any(seeds.glob("*.md")):
        return seeds
    return LEGACY_PROMPTS_V1 / "recon_agents"


def prompt_overrides_root() -> Path:
    """Optional operator overrides for system prompts (basename.md)."""
    return CONFIG_ROOT / "prompts" / "overrides"


def effective_prompt_pin_root() -> Path:
    """Root hashed at ``vf init`` for prompt_pin.

    Prefers the full ``seeds/`` tree when populated; else legacy ``prompts/v1``.
    """
    if SEEDS_ROOT.is_dir() and (SEEDS_ROOT / "system").is_dir():
        if any((SEEDS_ROOT / "system").glob("*.md")):
            return SEEDS_ROOT
    return LEGACY_PROMPTS_V1

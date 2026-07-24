"""Operator-editable hunt skill generator prompt (generate_skill.md).

Package seed: seeds/system/generate_skill.md
Operator override: config/prompts/generate_skill.md
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from vulnforge.packet import load_prompt_slice
from vulnforge.paths import CONFIG_ROOT, PROJECT_ROOT, system_prompts_root

PACKAGE_PROMPTS = system_prompts_root()
OVERRIDE_DIR = CONFIG_ROOT / "prompts"
OVERRIDE_PATH = OVERRIDE_DIR / "generate_skill.md"
AUTHOR_PROMPT_NAME = "generate_skill.md"
MAX_AUTHOR_PROMPT_BYTES = 256 * 1024

_FALLBACK = (
    "Author a VulnForge hunt class skill in Cloudflare Agent Skills style. "
    "Reply with JSON only: {\"id\",\"title\",\"description\",\"body_md\"} "
    "where description is a multi-sentence Use when… trigger blurb, and "
    "body_md has YAML frontmatter, Mission or Principles, Rules quick "
    "reference table, Hunt workflow or Method, Anti-patterns table, Scope/"
    "related skills, and Submit checklist. Prefer evidence over pre-training. "
    "For multiple skills, return {\"skills\": [ ... ]}."
)


class AuthorPromptError(ValueError):
    """Skill-generator prompt load/save failed."""


def package_prompt_path() -> Path:
    return PACKAGE_PROMPTS / AUTHOR_PROMPT_NAME


def override_prompt_path() -> Path:
    return OVERRIDE_PATH


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            if text.strip():
                return text
    except (OSError, PermissionError):
        return None
    return None


def load_author_prompt() -> str:
    """Load operator override, else package seed, else hard-coded fallback."""
    override = _read_text(OVERRIDE_PATH)
    if override is not None:
        return override
    try:
        return load_prompt_slice(PACKAGE_PROMPTS, AUTHOR_PROMPT_NAME)
    except (OSError, FileNotFoundError, PermissionError):
        return _FALLBACK


def get_author_prompt() -> dict[str, Any]:
    """Return body + metadata for the Dev editor / API."""
    if OVERRIDE_PATH.is_file() and (OVERRIDE_PATH.read_text(encoding="utf-8").strip()):
        body = OVERRIDE_PATH.read_text(encoding="utf-8")
        return {
            "body_md": body,
            "source": "override",
            "path": str(OVERRIDE_PATH),
            "package_path": str(package_prompt_path()),
            "has_override": True,
        }
    try:
        body = load_prompt_slice(PACKAGE_PROMPTS, AUTHOR_PROMPT_NAME)
        source = "package"
    except (OSError, FileNotFoundError, PermissionError):
        body = _FALLBACK
        source = "fallback"
    return {
        "body_md": body,
        "source": source,
        "path": str(package_prompt_path()) if source == "package" else None,
        "package_path": str(package_prompt_path()),
        "has_override": False,
    }


def save_author_prompt(body_md: str) -> dict[str, Any]:
    """Write operator override. Returns get_author_prompt()-shaped dict."""
    text = str(body_md or "")
    if not text.strip():
        raise AuthorPromptError("body_md is required and must be non-empty")
    raw = text.encode("utf-8")
    if len(raw) > MAX_AUTHOR_PROMPT_BYTES:
        raise AuthorPromptError(
            f"body_md exceeds {MAX_AUTHOR_PROMPT_BYTES} bytes"
        )
    OVERRIDE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = OVERRIDE_PATH.with_suffix(".md.tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(OVERRIDE_PATH)
    except OSError as e:
        try:
            if tmp.is_file():
                tmp.unlink()
        except OSError:
            pass
        raise AuthorPromptError(f"write failed: {e}") from e
    return get_author_prompt()


def reseed_author_prompt() -> dict[str, Any]:
    """Remove operator override so package seed is used again."""
    try:
        if OVERRIDE_PATH.is_file():
            OVERRIDE_PATH.unlink()
    except OSError as e:
        raise AuthorPromptError(f"reseed failed: {e}") from e
    return get_author_prompt()

"""Run fingerprint: what VulnForge, model and prompts produced a benchmark run.

Without a fingerprint two runs cannot be compared honestly ("what changed?").
Captured once when a live run starts and stored on the BenchmarkRun.
Never contains API keys: only the endpoint host.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from vulnforge.paths import PROJECT_ROOT

SYSTEM_PROMPTS_DIR = PROJECT_ROOT / "seeds" / "system"

# Keys a compare view diffs, in display order.
FINGERPRINT_KEYS = (
    "git_sha",
    "git_dirty",
    "model",
    "endpoint_host",
    "api_mode",
    "prompts_hash",
    "hunt_profiles_hash",
    "tools_hash",
    "validate_llm",
)


def _sha(parts: Iterable[bytes]) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
        h.update(b"\0")
    return h.hexdigest()[:16]


def hash_tree(root: Path, *, suffixes: tuple[str, ...] = (".md", ".json", ".yaml", ".yml")) -> str:
    """Stable content hash of files under ``root`` (relative path + bytes)."""
    root = Path(root)
    if not root.is_dir():
        return ""
    parts: list[bytes] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or (suffixes and p.suffix.lower() not in suffixes):
            continue
        try:
            parts.append(str(p.relative_to(root)).replace("\\", "/").encode())
            parts.append(p.read_bytes())
        except OSError:
            continue
    return _sha(parts) if parts else ""


def git_state(cwd: Path = PROJECT_ROOT) -> tuple[str, bool]:
    """(HEAD sha, tracked-files-dirty). Empty sha when git is unavailable."""
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=no"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
        )
    except (OSError, subprocess.SubprocessError):
        return "", False
    return sha, dirty


def endpoint_host(base_url: str) -> str:
    """Host[:port] only. Drops scheme, userinfo, path and query."""
    raw = str(base_url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return host


def tools_hash() -> str:
    try:
        from vulnforge.tools.registry import list_agent_specs

        specs = list_agent_specs()
    except Exception:  # noqa: BLE001 — fingerprint is best-effort
        return ""
    rows = sorted(
        (
            s.name,
            json.dumps(dict(s.parameters or {}), sort_keys=True, default=str),
            ",".join(s.stages),
        )
        for s in specs
    )
    return _sha(json.dumps(r).encode() for r in rows)


def hunt_profiles_hash() -> str:
    try:
        from vulnforge.hunt_profiles import collection_root

        return hash_tree(collection_root())
    except Exception:  # noqa: BLE001 — fingerprint is best-effort
        return ""


def capture_fingerprint(cfg: dict[str, Any], *, validate_llm: bool) -> dict[str, Any]:
    """Fingerprint for a live run from the Settings config it will use."""
    llm = cfg.get("llm") if isinstance(cfg.get("llm"), dict) else {}
    sha, dirty = git_state()
    return {
        "git_sha": sha,
        "git_dirty": dirty,
        "model": str(llm.get("model") or "").strip(),
        "endpoint_host": endpoint_host(str(llm.get("base_url") or "")),
        "api_mode": str(llm.get("api_mode") or "").strip(),
        "prompts_hash": hash_tree(SYSTEM_PROMPTS_DIR),
        "hunt_profiles_hash": hunt_profiles_hash(),
        "tools_hash": tools_hash(),
        "validate_llm": bool(validate_llm),
    }


def fingerprint_diff(a: dict[str, Any] | None, b: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Changed fingerprint keys between two runs, in display order."""
    a = a if isinstance(a, dict) else {}
    b = b if isinstance(b, dict) else {}
    out = []
    for key in FINGERPRINT_KEYS:
        if a.get(key) != b.get(key):
            out.append({"key": key, "a": a.get(key), "b": b.get(key)})
    return out


__all__ = [
    "FINGERPRINT_KEYS",
    "capture_fingerprint",
    "endpoint_host",
    "fingerprint_diff",
    "git_state",
    "hash_tree",
]

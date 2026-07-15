"""Mechanical sink preindex â€” seed_sinks for recon/hunt (no LLM)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vulnforge.util import normalize_relpath

# kind â†’ compiled patterns (line-level, case-sensitive where idiomatic)
_SINK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sql", re.compile(r"""(?:execute|executemany|raw|cursor\.execute)\s*\(|SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM""", re.I)),
    ("sql", re.compile(r"""(?:text|sql)\s*\(\s*f['\"]|%\s*\(|\.format\s*\(.*(?:SELECT|INSERT|UPDATE)""", re.I)),
    ("exec", re.compile(r"""(?:subprocess\.(?:run|call|Popen|check_output)|os\.system|os\.popen|exec\s*\(|eval\s*\(|Runtime\.exec|child_process|shell_exec|passthru)\s*\(""", re.I)),
    ("path", re.compile(r"""(?:open\s*\(|Path\s*\(|readFileSync|writeFileSync|send_file|sendfile|FileResponse|os\.path\.join)\s*""")),
    ("jwt", re.compile(r"""(?:jwt\.(?:decode|encode|verify)|jsonwebtoken|jose\.|HS256|RS256|verify\s*\(.*token)""", re.I)),
    ("llm", re.compile(r"""(?:openai|anthropic|chat\.completions|ChatCompletion|tool_calls|function_call|prompt\s*=|system_prompt|langchain|ChatOpenAI|responses\.create)""", re.I)),
    ("auth", re.compile(r"""(?:@login_required|@require_|require_auth|authenticate|authorize|check_permission|has_permission|IsAuthenticated|current_user|get_current_user|session\[.user)""", re.I)),
    ("template", re.compile(r"""(?:render_template|jinja2|Template\s*\(|Mustache|\.render\s*\(|innerHTML\s*=|dangerouslySetInnerHTML|v-html)""", re.I)),
    ("deserialize", re.compile(r"""(?:pickle\.loads|yaml\.load\s*\(|unserialize|ObjectInputStream|JSON\.parse\s*\()""", re.I)),
    ("ssrf", re.compile(r"""(?:requests\.(?:get|post|put|request)|httpx\.|urllib\.request|fetch\s*\(|axios\.|HttpClient)""", re.I)),
]

_CODE_EXTS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php",
    ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".vue", ".svelte", ".kt", ".scala",
}


def _ignored(rel: str, ignore_globs: list[str]) -> bool:
    from fnmatch import fnmatch

    rel_n = normalize_relpath(rel)
    for g in ignore_globs:
        g_n = g.replace("\\", "/")
        if fnmatch(rel_n, g_n) or fnmatch(Path(rel_n).name, g_n):
            return True
        if g_n.startswith("**/") and fnmatch(rel_n, g_n[3:]):
            return True
    return False


def build_sink_preindex(
    target_root: Path,
    ignore_globs: list[str] | None = None,
    *,
    max_files: int = 4000,
    max_sinks: int = 500,
    max_file_bytes: int = 400_000,
) -> list[dict[str, Any]]:
    """
    Scan target for mechanical sink lines.

    Returns list of {path, line, kind, text} (text truncated).
    """
    target_root = Path(target_root).resolve()
    globs = list(ignore_globs or [])
    sinks: list[dict[str, Any]] = []
    files_seen = 0
    for path in sorted(target_root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() not in _CODE_EXTS and path.name not in {
            "Dockerfile", "Makefile",
        }:
            continue
        rel = normalize_relpath(str(path.relative_to(target_root)))
        if _ignored(rel, globs):
            continue
        files_seen += 1
        if files_seen > max_files:
            break
        try:
            if path.stat().st_size > max_file_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if len(line) > 400:
                line = line[:400]
            for kind, rx in _SINK_PATTERNS:
                if rx.search(line):
                    sinks.append(
                        {
                            "path": rel,
                            "line": i,
                            "kind": kind,
                            "text": line.strip()[:160],
                        }
                    )
                    if len(sinks) >= max_sinks:
                        return sinks
                    break  # one kind per line
    return sinks


def filter_sinks_for_paths(
    sinks: list[dict[str, Any]],
    path_hints: list[str] | None,
    *,
    top_k: int = 12,
    kinds: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter/rank sinks to those under path_hints (or all) for hunt packets."""
    if not sinks:
        return []
    hints = [normalize_relpath(p) for p in (path_hints or []) if p]
    out: list[dict[str, Any]] = []
    for s in sinks:
        if kinds and s.get("kind") not in kinds:
            continue
        p = normalize_relpath(str(s.get("path") or ""))
        if hints:
            if not any(
                p == h or p.startswith(h.rstrip("/") + "/") or h.startswith(p.rstrip("/") + "/")
                for h in hints
                if h
            ):
                continue
        out.append(s)
        if len(out) >= top_k:
            break
    # Global fallback only when no path_hints were provided.
    # If hints were set but matched nothing, return [] so packets stay scoped
    # (global sinks fight soft jail and encourage widen thrash).
    if not out and sinks and not hints:
        return sinks[:top_k]
    return out


def sink_kinds_present(sinks: list[dict[str, Any]], path_hints: list[str] | None = None) -> set[str]:
    filtered = filter_sinks_for_paths(sinks, path_hints, top_k=10_000)
    return {str(s.get("kind")) for s in filtered if s.get("kind")}


# Class routing: which sink families justify a class on shared paths.
# Prefer hunt profile metadata (sink_families) when the collection is available;
# this static map remains the offline fallback.
CLASS_SINK_FAMILIES: dict[str, set[str]] = {
    "injection": {"sql", "exec", "template", "deserialize", "path"},
    "ai-llm": {"llm"},
    "access-control": {"auth", "jwt"},
    "cryptography": {"jwt"},
    "web-protocol-auth": {"auth", "jwt"},
    "client-side": {"template"},
    "feature-abuse": {"ssrf"},
    "graphql": {"auth"},
}


def _resolved_sink_families(cls: str) -> set[str] | None:
    """Return family set for class, or None if unrestricted / unknown."""
    want = str(cls or "").strip().lower()
    try:
        from vulnforge.hunt_profiles import sink_families_for_class

        fam_list = sink_families_for_class(want)
        # Profile present with empty families → unrestricted (same as static miss)
        if fam_list:
            return set(fam_list)
        # If profile exists and explicitly empty, allow; if no profile meta, fall through
        from vulnforge.hunt_profiles import get_profile

        try:
            get_profile(want, include_body=False)
            return None  # registered profile with no sink filter
        except Exception:
            pass
    except Exception:
        pass
    fam = CLASS_SINK_FAMILIES.get(want)
    return fam


def class_has_sink_family(cls: str, kinds: set[str]) -> bool:
    fam = _resolved_sink_families(cls)
    if not fam:
        return True  # unknown / wildcard / unrestricted — allow
    return bool(fam & kinds)


def merged_class_sink_families() -> dict[str, set[str]]:
    """Static map merged with active profile sink_families (profile wins)."""
    out = {k: set(v) for k, v in CLASS_SINK_FAMILIES.items()}
    try:
        from vulnforge.hunt_profiles import class_sink_families_map

        for k, v in class_sink_families_map().items():
            if v:
                out[k] = set(v)
    except Exception:
        pass
    return out

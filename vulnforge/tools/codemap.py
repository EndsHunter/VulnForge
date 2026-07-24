"""Mechanical codemap: path-backed modules, entrypoints, optional import edges.

No LLM. Agents may annotate via note(kind=codemap); structure is always
derived from the target tree + inventory signals.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Optional

from vulnforge.tools.grep_index import ENTRYPOINT_NAMES, _ignored
from vulnforge.util import normalize_relpath, utc_now_iso

# Package / workspace markers (basename)
_PACKAGE_MARKERS = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "go.mod",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "composer.json",
        "Gemfile",
        "mix.exs",
        "__init__.py",
    }
)

# Basename / path tokens that hint security-relevant areas (not CWE claims)
_SIGNAL_TOKENS = frozenset(
    {
        "auth",
        "session",
        "login",
        "oauth",
        "jwt",
        "token",
        "admin",
        "api",
        "graphql",
        "gql",
        "worker",
        "queue",
        "job",
        "crypto",
        "crypt",
        "cipher",
        "secret",
        "password",
        "upload",
        "download",
        "payment",
        "billing",
        "webhook",
        "middleware",
        "permission",
        "rbac",
        "acl",
        "sso",
        "saml",
        "rpc",
        "grpc",
        "ws",
        "websocket",
        "inject",
        "sql",
        "db",
        "database",
        "cache",
        "redis",
        "kafka",
        "config",
        "settings",
        "handler",
        "controller",
        "route",
        "router",
        "view",
        "template",
        "parser",
        "deserialize",
        "serialize",
        "ai",
        "llm",
        "agent",
        "rag",
        "mcp",
        "tool",
        "plugin",
        "extension",
        "install",
        "update",
        "ci",
        "docker",
        "k8s",
        "kube",
    }
)

_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".cache",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "target",  # Rust/Java build; still allow if package marker at that level only via marker
    }
)

# Cheap import patterns (capped scrape; not a real resolver)
_IMPORT_PY = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))",
    re.MULTILINE,
)
_IMPORT_JS = re.compile(
    r"""(?:from\s+['"]([^'"]+)['"]|require\s*\(\s*['"]([^'"]+)['"]\s*\)|import\s*\(\s*['"]([^'"]+)['"]\s*\))""",
)
_IMPORT_GO = re.compile(
    r'^\s*import\s+(?:\(\s*|"([^"]+)"|`([^`]+)`)',
    re.MULTILINE,
)
_IMPORT_GO_LINE = re.compile(r'^\s*"([^"]+)"\s*$', re.MULTILINE)

_CODE_EXTS = frozenset({".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java"})


def _cfg_codemap(cfg: Optional[dict]) -> dict[str, Any]:
    c = (cfg or {}).get("codemap") if isinstance(cfg, dict) else None
    if not isinstance(c, dict):
        c = {}
    return {
        "enabled": bool(c.get("enabled", True)),
        "max_modules": max(1, int(c.get("max_modules", 80))),
        "max_depth": max(1, int(c.get("max_depth", 4))),
        "max_edges": max(0, int(c.get("max_edges", 120))),
        "max_import_files_scan": max(0, int(c.get("max_import_files_scan", 200))),
        "build_import_edges": bool(c.get("build_import_edges", True)),
    }


def _mod_id(path: str) -> str:
    p = normalize_relpath(path) or "."
    return f"mod:{p}"


def _signals_for_path(path: str) -> list[str]:
    pl = normalize_relpath(path).lower()
    parts = re.split(r"[/_.\-]+", pl)
    found: list[str] = []
    seen: set[str] = set()
    for tok in parts:
        if tok in _SIGNAL_TOKENS and tok not in seen:
            seen.add(tok)
            found.append(tok)
    return found[:12]


def _parent_dirs(rel: str, max_depth: int) -> list[str]:
    """Return ancestor dir paths from shallow to deep (excluding file itself)."""
    rel = normalize_relpath(rel)
    if not rel or rel == ".":
        return []
    parts = rel.split("/")
    # if file path, drop filename
    if "." in parts[-1] and not parts[-1].startswith("."):
        # heuristic: treat last segment as file when it has an extension
        name = parts[-1]
        if Path(name).suffix:
            parts = parts[:-1]
    out: list[str] = []
    for i in range(1, min(len(parts), max_depth) + 1):
        out.append("/".join(parts[:i]))
    return out


def _is_package_root(target: Path, rel_dir: str, files_under: set[str]) -> bool:
    """True if rel_dir looks like a package/workspace root."""
    rel_dir = normalize_relpath(rel_dir)
    if rel_dir in ("", "."):
        # root is package if markers at top
        for m in _PACKAGE_MARKERS:
            if m in files_under or any(
                f == m or f.endswith("/" + m) for f in files_under if "/" not in f
            ):
                return True
        return False
    prefix = rel_dir.rstrip("/") + "/"
    for f in files_under:
        if f.startswith(prefix):
            base = f[len(prefix) :]
            if "/" not in base and base in _PACKAGE_MARKERS:
                return True
        elif f == rel_dir + "/" + "__init__.py" or f.endswith(
            "/" + rel_dir.split("/")[-1] + "/__init__.py"
        ):
            pass
    # direct children markers
    for m in _PACKAGE_MARKERS:
        cand = f"{rel_dir}/{m}"
        if cand in files_under:
            return True
    # packages/*, apps/*, services/* convention
    top = rel_dir.split("/", 1)[0]
    if top in ("packages", "apps", "services", "libs", "src") and "/" in rel_dir:
        return True
    if top in ("packages", "apps", "services", "libs") and rel_dir.count("/") == 1:
        return True
    return False


def _collect_files(
    target_root: Path,
    ignore_globs: list[str],
    max_depth: int,
) -> tuple[list[str], Counter[str], list[str]]:
    """Walk target; return (files, extensions, entrypoints)."""
    target_root = Path(target_root).resolve()
    files: list[str] = []
    ext_hist: Counter[str] = Counter()
    entrypoints: list[str] = []

    if target_root.is_file():
        name = target_root.name
        files = [name]
        ext_hist[target_root.suffix.lower() or "<none>"] += 1
        if name in ENTRYPOINT_NAMES:
            entrypoints.append(name)
        return files, ext_hist, entrypoints

    for path in sorted(target_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            rel = normalize_relpath(str(path.relative_to(target_root)))
        except ValueError:
            continue
        parts = rel.split("/")
        # skip deep / known noise dirs
        if any(p in _SKIP_DIR_NAMES for p in parts[:-1]):
            continue
        if len(parts) - 1 > max_depth + 6:
            # still count files under deep trees but module depth is capped later
            pass
        if _ignored(rel, ignore_globs):
            continue
        files.append(rel)
        ext_hist[path.suffix.lower() or "<none>"] += 1
        if path.name in ENTRYPOINT_NAMES:
            entrypoints.append(rel)
    return files, ext_hist, entrypoints


def build_codemap(
    target: Path,
    inventory: Optional[dict] = None,
    *,
    cfg: Optional[dict] = None,
    ignore_globs: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Build a mechanical codemap for *target*.

    Prefer reusing inventory counts when provided; always walks (or uses
    single-file) for structure. Never raises on partial trees — returns
    best-effort map.
    """
    opts = _cfg_codemap(cfg)
    target = Path(target)
    inv = inventory if isinstance(inventory, dict) else {}
    ignore = list(
        ignore_globs
        if ignore_globs is not None
        else ((cfg or {}).get("run") or {}).get("ignore_globs") or []
    )

    if not opts["enabled"]:
        return {
            "version": 1,
            "generated_at": utc_now_iso(),
            "source": "mechanical",
            "target_kind": "disabled",
            "summary": {
                "file_count": inv.get("file_count") or 0,
                "languages": {},
                "package_roots": [],
                "entrypoint_count": 0,
            },
            "modules": [],
            "entrypoints": [],
            "edges": [],
            "annotations": [],
        }

    single_file = target.is_file() or inv.get("kind") == "single_file"
    if single_file:
        return _build_single_file(target, inv)

    try:
        files, ext_hist, entrypoints = _collect_files(
            target if target.is_dir() else target.parent,
            ignore,
            opts["max_depth"],
        )
    except OSError:
        # Fall back to inventory samples only
        files = list(inv.get("sample_paths") or [])
        ext_hist = Counter()
        for k, v in (inv.get("extensions") or {}).items():
            try:
                ext_hist[str(k)] = int(v)
            except (TypeError, ValueError):
                pass
        entrypoints = list(inv.get("entrypoints") or [])

    # Prefer inventory entrypoints when walk missed some
    for e in inv.get("entrypoints") or []:
        e_n = normalize_relpath(str(e))
        if e_n and e_n not in entrypoints:
            entrypoints.append(e_n)

    file_set = set(files)
    file_count = int(inv.get("file_count") or len(files))

    # Count files per directory prefix
    dir_files: dict[str, list[str]] = defaultdict(list)
    dir_exts: dict[str, Counter[str]] = defaultdict(Counter)
    for f in files:
        f_n = normalize_relpath(f)
        parent = str(Path(f_n).parent).replace("\\", "/")
        if parent == ".":
            dir_files["."].append(f_n)
            dir_exts["."].update([Path(f_n).suffix.lower() or "<none>"])
        else:
            # attribute to each ancestor up to max_depth
            parts = parent.split("/")
            for i in range(1, len(parts) + 1):
                d = "/".join(parts[:i])
                dir_files[d].append(f_n)
                dir_exts[d].update([Path(f_n).suffix.lower() or "<none>"])
            dir_files["."].append(f_n)
            dir_exts["."].update([Path(f_n).suffix.lower() or "<none>"])

    # Candidate module directories
    candidates: list[str] = []
    # top-level dirs
    top_dirs = sorted(
        {
            normalize_relpath(f).split("/", 1)[0]
            for f in files
            if "/" in normalize_relpath(f)
        }
    )
    for d in top_dirs:
        if d in _SKIP_DIR_NAMES:
            continue
        candidates.append(d)
        # second level under packages/apps/services/src/libs
        if d in ("packages", "apps", "services", "libs", "src", "internal", "cmd"):
            children = sorted(
                {
                    "/".join(normalize_relpath(f).split("/")[:2])
                    for f in files
                    if normalize_relpath(f).startswith(d + "/")
                    and normalize_relpath(f).count("/") >= 1
                }
            )
            for c in children:
                if c != d:
                    candidates.append(c)

    # package roots by markers
    package_roots: list[str] = []
    for d in list(dir_files.keys()):
        if d == ".":
            continue
        depth = 0 if d == "." else d.count("/") + 1
        if depth > opts["max_depth"]:
            continue
        if _is_package_root(target, d, file_set):
            if d not in package_roots:
                package_roots.append(d)
            if d not in candidates:
                candidates.append(d)

    # entrypoint parent dirs
    for ep in entrypoints:
        parent = str(Path(normalize_relpath(ep)).parent).replace("\\", "/")
        if parent and parent != "." and parent not in candidates:
            candidates.append(parent)

    # Dedupe and rank: package roots first, then by file count
    ranked: list[tuple[int, int, str]] = []
    seen_c: set[str] = set()
    for d in candidates:
        d_n = normalize_relpath(d)
        if not d_n or d_n in seen_c:
            continue
        seen_c.add(d_n)
        depth = d_n.count("/") + 1
        if depth > opts["max_depth"]:
            continue
        n_files = len(set(dir_files.get(d_n) or []))
        if n_files == 0 and d_n not in package_roots:
            continue
        is_pkg = 0 if d_n in package_roots else 1
        ranked.append((is_pkg, -n_files, d_n))
    ranked.sort()

    modules: list[dict[str, Any]] = []
    module_paths: list[str] = []
    for _is_pkg, _neg_n, d_n in ranked[: opts["max_modules"]]:
        label = d_n.split("/")[-1] if d_n != "." else "root"
        kind = "package" if d_n in package_roots else "dir"
        # leaf files under this dir (not in deeper selected modules — soft)
        kids_files = sorted(set(dir_files.get(d_n) or []))
        # immediate child module ids later
        exts = dict(dir_exts.get(d_n) or {})
        sigs = _signals_for_path(d_n)
        # add signals from child basenames
        for f in kids_files[:40]:
            for s in _signals_for_path(f):
                if s not in sigs:
                    sigs.append(s)
            if len(sigs) >= 12:
                break
        modules.append(
            {
                "id": _mod_id(d_n),
                "path": d_n,
                "kind": kind,
                "label": label,
                "file_count": len(kids_files) if kids_files else int(-_neg_n),
                "extensions": {k: int(v) for k, v in sorted(exts.items())[:20]},
                "signals": sigs[:12],
                "children": [],
            }
        )
        module_paths.append(d_n)

    # Wire children: nested module paths
    path_to_idx = {m["path"]: i for i, m in enumerate(modules)}
    for m in modules:
        p = m["path"]
        for other in module_paths:
            if other == p:
                continue
            if other.startswith(p.rstrip("/") + "/"):
                # direct child only
                rest = other[len(p) + 1 :]
                if "/" not in rest:
                    m["children"].append(_mod_id(other))

    # Entrypoint records
    ep_records = []
    for ep in entrypoints[:80]:
        ep_n = normalize_relpath(ep)
        ep_records.append(
            {
                "path": ep_n,
                "kind": "file",
                "marker": Path(ep_n).name,
            }
        )

    # Optional import edges
    edges: list[dict[str, Any]] = []
    if opts["build_import_edges"] and opts["max_edges"] > 0 and not single_file:
        root = target if target.is_dir() else target.parent
        edges = _build_import_edges(
            root,
            files,
            module_paths,
            max_files=opts["max_import_files_scan"],
            max_edges=opts["max_edges"],
        )

    languages = {
        k: int(v)
        for k, v in sorted(
            (ext_hist or Counter(inv.get("extensions") or {})).items(),
            key=lambda kv: (-kv[1], kv[0]),
        )[:30]
        if k and k != "<none>"
    }

    return {
        "version": 1,
        "generated_at": utc_now_iso(),
        "source": "mechanical",
        "target_kind": "directory",
        "summary": {
            "file_count": file_count,
            "languages": languages,
            "package_roots": sorted(package_roots)[:40],
            "entrypoint_count": len(ep_records),
            "module_count": len(modules),
        },
        "modules": modules,
        "entrypoints": ep_records,
        "edges": edges,
        "annotations": [],
    }


def _build_single_file(target: Path, inv: dict) -> dict[str, Any]:
    name = target.name if target.is_file() else str(
        (inv.get("single_file") or {}).get("name")
        or (inv.get("entrypoints") or ["file"])[0]
    )
    name = normalize_relpath(name)
    ext = Path(name).suffix.lower()
    return {
        "version": 1,
        "generated_at": utc_now_iso(),
        "source": "mechanical",
        "target_kind": "single_file",
        "summary": {
            "file_count": 1,
            "languages": {ext: 1} if ext else {},
            "package_roots": [],
            "entrypoint_count": 1,
            "module_count": 1,
        },
        "modules": [
            {
                "id": _mod_id(name),
                "path": name,
                "kind": "file",
                "label": Path(name).stem or name,
                "file_count": 1,
                "extensions": {ext: 1} if ext else {},
                "signals": _signals_for_path(name),
                "children": [],
            }
        ],
        "entrypoints": [{"path": name, "kind": "file", "marker": Path(name).name}],
        "edges": [],
        "annotations": [],
    }


def _module_for_path(path: str, module_paths: list[str]) -> Optional[str]:
    """Longest module path prefix for *path*."""
    p = normalize_relpath(path)
    best: Optional[str] = None
    best_len = -1
    for m in module_paths:
        m_n = normalize_relpath(m)
        if p == m_n or p.startswith(m_n.rstrip("/") + "/"):
            if len(m_n) > best_len:
                best = m_n
                best_len = len(m_n)
    return best


def _resolve_import_to_module(
    imp: str,
    source_path: str,
    module_paths: list[str],
    file_set: set[str],
) -> Optional[str]:
    """Best-effort map import string → module path."""
    imp = (imp or "").strip().strip("\"'")
    if not imp or imp.startswith(".") and imp in (".", ".."):
        # relative — resolve against source dir
        pass
    # Skip stdlib-ish / bare bare packages without path evidence
    candidates: list[str] = []
    if imp.startswith("."):
        # relative JS/py
        base = str(Path(source_path).parent).replace("\\", "/")
        if base == ".":
            base = ""
        rel_imp = imp.lstrip(".")
        # rough: ./foo or ../bar
        try:
            joined = normalize_relpath(
                str((Path(source_path).parent / Path(imp)).as_posix())
            )
            candidates.append(joined)
        except Exception:
            if base:
                candidates.append(normalize_relpath(base + "/" + rel_imp.replace(".", "/")))
    else:
        # absolute-ish: auth.session → auth/session, @scope/pkg skip
        if imp.startswith("@"):
            return None
        dotted = imp.replace(".", "/")
        candidates.append(dotted)
        # first segment only for package-level edge
        if "/" in dotted:
            candidates.append(dotted.split("/")[0])
        else:
            candidates.append(dotted)

    for c in candidates:
        c_n = normalize_relpath(c)
        # exact file
        for ext in ("", ".py", ".js", ".ts", ".tsx", ".jsx", ".go"):
            cand_f = c_n if not ext else c_n + ext
            if cand_f in file_set:
                return _module_for_path(cand_f, module_paths)
            init = c_n + "/__init__.py"
            if init in file_set:
                return _module_for_path(init, module_paths)
        # module dir match
        mod = _module_for_path(c_n, module_paths)
        if mod and mod in module_paths:
            return mod
        # match module path by label/suffix
        for m in module_paths:
            if m == c_n or m.endswith("/" + c_n) or m.split("/")[-1] == c_n.split("/")[-1]:
                if c_n.split("/")[-1] and (
                    m == c_n
                    or m.endswith("/" + c_n)
                    or (
                        len(c_n) >= 3
                        and m.split("/")[-1] == c_n.split("/")[-1]
                        and c_n.count("/") == 0
                    )
                ):
                    # only accept short bare name if unique-ish path contains packages/
                    if c_n.count("/") == 0:
                        hits = [x for x in module_paths if x.split("/")[-1] == c_n]
                        if len(hits) == 1:
                            return hits[0]
                    else:
                        return m
    return None


def _build_import_edges(
    root: Path,
    files: list[str],
    module_paths: list[str],
    *,
    max_files: int,
    max_edges: int,
) -> list[dict[str, Any]]:
    if max_files <= 0 or max_edges <= 0 or not module_paths:
        return []
    file_set = set(normalize_relpath(f) for f in files)
    # Prefer code files under modules
    code_files = [
        f
        for f in files
        if Path(f).suffix.lower() in _CODE_EXTS
    ]
    # Prefer files near module roots
    def rank(f: str) -> tuple[int, str]:
        depth = f.count("/")
        return (depth, f)

    code_files = sorted(code_files, key=rank)[:max_files]
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for rel in code_files:
        if len(edges) >= max_edges:
            break
        src_mod = _module_for_path(rel, module_paths)
        if not src_mod:
            continue
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:50_000]
        except OSError:
            continue
        ext = Path(rel).suffix.lower()
        imports: list[str] = []
        if ext == ".py":
            for m in _IMPORT_PY.finditer(text):
                imports.append(m.group(1) or m.group(2) or "")
        elif ext in (".js", ".ts", ".tsx", ".jsx"):
            for m in _IMPORT_JS.finditer(text):
                imports.append(m.group(1) or m.group(2) or m.group(3) or "")
        elif ext == ".go":
            for m in _IMPORT_GO_LINE.finditer(text):
                imports.append(m.group(1) or "")
        for imp in imports[:40]:
            if len(edges) >= max_edges:
                break
            dst = _resolve_import_to_module(imp, rel, module_paths, file_set)
            if not dst or dst == src_mod:
                continue
            key = (src_mod, dst)
            if key in seen:
                continue
            seen.add(key)
            edges.append(
                {
                    "from": _mod_id(src_mod),
                    "to": _mod_id(dst),
                    "kind": "import",
                    "evidence": f"{Path(rel).name}: {imp[:80]}",
                }
            )
    return edges


def slice_codemap(
    codemap: Optional[dict],
    *,
    path_hints: Optional[list[str]] = None,
    area: str = "",
    max_modules: int = 8,
    max_annotations: int = 12,
) -> dict[str, Any]:
    """Area/path-focused subset for hunt packets."""
    if not isinstance(codemap, dict):
        return {
            "modules": [],
            "entrypoints": [],
            "edges": [],
            "annotations": [],
            "summary": {},
        }
    hints = [normalize_relpath(str(h)) for h in (path_hints or []) if h]
    area_s = str(area or "").strip().lower()
    tokens = [
        t
        for t in re.split(r"[\s/_\-]+", area_s)
        if len(t) >= 3 and t not in {"the", "and", "for", "with", "from", "app"}
    ]

    modules = [m for m in (codemap.get("modules") or []) if isinstance(m, dict)]
    matched: list[dict] = []
    for m in modules:
        path = normalize_relpath(str(m.get("path") or ""))
        label = str(m.get("label") or "").lower()
        sigs = [str(s).lower() for s in (m.get("signals") or [])]
        hit = False
        if hints:
            for h in hints:
                if (
                    path == h
                    or path.startswith(h.rstrip("/") + "/")
                    or h.startswith(path.rstrip("/") + "/")
                    or path in h
                    or h in path
                ):
                    hit = True
                    break
        if not hit and area_s:
            if area_s in path.lower() or area_s in label or area_s in sigs:
                hit = True
            elif tokens and (
                any(t in path.lower() or t in label for t in tokens)
                or any(t in sigs for t in tokens)
            ):
                hit = True
        if hit:
            matched.append(m)
        if len(matched) >= max_modules:
            break

    if not matched:
        matched = modules[: min(3, max_modules)]

    mod_ids = {m.get("id") for m in matched}
    mod_paths = [normalize_relpath(str(m.get("path") or "")) for m in matched]

    eps = []
    for ep in codemap.get("entrypoints") or []:
        if not isinstance(ep, dict):
            continue
        p = normalize_relpath(str(ep.get("path") or ""))
        if any(p == mp or p.startswith(mp.rstrip("/") + "/") for mp in mod_paths if mp):
            eps.append(ep)
        if len(eps) >= 12:
            break

    edges = []
    for e in codemap.get("edges") or []:
        if not isinstance(e, dict):
            continue
        if e.get("from") in mod_ids or e.get("to") in mod_ids:
            edges.append(e)
        if len(edges) >= 20:
            break

    anns = []
    for a in codemap.get("annotations") or []:
        if not isinstance(a, dict):
            continue
        p = normalize_relpath(str(a.get("path") or ""))
        if not p or any(
            p == mp or p.startswith(mp.rstrip("/") + "/") or mp in p
            for mp in mod_paths
            if mp
        ):
            anns.append(a)
        if len(anns) >= max_annotations:
            break

    return {
        "summary": codemap.get("summary") or {},
        "modules": matched,
        "entrypoints": eps,
        "edges": edges,
        "annotations": anns,
        "area": area,
        "path_hints": hints,
    }


def format_codemap_for_packet(
    codemap: Optional[dict],
    *,
    max_chars: int = 2500,
    path_hints: Optional[list[str]] = None,
    area: str = "",
    sliced: bool = False,
) -> str:
    """Compact text/JSON for LLM packets."""
    if not isinstance(codemap, dict) or not (
        codemap.get("modules") or codemap.get("entrypoints")
    ):
        return "(no codemap)"
    data = (
        slice_codemap(codemap, path_hints=path_hints, area=area)
        if sliced or path_hints or area
        else {
            "summary": codemap.get("summary") or {},
            "modules": (codemap.get("modules") or [])[:20],
            "entrypoints": (codemap.get("entrypoints") or [])[:15],
            "edges": (codemap.get("edges") or [])[:15],
            "annotations": (codemap.get("annotations") or [])[:12],
        }
    )
    # Slim modules for packet
    slim_mods = []
    for m in data.get("modules") or []:
        if not isinstance(m, dict):
            continue
        slim_mods.append(
            {
                "path": m.get("path"),
                "kind": m.get("kind"),
                "label": m.get("label"),
                "file_count": m.get("file_count"),
                "signals": (m.get("signals") or [])[:8],
            }
        )
    payload = {
        "summary": data.get("summary"),
        "modules": slim_mods,
        "entrypoints": [
            e.get("path") if isinstance(e, dict) else e
            for e in (data.get("entrypoints") or [])[:12]
        ],
        "edges": (data.get("edges") or [])[:12],
        "annotations": (data.get("annotations") or [])[:10],
    }
    import json

    text = json.dumps(payload, indent=2, ensure_ascii=True)
    if len(text) > max_chars:
        text = text[: max_chars - 20] + "\n…(truncated)"
    return text


def nearest_module(
    codemap: Optional[dict], path: str
) -> Optional[dict[str, Any]]:
    """Longest-prefix module for a finding/source path."""
    if not isinstance(codemap, dict) or not path:
        return None
    p = normalize_relpath(path)
    best: Optional[dict] = None
    best_len = -1
    for m in codemap.get("modules") or []:
        if not isinstance(m, dict):
            continue
        mp = normalize_relpath(str(m.get("path") or ""))
        if not mp:
            continue
        if p == mp or p.startswith(mp.rstrip("/") + "/") or mp == p:
            if len(mp) > best_len:
                best = m
                best_len = len(mp)
    return best


def path_hints_for_area(
    codemap: Optional[dict],
    area: str,
    *,
    limit: int = 15,
) -> list[str]:
    """Derive path_hints for a named area from codemap modules."""
    if not isinstance(codemap, dict):
        return []
    area_s = str(area or "").strip()
    if not area_s:
        return []
    if area_s in ("app", ".", "root", "target"):
        roots = (codemap.get("summary") or {}).get("package_roots") or []
        if roots:
            return [normalize_relpath(str(r)) for r in roots[:limit]]
        eps = [
            normalize_relpath(str(e.get("path")))
            for e in (codemap.get("entrypoints") or [])
            if isinstance(e, dict) and e.get("path")
        ]
        return eps[:limit]

    sliced = slice_codemap(codemap, area=area_s, max_modules=limit)
    hints: list[str] = []
    for m in sliced.get("modules") or []:
        if isinstance(m, dict) and m.get("path"):
            hints.append(normalize_relpath(str(m["path"])))
    return hints[:limit]


def annotations_from_notes(notes: list[dict]) -> list[dict[str, Any]]:
    """Normalize notes rows / session notes into codemap annotations."""
    out: list[dict[str, Any]] = []
    for n in notes or []:
        if not isinstance(n, dict):
            continue
        kind = n.get("kind")
        if kind and kind != "codemap":
            continue
        payload = n.get("payload")
        task_id = n.get("task_id")
        ann: dict[str, Any] = {"source": "agent_note", "task_id": task_id}
        if isinstance(payload, str):
            ann["note"] = payload.strip()[:500]
            ann["path"] = ""
            ann["symbol"] = ""
        elif isinstance(payload, dict):
            ann["path"] = normalize_relpath(str(payload.get("path") or ""))[:400]
            ann["symbol"] = str(payload.get("symbol") or payload.get("name") or "")[
                :120
            ]
            ann["note"] = str(
                payload.get("note") or payload.get("text") or payload.get("why") or ""
            )[:500]
            if not ann["path"] and not ann["note"]:
                # dump short
                ann["note"] = str(payload)[:300]
        else:
            ann["note"] = str(payload)[:300]
            ann["path"] = ""
            ann["symbol"] = ""
        if ann.get("note") or ann.get("path"):
            out.append(ann)
    return out


def merge_annotations_into_codemap(
    codemap: dict,
    notes: list[dict],
    *,
    max_annotations: int = 200,
) -> dict:
    """Return copy of codemap with agent annotations merged (deduped)."""
    base = dict(codemap) if isinstance(codemap, dict) else {}
    existing = [
        a for a in (base.get("annotations") or []) if isinstance(a, dict)
    ]
    new_anns = annotations_from_notes(notes)
    seen: set[tuple[str, str, str]] = set()
    merged: list[dict] = []
    for a in existing + new_anns:
        key = (
            normalize_relpath(str(a.get("path") or "")),
            str(a.get("symbol") or ""),
            str(a.get("note") or "")[:80],
        )
        if key in seen:
            continue
        seen.add(key)
        merged.append(a)
        if len(merged) >= max_annotations:
            break
    base["annotations"] = merged
    if base.get("source") == "mechanical" and new_anns:
        base["source"] = "merge"
    return base


def codemap_summary_for_ui(codemap: Optional[dict]) -> dict[str, Any]:
    """Compact dict for Mission snapshot."""
    if not isinstance(codemap, dict):
        return {
            "has_codemap": False,
            "module_count": 0,
            "file_count": 0,
            "package_roots": [],
            "languages": {},
            "entrypoint_count": 0,
            "annotation_count": 0,
            "source": None,
            "generated_at": None,
        }
    summary = codemap.get("summary") if isinstance(codemap.get("summary"), dict) else {}
    mods = codemap.get("modules") or []
    anns = codemap.get("annotations") or []
    return {
        "has_codemap": bool(mods or codemap.get("entrypoints")),
        "module_count": len(mods)
        if isinstance(mods, list)
        else int(summary.get("module_count") or 0),
        "file_count": int(summary.get("file_count") or 0),
        "package_roots": list(summary.get("package_roots") or [])[:20],
        "languages": dict(summary.get("languages") or {}),
        "entrypoint_count": int(
            summary.get("entrypoint_count")
            or len(codemap.get("entrypoints") or [])
        ),
        "annotation_count": len(anns) if isinstance(anns, list) else 0,
        "edge_count": len(codemap.get("edges") or [])
        if isinstance(codemap.get("edges"), list)
        else 0,
        "source": codemap.get("source"),
        "generated_at": codemap.get("generated_at"),
        "target_kind": codemap.get("target_kind"),
    }

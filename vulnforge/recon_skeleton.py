"""R0 mechanical architecture skeleton (no LLM, no network).

Builds a ``vulnforge/architecture@2`` map with ``origin: "mechanical"`` from
facts VulnForge already computes: codemap modules / entrypoints / import edges
and the sink pre-index. Zones are heuristic *suggestions*
(``zone_source: "heuristic"``); recon labels and corrects them later.

Stored beside the run (``{run_dir}/architecture_skeleton.json``), never in
``runs.architecture_json``: the skeleton must not make ``has_architecture``
true or change recon / hunt planning. Spec: ``docs/harness/recon/FLOWS.md``.

Honesty: a zone, an import edge or a sink attachment is a steering hint, not
evidence. An empty zone never means safe.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from vulnforge.architecture_schema import (
    SCHEMA_V2,
    ZONE_KINDS,
    ZONE_LABELS,
    normalize_architecture_v2,
    slugify,
)
from vulnforge.util import normalize_relpath

SKELETON_FILENAME = "architecture_skeleton.json"

MAX_COMPONENTS = 24
# Reserve two slots for the synthetic datastore / external-http components.
MAX_GROUPS = MAX_COMPONENTS - 2
MAX_SCAN_FILES = 400
MAX_SCAN_BYTES = 200_000
MAX_ROUTES_PER_COMPONENT = 12
MAX_BOUNDARIES = 8

DATASTORE_ID = "datastore"
EXTERNAL_HTTP_ID = "external-http"

# --- heuristics (line-level, cheap) ----------------------------------------

_ROUTE_RX: list[re.Pattern[str]] = [
    # Flask / FastAPI / Bottle / Sanic: @app.route("/x"), @router.get("/x")
    re.compile(
        r"""@\s*[\w.]*\.(route|get|post|put|patch|delete|head|options|api_route|websocket)\s*\(\s*['"]([^'"]*)['"]""",
        re.I,
    ),
    # Express / Koa / Fastify: app.get('/x', ...), router.post("/x"
    re.compile(
        r"""\b(?:app|router|server|api|routes?)\.(get|post|put|patch|delete|all|use)\s*\(\s*['"`](/[^'"`]*)['"`]""",
        re.I,
    ),
    # Spring: @GetMapping("/x") / @RequestMapping(value="/x")
    re.compile(
        r"""@(Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?['"]([^'"]*)['"]""",
    ),
    # Go net/http / mux / gin: HandleFunc("/x", ...), r.GET("/x"
    re.compile(
        r"""\.(HandleFunc|Handle|GET|POST|PUT|PATCH|DELETE)\s*\(\s*"(/[^"]*)\"""",
    ),
    # Django urls: path("x/", view)
    re.compile(r"""^\s*(re_path|path|url)\s*\(\s*r?['"]([^'"]*)['"]\s*,"""),
]
_AUTH_GATE_RX = re.compile(
    r"""(@login_required|@auth\b|@requires?_auth\w*|@authenticated|@jwt_required|@permission_required|@PreAuthorize|@Secured|@RolesAllowed|Depends\(\s*get_current_user|IsAuthenticated|passport\.authenticate|requireAuth|ensureAuthenticated|authMiddleware|auth_required)""",
)
_AUTH_PATH_SIGNALS = frozenset(
    {"auth", "session", "login", "oauth", "jwt", "sso", "saml", "rbac", "acl", "permission"}
)
_HTTP_PATH_SIGNALS = frozenset(
    {
        "api",
        "route",
        "router",
        "routes",
        "handler",
        "handlers",
        "controller",
        "controllers",
        "views",
        "view",
        "graphql",
        "gql",
        "webhook",
        "webhooks",
        "rpc",
        "grpc",
        "ws",
        "websocket",
        "endpoints",
        "server",
        "web",
    }
)
_INTERNAL_PATH_SIGNALS = frozenset(
    {
        "worker",
        "workers",
        "queue",
        "job",
        "jobs",
        "tasks",
        "settings",
        "config",
        "db",
        "database",
        "models",
        "model",
        "cache",
        "redis",
        "kafka",
        "migrations",
        "storage",
    }
)
_BUILD_PATH_SIGNALS = frozenset(
    {
        ".github",
        ".gitlab-ci.yml",
        ".circleci",
        "ci",
        "scripts",
        "script",
        "build",
        "install",
        "docker",
        "dockerfile",
        "makefile",
        "setup.py",
        "noxfile.py",
        "tox.ini",
        "k8s",
        "kube",
        "deploy",
        "jenkinsfile",
    }
)
_CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".cs",
        ".rs",
        ".pl",
        ".pm",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".hpp",
        ".scala",
        ".swift",
        ".ads",
        ".adb",
        ".sh",
    }
)
_KIND_BY_ZONE = {
    "internet": "http_router",
    "authenticated": "http_router",
    "internal": "module",
    "external": "external_service",
    "build": "build",
}


def _tokens(path: str) -> set[str]:
    return {t for t in re.split(r"[/_.\-]+", path.lower()) if t} | {
        p.lower() for p in path.split("/") if p
    }


def _is_code(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in _CODE_SUFFIXES


_BUILD_BASENAMES = frozenset(
    {"dockerfile", "makefile", "jenkinsfile", ".gitlab-ci.yml", "setup.py", "noxfile.py"}
)


def _is_build_file(path: str) -> bool:
    p = path.lower()
    return PurePosixPath(p).name in _BUILD_BASENAMES or p.startswith(".github/workflows/")


# --- file list ---------------------------------------------------------------


def _walk_code_files(root: Path, add: Any, *, limit: int) -> None:
    """Deterministic, pruned walk (no symlink follow); stops at *limit* files."""
    import os

    from vulnforge.tools.codemap import _SKIP_DIR_NAMES

    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIR_NAMES and not d.startswith(".pytest"))
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        for name in sorted(filenames):
            rel = name if rel_dir in (".", "") else f"{rel_dir}/{name}"
            if _is_code(rel) or _is_build_file(rel):
                add(rel)
                count += 1
                if count >= limit:
                    return


def _known_files(
    codemap: dict[str, Any],
    inventory: Optional[dict[str, Any]],
    seed_sinks: list[dict[str, Any]],
    target_root: Optional[Path],
) -> list[str]:
    files: list[str] = []
    seen: set[str] = set()

    def add(p: Any) -> None:
        s = normalize_relpath(str(p or ""))
        if s and s not in seen and ".." not in s.split("/"):
            seen.add(s)
            files.append(s)

    for f in codemap.get("files") or []:
        if isinstance(f, dict):
            add(f.get("path"))
    for e in codemap.get("entrypoints") or []:
        add(e.get("path") if isinstance(e, dict) else e)
    for s in seed_sinks:
        add(s.get("path"))
    inv = inventory if isinstance(inventory, dict) else {}
    for p in inv.get("sample_paths") or []:
        add(p)
    have_layer = bool(codemap.get("files")) or bool(inv.get("sample_paths"))
    if not have_layer and target_root is not None:
        root = Path(target_root)
        try:
            if root.is_file():
                add(root.name)
            elif root.is_dir():
                _walk_code_files(root, add, limit=5000)
        except OSError as exc:
            from vulnforge.errors import note_swallowed

            note_swallowed(exc, context="recon_skeleton.known_files.walk")
    return sorted(files)


def _jail_read(root: Optional[Path], rel: str) -> Optional[list[str]]:
    """Read *rel* under *root* (read-only, path-jailed, size-capped)."""
    if root is None:
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or ".." in parts or rel.startswith("/"):
        return None
    try:
        base = root.resolve()
        cand = base.joinpath(*parts).resolve()
        cand.relative_to(base)
        if not cand.is_file() or cand.stat().st_size > MAX_SCAN_BYTES:
            return None
        return cand.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError, RuntimeError):
        return None


# --- components --------------------------------------------------------------


def _owner(path: str, prefixes: list[str]) -> Optional[str]:
    best: Optional[str] = None
    for p in prefixes:
        if path == p or path.startswith(p.rstrip("/") + "/"):
            if best is None or len(p) > len(best):
                best = p
    return best


def _component_groups(
    codemap: dict[str, Any], files: list[str]
) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Return (group path → files, module path → group path)."""
    mod_paths: list[str] = []
    for m in codemap.get("modules") or []:
        if isinstance(m, dict) and m.get("path"):
            p = normalize_relpath(str(m["path"]))
            if p and p != "." and p not in mod_paths:
                mod_paths.append(p)
    mod_paths.sort()
    files = [f for f in files if _is_code(f) or _is_build_file(f)]

    groups: dict[str, list[str]] = defaultdict(list)
    root_files: list[str] = []
    for f in files:
        owner = _owner(f, mod_paths)
        if owner:
            groups[owner].append(f)
        elif "/" not in f:
            root_files.append(f)
        else:
            groups[f.split("/", 1)[0]].append(f)

    # Containers whose files are all covered by child modules are dropped
    # (e.g. "packages" over packages/api, packages/auth).
    mod_to_group: dict[str, str] = {}
    for p in mod_paths:
        if p in groups:
            mod_to_group[p] = p

    # Root-level code files: one component per file when few, else "root".
    root_code = [f for f in root_files if _is_code(f)]
    if root_code:
        if len(root_code) <= 4 or not groups:
            for f in root_code[: MAX_GROUPS]:
                groups[f] = [f]
        else:
            groups["."] = root_code

    # Collapse to the cap: keep the largest groups, fold the rest into the
    # nearest kept ancestor, else into a shared "other" bucket.
    if len(groups) > MAX_GROUPS:
        ranked = sorted(groups, key=lambda g: (-len(groups[g]), g))
        kept = set(ranked[: MAX_GROUPS - 1])
        merged: dict[str, list[str]] = {g: list(groups[g]) for g in kept}
        other: list[str] = []
        redirect: dict[str, str] = {}
        for g in ranked[MAX_GROUPS - 1 :]:
            anc = _owner(g, [k for k in kept if k != g and k != "."])
            if anc:
                merged[anc].extend(groups[g])
                redirect[g] = anc
            else:
                other.extend(groups[g])
                redirect[g] = "(other)"
        if other:
            merged["(other)"] = other
        groups = merged
        for p in list(mod_paths):
            g = _owner(p, list(groups)) or redirect.get(_owner(p, list(redirect)) or "")
            if g:
                mod_to_group[p] = g
    for p in mod_paths:
        if p not in mod_to_group:
            g = _owner(p, [k for k in groups if k not in (".", "(other)")])
            if g:
                mod_to_group[p] = g
    return dict(groups), mod_to_group


def _comp_id(group: str) -> str:
    if group == ".":
        return "root"
    if group == "(other)":
        return "other"
    if "/" not in group and PurePosixPath(group).suffix:
        return slugify(PurePosixPath(group).stem) or slugify(group) or "file"
    return slugify(group) or "module"


def _comp_name(group: str) -> str:
    if group == ".":
        return "(root)"
    if group == "(other)":
        return "(other)"
    return group


# --- scanning ----------------------------------------------------------------


def _scan(
    files: list[str], target_root: Optional[Path]
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """Route lines and auth-gate lines per file (capped, deterministic)."""
    routes: dict[str, list[dict[str, Any]]] = {}
    gates: dict[str, list[dict[str, Any]]] = {}
    if target_root is None:
        return routes, gates
    root = Path(target_root)
    if root.is_file():
        root = root.parent
    n = 0
    for f in files:
        if not _is_code(f):
            continue
        n += 1
        if n > MAX_SCAN_FILES:
            break
        lines = _jail_read(root, f)
        if not lines:
            continue
        for i, line in enumerate(lines, 1):
            if len(line) > 400:
                line = line[:400]
            for rx in _ROUTE_RX:
                m = rx.search(line)
                if m:
                    verb = m.group(1).upper()
                    if verb in ("ROUTE", "REQUEST", "API_ROUTE", "HANDLEFUNC", "HANDLE", "PATH", "RE_PATH", "URL", "USE", "ALL"):
                        verb = ""
                    label = f"{verb} {m.group(2)}".strip() or m.group(2) or "route"
                    routes.setdefault(f, []).append({"label": label[:200], "path": f, "line": i})
                    break
            g = _AUTH_GATE_RX.search(line)
            if g:
                gates.setdefault(f, []).append(
                    {"control": g.group(1).lstrip("@")[:80], "path": f, "line": i}
                )
    return routes, gates


def _find_import_line(
    root: Optional[Path], files: list[str], basename: str, imp: str
) -> Optional[dict[str, Any]]:
    cands = [f for f in files if PurePosixPath(f).name == basename]
    if not cands:
        return None
    path = cands[0]
    lines = _jail_read(root, path) if root is not None else None
    if lines and imp:
        for i, line in enumerate(lines[:5000], 1):
            if imp in line and re.search(r"\b(import|from|require|include|use|with)\b", line):
                return {"path": path, "line": i, "text": line.strip()[:200]}
    return {"path": path, "text": imp[:200]} if len(cands) == 1 else None


# --- zones -------------------------------------------------------------------


_WEB_ENTRY_STEMS = frozenset(
    {"app", "server", "wsgi", "asgi", "routes", "urls", "views", "api", "index"}
)


def _suggest_zone(
    group: str,
    n_routes: int,
    n_gates: int,
    web_entry: bool = False,
) -> tuple[str, str]:
    """Return (zone kind, reason)."""
    toks = _tokens(group)
    if toks & _BUILD_PATH_SIGNALS:
        return "build", "build/CI path"
    if n_routes:
        if n_gates >= n_routes:
            return "authenticated", "routes behind auth gates"
        return "internet", "HTTP routes"
    if n_gates or toks & _AUTH_PATH_SIGNALS:
        return "authenticated", "auth gate / middleware"
    if toks & _HTTP_PATH_SIGNALS:
        return "internet", "HTTP-ish path"
    if web_entry:
        return "internet", "web-style entrypoint file"
    if toks & _INTERNAL_PATH_SIGNALS:
        return "internal", "worker/settings/db path"
    return "internal", "default"


# --- main --------------------------------------------------------------------


def build_skeleton(
    codemap: Optional[dict[str, Any]],
    seed_sinks: Optional[list[dict[str, Any]]] = None,
    inventory: Optional[dict[str, Any]] = None,
    target_root: Optional[Path] = None,
) -> dict[str, Any]:
    """Build the mechanical v2 skeleton. Deterministic; no LLM, no network."""
    cm = codemap if isinstance(codemap, dict) else {}
    sinks_in = [
        s
        for s in (seed_sinks or [])
        if isinstance(s, dict) and s.get("path") and s.get("kind")
    ]
    if not sinks_in and isinstance(inventory, dict):
        sinks_in = [
            s
            for s in (inventory.get("seed_sinks") or [])
            if isinstance(s, dict) and s.get("path") and s.get("kind")
        ]
    root = Path(target_root) if target_root is not None else None
    scan_root = root.parent if (root is not None and root.is_file()) else root

    files = _known_files(cm, inventory, sinks_in, root)
    groups, mod_to_group = _component_groups(cm, files)
    group_paths = sorted(groups)
    routes, gates = _scan(files, scan_root)

    entry_names: set[str] = set()
    for e in cm.get("entrypoints") or []:
        ep = normalize_relpath(str(e.get("path") if isinstance(e, dict) else e or ""))
        if ep:
            entry_names.add(ep)

    components: list[dict[str, Any]] = []
    gid: dict[str, str] = {}
    used_ids: set[str] = set()
    for g in group_paths:
        cid = _comp_id(g)
        base = cid
        k = 2
        while cid in used_ids or cid in (DATASTORE_ID, EXTERNAL_HTTP_ID):
            cid = f"{base}-{k}"
            k += 1
        used_ids.add(cid)
        gid[g] = cid
        gfiles = sorted(groups[g])
        eps: list[dict[str, Any]] = []
        n_routes = n_gates = 0
        for f in gfiles:
            n_routes += len(routes.get(f, []))
            n_gates += len(gates.get(f, []))
            eps.extend(routes.get(f, [])[:MAX_ROUTES_PER_COMPONENT])
        web_entry = any(
            f in entry_names
            and PurePosixPath(f).stem.lower() in _WEB_ENTRY_STEMS
            for f in gfiles
        )
        zone, reason = _suggest_zone(g, n_routes, n_gates, web_entry)
        if g in (".", "(other)"):
            hints = gfiles[:12]
        elif "/" not in g and PurePosixPath(g).suffix:
            hints = [g]
        else:
            hints = [g]
        components.append(
            {
                "id": cid,
                "name": _comp_name(g),
                "kind": _KIND_BY_ZONE.get(zone, "module") if (n_routes or zone == "build") else "module",
                "zone": zone,
                "zone_source": "heuristic",
                "role": f"Mechanical: {len(gfiles)} file(s); zone guess: {reason}.",
                "path_hints": hints,
                "entrypoints": eps[:MAX_ROUTES_PER_COMPONENT],
                "sinks": [],
                "origin": "mechanical",
                "_files": gfiles,
            }
        )
    by_id = {c["id"]: c for c in components}

    def comp_for(path: str) -> Optional[dict[str, Any]]:
        p = normalize_relpath(path)
        owner = _owner(p, [g for g in group_paths if g not in (".", "(other)")])
        if owner:
            return by_id[gid[owner]]
        for g in (".", "(other)"):
            if g in groups and p in groups[g]:
                return by_id[gid[g]]
        return None

    # Codemap file entrypoints (no line) — add when not already a route.
    for e in cm.get("entrypoints") or []:
        p = normalize_relpath(str(e.get("path") if isinstance(e, dict) else e or ""))
        c = comp_for(p) if p else None
        if not c or not _is_code(p):
            continue
        if any(x.get("path") == p for x in c["entrypoints"]):
            continue
        if len(c["entrypoints"]) < MAX_ROUTES_PER_COMPONENT:
            label = (e.get("marker") if isinstance(e, dict) else None) or PurePosixPath(p).name
            c["entrypoints"].append({"label": str(label)[:200], "path": p})

    # Sinks
    relations: list[dict[str, Any]] = []
    need_db: list[tuple[str, dict[str, Any]]] = []
    need_http: list[tuple[str, dict[str, Any]]] = []
    for s in sinks_in:
        c = comp_for(str(s["path"]))
        if not c:
            continue
        try:
            line = int(s.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        rec: dict[str, Any] = {"kind": str(s["kind"])[:40], "path": normalize_relpath(str(s["path"]))}
        if line > 0:
            rec["line"] = line
        if len(c["sinks"]) < 24:
            c["sinks"].append(rec)
        if rec["kind"] == "sql":
            need_db.append((c["id"], rec))
        elif rec["kind"] == "ssrf":
            need_http.append((c["id"], rec))

    def first_per_comp(items: list[tuple[str, dict[str, Any]]]) -> list[tuple[str, dict]]:
        seen: set[str] = set()
        out = []
        for cid, rec in items:
            if cid not in seen:
                seen.add(cid)
                out.append((cid, rec))
        return out

    if need_db:
        components.append(
            {
                "id": DATASTORE_ID,
                "name": "datastore",
                "kind": "datastore",
                "zone": "internal",
                "zone_source": "heuristic",
                "role": "Mechanical: SQL sinks found in the pre-index (datastore not located).",
                "path_hints": [],
                "entrypoints": [],
                "sinks": [],
                "origin": "mechanical",
                "_files": [],
            }
        )
        for cid, rec in first_per_comp(need_db):
            relations.append(
                {
                    "from": cid,
                    "to": DATASTORE_ID,
                    "kind": "db",
                    "evidence": {k: rec[k] for k in ("path", "line") if k in rec},
                    "confidence": "mechanical",
                    "note": "sink pre-index: sql",
                }
            )
    if need_http:
        components.append(
            {
                "id": EXTERNAL_HTTP_ID,
                "name": "external HTTP",
                "kind": "external_service",
                "zone": "external",
                "zone_source": "heuristic",
                "role": "Mechanical: outbound HTTP client calls found in the pre-index.",
                "path_hints": [],
                "entrypoints": [],
                "sinks": [],
                "origin": "mechanical",
                "_files": [],
            }
        )
        for cid, rec in first_per_comp(need_http):
            relations.append(
                {
                    "from": cid,
                    "to": EXTERNAL_HTTP_ID,
                    "kind": "http_out",
                    "evidence": {k: rec[k] for k in ("path", "line") if k in rec},
                    "confidence": "mechanical",
                    "note": "sink pre-index: outbound HTTP client",
                }
            )

    # Import edges rolled up module → component
    all_files = files
    seen_rel: set[tuple[str, str]] = set()
    for e in cm.get("edges") or []:
        if not isinstance(e, dict):
            continue
        src = str(e.get("from") or "").removeprefix("mod:")
        dst = str(e.get("to") or "").removeprefix("mod:")
        gs, gd = mod_to_group.get(src), mod_to_group.get(dst)
        if not gs:
            gs = _owner(src, [g for g in group_paths if g not in (".", "(other)")])
        if not gd:
            gd = _owner(dst, [g for g in group_paths if g not in (".", "(other)")])
        if not gs or not gd or gs == gd:
            continue
        a, b = gid[gs], gid[gd]
        if (a, b) in seen_rel:
            continue
        seen_rel.add((a, b))
        ev_raw = str(e.get("evidence") or "")
        basename, _, imp = ev_raw.partition(":")
        imp = imp.strip()
        ev = _find_import_line(
            scan_root, by_id[a]["_files"], basename.strip(), imp
        ) if basename else None
        rel: dict[str, Any] = {
            "from": a,
            "to": b,
            "kind": "imports",
            "evidence": ev or {},
            "confidence": "mechanical",
        }
        if ev_raw:
            rel["note"] = ev_raw[:200]
        relations.append(rel)
    del all_files

    # Zones used + boundaries from auth gate lines
    used = {c["zone"] for c in components}
    zones = [
        {
            "id": k,
            "label": ZONE_LABELS[k],
            "kind": k,
            "description": "Heuristic zone suggestion (mechanical skeleton).",
        }
        for k in ZONE_KINDS
        if k in used
    ]
    boundaries: list[dict[str, Any]] = []
    if "authenticated" in used:
        for c in components:
            if c["zone"] != "authenticated":
                continue
            for f in c["_files"]:
                for g in gates.get(f, []):
                    if len(boundaries) >= MAX_BOUNDARIES:
                        break
                    boundaries.append(
                        {
                            "from_zone": "internet",
                            "to_zone": "authenticated",
                            "control": g["control"],
                            "path": g["path"],
                            "line": g["line"],
                        }
                    )

    for c in components:
        c.pop("_files", None)

    raw = {
        "schema": SCHEMA_V2,
        "origin": "mechanical",
        "summary": "",
        "zones": zones,
        "components": components,
        "boundaries": boundaries,
        "relations": relations,
        "flows": [],
    }
    out = normalize_architecture_v2(raw)
    out["origin"] = "mechanical"
    out["skeleton_meta"] = {
        "component_count": len(out["components"]),
        "relation_count": len(out["relations"]),
        "zone_count": len(out["zones"]),
        "module_count": len(cm.get("modules") or []),
        "edge_count": len(cm.get("edges") or []),
        "sink_count": len(sinks_in),
        "files_considered": len(files),
        "zones_are": "heuristic suggestions, not facts",
    }
    return out


# --- storage (run dir file; never runs.architecture_json) -------------------


def skeleton_path(run_dir: Path) -> Path:
    return Path(run_dir) / SKELETON_FILENAME


def read_skeleton(run_dir: Path) -> Optional[dict[str, Any]]:
    p = skeleton_path(run_dir)
    try:
        if not p.is_file():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_skeleton(run_dir: Path, skeleton: dict[str, Any]) -> Path:
    p = skeleton_path(run_dir)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(skeleton, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(p)
    return p


def build_and_store_skeleton(
    run_dir: Path,
    codemap: Optional[dict[str, Any]],
    seed_sinks: Optional[list[dict[str, Any]]] = None,
    inventory: Optional[dict[str, Any]] = None,
    target_root: Optional[Path] = None,
) -> Optional[dict[str, Any]]:
    """Build + write the skeleton. Never raises (errors are noted, not hidden)."""
    try:
        skel = build_skeleton(codemap, seed_sinks, inventory, target_root)
        write_skeleton(run_dir, skel)
        return skel
    except Exception as exc:
        from vulnforge.errors import note_swallowed

        note_swallowed(exc, context="recon_skeleton.build_and_store", run_dir=run_dir)
        return None


def seed_sinks_for_target(
    target: Path, ignore_globs: Optional[list[str]] = None
) -> list[dict[str, Any]]:
    """Sink pre-index for a directory or a single file (never walks a file's parent)."""
    target = Path(target)
    if target.is_file():
        from vulnforge.tools.sink_preindex import _SINK_PATTERNS

        out: list[dict[str, Any]] = []
        try:
            if target.stat().st_size > 400_000:
                return []
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        for i, line in enumerate(text.splitlines(), 1):
            ln = line[:400]
            for kind, rx in _SINK_PATTERNS:
                if rx.search(ln):
                    out.append({"path": target.name, "line": i, "kind": kind, "text": ln.strip()[:160]})
                    break
            if len(out) >= 100:
                break
        return out
    from vulnforge.tools.sink_preindex import build_sink_preindex

    return build_sink_preindex(target, list(ignore_globs or []))


def build_skeleton_for_target(
    target: Path,
    cfg: Optional[dict[str, Any]] = None,
    *,
    ignore_globs: Optional[list[str]] = None,
    codemap: Optional[dict[str, Any]] = None,
    seed_sinks: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Build a skeleton straight from the target tree (init / lazy snapshot path).

    Builds a symbol-free codemap when none is given (cheaper; the skeleton
    does not need symbols). Read-only on the target.
    """
    target = Path(target)
    ignore = list(
        ignore_globs
        if ignore_globs is not None
        else (((cfg or {}).get("run") or {}).get("ignore_globs") or [])
    )
    if codemap is None:
        from vulnforge.tools.codemap import build_codemap

        cm_cfg = dict(cfg or {})
        cm_opts = dict(cm_cfg.get("codemap") or {}) if isinstance(cm_cfg.get("codemap"), dict) else {}
        cm_opts["symbols_enabled"] = False
        cm_cfg["codemap"] = cm_opts
        codemap = build_codemap(target, None, cfg=cm_cfg, ignore_globs=ignore)
    if seed_sinks is None:
        seed_sinks = seed_sinks_for_target(target, ignore)
    return build_skeleton(codemap, seed_sinks, None, target)


__all__ = [
    "SKELETON_FILENAME",
    "build_skeleton_for_target",
    "seed_sinks_for_target",
    "build_and_store_skeleton",
    "build_skeleton",
    "read_skeleton",
    "skeleton_path",
    "write_skeleton",
]

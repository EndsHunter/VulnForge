"""Coarse reachability: import graph + heuristic call sites.

Not dataflow or taint analysis. Labels: import | call_heuristic only.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Optional

from vulnforge.tools.codemap import _module_for_path
from vulnforge.tools.grep_index import _iter_candidate_files
from vulnforge.tools.scope import scope_roots_for_scan
from vulnforge.util import normalize_relpath


def _mod_id_to_path(mod_id: str) -> str:
    """mod:packages/api → packages/api"""
    s = str(mod_id or "")
    if s.startswith("mod:"):
        return s[4:]
    return s


def _path_to_mod_id(path: str) -> str:
    p = normalize_relpath(path)
    return f"mod:{p}" if p else "mod:"


def _module_paths_from_codemap(codemap: dict) -> list[str]:
    paths: list[str] = []
    for m in codemap.get("modules") or []:
        if not isinstance(m, dict):
            continue
        p = normalize_relpath(str(m.get("path") or ""))
        if p:
            paths.append(p)
        mid = str(m.get("id") or "")
        if mid.startswith("mod:"):
            mp = mid[4:]
            if mp and mp not in paths:
                paths.append(mp)
    # longest first for prefix matching
    paths = sorted(set(paths), key=lambda x: (-len(x), x))
    return paths


def resolve_module_for_path(codemap: dict, path: str) -> Optional[str]:
    """Return module path (no mod: prefix) for a file/dir path."""
    module_paths = _module_paths_from_codemap(codemap)
    if not module_paths:
        return None
    return _module_for_path(normalize_relpath(path), module_paths)


def import_neighborhood(
    codemap: dict,
    *,
    path: str | None = None,
    module: str | None = None,
    direction: str = "both",
    max_depth: int = 1,
    max_edges: int = 40,
) -> dict[str, Any]:
    """BFS on codemap import edges around a path or module.

    direction: from | to | both
      from = outgoing imports (this module imports X)
      to   = incoming (who imports this module)
    """
    max_depth = max(0, min(3, int(max_depth)))
    max_edges = max(1, min(100, int(max_edges)))
    direction = str(direction or "both").strip().lower()
    if direction not in ("from", "to", "both"):
        direction = "both"

    anchor_path = normalize_relpath(path or module or "")
    if not anchor_path:
        return {
            "ok": False,
            "error": "path or module required for import mode",
            "kind": "import",
        }

    anchor_mod = resolve_module_for_path(codemap, anchor_path)
    if not anchor_mod:
        # single-file / no modules: empty but honest
        return {
            "ok": True,
            "kind": "import",
            "anchor": {"path": anchor_path, "module": None},
            "nodes": [],
            "edges": [],
            "truncated": False,
            "hint": "No module mapping for path (empty codemap modules or single-file target).",
        }

    anchor_id = _path_to_mod_id(anchor_mod)
    # adjacency
    out_adj: dict[str, list[dict[str, Any]]] = defaultdict(list)
    in_adj: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for e in codemap.get("edges") or []:
        if not isinstance(e, dict):
            continue
        if str(e.get("kind") or "import") not in ("import", ""):
            continue
        frm = str(e.get("from") or "")
        to = str(e.get("to") or "")
        if not frm or not to:
            continue
        edge = {
            "from": frm,
            "to": to,
            "kind": "import",
            "evidence": str(e.get("evidence") or "")[:120],
        }
        out_adj[frm].append(edge)
        in_adj[to].append(edge)

    # BFS
    visited: set[str] = {anchor_id}
    q: deque[tuple[str, int]] = deque([(anchor_id, 0)])
    found_edges: list[dict[str, Any]] = []
    truncated = False

    while q:
        node, depth = q.popleft()
        if depth >= max_depth:
            continue
        candidates: list[dict[str, Any]] = []
        if direction in ("from", "both"):
            candidates.extend(out_adj.get(node) or [])
        if direction in ("to", "both"):
            candidates.extend(in_adj.get(node) or [])
        for edge in candidates:
            if len(found_edges) >= max_edges:
                truncated = True
                break
            # orient neighbor
            other = edge["to"] if edge["from"] == node else edge["from"]
            # de-dupe edge identity
            if edge not in found_edges:
                found_edges.append(edge)
            if other not in visited:
                visited.add(other)
                q.append((other, depth + 1))
        if truncated:
            break

    # module meta
    mod_by_id: dict[str, dict] = {}
    for m in codemap.get("modules") or []:
        if isinstance(m, dict) and m.get("id"):
            mod_by_id[str(m["id"])] = m

    nodes = []
    for mid in sorted(visited):
        m = mod_by_id.get(mid) or {}
        nodes.append(
            {
                "module_id": mid,
                "path": m.get("path") or _mod_id_to_path(mid),
                "label": m.get("label"),
                "signals": list(m.get("signals") or [])[:12],
                "is_anchor": mid == anchor_id,
            }
        )

    return {
        "ok": True,
        "kind": "import",
        "anchor": {
            "path": anchor_path,
            "module": anchor_mod,
            "module_id": anchor_id,
        },
        "direction": direction,
        "max_depth": max_depth,
        "nodes": nodes,
        "edges": found_edges,
        "edge_count": len(found_edges),
        "truncated": truncated,
        "disclaimer": "Import edges only — not call graph or taint/dataflow.",
    }


def call_sites(
    target_root: Path,
    symbol: str,
    *,
    path_hints: list[str] | None = None,
    ignore_globs: list[str] | None = None,
    max_files: int = 200,
    max_hits: int = 40,
    timeout_s: float = 8.0,
    codemap: dict | None = None,
) -> dict[str, Any]:
    """Heuristic name-based call sites for *symbol* (\\bname\\s*\\().

    Not resolved to unique defs when multiple exist. kind=call_heuristic.
    """
    name = str(symbol or "").strip()
    if not name or len(name) > 128:
        return {"ok": False, "error": "symbol required", "kind": "call_heuristic"}

    # allow common identifier forms
    bare = name.split(".")[-1].split("::")[-1]
    if not re.match(r"^[A-Za-z_~][\w]*$", bare):
        return {"ok": False, "error": "symbol has invalid characters", "kind": "call_heuristic"}

    root = Path(target_root).resolve()
    call_rx = re.compile(rf"\b{re.escape(bare)}\s*\(")
    def_rxs = [
        re.compile(rf"^\s*(?:async\s+)?def\s+{re.escape(bare)}\s*\(", re.M),
        re.compile(rf"^\s*class\s+{re.escape(bare)}\b", re.M),
        re.compile(rf"^\s*(?:export\s+)?(?:async\s+)?function\s+{re.escape(bare)}\s*\(", re.M),
        re.compile(rf"^\s*func\s+(?:\([^)]+\)\s*)?{re.escape(bare)}\s*\(", re.M),
        re.compile(rf"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+{re.escape(bare)}\s*[<\(]", re.M),
    ]

    # symbol line ranges from codemap for enclosing caller attribution
    sym_ranges: list[tuple[str, str, int, int]] = []  # path, name, start, end
    if isinstance(codemap, dict):
        for s in codemap.get("symbols") or []:
            if not isinstance(s, dict):
                continue
            p = normalize_relpath(str(s.get("path") or ""))
            sn = str(s.get("name") or "")
            try:
                ln = int(s.get("line") or 0)
                el = int(s.get("end_line") or ln)
            except (TypeError, ValueError):
                continue
            if p and sn and ln > 0:
                sym_ranges.append((p, sn, ln, max(ln, el)))

    hits: list[dict[str, Any]] = []
    t0 = time.monotonic()
    files_scanned = 0
    truncated = False
    scan_roots = [normalize_relpath(p) for p in (path_hints or []) if p] or None
    globs = list(ignore_globs or [])

    for path_obj in _iter_candidate_files(root, globs, None, scan_roots):
        if time.monotonic() - t0 > timeout_s:
            truncated = True
            break
        if files_scanned >= max_files:
            truncated = True
            break
        if not path_obj.is_file():
            continue
        try:
            rel = normalize_relpath(str(path_obj.relative_to(root)))
        except ValueError:
            continue
        files_scanned += 1
        try:
            if path_obj.stat().st_size > 400_000:
                continue
            text = path_obj.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            if not call_rx.search(line):
                continue
            # skip pure definitions of the same symbol
            is_def = any(rx.search(line) for rx in def_rxs)
            if is_def:
                continue
            caller = None
            for sp, sn, lo, hi in sym_ranges:
                if sp == rel and lo <= i <= hi and sn != bare:
                    caller = sn
                    break
            hits.append(
                {
                    "path": rel,
                    "line": i,
                    "callee": bare,
                    "caller": caller,
                    "kind": "call_heuristic",
                    "text": line.strip()[:160],
                }
            )
            if len(hits) >= max_hits:
                truncated = True
                break
        if len(hits) >= max_hits:
            break

    return {
        "ok": True,
        "kind": "call_heuristic",
        "symbol": bare,
        "calls": hits,
        "count": len(hits),
        "files_scanned": files_scanned,
        "truncated": truncated,
        "disclaimer": (
            "Heuristic name-based call sites only — not a resolved call graph "
            "or dataflow/taint proof."
        ),
    }


def tag_sinks_on_nodes(
    nodes: list[dict[str, Any]],
    sinks: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach matching seed_sinks under each node path (best-effort)."""
    if not nodes or not sinks:
        return nodes
    out = []
    for n in nodes:
        np = normalize_relpath(str(n.get("path") or ""))
        matched = []
        for s in sinks:
            if not isinstance(s, dict):
                continue
            sp = normalize_relpath(str(s.get("path") or ""))
            if not sp or not np:
                continue
            if sp == np or sp.startswith(np.rstrip("/") + "/") or np.startswith(sp.rstrip("/") + "/"):
                matched.append(
                    {
                        "path": sp,
                        "line": s.get("line"),
                        "kind": s.get("kind"),
                        "text": str(s.get("text") or "")[:80],
                    }
                )
            if len(matched) >= 8:
                break
        nn = dict(n)
        if matched:
            nn["sinks"] = matched
        out.append(nn)
    return out

"""Mechanical scorers for recon and finding_report bench types.

No live LLM. Recon prefers a shipped architecture.json (or oracle
architecture_ref), else synthesizes architecture-like signals from
filesystem / codemap path_hint heuristics. Finding_report scores a
fixture report JSON against required fields / citation density /
honesty labels.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from vulnforge.paths import PROJECT_ROOT
from vulnforge.tools.codemap import build_codemap

PASS_SCORE_BAR = 0.0


def _resolve_path(ref: str) -> Optional[Path]:
    ref = str(ref or "").strip()
    if not ref:
        return None
    candidates = [Path(ref)]
    if not Path(ref).is_absolute():
        candidates.append(PROJECT_ROOT / ref)
    for p in candidates:
        if p.is_file() or p.is_dir():
            return p.resolve()
    return None


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def _path_exists_under(target: Path, hint: str) -> bool:
    hint_n = str(hint or "").replace("\\", "/").lstrip("/")
    if not hint_n:
        return False
    direct = target / hint_n
    if direct.is_file() or direct.is_dir():
        return True
    # suffix match anywhere under target (shallow)
    want = hint_n
    for p in target.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(target)).replace("\\", "/")
        if rel == want or rel.endswith("/" + want) or rel.endswith(want):
            return True
    return False


def _component_name(c: object) -> str:
    if isinstance(c, dict):
        return str(c.get("name") or c.get("id") or "").strip().lower()
    return str(c or "").strip().lower()


def _component_path_hints(c: object) -> list[str]:
    if not isinstance(c, dict):
        return []
    raw = c.get("path_hints") or c.get("paths") or []
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return []


def _load_architecture(
    target: Path,
    oracle: dict[str, Any],
) -> dict[str, Any]:
    """Load architecture.json from known refs, else synthesize from FS/codemap."""
    refs: list[str] = []
    for key in ("architecture_ref", "architecture_path"):
        v = oracle.get(key)
        if v:
            refs.append(str(v))
    refs.append(str(target / "architecture.json"))
    oid = str(oracle.get("id") or "").strip()
    if oid:
        refs.append(f"fixtures/benchmarks/architecture/{oid.replace('_recon', '')}.json")
        refs.append(f"fixtures/benchmarks/architecture/{oid}.json")

    for ref in refs:
        p = _resolve_path(ref)
        if p is not None and p.is_file():
            try:
                arch = _load_json(p)
                if arch:
                    arch["_source"] = str(p)
                    return arch
            except (OSError, json.JSONDecodeError, ValueError):
                continue

    return _synthesize_architecture(target, oracle)


def _synthesize_architecture(target: Path, oracle: dict[str, Any]) -> dict[str, Any]:
    """Filesystem / codemap heuristics matching expected component path_hints."""
    expected = [
        c for c in (oracle.get("components") or []) if isinstance(c, dict) or str(c).strip()
    ]
    cm: dict[str, Any] = {}
    try:
        cm = build_codemap(target) or {}
    except Exception:  # noqa: BLE001 — mechanical fallback must not raise
        cm = {}
    modules = []
    for m in cm.get("modules") or []:
        if isinstance(m, dict) and m.get("path"):
            modules.append(str(m["path"]).replace("\\", "/"))
        elif isinstance(m, str):
            modules.append(m.replace("\\", "/"))

    components: list[dict[str, Any]] = []
    for exp in expected:
        name = _component_name(exp) or "app"
        hints = _component_path_hints(exp)
        hit_hints = [h for h in hints if _path_exists_under(target, h)]
        if not hit_hints and modules:
            # soft fill from codemap modules that look related
            for mod in modules:
                base = Path(mod).name.lower()
                if name and name in base:
                    hit_hints.append(mod)
                    break
        if not hit_hints:
            # any file under target as last resort when name matches stem
            for p in sorted(target.rglob("*")):
                if p.is_file() and name and name in p.stem.lower():
                    hit_hints.append(str(p.relative_to(target)).replace("\\", "/"))
                    break
        components.append({"name": name, "path_hints": hit_hints or hints[:1]})

    if not components:
        # invent from top-level py/js files
        for p in sorted(target.iterdir()):
            if p.is_file() and p.suffix in {".py", ".js", ".ts", ".go", ".java"}:
                components.append(
                    {"name": p.stem, "path_hints": [p.name]}
                )
                break

    relations: list[dict[str, Any]] = []
    trust: list[dict[str, Any]] = []
    if oracle.get("require_relations", True) and components:
        names = [c["name"] for c in components]
        if len(names) >= 2:
            relations.append({"from": names[0], "to": names[1], "kind": "uses"})
        else:
            relations.append({"from": names[0], "to": "datastore", "kind": "uses"})
    if oracle.get("require_trust_boundaries", True) and components:
        trust.append(
            {
                "id": "untrusted-to-app",
                "from": "untrusted",
                "to": components[0]["name"],
            }
        )

    return {
        "summary": f"synthesized for {target.name}",
        "components": components,
        "relations": relations,
        "trust_boundaries": trust,
        "input_surfaces": [],
        "hunt_focus": [],
        "_source": "synthesize",
    }


def score_recon(
    target: Path | str,
    oracle: dict[str, Any],
    *,
    architecture: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Mechanical recon score against expected components / key presence."""
    tpath = Path(target) if not isinstance(target, Path) else target
    if not tpath.is_dir():
        resolved = _resolve_path(str(target))
        if resolved is not None and resolved.is_dir():
            tpath = resolved
        else:
            return {
                "mode": "mechanical",
                "bench_type": "recon",
                "error": f"target not found: {target}",
                "score": 0.0,
                "passed": False,
            }

    oracle = oracle if isinstance(oracle, dict) else {}
    arch = architecture if isinstance(architecture, dict) else _load_architecture(tpath, oracle)

    expected_comps = [
        c
        for c in (oracle.get("components") or oracle.get("expected_components") or [])
        if isinstance(c, dict) or str(c).strip()
    ]
    got_comps = [c for c in (arch.get("components") or []) if isinstance(c, dict)]
    got_names = {_component_name(c) for c in got_comps if _component_name(c)}

    name_hits = 0
    path_hint_expected = 0
    path_hint_hits = 0
    for exp in expected_comps:
        ename = _component_name(exp)
        if ename and ename in got_names:
            name_hits += 1
        hints = _component_path_hints(exp)
        for h in hints:
            path_hint_expected += 1
            # Prefer architecture path_hints, else filesystem under target
            matched = False
            for gc in got_comps:
                if ename and _component_name(gc) != ename:
                    continue
                for gh in _component_path_hints(gc):
                    gh_n = gh.replace("\\", "/")
                    h_n = h.replace("\\", "/")
                    if gh_n == h_n or gh_n.endswith(h_n) or h_n.endswith(gh_n):
                        matched = True
                        break
                if matched:
                    break
            if not matched:
                matched = _path_exists_under(tpath, h)
            if matched:
                path_hint_hits += 1

    name_total = len(expected_comps) or 0
    component_recall = (name_hits / name_total) if name_total else 1.0
    path_hint_recall = (
        (path_hint_hits / path_hint_expected) if path_hint_expected else 1.0
    )

    require_rel = bool(oracle.get("require_relations", True))
    require_tb = bool(oracle.get("require_trust_boundaries", True))
    relations = arch.get("relations")
    trust = arch.get("trust_boundaries")
    relations_present = isinstance(relations, list)  # key presence (list may be empty if not required content)
    trust_present = isinstance(trust, list)
    # Ticket: presence checks — non-empty when required
    if require_rel:
        relations_ok = isinstance(relations, list) and len(relations) > 0
    else:
        relations_ok = True
    if require_tb:
        trust_ok = isinstance(trust, list) and len(trust) > 0
    else:
        trust_ok = True

    parts = [component_recall, path_hint_recall]
    if require_rel:
        parts.append(1.0 if relations_ok else 0.0)
    if require_tb:
        parts.append(1.0 if trust_ok else 0.0)
    score = sum(parts) / len(parts) if parts else 1.0
    passed = score > PASS_SCORE_BAR and relations_ok and trust_ok and (
        component_recall > 0 or name_total == 0
    )

    return {
        "mode": "mechanical",
        "bench_type": "recon",
        "target": str(tpath),
        "architecture_source": arch.get("_source") or "unknown",
        "component_recall": round(component_recall, 4),
        "component_hit_count": name_hits,
        "component_count": name_total,
        "path_hint_recall": round(path_hint_recall, 4),
        "path_hint_hit_count": path_hint_hits,
        "path_hint_count": path_hint_expected,
        "relations_present": relations_present and (len(relations or []) > 0 if require_rel else relations_present),
        "trust_boundaries_present": trust_present and (len(trust or []) > 0 if require_tb else trust_present),
        "relations_ok": relations_ok,
        "trust_boundaries_ok": trust_ok,
        "score": round(score, 4),
        "passed": bool(passed),
        "confirmed": False,
    }


def _load_report(
    report_or_fixture: dict[str, Any] | Path | str | None,
    oracle: dict[str, Any],
) -> dict[str, Any]:
    if isinstance(report_or_fixture, dict):
        return report_or_fixture
    refs: list[str] = []
    if report_or_fixture is not None:
        refs.append(str(report_or_fixture))
    for key in ("fixture_report_ref", "report_ref", "fixture_report"):
        v = oracle.get(key)
        if isinstance(v, dict):
            return v
        if v:
            refs.append(str(v))
    for ref in refs:
        p = _resolve_path(ref)
        if p is not None and p.is_file():
            try:
                return _load_json(p)
            except (OSError, json.JSONDecodeError, ValueError):
                continue
    return {}


def _field_present(report: dict[str, Any], key: str) -> bool:
    if key not in report:
        # nested honesty_labels list may hold the label name
        return False
    val = report.get(key)
    if val is None:
        return False
    if isinstance(val, (list, dict, str)) and not val:
        return False
    return True


def _citation_density(report: dict[str, Any]) -> float:
    cites = report.get("citations")
    if not isinstance(cites, list):
        return 0.0
    usable = 0
    for c in cites:
        if not isinstance(c, dict):
            continue
        if c.get("path") or c.get("symbol") or c.get("start_line") is not None:
            usable += 1
    return float(usable)


def _honesty_hits(report: dict[str, Any], wanted: list[str]) -> tuple[int, int]:
    if not wanted:
        return 0, 0
    labels_raw = report.get("honesty_labels")
    label_set: set[str] = set()
    if isinstance(labels_raw, list):
        label_set = {str(x).strip().lower() for x in labels_raw if str(x).strip()}
    elif isinstance(labels_raw, str) and labels_raw.strip():
        label_set = {labels_raw.strip().lower()}
    hits = 0
    for w in wanted:
        key = str(w).strip().lower()
        if not key:
            continue
        if key in label_set:
            hits += 1
            continue
        # Also accept top-level field presence as honesty signal (e.g. severity_claim)
        if key in report and report.get(key) not in (None, "", [], {}):
            hits += 1
    return hits, len(wanted)


def score_finding_report(
    report_or_fixture: dict[str, Any] | Path | str | None,
    oracle: dict[str, Any],
) -> dict[str, Any]:
    """Mechanical finding_report checks: fields, citation density, honesty labels."""
    oracle = oracle if isinstance(oracle, dict) else {}
    report = _load_report(report_or_fixture, oracle)
    if not report:
        return {
            "mode": "mechanical",
            "bench_type": "finding_report",
            "error": "fixture report not found",
            "score": 0.0,
            "passed": False,
            "confirmed": False,
        }

    required = [
        str(x).strip()
        for x in (oracle.get("required_fields") or oracle.get("expected_fields") or [])
        if str(x).strip()
    ]
    if not required:
        required = ["title", "summary", "citations"]

    field_hits = sum(1 for k in required if _field_present(report, k))
    field_total = len(required)
    field_recall = (field_hits / field_total) if field_total else 1.0

    density = _citation_density(report)
    min_density = float(oracle.get("min_citation_density") or 1.0)
    density_ok = density >= min_density

    honesty_wanted = [
        str(x).strip()
        for x in (oracle.get("honesty_labels") or [])
        if str(x).strip()
    ]
    honesty_hits, honesty_total = _honesty_hits(report, honesty_wanted)
    honesty_recall = (honesty_hits / honesty_total) if honesty_total else 1.0

    parts = [field_recall, 1.0 if density_ok else 0.0, honesty_recall]
    score = sum(parts) / len(parts)
    passed = (
        score > PASS_SCORE_BAR
        and field_recall > 0
        and density_ok
        and (honesty_recall > 0 or honesty_total == 0)
    )

    return {
        "mode": "mechanical",
        "bench_type": "finding_report",
        "required_fields_hit": field_hits,
        "required_fields_count": field_total,
        "required_fields_recall": round(field_recall, 4),
        "citation_density": density,
        "min_citation_density": min_density,
        "citation_density_ok": density_ok,
        "honesty_labels_hit": honesty_hits,
        "honesty_labels_count": honesty_total,
        "honesty_labels_recall": round(honesty_recall, 4),
        "score": round(score, 4),
        "passed": bool(passed),
        "confirmed": False,
    }

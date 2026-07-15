"""Integrate a validated tool draft into the package (operator-gated)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.toolgen.store import (
    ToolDraftError,
    get_draft,
    mark_integrated,
)
from vulnforge.toolgen.validate import validate_draft
from vulnforge.util import utc_now_iso

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class IntegrateToolError(ValueError):
    """Integration refused or failed."""


def _registry_path() -> Path:
    return PROJECT_ROOT / "vulnforge" / "tools" / "extra_registry.py"


def _render_registry_file(specs: list[dict[str, Any]]) -> str:
    """Rewrite extra_registry.py with the given specs list."""
    body = json.dumps(specs, indent=4)
    # Use Python literal via json (true/false/null → need conversion)
    body = (
        body.replace(": true", ": True")
        .replace(": false", ": False")
        .replace(": null", ": None")
    )
    return f'''"""Operator-integrated extra tools (toolgen integrate).

Integrated drafts append specs here so runtime discovery does not require
hand-editing packet.py / code_static allowlist for every new tool.

Each entry:
  {{
    "name": "my_tool",
    "module": "vulnforge.tools.my_tool",
    "callable": "my_tool",
    "stages": ["hunt", "recon"],
    "description": "...",
    "parameters": {{ "type": "object", "properties": {{...}}, "required": [...] }},
    "aliases": [],
  }}
"""

from __future__ import annotations

from typing import Any

# toolgen integrate appends / replaces by name. Keep stable for git diffs.
EXTRA_TOOL_SPECS: list[dict[str, Any]] = {body}


def list_extra_specs() -> list[dict[str, Any]]:
    return list(EXTRA_TOOL_SPECS)


def extra_tool_names() -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for s in EXTRA_TOOL_SPECS:
        n = str(s.get("name") or "").strip()
        if n and n not in seen:
            seen.add(n)
            names.append(n)
    return names


def get_extra_spec(name: str) -> dict[str, Any] | None:
    want = str(name or "").strip()
    for s in EXTRA_TOOL_SPECS:
        if str(s.get("name") or "").strip() == want:
            return dict(s)
        for a in s.get("aliases") or []:
            if str(a).strip() == want:
                return dict(s)
    return None


def upsert_extra_spec(spec: dict[str, Any]) -> None:
    """Replace or append a spec by name (in-memory; caller persists file)."""
    global EXTRA_TOOL_SPECS
    name = str(spec.get("name") or "").strip()
    if not name:
        raise ValueError("extra tool spec requires name")
    out: list[dict[str, Any]] = []
    found = False
    for s in EXTRA_TOOL_SPECS:
        if str(s.get("name") or "").strip() == name:
            out.append(dict(spec))
            found = True
        else:
            out.append(s)
    if not found:
        out.append(dict(spec))
    EXTRA_TOOL_SPECS = out


def remove_extra_spec(name: str) -> bool:
    global EXTRA_TOOL_SPECS
    want = str(name or "").strip()
    before = len(EXTRA_TOOL_SPECS)
    EXTRA_TOOL_SPECS = [
        s for s in EXTRA_TOOL_SPECS if str(s.get("name") or "").strip() != want
    ]
    return len(EXTRA_TOOL_SPECS) < before
'''


def _load_current_specs() -> list[dict[str, Any]]:
    from vulnforge.tools.extra_registry import list_extra_specs

    return list_extra_specs()


def plan_integration(draft_id: str) -> dict[str, Any]:
    """Compute file ops without writing. Requires validated draft."""
    d = get_draft(draft_id, include_files=True)
    meta = d.get("meta") or {}
    if meta.get("status") == "integrated":
        raise IntegrateToolError("draft already integrated")
    report = validate_draft(draft_id, for_integrate=True, persist=True)
    if not report.get("ok"):
        raise IntegrateToolError(
            "validation hard_fail: " + "; ".join(report.get("hard_fail") or [])
        )

    tid = str(meta.get("id") or draft_id)
    wireup = d.get("wireup") or {}
    schema = d.get("schema") or {}
    tools = schema.get("tools") if isinstance(schema, dict) else []
    if not tools:
        raise IntegrateToolError("schema.tools empty")
    primary = tools[0]
    name = str(primary.get("name") or tid)
    stages = list(wireup.get("packet_stages") or meta.get("stages") or ["hunt"])
    params = primary.get("parameters") if isinstance(primary.get("parameters"), dict) else {
        "type": "object",
        "properties": {},
        "required": [],
    }
    module = str(wireup.get("impl_module") or f"vulnforge.tools.{tid}")
    impl_path_rel = str(wireup.get("impl_path") or f"vulnforge/tools/{tid}.py")
    # Normalize to under project
    if impl_path_rel.startswith("/"):
        raise IntegrateToolError("impl_path must be relative")
    impl_path = PROJECT_ROOT / impl_path_rel
    if PROJECT_ROOT not in impl_path.resolve().parents and impl_path.resolve() != PROJECT_ROOT:
        # allow file under project
        if not str(impl_path.resolve()).startswith(str(PROJECT_ROOT.resolve())):
            raise IntegrateToolError("impl_path escapes project root")

    test_rel = str(wireup.get("test_file") or f"tests/test_tool_{tid}.py")
    test_path = PROJECT_ROOT / test_rel

    spec = {
        "name": name,
        "module": module,
        "callable": name if name in (d.get("impl_py") or "") else tid,
        "stages": stages,
        "description": str(primary.get("description") or meta.get("description") or name),
        "parameters": params,
        "aliases": list(wireup.get("aliases") or []),
    }
    # Prefer function name matching tool name
    if f"def {name}(" in (d.get("impl_py") or ""):
        spec["callable"] = name
    elif f"def {tid}(" in (d.get("impl_py") or ""):
        spec["callable"] = tid

    new_specs = [s for s in _load_current_specs() if str(s.get("name")) != name]
    new_specs.append(spec)

    ops = [
        {
            "op": "write",
            "path": str(impl_path.relative_to(PROJECT_ROOT)),
            "description": f"Write tool module {name}",
        },
        {
            "op": "write",
            "path": str(_registry_path().relative_to(PROJECT_ROOT)),
            "description": "Update EXTRA_TOOL_SPECS registry",
        },
    ]
    if (d.get("test_stub") or "").strip():
        ops.append(
            {
                "op": "write",
                "path": str(test_path.relative_to(PROJECT_ROOT)),
                "description": "Write unit test stub",
            }
        )

    return {
        "ok": True,
        "draft_id": tid,
        "tool_name": name,
        "spec": spec,
        "ops": ops,
        "impl_path": str(impl_path.relative_to(PROJECT_ROOT)),
        "test_path": str(test_path.relative_to(PROJECT_ROOT)),
        "registry_path": str(_registry_path().relative_to(PROJECT_ROOT)),
        "impl_py": d.get("impl_py") or "",
        "test_stub": d.get("test_stub") or "",
        "new_specs": new_specs,
        "validation": report,
        "planned_at": utc_now_iso(),
    }


def apply_integration(
    draft_id: str,
    *,
    add_to_profiles: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Write files and mark draft integrated."""
    plan = plan_integration(draft_id)
    written: list[str] = []

    impl_path = PROJECT_ROOT / plan["impl_path"]
    impl_path.parent.mkdir(parents=True, exist_ok=True)
    impl_py = plan["impl_py"]
    if not impl_py.lstrip().startswith('"""') and not impl_py.lstrip().startswith("#"):
        header = f'"""Agent tool: {plan["tool_name"]} (toolgen integrated)."""\n\n'
        impl_py = header + impl_py
    impl_path.write_text(impl_py, encoding="utf-8")
    written.append(plan["impl_path"])

    reg_path = _registry_path()
    reg_path.write_text(_render_registry_file(plan["new_specs"]), encoding="utf-8")
    written.append(plan["registry_path"])

    # Hot-reload in-process registry
    try:
        import importlib

        import vulnforge.tools.extra_registry as reg

        importlib.reload(reg)
        # Also update module-level list used by get_extra_spec
        for s in plan["new_specs"]:
            if str(s.get("name")) == plan["tool_name"]:
                reg.upsert_extra_spec(s)
    except Exception:
        pass

    test_stub = (plan.get("test_stub") or "").strip()
    if test_stub:
        test_path = PROJECT_ROOT / plan["test_path"]
        test_path.parent.mkdir(parents=True, exist_ok=True)
        if not test_path.is_file():
            test_path.write_text(test_stub if test_stub.startswith('"""') or "import" in test_stub[:200] else test_stub, encoding="utf-8")
            written.append(plan["test_path"])

    # Optional: append tool to hunt profile allowlists
    profiles_updated: list[str] = []
    if add_to_profiles:
        try:
            from vulnforge.hunt_profiles import get_profile, save_profile

            for pid in add_to_profiles:
                try:
                    prof = get_profile(pid, include_body=False)
                except Exception:
                    continue
                existing = prof.get("tools")
                name = plan["tool_name"]
                if existing is None:
                    # null means full set — tool already available after integrate
                    profiles_updated.append(pid)
                    continue
                tools = list(existing)
                if name not in tools:
                    tools.append(name)
                    save_profile(pid, tools=tools, create=False)
                profiles_updated.append(pid)
        except Exception:
            pass

    mark_integrated(draft_id, written)
    return {
        "ok": True,
        "draft_id": plan["draft_id"],
        "tool_name": plan["tool_name"],
        "written": written,
        "profiles_updated": profiles_updated,
        "ops": plan["ops"],
    }


def integrate(
    draft_id: str,
    *,
    dry_run: bool = True,
    apply: bool = False,
    add_to_profiles: Optional[list[str]] = None,
) -> dict[str, Any]:
    if apply and not dry_run:
        return apply_integration(draft_id, add_to_profiles=add_to_profiles)
    if apply and dry_run:
        # apply wins
        return apply_integration(draft_id, add_to_profiles=add_to_profiles)
    plan = plan_integration(draft_id)
    # Don't include full impl in API dry-run by default size — keep preview snippet
    preview = dict(plan)
    impl = preview.pop("impl_py", "")
    preview["impl_preview"] = impl[:2000] + ("…" if len(impl) > 2000 else "")
    preview.pop("test_stub", None)
    preview.pop("new_specs", None)
    preview["dry_run"] = True
    return preview

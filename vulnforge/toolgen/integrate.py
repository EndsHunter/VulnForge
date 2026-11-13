"""Integrate a validated tool draft into the package (operator-gated)."""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.errors import note_swallowed
from vulnforge.paths import PROJECT_ROOT
from vulnforge.toolgen.store import (
    ToolDraftError,
    get_draft,
    mark_integrated,
)
from vulnforge.toolgen.validate import validate_draft
from vulnforge.util import utc_now_iso


class IntegrateToolError(ValueError):
    """Integration refused or failed."""


class IntegrateConflictError(IntegrateToolError):
    """Apply refused: stale/missing dry-run plan, or an unapproved overwrite."""


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
    # Safe module leaf (draft ids are usually snake_case already).
    safe_leaf = re.sub(r"[^a-z0-9_]", "_", tid.lower().replace("-", "_"))
    if not safe_leaf or safe_leaf[0].isdigit():
        safe_leaf = f"tool_{safe_leaf or 'x'}"
    stages = list(wireup.get("packet_stages") or meta.get("stages") or ["hunt"])
    params = primary.get("parameters") if isinstance(primary.get("parameters"), dict) else {
        "type": "object",
        "properties": {},
        "required": [],
    }
    # Prefer agent SPEC modules (auto-discovered). Explicit wireup still wins.
    default_agent_module = f"vulnforge.tools.agent.{safe_leaf}"
    default_agent_path = f"vulnforge/tools/agent/{safe_leaf}.py"
    module = str(wireup.get("impl_module") or default_agent_module)
    impl_path_rel = str(wireup.get("impl_path") or default_agent_path)
    write_agent_spec = "tools.agent." in module or "/agent/" in impl_path_rel.replace(
        "\\", "/"
    )
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

    description = str(primary.get("description") or meta.get("description") or name)
    aliases = list(wireup.get("aliases") or [])
    callable_name = name if name in (d.get("impl_py") or "") else tid
    if f"def {name}(" in (d.get("impl_py") or ""):
        callable_name = name
    elif f"def {tid}(" in (d.get("impl_py") or ""):
        callable_name = tid

    # extra_registry entry still used when not writing a discoverable agent SPEC.
    spec = {
        "name": name,
        "module": module if not write_agent_spec else f"vulnforge.tools.agent.{safe_leaf}",
        "callable": "run" if write_agent_spec else callable_name,
        "stages": stages,
        "description": description,
        "parameters": params,
        "aliases": aliases,
    }

    new_specs = [s for s in _load_current_specs() if str(s.get("name")) != name]
    if not write_agent_spec:
        new_specs.append(spec)

    ops = [
        {
            "op": "write",
            "path": str(impl_path.relative_to(PROJECT_ROOT)),
            "description": (
                f"Write agent SPEC tool {name}"
                if write_agent_spec
                else f"Write tool module {name}"
            ),
        },
    ]
    if not write_agent_spec:
        ops.append(
            {
                "op": "write",
                "path": str(_registry_path().relative_to(PROJECT_ROOT)),
                "description": "Update EXTRA_TOOL_SPECS registry",
            }
        )
    if (d.get("test_stub") or "").strip():
        ops.append(
            {
                "op": "write",
                "path": str(test_path.relative_to(PROJECT_ROOT)),
                "description": "Write unit test stub",
            }
        )

    impl_py = d.get("impl_py") or ""
    if write_agent_spec:
        impl_py = _wrap_agent_spec_module(
            name=name,
            stages=stages,
            description=description,
            params=params,
            aliases=aliases,
            impl_py=impl_py,
            callable_name=callable_name,
        )

    test_stub = d.get("test_stub") or ""
    contents: dict[str, str] = {str(impl_path.relative_to(PROJECT_ROOT)): impl_py}
    if not write_agent_spec:
        contents[str(_registry_path().relative_to(PROJECT_ROOT))] = _render_registry_file(
            new_specs
        )
    if test_stub.strip():
        contents[str(test_path.relative_to(PROJECT_ROOT))] = test_stub
    registry_rel = str(_registry_path().relative_to(PROJECT_ROOT))
    test_rel_norm = str(test_path.relative_to(PROJECT_ROOT))
    for op in ops:
        _describe_op(
            op,
            contents.get(op["path"], ""),
            is_registry=op["path"] == registry_rel,
            is_test=op["path"] == test_rel_norm,
        )

    return {
        "ok": True,
        "draft_id": tid,
        "tool_name": name,
        "spec": spec,
        "ops": ops,
        "plan_hash": _plan_hash(ops, contents),
        "overwrites": [o["path"] for o in ops if o.get("overwrite")],
        "impl_path": str(impl_path.relative_to(PROJECT_ROOT)),
        "test_path": str(test_path.relative_to(PROJECT_ROOT)),
        "registry_path": str(_registry_path().relative_to(PROJECT_ROOT)),
        "write_agent_spec": write_agent_spec,
        "impl_py": impl_py,
        "test_stub": test_stub,
        "contents": contents,
        "new_specs": new_specs,
        "validation": report,
        "planned_at": utc_now_iso(),
    }


def _describe_op(op: dict[str, Any], content: str, *, is_registry: bool, is_test: bool) -> None:
    """Annotate a planned write with existence, overwrite risk and a unified diff."""
    path = PROJECT_ROOT / op["path"]
    exists = path.is_file()
    current = path.read_text(encoding="utf-8", errors="replace") if exists else ""
    op["exists"] = exists
    if is_test and exists:
        # apply never replaces an existing test file
        op["op"] = "skip"
        op["description"] = "Test file exists; left unchanged"
        op["overwrite"] = False
        op["diff"] = ""
        return
    # The registry is rewritten by design; any other existing file is an overwrite.
    op["overwrite"] = bool(exists and not is_registry and current != content)
    op["diff"] = "".join(
        difflib.unified_diff(
            current.splitlines(keepends=True),
            content.splitlines(keepends=True),
            fromfile=f"a/{op['path']}" if exists else "/dev/null",
            tofile=f"b/{op['path']}",
        )
    )


def _plan_hash(ops: list[dict[str, Any]], contents: dict[str, str]) -> str:
    """Stable hash of what apply would write and what it would replace."""
    h = hashlib.sha256()
    for op in ops:
        h.update(json.dumps([op["op"], op["path"], bool(op.get("exists"))]).encode())
        h.update(b"\0")
        h.update(contents.get(op["path"], "").encode("utf-8"))
        h.update(b"\0")
        h.update((op.get("diff") or "").encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()


def _wrap_agent_spec_module(
    *,
    name: str,
    stages: list[str],
    description: str,
    params: dict[str, Any],
    aliases: list[str],
    impl_py: str,
    callable_name: str,
) -> str:
    """Wrap a draft impl into tools/agent SPEC + run() if not already a SPEC module."""
    if "SPEC = ToolSpec" in impl_py and "def run(" in impl_py:
        return impl_py
    props = params.get("properties") if isinstance(params.get("properties"), dict) else {}
    required = params.get("required") if isinstance(params.get("required"), list) else []
    # Keep draft body; add SPEC + thin run that calls the primary def.
    stages_lit = ", ".join(repr(s) for s in stages)
    aliases_lit = ", ".join(repr(a) for a in aliases)
    required_lit = ", ".join(repr(r) for r in required)
    props_json = json.dumps(props, indent=4)
    props_py = (
        props_json.replace(": true", ": True")
        .replace(": false", ": False")
        .replace(": null", ": None")
    )
    header = f'''"""Agent tool: {name} (toolgen integrated SPEC module)."""

from __future__ import annotations

from typing import Any

from vulnforge.tools.base import ToolSpec

SPEC = ToolSpec(
    name={name!r},
    stages=({stages_lit}{"," if len(stages) == 1 else ""}),
    description={description!r},
    parameters={props_py},
    required=({required_lit}{"," if len(required) == 1 else ""}),
    aliases=({aliases_lit}{"," if len(aliases) == 1 else ""}),
)

'''
    body = impl_py.strip() + "\n\n"
    # If draft already defines run, keep it; else wrap callable_name.
    if re.search(r"^def run\s*\(", impl_py, re.M):
        return header + body
    wrapper = f'''
def run(ctx: dict, **args: Any) -> dict[str, Any]:
    return {callable_name}(ctx, **args)
'''
    return header + body + wrapper


def apply_integration(
    draft_id: str,
    *,
    plan_hash: Optional[str],
    allow_overwrite: bool = False,
    add_to_profiles: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Write files and mark draft integrated.

    Refuses unless ``plan_hash`` matches a fresh dry-run of the same draft and
    tree state, and unless ``allow_overwrite`` is set when an existing module
    file would be replaced.
    """
    plan = plan_integration(draft_id)
    want = str(plan_hash or "").strip()
    if not want:
        raise IntegrateConflictError("apply requires plan_hash from a dry-run; run dry-run first")
    if want != plan["plan_hash"]:
        raise IntegrateConflictError(
            "draft or target files changed since the dry-run; re-run dry-run and review the diff"
        )
    if plan["overwrites"] and not allow_overwrite:
        raise IntegrateConflictError(
            "apply would overwrite existing file(s): "
            + ", ".join(plan["overwrites"])
            + " (pass allow_overwrite to confirm)"
        )
    written: list[str] = []
    contents: dict[str, str] = plan["contents"]
    for op in plan["ops"]:
        if op["op"] != "write":
            continue
        rel = op["path"]
        target = PROJECT_ROOT / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents.get(rel, ""), encoding="utf-8")
        written.append(rel)

    if not plan.get("write_agent_spec"):
        # Hot-reload in-process registry
        try:
            import importlib

            import vulnforge.tools.extra_registry as reg

            importlib.reload(reg)
            for s in plan["new_specs"]:
                if str(s.get("name")) == plan["tool_name"]:
                    reg.upsert_extra_spec(s)
        except Exception as exc:
            note_swallowed(exc, context="toolgen_integrate.reload_extra_registry")
    else:
        # Agent SPEC modules: refresh discovery cache
        try:
            from vulnforge.tools.registry import clear_registry_cache

            clear_registry_cache()
        except Exception as exc:
            note_swallowed(exc, context="toolgen_integrate.clear_registry_cache")

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
        except Exception as exc:
            note_swallowed(exc, context="toolgen_integrate.attach_profiles")

    mark_integrated(draft_id, written)
    return {
        "ok": True,
        "draft_id": plan["draft_id"],
        "tool_name": plan["tool_name"],
        "written": written,
        "profiles_updated": profiles_updated,
        "ops": [{k: v for k, v in op.items() if k != "diff"} for op in plan["ops"]],
    }


def integrate(
    draft_id: str,
    *,
    dry_run: bool = True,
    apply: bool = False,
    plan_hash: Optional[str] = None,
    allow_overwrite: bool = False,
    add_to_profiles: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Dry-run (default) returns the plan with per-file diffs and ``plan_hash``.

    ``apply=True`` writes only when ``plan_hash`` matches that dry-run.
    """
    if apply:
        return apply_integration(
            draft_id,
            plan_hash=plan_hash,
            allow_overwrite=allow_overwrite,
            add_to_profiles=add_to_profiles,
        )
    plan = plan_integration(draft_id)
    preview = dict(plan)
    impl = preview.pop("impl_py", "")
    preview["impl_preview"] = impl[:2000] + ("…" if len(impl) > 2000 else "")
    preview.pop("test_stub", None)
    preview.pop("new_specs", None)
    preview.pop("contents", None)
    preview["dry_run"] = True
    return preview

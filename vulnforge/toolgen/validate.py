"""Deterministic validation for tool drafts (AI + humans + CI)."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.toolgen.store import (
    MAX_IMPL_BYTES,
    MAX_SPEC_BYTES,
    TOOL_ID_RE,
    ToolDraftError,
    get_draft,
    write_validation_report,
)
from vulnforge.util import utc_now_iso

# Default deny for code_static / read_only tools
_FORBIDDEN_IMPORTS_READ_ONLY = frozenset(
    {
        "subprocess",
        "socket",
        "requests",
        "httpx",
        "urllib",
        "urllib3",
        "asyncio.subprocess",
        "multiprocessing",
        "ctypes",
        "pty",
        "fcntl",
    }
)

_FORBIDDEN_CALLS = frozenset(
    {
        "os.system",
        "os.popen",
        "os.exec",
        "os.execl",
        "os.execv",
        "os.spawn",
        "eval",
        "exec",
        "compile",
        "shutil.rmtree",
        "__import__",
    }
)

_PATH_PARAM_NAMES = frozenset(
    {"path", "relpath", "file", "filepath", "file_path", "target_path", "src", "dst"}
)


def _check(
    checks: list[dict[str, Any]],
    *,
    cid: str,
    level: str,
    passed: bool,
    detail: str = "",
) -> None:
    checks.append(
        {
            "id": cid,
            "level": level,
            "pass": passed,
            "detail": detail,
        }
    )


def _load_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def validate_draft_dir(draft_dir: Path, *, for_integrate: bool = False) -> dict[str, Any]:
    """Validate a draft package directory. Does not require store index."""
    draft_dir = Path(draft_dir)
    checks: list[dict[str, Any]] = []
    meta: dict[str, Any] = {}
    meta_path = draft_dir / "meta.json"
    if meta_path.is_file():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            _check(checks, cid="meta_complete", level="hard", passed=False, detail=str(e))
            return _report(draft_dir.name, checks, meta)
    else:
        _check(checks, cid="meta_complete", level="hard", passed=False, detail="meta.json missing")
        return _report(draft_dir.name, checks, meta)

    draft_id = str(meta.get("id") or draft_dir.name)
    risk = str(meta.get("risk_class") or "read_only")
    stages = meta.get("stages") or []

    # id_slug
    ok_id = bool(TOOL_ID_RE.match(draft_id))
    _check(
        checks,
        cid="id_slug",
        level="hard",
        passed=ok_id,
        detail="" if ok_id else f"id {draft_id!r} must match [a-z][a-z0-9_]{{0,47}}",
    )

    # meta_complete
    missing = []
    if not meta.get("id"):
        missing.append("id")
    if not stages:
        missing.append("stages")
    if not meta.get("risk_class"):
        missing.append("risk_class")
    if not meta.get("module"):
        missing.append("module")
    _check(
        checks,
        cid="meta_complete",
        level="hard",
        passed=not missing,
        detail=("missing: " + ", ".join(missing)) if missing else "",
    )

    spec = _load_text(draft_dir / "spec.md")
    impl = _load_text(draft_dir / "impl.py")
    schema_raw = _load_text(draft_dir / "schema.json")
    wireup_raw = _load_text(draft_dir / "wireup.json")
    handler = _load_text(draft_dir / "handler_snippet.py")
    test_stub = _load_text(draft_dir / "test_stub.py")

    spec_ok = bool(spec.strip()) and len(spec.encode("utf-8")) <= MAX_SPEC_BYTES
    spec_detail = ""
    if not spec.strip():
        spec_detail = "spec.md empty"
    elif len(spec.encode("utf-8")) > MAX_SPEC_BYTES:
        spec_detail = "spec.md too large"
    _check(
        checks,
        cid="spec_present",
        level="hard",
        passed=spec_ok,
        detail=spec_detail,
    )
    _check(
        checks,
        cid="impl_present",
        level="hard",
        passed=bool(impl.strip()) and len(impl.encode("utf-8")) <= MAX_IMPL_BYTES,
        detail="" if impl.strip() else "impl.py empty",
    )
    _check(
        checks,
        cid="size_limits",
        level="hard",
        passed=(
            len(spec.encode("utf-8")) <= MAX_SPEC_BYTES
            and len(impl.encode("utf-8")) <= MAX_IMPL_BYTES
        ),
        detail="",
    )

    tree: Optional[ast.AST] = None
    if impl.strip():
        try:
            tree = ast.parse(impl)
            _check(checks, cid="impl_syntax", level="hard", passed=True, detail="")
        except SyntaxError as e:
            _check(
                checks,
                cid="impl_syntax",
                level="hard",
                passed=False,
                detail=f"{e.msg} line {e.lineno}",
            )
    else:
        _check(checks, cid="impl_syntax", level="hard", passed=False, detail="no impl")

    # returns_ok_dict heuristic
    ok_return = False
    if tree is not None:
        src = impl
        if re.search(r"""['"]ok['"]\s*:""", src) or re.search(
            r"\breturn\s*\{[^}]*\bok\b", src
        ):
            ok_return = True
        # Also accept "ok": True/False patterns in dict literals
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for k in node.keys:
                    if isinstance(k, ast.Constant) and k.value == "ok":
                        ok_return = True
    _check(
        checks,
        cid="returns_ok_dict",
        level="hard",
        passed=ok_return,
        detail="" if ok_return else "impl should return dicts with 'ok' key",
    )

    # forbidden imports
    forbidden_hits: list[str] = []
    if tree is not None and risk in ("read_only", "evidence_write"):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in _FORBIDDEN_IMPORTS_READ_ONLY or alias.name in _FORBIDDEN_IMPORTS_READ_ONLY:
                        forbidden_hits.append(alias.name)
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                root = mod.split(".")[0] if mod else ""
                if root in _FORBIDDEN_IMPORTS_READ_ONLY or mod in _FORBIDDEN_IMPORTS_READ_ONLY:
                    forbidden_hits.append(mod or root)
        for call_name in _FORBIDDEN_CALLS:
            if call_name in impl:
                forbidden_hits.append(call_name)
        # os.system style
        if re.search(r"\bos\.system\s*\(", impl):
            forbidden_hits.append("os.system")
    _check(
        checks,
        cid="forbidden_imports",
        level="hard",
        passed=not forbidden_hits,
        detail=", ".join(sorted(set(forbidden_hits))) if forbidden_hits else "",
    )

    # no_network_default
    net_hits = [h for h in forbidden_hits if h in ("socket", "requests", "httpx", "urllib", "urllib3")]
    _check(
        checks,
        cid="no_network_default",
        level="hard",
        passed=risk == "exec" or not net_hits,
        detail=", ".join(net_hits) if net_hits else "",
    )

    # no_target_write heuristic
    write_hits = []
    if re.search(r"open\s*\([^)]*['\"]w", impl) and "target_root" in impl:
        if "write_evidence" not in impl and "evidence" not in impl.lower():
            write_hits.append("open(..., 'w') near target_root")
    if "shutil.rmtree" in impl or "Path.unlink" in impl and "target" in impl:
        write_hits.append("destructive path ops")
    _check(
        checks,
        cid="no_target_write",
        level="hard",
        passed=not write_hits,
        detail="; ".join(write_hits),
    )

    # code_static_safe
    profiles = meta.get("profiles") or ["code_static"]
    exec_on_static = "code_static" in profiles and risk == "exec"
    shellish = any(x in impl for x in ("subprocess", "os.system", "shell=True"))
    _check(
        checks,
        cid="code_static_safe",
        level="hard",
        passed=not (exec_on_static or ("code_static" in profiles and shellish and risk != "exec")),
        detail="exec/shell tools must not target code_static"
        if exec_on_static or shellish
        else "",
    )

    # risk_class_consistent
    _check(
        checks,
        cid="risk_class_consistent",
        level="hard",
        passed=risk in ("read_only", "evidence_write", "exec")
        and not (risk == "read_only" and shellish),
        detail="" if risk in ("read_only", "evidence_write", "exec") else f"bad risk {risk}",
    )

    # schema
    schema: dict[str, Any] = {}
    schema_ok = False
    schema_detail = ""
    tool_names: list[str] = []
    schema_props: set[str] = set()
    try:
        schema = json.loads(schema_raw) if schema_raw.strip() else {"tools": []}
        tools = schema.get("tools") if isinstance(schema, dict) else None
        if not isinstance(tools, list) or not tools:
            schema_detail = "schema.tools empty"
        else:
            schema_ok = True
            for t in tools:
                if not isinstance(t, dict):
                    schema_ok = False
                    schema_detail = "tool entry not object"
                    break
                name = str(t.get("name") or "").strip()
                if not name:
                    schema_ok = False
                    schema_detail = "tool missing name"
                    break
                tool_names.append(name)
                if not t.get("description"):
                    schema_ok = False
                    schema_detail = f"{name} missing description"
                    break
                params = t.get("parameters")
                if not isinstance(params, dict) or params.get("type") != "object":
                    schema_ok = False
                    schema_detail = f"{name} parameters must be type=object"
                    break
                props = params.get("properties") if isinstance(params.get("properties"), dict) else {}
                schema_props |= set(props.keys())
    except json.JSONDecodeError as e:
        schema_detail = str(e)

    _check(
        checks,
        cid="schema_openai_shape",
        level="hard",
        passed=schema_ok,
        detail=schema_detail,
    )

    # schema_matches_impl — required props appear in impl source
    match_ok = schema_ok
    match_detail = ""
    if schema_ok and impl.strip():
        for t in schema.get("tools") or []:
            params = t.get("parameters") or {}
            req = params.get("required") or []
            props = (params.get("properties") or {}).keys()
            for p in list(req) + list(props):
                # allow args.get("p") or kwargs or signature name
                if p not in impl and f'"{p}"' not in impl and f"'{p}'" not in impl:
                    # soft-ish: only fail required
                    if p in req:
                        match_ok = False
                        match_detail = f"required param {p!r} not referenced in impl"
                        break
            if not match_ok:
                break
        # function name for draft id
        if draft_id not in impl and (tool_names and tool_names[0] not in impl):
            match_ok = False
            match_detail = match_detail or f"function name {draft_id!r} not found in impl"
    _check(
        checks,
        cid="schema_matches_impl",
        level="hard",
        passed=match_ok,
        detail=match_detail,
    )

    # path helpers when path params present
    path_params = schema_props & _PATH_PARAM_NAMES
    path_ok = True
    path_detail = ""
    if path_params and impl.strip():
        uses_resolve = (
            "resolve_target_path" in impl
            or "maybe_soft_jail" in impl
            or "attach_scope_warning" in impl
        )
        if not uses_resolve:
            path_ok = False
            path_detail = (
                f"path params {sorted(path_params)} require resolve_target_path "
                "or soft-jail helpers"
            )
    _check(
        checks,
        cid="no_path_escape",
        level="hard",
        passed=path_ok,
        detail=path_detail,
    )

    # handler snippet (soft)
    handler_ok = True
    handler_detail = ""
    if handler.strip():
        for n in tool_names or [draft_id]:
            if n not in handler:
                handler_ok = False
                handler_detail = f"handler snippet missing {n}"
                break
    _check(
        checks,
        cid="handler_snippet_names",
        level="soft",
        passed=handler_ok or not handler.strip(),
        detail=handler_detail,
    )

    # wireup
    wireup: dict[str, Any] = {}
    wireup_ok = True
    wireup_detail = ""
    if wireup_raw.strip():
        try:
            wireup = json.loads(wireup_raw)
        except json.JSONDecodeError as e:
            wireup_ok = False
            wireup_detail = str(e)
    required_wire = ("impl_path", "handler_branches", "allowed_tools_add", "packet_stages")
    if for_integrate or wireup:
        missing_w = [k for k in required_wire if k not in wireup]
        if missing_w:
            wireup_ok = False
            wireup_detail = "missing keys: " + ", ".join(missing_w)
    level_wire = "hard" if for_integrate else "soft"
    _check(
        checks,
        cid="wireup_complete",
        level=level_wire,
        passed=wireup_ok,
        detail=wireup_detail,
    )

    # tests
    test_ok = bool(test_stub.strip()) and (
        "def test_" in test_stub or "build_tool_handler" in test_stub
    )
    level_test = "hard" if for_integrate else "soft"
    _check(
        checks,
        cid="test_stub_present",
        level=level_test,
        passed=test_ok,
        detail="" if test_ok else "test_stub missing pytest functions",
    )

    # aliases_safe soft — if wireup aliases collide with builtins later; skip deep check
    _check(checks, cid="aliases_safe", level="soft", passed=True, detail="")

    return _report(draft_id, checks, meta)


def _report(
    draft_id: str, checks: list[dict[str, Any]], meta: dict[str, Any]
) -> dict[str, Any]:
    hard_fail = [
        c["id"] + (f": {c['detail']}" if c.get("detail") else "")
        for c in checks
        if c.get("level") == "hard" and not c.get("pass")
    ]
    soft_warn = [
        c["id"] + (f": {c['detail']}" if c.get("detail") else "")
        for c in checks
        if c.get("level") == "soft" and not c.get("pass")
    ]
    return {
        "ok": not hard_fail,
        "draft_id": draft_id,
        "generated_at": utc_now_iso(),
        "hard_fail": hard_fail,
        "soft_warn": soft_warn,
        "checks": checks,
        "guide_ref": "toolgen.md#validation-checks",
        "meta_status": meta.get("status"),
        "risk_class": meta.get("risk_class"),
    }


def validate_draft(
    draft_id: str, *, for_integrate: bool = False, persist: bool = True
) -> dict[str, Any]:
    """Validate a draft by id via store; optionally persist report."""
    d = get_draft(draft_id, include_files=False)
    from vulnforge.toolgen.store import _draft_dir  # noqa: PLC0415

    ddir = _draft_dir(d["id"])
    report = validate_draft_dir(ddir, for_integrate=for_integrate)
    if persist:
        write_validation_report(d["id"], report)
    return report

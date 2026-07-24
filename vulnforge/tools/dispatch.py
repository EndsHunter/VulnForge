"""Name → run(ctx, **args) dispatch for agent tools (registry + extras)."""

from __future__ import annotations

import importlib
import inspect
from typing import Any, Callable

from vulnforge.tools.registry import get_agent_runner, resolve_canonical_name


def _dispatch_extra(name: str, ctx: dict, args: dict) -> dict[str, Any] | None:
    """Run an operator-integrated extra tool; None if not registered."""
    from vulnforge.tools.extra_registry import get_extra_spec

    spec = get_extra_spec(name)
    if not spec:
        return None
    mod_path = str(spec.get("module") or "").strip()
    callable_name = str(spec.get("callable") or spec.get("name") or "").strip()
    if not mod_path or not callable_name:
        return {"ok": False, "error": f"extra tool {name} misconfigured"}
    try:
        mod = importlib.import_module(mod_path)
        fn = getattr(mod, callable_name)
    except Exception as e:
        return {"ok": False, "error": f"extra tool import failed: {e}"}
    try:
        sig = inspect.signature(fn)
        params = sig.parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return fn(ctx, **(args or {}))
        allowed = {
            k: v for k, v in (args or {}).items() if k in params and k != "ctx"
        }
        return fn(ctx, **allowed)
    except TypeError:
        return fn(ctx, **(args or {}))


def run_tool(name: str, ctx: dict, args: dict | None = None) -> dict[str, Any]:
    """Dispatch one tool call by name (agent registry, then extras)."""
    args = args or {}
    want = str(name or "").strip()
    if not want:
        return {"ok": False, "error": "unknown tool "}

    runner = get_agent_runner(want)
    if runner is not None:
        try:
            return runner(ctx, **args)
        except TypeError as e:
            return {"ok": False, "error": f"bad args: {e}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # Alias may not map if registry empty; try extras by original name
    extra = _dispatch_extra(want, ctx, args)
    if extra is not None:
        return extra

    # Helpful: if canonical known but runner missing (should not happen)
    canon = resolve_canonical_name(want)
    if canon:
        return {"ok": False, "error": f"tool {canon} has no runner"}

    return {"ok": False, "error": f"unknown tool {want}"}


def build_tool_handler(ctx: dict) -> Callable[[str, dict], dict]:
    """Return callable(name, args) -> result for the agent loop."""

    def handler(name: str, args: dict) -> dict[str, Any]:
        try:
            return run_tool(name, ctx, args or {})
        except TypeError as e:
            return {"ok": False, "error": f"bad args: {e}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    return handler

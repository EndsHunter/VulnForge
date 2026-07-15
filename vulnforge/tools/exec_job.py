"""
Experimental process execution for profile code_exec only.

v1 default profile code_static MUST NOT call this.
Windows: Job Objects / WSL2 sandbox TBD — see design spec.
"""

from __future__ import annotations

from typing import Any


def run_poc(ctx: dict, command: list[str] | str, timeout_seconds: int = 30) -> dict[str, Any]:
    """
    Run a PoC command in a restricted environment.

    TODO:
      - assert ctx["profile"] == "code_exec"
      - cwd = evidence work dir only
      - no network if possible
      - timeout kill
      - capture stdout/stderr (capped)
      - NEVER modify target tree
      - Windows Job Object or WSL wrapper
    """
    # PSEUDO:
    #   if ctx.get("profile") != "code_exec":
    #       return {"ok": False, "error": "run_poc disabled for this profile"}
    #   # subprocess with restrictions...
    #   return {"ok": True, "exit_code": ..., "stdout": ..., "stderr": ...}
    raise NotImplementedError("TODO: run_poc — deferred until code_exec profile")


def sandbox_available() -> bool:
    """TODO: detect Job Object / WSL / Docker availability."""
    raise NotImplementedError("TODO: sandbox_available")

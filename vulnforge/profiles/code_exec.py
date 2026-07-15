"""
Deferred profile: code_static tools + sandboxed run_poc.
"""

from __future__ import annotations


class CodeExecProfile:
    name = "code_exec"
    allow_exec = True

    def allowed_tools(self) -> list[str]:
        """TODO: code_static tools + run_poc when sandbox_available()."""
        raise NotImplementedError("TODO: CodeExecProfile.allowed_tools — deferred")

    def validate_sandbox(self) -> bool:
        """TODO: refuse init if no Job Object/WSL/Docker sandbox."""
        raise NotImplementedError("TODO: CodeExecProfile.validate_sandbox")

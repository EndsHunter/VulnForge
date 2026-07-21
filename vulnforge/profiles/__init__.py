"""Run profiles."""

from __future__ import annotations

from vulnforge.profiles.code_static import CodeStaticProfile


def get_profile(name: str):
    reg = {
        "code_static": CodeStaticProfile,
    }
    if name not in reg:
        # deferred / removed profiles: refuse clearly
        if name in ("code_exec",):
            raise ValueError(f"profile {name!r} not implemented yet; use code_static")
        if name in ("binary_re",):
            raise ValueError(
                f"profile {name!r} was removed; VulnForge is source-code analysis only "
                f"(use code_static on a source tree)"
            )
        raise ValueError(f"unknown profile: {name}")
    return reg[name]()

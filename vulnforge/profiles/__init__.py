"""Run profiles."""

from __future__ import annotations

from vulnforge.profiles.code_static import CodeStaticProfile


def get_profile(name: str):
    reg = {
        "code_static": CodeStaticProfile,
    }
    if name not in reg:
        # deferred profiles: refuse clearly
        if name in ("code_exec", "binary_re"):
            raise ValueError(f"profile {name!r} not implemented yet; use code_static")
        raise ValueError(f"unknown profile: {name}")
    return reg[name]()

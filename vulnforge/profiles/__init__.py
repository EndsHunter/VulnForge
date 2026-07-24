"""Run profiles."""

from __future__ import annotations

from vulnforge.profiles.code_static import CodeStaticProfile


def get_profile(name: str):
    reg = {
        "code_static": CodeStaticProfile,
    }
    if name not in reg:
        raise ValueError(f"unknown profile: {name}")
    return reg[name]()

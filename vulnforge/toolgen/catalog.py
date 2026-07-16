"""Integrated tool catalog derived from profile allowlist + packet schemas + extras."""

from __future__ import annotations

from typing import Any

from vulnforge.packet import tool_schemas_for
from vulnforge.profiles.code_static import CodeStaticProfile
from vulnforge.tools.extra_registry import list_extra_specs

STAGES = ("recon", "hunt", "develop_poc")

# Harness-injected submit tools (session callables, not pure tools/* modules).
HARNESS_TOOLS = frozenset(
    {
        "submit_architecture",
        "submit_candidate",
        "submit_none",
        "list_hunt_profiles",
        "request_hunt",
    }
)


def _schema_fn(entry: dict) -> dict[str, Any]:
    fn = entry.get("function") if isinstance(entry, dict) else None
    if not isinstance(fn, dict):
        return {}
    return fn


def _merge_param_props(
    base: dict[str, Any], props: dict[str, Any], required: list[str]
) -> None:
    for k, v in (props or {}).items():
        if k not in base["properties"]:
            base["properties"][k] = v
        # Prefer longer description if both exist
        elif isinstance(v, dict) and isinstance(base["properties"].get(k), dict):
            old_d = str(base["properties"][k].get("description") or "")
            new_d = str(v.get("description") or "")
            if len(new_d) > len(old_d):
                base["properties"][k] = {**base["properties"][k], **v}
    for r in required or []:
        if r not in base["required"]:
            base["required"].append(r)


def list_tools(*, profile: str = "code_static") -> list[dict[str, Any]]:
    """Return integrated tools with stages, description, and parameters."""
    by_name: dict[str, dict[str, Any]] = {}

    # Seed from schemas so description/params are authoritative for LLM surface.
    # apply_defaults=False: catalog shows full integrated surface, not operator defaults.
    for stage in STAGES:
        for entry in tool_schemas_for(profile, stage, apply_defaults=False):
            fn = _schema_fn(entry)
            name = str(fn.get("name") or "").strip()
            if not name:
                continue
            params = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else {}
            props = params.get("properties") if isinstance(params.get("properties"), dict) else {}
            req = params.get("required") if isinstance(params.get("required"), list) else []
            if name not in by_name:
                by_name[name] = {
                    "name": name,
                    "description": str(fn.get("description") or "").strip(),
                    "stages": [],
                    "parameters": {
                        "type": "object",
                        "properties": dict(props),
                        "required": list(req),
                    },
                    "source": "builtin",
                    "harness": name in HARNESS_TOOLS,
                    "in_profile_allowlist": False,
                }
            else:
                # Merge richer description / params across stages
                desc = str(fn.get("description") or "").strip()
                if len(desc) > len(by_name[name]["description"]):
                    by_name[name]["description"] = desc
                _merge_param_props(by_name[name]["parameters"], props, list(req))
            if stage not in by_name[name]["stages"]:
                by_name[name]["stages"].append(stage)

    # Extras (may already be folded into tool_schemas_for; still mark source)
    for spec in list_extra_specs():
        name = str(spec.get("name") or "").strip()
        if not name:
            continue
        stages = [str(s) for s in (spec.get("stages") or []) if str(s).strip()]
        params = spec.get("parameters") if isinstance(spec.get("parameters"), dict) else {
            "type": "object",
            "properties": {},
            "required": [],
        }
        if name not in by_name:
            by_name[name] = {
                "name": name,
                "description": str(spec.get("description") or "").strip(),
                "stages": list(stages),
                "parameters": {
                    "type": params.get("type") or "object",
                    "properties": dict(params.get("properties") or {}),
                    "required": list(params.get("required") or []),
                },
                "source": "extra",
                "harness": False,
                "in_profile_allowlist": False,
            }
        else:
            by_name[name]["source"] = "extra"
            for s in stages:
                if s not in by_name[name]["stages"]:
                    by_name[name]["stages"].append(s)

    allow = set()
    if profile == "code_static":
        allow = set(CodeStaticProfile().allowed_tools())
    for name, row in by_name.items():
        row["in_profile_allowlist"] = name in allow
        row["stages"] = [s for s in STAGES if s in row["stages"]] or row["stages"]

    # Include allowlist-only names that somehow lack schemas
    for name in sorted(allow):
        if name not in by_name:
            by_name[name] = {
                "name": name,
                "description": "(no OpenAI schema registered)",
                "stages": [],
                "parameters": {"type": "object", "properties": {}, "required": []},
                "source": "allowlist_only",
                "harness": name in HARNESS_TOOLS,
                "in_profile_allowlist": True,
            }

    return sorted(by_name.values(), key=lambda r: r["name"])


def get_tool(name: str, *, profile: str = "code_static") -> dict[str, Any] | None:
    want = str(name or "").strip()
    for t in list_tools(profile=profile):
        if t["name"] == want:
            return t
    return None


def known_tool_names(*, profile: str = "code_static") -> list[str]:
    return [t["name"] for t in list_tools(profile=profile)]

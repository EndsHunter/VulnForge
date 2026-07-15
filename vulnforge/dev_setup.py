"""Full Dev dashboard setup export/import for transferring to a fresh install.

Bundles operator collections under config/:
  - hunt profiles
  - recon agents
  - skill generator prompt override
  - tool drafts
  - UI/LLM settings
"""

from __future__ import annotations

from typing import Any, Optional

from vulnforge.util import utc_now_iso

SETUP_FORMAT = "vulnforge.dev_setup/v1"


class DevSetupError(ValueError):
    """Invalid or incomplete Dev setup bundle."""


def export_dev_setup() -> dict[str, Any]:
    """Snapshot all operator Dev setup as a single JSON-serializable object."""
    from vulnforge.hunt_profiles import export_collection as export_hunts
    from vulnforge.hunt_profiles.author_prompt import get_author_prompt
    from vulnforge.recon_agents import export_collection as export_recon
    from vulnforge.settings import load_ui_settings
    from vulnforge.toolgen.store import export_all_drafts

    hunt = export_hunts()
    recon = export_recon()
    drafts = export_all_drafts()
    author = get_author_prompt()
    skill_gen: Optional[dict[str, Any]] = None
    if author.get("has_override") and str(author.get("body_md") or "").strip():
        skill_gen = {
            "body_md": author.get("body_md"),
            "source": "override",
        }
    else:
        # Still include package/fallback body so a transfer can re-apply as override
        # only when explicitly present as override; export null section otherwise.
        skill_gen = None

    ui = load_ui_settings()

    return {
        "format": SETUP_FORMAT,
        "exported_at": utc_now_iso(),
        "sections": {
            "hunt_profiles": hunt,
            "recon_agents": recon,
            "skill_generator": skill_gen,
            "tool_drafts": drafts,
            "ui_settings": ui,
        },
        "summary": {
            "hunt_profiles": len(hunt.get("profiles") or []),
            "recon_agents": len(recon.get("agents") or []),
            "skill_generator_override": bool(skill_gen),
            "tool_drafts": int(drafts.get("count") or 0),
            "ui_settings": True,
        },
    }


def import_dev_setup(
    data: dict[str, Any],
    *,
    mode: str = "merge",
    include: Optional[list[str]] = None,
) -> dict[str, Any]:
    """
    Import a Dev setup bundle (or a legacy single-collection export).

    mode: merge | replace — applied to collections that support it.
    include: optional section allowlist (hunt_profiles, recon_agents,
             skill_generator, tool_drafts, ui_settings).
    """
    mode_n = str(mode or "merge").lower().strip()
    if mode_n not in ("merge", "replace"):
        raise DevSetupError("mode must be 'merge' or 'replace'")
    if not isinstance(data, dict):
        raise DevSetupError("import data must be an object")

    fmt = str(data.get("format") or "")
    results: dict[str, Any] = {"ok": True, "mode": mode_n, "sections": {}}

    # Legacy single-collection files still work via the unified endpoint.
    if fmt == "vulnforge.hunt_collection/v1" or (
        "profiles" in data and "sections" not in data and not fmt.startswith("vulnforge.dev_setup")
    ):
        from vulnforge.hunt_profiles import HuntProfileError, import_collection

        try:
            results["sections"]["hunt_profiles"] = import_collection(
                data, mode=mode_n
            )
        except HuntProfileError as e:
            raise DevSetupError(str(e)) from e
        results["format"] = "legacy_hunt_collection"
        return results

    if fmt == "vulnforge.recon_collection/v1" or (
        "agents" in data and "sections" not in data and not fmt.startswith("vulnforge.dev_setup")
    ):
        from vulnforge.recon_agents import ReconAgentError, import_collection

        try:
            results["sections"]["recon_agents"] = import_collection(
                data, mode=mode_n
            )
        except ReconAgentError as e:
            raise DevSetupError(str(e)) from e
        results["format"] = "legacy_recon_collection"
        return results

    if fmt in ("vulnforge.tool_drafts/v1", "vulnforge.tool_draft/v1"):
        from vulnforge.toolgen.store import ToolDraftError, import_drafts_collection

        try:
            results["sections"]["tool_drafts"] = import_drafts_collection(
                data, mode=mode_n
            )
        except ToolDraftError as e:
            raise DevSetupError(str(e)) from e
        results["format"] = "legacy_tool_drafts"
        return results

    if fmt and fmt != SETUP_FORMAT:
        if not fmt.startswith("vulnforge.dev_setup/"):
            raise DevSetupError(f"unsupported setup format: {fmt}")

    sections = data.get("sections")
    if not isinstance(sections, dict):
        # Allow flat top-level keys without wrapper
        sections = {
            k: data[k]
            for k in (
                "hunt_profiles",
                "recon_agents",
                "skill_generator",
                "tool_drafts",
                "ui_settings",
            )
            if k in data
        }
        if not sections:
            raise DevSetupError(
                "expected format vulnforge.dev_setup/v1 with sections, "
                "or a legacy hunt/recon/tool_drafts export"
            )

    allow = set(include) if include else None

    def _want(name: str) -> bool:
        return allow is None or name in allow

    # ---- hunt profiles ----
    if _want("hunt_profiles") and sections.get("hunt_profiles") is not None:
        from vulnforge.hunt_profiles import HuntProfileError, import_collection

        try:
            results["sections"]["hunt_profiles"] = import_collection(
                sections["hunt_profiles"], mode=mode_n
            )
        except HuntProfileError as e:
            raise DevSetupError(f"hunt_profiles: {e}") from e

    # ---- recon agents ----
    if _want("recon_agents") and sections.get("recon_agents") is not None:
        from vulnforge.recon_agents import ReconAgentError, import_collection

        try:
            results["sections"]["recon_agents"] = import_collection(
                sections["recon_agents"], mode=mode_n
            )
        except ReconAgentError as e:
            raise DevSetupError(f"recon_agents: {e}") from e

    # ---- skill generator override ----
    if _want("skill_generator") and "skill_generator" in sections:
        from vulnforge.hunt_profiles.author_prompt import (
            AuthorPromptError,
            reseed_author_prompt,
            save_author_prompt,
        )

        sg = sections.get("skill_generator")
        try:
            if sg is None:
                if mode_n == "replace":
                    reseed_author_prompt()
                    results["sections"]["skill_generator"] = {
                        "ok": True,
                        "action": "reseed",
                    }
            elif isinstance(sg, dict) and str(sg.get("body_md") or "").strip():
                save_author_prompt(str(sg["body_md"]))
                results["sections"]["skill_generator"] = {
                    "ok": True,
                    "action": "override",
                }
            elif isinstance(sg, str) and sg.strip():
                save_author_prompt(sg)
                results["sections"]["skill_generator"] = {
                    "ok": True,
                    "action": "override",
                }
            else:
                results["sections"]["skill_generator"] = {
                    "ok": True,
                    "action": "skipped",
                }
        except AuthorPromptError as e:
            raise DevSetupError(f"skill_generator: {e}") from e

    # ---- tool drafts ----
    if _want("tool_drafts") and sections.get("tool_drafts") is not None:
        from vulnforge.toolgen.store import ToolDraftError, import_drafts_collection

        try:
            results["sections"]["tool_drafts"] = import_drafts_collection(
                sections["tool_drafts"], mode=mode_n
            )
        except ToolDraftError as e:
            raise DevSetupError(f"tool_drafts: {e}") from e

    # ---- UI settings ----
    if _want("ui_settings") and sections.get("ui_settings") is not None:
        from vulnforge.settings import save_ui_settings

        ui = sections["ui_settings"]
        if not isinstance(ui, dict):
            raise DevSetupError("ui_settings must be an object")
        saved = save_ui_settings(ui)
        results["sections"]["ui_settings"] = {
            "ok": True,
            "keys": sorted(k for k in saved if k != "updated_at"),
        }

    if not results["sections"]:
        raise DevSetupError("no recognized sections to import")

    results["format"] = SETUP_FORMAT
    return results

"""Recon agent collection — runtime authority for recon agent ids and bodies.

Package prompts under prompts/v1/recon_agents/ are a seed library only.
After first ensure_collection(), operators edit config/recon_agents/.
"""

from __future__ import annotations

from vulnforge.recon_agents.store import (
    AGENT_ID_RE,
    COLLECTION_FORMAT,
    ReconAgentError,
    active_agents,
    all_agent_ids,
    catalog_for_ui,
    collection_root,
    delete_agent,
    ensure_collection,
    export_collection,
    get_agent,
    get_body,
    import_collection,
    list_agents,
    reseed_from_package,
    reset_collection_root_override,
    save_agent,
    set_collection_root,
)

__all__ = [
    "AGENT_ID_RE",
    "COLLECTION_FORMAT",
    "ReconAgentError",
    "active_agents",
    "all_agent_ids",
    "catalog_for_ui",
    "collection_root",
    "delete_agent",
    "ensure_collection",
    "export_collection",
    "get_agent",
    "get_body",
    "import_collection",
    "list_agents",
    "reseed_from_package",
    "reset_collection_root_override",
    "save_agent",
    "set_collection_root",
]

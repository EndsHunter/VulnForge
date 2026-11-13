#!/usr/bin/env python3
"""Fail if living docs drift from seeds, CLI subcommands, or agent tools.

Run from repo root: python scripts/check_docs.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _table_first_col_md(text: str) -> set[str]:
    return set(re.findall(r"^\| `([A-Za-z0-9_.-]+\.md)` \|", text, re.M))


def check_seed_catalog() -> list[str]:
    errors: list[str] = []
    seeds = {p.name for p in (ROOT / "seeds" / "system").glob("*.md")}
    catalog = _read("docs/system/README.md")
    toolgen = _read("docs/system/TOOLGEN.md")
    mentioned = _table_first_col_md(catalog) | _table_first_col_md(toolgen)
    missing_from_docs = sorted(seeds - mentioned)
    phantom = sorted(n for n in mentioned if n not in seeds)
    if missing_from_docs:
        errors.append(
            "docs/system catalog missing seed files: " + ", ".join(missing_from_docs)
        )
    if phantom:
        errors.append(
            "docs/system catalog names files that are not in seeds/system: "
            + ", ".join(phantom)
        )
    return errors


def _cli_subcommand_names() -> set[str]:
    """Parse add_parser(\"name\" names from cli.py without importing vulnforge."""
    text = _read("vulnforge/cli.py")
    return set(re.findall(r'add_parser\(\s*"([a-z0-9-]+)"', text))


def check_cli_in_protocol() -> list[str]:
    cmds = _cli_subcommand_names()
    proto = _read("PROTOCOL.md")
    missing = sorted(c for c in cmds if f"vf {c}" not in proto and c not in proto)
    if missing:
        return [f"PROTOCOL.md does not name CLI commands: {', '.join(missing)}"]
    return []


def _agent_tool_names() -> set[str]:
    names = set()
    for p in (ROOT / "vulnforge" / "tools" / "agent").glob("*.py"):
        if p.name == "__init__.py":
            continue
        names.add(p.stem)
    return names


def check_tools_in_protocol() -> list[str]:
    proto = _read("PROTOCOL.md")
    missing = sorted(n for n in _agent_tool_names() if f"`{n}`" not in proto)
    if missing:
        return [f"PROTOCOL.md does not backtick agent tools: {', '.join(missing)}"]
    return []


def check_dashboard_tab_names() -> list[str]:
    """Run tabs are Review / Campaign / Atlas (docs/ui/REDESIGN.md); the old
    Mission / Hunts / Explorer / Report / Coverage mode rows must not return."""
    errors: list[str] = []
    for doc in ("README.md", "AGENTS.md"):
        text = _read(doc)
        for tab in ("Review", "Campaign", "Atlas"):
            if f"| **{tab}**" not in text:
                errors.append(f"{doc} dashboard table must name **{tab}** as a run tab")
        for stale in ("Mission", "Hunts", "Explorer", "Report", "Coverage"):
            if f"| **{stale}** |" in text:
                errors.append(
                    f"{doc} still lists **{stale}** as a dashboard mode; see docs/ui/REDESIGN.md"
                )
    return errors


def check_agents_posix_quickstart() -> list[str]:
    agents = _read("AGENTS.md")
    if "source .venv/bin/activate" not in agents:
        return ["AGENTS.md quick start must include POSIX venv activate"]
    return []


def check_phantom_paths() -> list[str]:
    errors: list[str] = []
    layout = _read("docs/LAYOUT.md")
    if "Legacy `prompts/`" in layout and not (ROOT / "prompts").exists():
        errors.append("docs/LAYOUT.md claims a prompts/ redirect tree that is gone")
    for rel in ("README.md", "toolgen.md"):
        text = _read(rel)
        if "./start_ornith_server.sh" in text and not (ROOT / "start_ornith_server.sh").exists():
            errors.append(f"{rel} points at ./start_ornith_server.sh, which is not in the tree")
    extra = ROOT / "vulnforge" / "tools" / "extra"
    if "optional `tools/extra/`" in layout and not extra.exists():
        errors.append("docs/LAYOUT.md mentions optional tools/extra/, which is not in the tree")
    return errors


def check_hunt_preamble_claim() -> list[str]:
    """Docs must match whether pack_hunt loads preamble.md (it does since #212)."""
    errors: list[str] = []
    packet = _read("vulnforge/packet.py")
    start = packet.find("def pack_hunt(")
    end = packet.find("\ndef ", start + 1)
    hunt_loads_preamble = '"preamble.md"' in packet[start:end]
    shared = _read("docs/system/SHARED.md")
    hunt = _read("docs/system/HUNT.md")
    if hunt_loads_preamble:
        if "Hunt packets do not include this file" in shared:
            errors.append("docs/system/SHARED.md says hunt skips preamble.md; pack_hunt loads it")
        if "`preamble.md` then `PRINCIPLES.md`" not in hunt:
            errors.append("docs/system/HUNT.md does not say hunt loads preamble.md then PRINCIPLES.md")
    elif "`preamble.md` then `PRINCIPLES.md`" in hunt:
        errors.append("docs/system/HUNT.md claims hunt packets include preamble.md; pack_hunt does not")
    return errors


def main() -> int:
    errors: list[str] = []
    for fn in (
        check_seed_catalog,
        check_cli_in_protocol,
        check_tools_in_protocol,
        check_dashboard_tab_names,
        check_agents_posix_quickstart,
        check_phantom_paths,
        check_hunt_preamble_claim,
    ):
        errors.extend(fn())
    if errors:
        print("docs check failed:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("docs check ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

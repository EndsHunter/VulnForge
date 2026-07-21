"""Stage: render - pure code, no LLM."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnforge.util import utc_now_iso, write_json


def run(task, db, run_dir: Path, cfg: dict) -> dict[str, Any]:
    paths = render_all(run_dir, db)
    return {"status": "succeeded", "written": paths}


def render_all(run_dir: Path, db) -> list[str]:
    out = Path(run_dir) / "project"
    out.mkdir(parents=True, exist_ok=True)
    write_state_md(out / "STATE.md", db, run_dir)
    write_codemap_md(out / "CODEMAP.md", db)
    write_report_md(out / "REPORT.md", db)
    write_findings_json(out / "findings.json", db)
    return [
        str(out / "STATE.md"),
        str(out / "CODEMAP.md"),
        str(out / "REPORT.md"),
        str(out / "findings.json"),
    ]


def write_state_md(path: Path, db, run_dir: Path | None = None) -> None:
    s = db.summary()
    run = s.get("run") or {}
    lines = [
        f"# STATE",
        f"",
        f"Generated: {utc_now_iso()}",
        f"Run dir: {run_dir or ''}",
        f"Target: {run.get('target_path')}",
        f"Profile: {run.get('profile')}",
        f"Prompt pin: {run.get('prompt_pin')}",
        f"",
        f"## Tasks",
        f"```json",
        json.dumps(s.get("tasks"), indent=2),
        f"```",
        f"",
        f"## Findings",
        f"```json",
        json.dumps(s.get("findings"), indent=2),
        f"```",
        f"",
        f"has_work: {s.get('has_work')}",
        f"",
        f"_This file is a projection. harness.db is authoritative._",
        f"",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_codemap_md(path: Path, db) -> None:
    notes = db.list_notes(kind="codemap")
    lines = ["# CODEMAP", "", "Interesting paths/symbols from the run.", ""]
    if not notes:
        lines.append("_No codemap notes yet._")
    for n in notes:
        lines.append(f"- task={n.get('task_id')}: `{json.dumps(n.get('payload'))[:300]}`")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_report_md(path: Path, db) -> None:
    confirmed = db.list_findings(states=["confirmed"])
    needs_human = db.list_findings(states=["needs_human"])
    rejected = db.list_findings(
        states=["rejected_mech", "rejected_llm", "rejected_human"]
    )
    candidates = db.list_findings(states=["candidate"])
    superseded = db.list_findings(states=["superseded"])
    lines = [
        "# Security audit report",
        "",
        f"Generated: {utc_now_iso()}",
        "",
        "> **Disclaimer:** `needs_human` means mechanical gates passed (shape, citations, "
        "evidence pack). `confirmed` means a **human accepted** the finding. Neither is "
        "proof of a working exploit.",
        "",
        f"Confirmed (human): {len(confirmed)} | Needs human: {len(needs_human)} | "
        f"Rejected: {len(rejected)} | Candidates: {len(candidates)} | "
        f"Superseded near-dups: {len(superseded)}",
        "",
        "## Needs human review (mech-passed)",
        "",
    ]
    if not needs_human:
        lines.append("_None._")
        lines.append("")
    for f in needs_human:
        b = f.body
        tm = b.get("threat_model") or {}
        lines.extend(
            [
                f"### {b.get('title', f.stable_key)}",
                "",
                f"- **id:** {f.id}",
                f"- **class:** {b.get('weakness_class')}",
                f"- **severity_claim:** {b.get('severity_claim', 'n/a')}",
                f"- **attacker:** {tm.get('attacker')}",
                f"- **impact:** {tm.get('impact')}",
                "",
                b.get("summary") or "",
                "",
            ]
        )

    lines.extend(
        [
            "## Confirmed findings (human-accepted)",
            "",
        ]
    )
    if not confirmed:
        lines.append("_None._")
        lines.append("")
    for f in confirmed:
        b = f.body
        tm = b.get("threat_model") or {}
        near = ""
        if b.get("merged_classes") or b.get("near_dup_titles"):
            near = (
                f"- **near-dup merge:** classes={b.get('merged_classes')}; "
                f"titles={b.get('near_dup_titles')}"
            )
        lines.extend(
            [
                f"### {b.get('title', f.stable_key)}",
                f"",
                f"- **id:** {f.id}",
                f"- **stable_key:** `{f.stable_key}`",
                f"- **class:** {b.get('weakness_class')}",
                f"- **severity_claim:** {b.get('severity_claim', 'n/a')}",
                f"- **attacker:** {tm.get('attacker')}",
                f"- **boundary:** {tm.get('boundary')}",
                f"- **impact:** {tm.get('impact')}",
            ]
        )
        if near:
            lines.append(near)
        lines.extend(
            [
                f"",
                b.get("summary") or "",
                f"",
                f"**Citations:**",
                f"",
            ]
        )
        for c in b.get("citations") or []:
            lines.append(f"- `{c.get('path')}` lines {c.get('start_line')}-{c.get('end_line')}")
        if f.evidence_id or b.get("evidence_id"):
            lines.append(f"- evidence: `{f.evidence_id or b.get('evidence_id')}`")
        lines.append("")

    # Coverage matrix when data exists
    try:
        matrix = db.coverage_matrix()
    except Exception:
        matrix = None
    if matrix and matrix.get("cells"):
        lines.extend(["## Coverage matrix (area x class)", ""])
        lines.append(
            "_Depth: empty=planned, shallow=no substantial tools "
            "(read_file/grep), none=honest miss, "
            "candidate=filed. Shallow/aborted != safe._"
        )
        lines.append("")
        classes = matrix.get("classes") or []
        areas = matrix.get("areas") or []
        cell_map = {
            (c["area"], c["class"]): c for c in matrix.get("cells") or []
        }
        if classes and areas:
            header = "| area | " + " | ".join(classes) + " |"
            sep = "| --- | " + " | ".join(["---"] * len(classes)) + " |"
            lines.append(header)
            lines.append(sep)
            for a in areas:
                row = [a]
                for cl in classes:
                    cell = cell_map.get((a, cl))
                    if not cell:
                        row.append(".")
                    else:
                        d = cell.get("last_depth") or "planned"
                        v = cell.get("visit_count") or 0
                        row.append(f"{d}x{v}")
                lines.append("| " + " | ".join(row) + " |")
            lines.append("")

    lines.extend(["## Rejected (summary)", ""])
    if not rejected:
        lines.append("_None._")
    else:
        for f in rejected:
            reasons = (f.body.get("validation_reasons") or [])[-3:]
            lines.append(
                f"- **{f.body.get('title', f.id)}** ({f.state}): {reasons}"
            )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_findings_json(path: Path, db) -> None:
    all_f = db.list_findings()
    payload = {
        "generated_at": utc_now_iso(),
        "findings": [
            {
                "id": f.id,
                "stable_key": f.stable_key,
                "state": f.state,
                "evidence_id": f.evidence_id,
                "body": f.body,
            }
            for f in all_f
        ],
    }
    write_json(path, payload)

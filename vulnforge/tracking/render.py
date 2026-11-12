"""Render a finding as an external issue title + Markdown body (#189).

Honesty: every body carries a standing line that the issue is not exploit
proof — for ``confirmed`` (human-accepted) as well as ``needs_human`` (not
confirmed), with or without a PoC run on disk.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.tracking.base import TrackPayload, marker_line

NOT_PROOF_LINE = (
    "**Not exploit proof.** VulnForge is static analysis. `confirmed` means a human "
    "accepted the finding in review; neither that nor any PoC run proves exploitability."
)
STATE_LINES = {
    "confirmed": "**State: `confirmed`** — accepted by human review.",
    "needs_human": (
        "**State: `needs_human` — NOT confirmed.** Automated gates passed; no human has "
        "accepted this finding."
    ),
}

# Only these pack files are excerpted. Never PoC code or paths stored on the finding.
EXCERPT_ALLOWLIST = ("notes.md", "evidence.md", "summary.md", "README.md")
EXCERPT_MAX_CHARS = 3000
BODY_MAX_CHARS = 60000
TITLE_MAX_CHARS = 200

_MENTION_RE = re.compile(r"@(?=[A-Za-z0-9_-])")


def neutralize(text: Any) -> str:
    """Stop model-written text from @-mentioning users or teams."""
    return _MENTION_RE.sub("@​", str(text or ""))


def _one_line(text: Any, limit: int) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _clip(text: Any, limit: int) -> str:
    s = str(text or "").strip()
    return s if len(s) <= limit else s[:limit] + "\n…[truncated]"


def _fence(content: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", content)), default=0)
    tick = "`" * max(3, longest + 1)
    return f"{tick}\n{content}\n{tick}"


def evidence_excerpt(run_dir: Path, evidence_id: Any) -> tuple[Optional[str], Optional[str]]:
    """Return ``(relpath, excerpt)`` from an allowlisted file in the pack, or ``(None, None)``.

    Jail: the pack id must pass ``sanitize_evidence_id`` unchanged, and the file
    must resolve (after symlinks) inside ``run_dir/evidence/<id>/``.
    """
    if not evidence_id:
        return None, None
    from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

    try:
        eid = sanitize_evidence_id(str(evidence_id))
    except InvalidEvidenceId:
        return None, None
    if eid != str(evidence_id).strip():
        return None, None
    try:
        ev_root = (Path(run_dir) / "evidence").resolve()
        pack = (ev_root / eid).resolve()
        pack.relative_to(ev_root)
    except (OSError, ValueError):
        return None, None
    if not pack.is_dir():
        return None, None
    for name in EXCERPT_ALLOWLIST:
        cand = pack / name
        try:
            real = cand.resolve()
            real.relative_to(pack)
        except (OSError, ValueError):
            continue
        if not real.is_file():
            continue
        try:
            text = real.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        return name, _clip(text, EXCERPT_MAX_CHARS)
    return None, None


def render_issue(
    finding: Any,
    *,
    run_dir: Path,
    run_id: str = "",
    labels: Optional[list[str]] = None,
) -> TrackPayload:
    body: dict = dict(getattr(finding, "body", None) or {})
    state = str(getattr(finding, "state", "") or "")
    stable_key = str(getattr(finding, "stable_key", "") or "")
    fid = getattr(finding, "id", "")
    title_raw = body.get("title") or f"Finding #{fid}"
    sev = str(body.get("severity_claim") or "unknown").upper()
    wc = str(body.get("weakness_class") or "unclassified")
    title = _one_line(neutralize(f"[VulnForge] {sev} {wc}: {title_raw}"), TITLE_MAX_CHARS)

    lines: list[str] = [
        STATE_LINES.get(state, f"**State: `{state}`**"),
        "",
        NOT_PROOF_LINE,
        "",
        f"- Severity claim: `{_one_line(sev, 40)}`",
        f"- Weakness class: `{_one_line(wc, 80)}`",
        f"- VulnForge finding: #{fid}" + (f" in run `{_one_line(run_id, 80)}`" if run_id else ""),
        "",
        "## Summary",
        "",
        neutralize(_clip(body.get("summary") or "No summary.", 4000)),
    ]
    tm = body.get("threat_model") if isinstance(body.get("threat_model"), dict) else {}
    if tm:
        lines += ["", "## Threat model", ""]
        for k in ("attacker", "boundary", "impact"):
            if tm.get(k):
                lines.append(f"- **{k.title()}:** {neutralize(_one_line(tm[k], 400))}")
    cites = [c for c in (body.get("citations") or []) if isinstance(c, dict) and c.get("path")]
    lines += ["", "## Locations", ""]
    if cites:
        for c in cites[:20]:
            loc = _one_line(c.get("path"), 300)
            if c.get("start_line") is not None:
                loc += f":{c.get('start_line')}"
                if c.get("end_line") not in (None, c.get("start_line")):
                    loc += f"-{c.get('end_line')}"
            sym = f" · `{_one_line(c.get('symbol'), 120)}`" if c.get("symbol") else ""
            lines.append(f"- `{loc}`{sym}")
    else:
        lines.append("- none recorded")
    eid = getattr(finding, "evidence_id", None) or body.get("evidence_id")
    rel, excerpt = evidence_excerpt(run_dir, eid)
    if eid:
        lines += ["", "## Evidence", "", f"- Pack: `{_one_line(eid, 120)}`"]
        if rel and excerpt is not None:
            lines += ["", f"Excerpt from `{rel}`:", "", _fence(neutralize(excerpt))]
    lines += [
        "",
        "---",
        "Tracked by VulnForge. Re-tracking replaces this title and body.",
        "",
        marker_line(stable_key),
    ]
    md = "\n".join(lines)
    if len(md) > BODY_MAX_CHARS:
        tail = "\n\n…[truncated]\n\n" + marker_line(stable_key)
        md = md[: BODY_MAX_CHARS - len(tail)] + tail
    return TrackPayload(
        stable_key=stable_key, title=title, body_md=md, labels=list(labels or [])
    )

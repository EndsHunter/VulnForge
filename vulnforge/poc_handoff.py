"""PoC handoff: hub frontmatter, readiness, validation-job export, HANDOFF.md.

Supports operator export of a self-contained bundle for an external or
in-process harness. Never executes PoCs and never changes finding state.
"""

from __future__ import annotations

import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any, Optional

from vulnforge.languages import POC_CODE_EXTS
from vulnforge.util import utc_now_iso

POC_DEVELOP_RELPATH = "poc_develop.md"
POC_RUN_RELPATH = "poc_run.json"
HANDOFF_RELPATH = "HANDOFF.md"

# Frontmatter keys operators / agents may set on poc_develop.md
FRONTMATTER_KEYS = frozenset(
    {
        "run",
        "entry",
        "success_regex",
        "timeout_s",
        "network",
        "language",
        "deps",
        "env",
    }
)

_FM_RE = re.compile(
    r"\A---\s*\n(.*?)\n---\s*\n?",
    re.DOTALL,
)


def parse_hub_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Parse optional YAML-like frontmatter from hub markdown.

    Returns (meta, body_without_frontmatter). Values are strings/ints/bools
    only — no nested structures (keep hub machine fields simple).
    """
    if not text:
        return {}, ""
    m = _FM_RE.match(text)
    if not m:
        return {}, text
    meta: dict[str, Any] = {}
    for line in m.group(1).splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if ":" not in raw:
            continue
        key, _, val = raw.partition(":")
        key = key.strip().lower()
        val = val.strip().strip('"').strip("'")
        if not key:
            continue
        if key == "timeout_s":
            try:
                meta[key] = int(val)
            except ValueError:
                meta[key] = val
        elif key == "env" and val:
            # space-separated KEY=VAL pairs
            env: dict[str, str] = {}
            for part in val.split():
                if "=" in part:
                    k, _, v = part.partition("=")
                    if k:
                        env[k] = v
            meta[key] = env
        else:
            meta[key] = val
    body = text[m.end() :]
    return meta, body


def format_hub_with_frontmatter(meta: dict[str, Any], body: str) -> str:
    """Serialize frontmatter + body. Only known keys are emitted."""
    lines = ["---"]
    for key in (
        "run",
        "entry",
        "success_regex",
        "timeout_s",
        "network",
        "language",
        "deps",
    ):
        if key not in meta or meta[key] in (None, ""):
            continue
        lines.append(f"{key}: {meta[key]}")
    env = meta.get("env")
    if isinstance(env, dict) and env:
        pairs = " ".join(f"{k}={v}" for k, v in env.items())
        lines.append(f"env: {pairs}")
    lines.append("---")
    body = body.lstrip("\n") if body else ""
    return "\n".join(lines) + "\n\n" + body


def extract_section(markdown: str, heading: str) -> str:
    """Return text under a ## heading until the next ## or end."""
    if not markdown:
        return ""
    # Allow optional leading frontmatter already stripped or not
    pat = re.compile(
        rf"(?im)^##\s+{re.escape(heading)}\s*\n(.*?)(?=^##\s+|\Z)",
        re.DOTALL,
    )
    m = pat.search(markdown)
    if not m:
        return ""
    return m.group(1).strip()


def list_pack_code_files(pack_dir: Path) -> list[str]:
    if not pack_dir.is_dir():
        return []
    names: list[str] = []
    try:
        for p in sorted(pack_dir.iterdir()):
            if p.is_file() and p.suffix.lower() in POC_CODE_EXTS:
                names.append(p.name)
    except OSError:
        return []
    return names


def resolve_run_command(
    meta: dict[str, Any],
    pack_dir: Path,
    *,
    code_files: Optional[list[str]] = None,
) -> tuple[Optional[str], Optional[str]]:
    """Return (command_string, entry_basename) or (None, error)."""
    codes = code_files if code_files is not None else list_pack_code_files(pack_dir)
    run = str(meta.get("run") or "").strip()
    entry = str(meta.get("entry") or "").strip()
    if run:
        # Infer entry from first token that looks like a pack file
        if not entry:
            for tok in run.replace("\\", "/").split():
                base = Path(tok).name
                if base in codes or (pack_dir / base).is_file():
                    entry = base
                    break
        return run, entry or None
    if entry:
        return _default_cmd_for_entry(entry), entry
    # Prefer conventional names
    for name in ("poc.py", "poc.sh", "poc.ps1", "poc.c"):
        if name in codes or (pack_dir / name).is_file():
            return _default_cmd_for_entry(name), name
    if codes:
        return _default_cmd_for_entry(codes[0]), codes[0]
    return None, "no_run_command_or_entry"


def _default_cmd_for_entry(entry: str) -> str:
    ext = Path(entry).suffix.lower()
    if ext == ".py":
        return f"python {entry}"
    if ext == ".sh":
        return f"bash {entry}"
    if ext == ".ps1":
        return f"powershell -NoProfile -File {entry}"
    if ext in (".c", ".cpp", ".cc"):
        return f"gcc -o poc_bin {entry} && ./poc_bin"
    if ext == ".js":
        return f"node {entry}"
    if ext == ".go":
        return f"go run {entry}"
    return f"python {entry}"


def assess_poc_readiness(
    *,
    finding_body: dict[str, Any],
    pack_dir: Optional[Path],
    hub_text: str = "",
    finding_state: str = "",
) -> dict[str, Any]:
    """Soft readiness for harness handoff (not a mech gate / not exploit proof)."""
    body = finding_body or {}
    issues: list[str] = []
    warnings: list[str] = []
    meta: dict[str, Any] = {}
    body_md = hub_text or ""

    if hub_text:
        meta, body_md = parse_hub_frontmatter(hub_text)
    elif pack_dir and (pack_dir / POC_DEVELOP_RELPATH).is_file():
        try:
            hub_text = (pack_dir / POC_DEVELOP_RELPATH).read_text(encoding="utf-8")
            meta, body_md = parse_hub_frontmatter(hub_text)
        except OSError as e:
            issues.append(f"hub_unreadable:{e}")

    code_files = list_pack_code_files(pack_dir) if pack_dir else []
    body_codes = body.get("poc_code_files")
    if isinstance(body_codes, list):
        for x in body_codes:
            n = Path(str(x)).name
            if n and n not in code_files and Path(n).suffix.lower() in POC_CODE_EXTS:
                # declared but maybe not on disk yet
                if pack_dir and not (pack_dir / n).is_file():
                    warnings.append(f"declared_code_missing:{n}")
                elif n not in code_files:
                    code_files.append(n)

    if not code_files:
        issues.append("missing_poc_code")

    expected = extract_section(body_md, "Expected signal")
    # Ignore placeholder/TODO text from scaffold
    if expected:
        low = expected.lower().strip()
        placeholderish = (
            low.startswith("_")
            or "what observable" in low
            or "todo" in low
            or low in ("-", "tbd", "n/a")
        )
        if placeholderish and ("assert" not in low and "regex" not in low):
            # Keep if frontmatter success_regex will cover; clear prose placeholder
            expected = ""
    success_regex = str(meta.get("success_regex") or "").strip()
    # Frontmatter success_regex counts as a success criterion for readiness
    if not expected and not success_regex:
        if code_files:
            issues.append("missing_expected_signal")
        else:
            warnings.append("missing_expected_signal")

    how = extract_section(body_md, "How to run")
    run_cmd, entry = resolve_run_command(meta, pack_dir or Path("."), code_files=code_files)
    if not run_cmd and not (how and len(how) >= 8):
        if code_files:
            warnings.append("missing_run_instructions")

    if not (body.get("citations") or body.get("sink_path")):
        warnings.append("missing_citations")

    st = (finding_state or "").lower()
    if st and st not in (
        "needs_human",
        "confirmed",
        "candidate",
        "pending_llm",
    ):
        warnings.append(f"unusual_state:{st}")

    ready = len(issues) == 0 and bool(code_files)
    return {
        "ready": ready,
        "issues": issues,
        "warnings": warnings,
        "frontmatter": meta,
        "code_files": sorted(set(code_files)),
        "run_command": run_cmd,
        "entry": entry,
        "success_regex": success_regex or None,
        "expected_signal_excerpt": (expected[:500] if expected else None),
        "timeout_s": meta.get("timeout_s"),
        "network": meta.get("network") or None,
        "hub_present": bool(hub_text and len(hub_text.strip()) >= 20),
    }


def build_handoff_markdown(
    *,
    finding_id: int,
    finding_body: dict[str, Any],
    state: str,
    stable_key: str,
    evidence_id: str,
    readiness: dict[str, Any],
    target_path: str = "",
    run_id: str = "",
) -> str:
    """One-page operator/harness contract."""
    body = finding_body or {}
    tm = body.get("threat_model") if isinstance(body.get("threat_model"), dict) else {}
    cites = body.get("citations") if isinstance(body.get("citations"), list) else []
    cite_lines = []
    for c in cites:
        if not isinstance(c, dict) or not c.get("path"):
            continue
        line = str(c["path"])
        if c.get("start_line") is not None:
            line += f":{c.get('start_line')}"
            if c.get("end_line") is not None and c.get("end_line") != c.get("start_line"):
                line += f"-{c.get('end_line')}"
        if c.get("symbol"):
            line += f" ({c.get('symbol')})"
        cite_lines.append(f"- `{line}`")

    run_cmd = readiness.get("run_command") or "(set `run:` in hub frontmatter)"
    signal = readiness.get("success_regex") or readiness.get("expected_signal_excerpt") or "(document expected signal)"
    issues = readiness.get("issues") or []
    warnings = readiness.get("warnings") or []

    parts = [
        f"# Validation job: finding {finding_id}",
        "",
        f"- **title:** {body.get('title') or stable_key or finding_id}",
        f"- **state:** {state}",
        f"- **stable_key:** `{stable_key or '-'}`",
        f"- **weakness_class:** {body.get('weakness_class') or '-'}",
        f"- **severity_claim:** {body.get('severity_claim') or '-'}",
        f"- **evidence_id:** `{evidence_id}`",
        f"- **run_id:** `{run_id or '-'}`",
        f"- **target_path:** `{target_path or '-'}`",
        f"- **harness_ready:** {bool(readiness.get('ready'))}",
        "",
        "## Claim",
        "",
        str(body.get("summary") or "_No summary._"),
        "",
        "### Threat model",
        "",
        f"- **Attacker:** {tm.get('attacker') or '-'}",
        f"- **Boundary:** {tm.get('boundary') or '-'}",
        f"- **Impact:** {tm.get('impact') or '-'}",
        "",
        "## Citations",
        "",
        "\n".join(cite_lines) if cite_lines else "_(none)_",
        "",
        "## Run",
        "",
        "```",
        f"cd evidence/{evidence_id}",
        str(run_cmd),
        "```",
        "",
        f"- **entry:** `{readiness.get('entry') or '-'}`",
        f"- **code_files:** {', '.join(f'`{n}`' for n in (readiness.get('code_files') or [])) or '_(none)_'}",
        f"- **timeout_s:** {readiness.get('timeout_s') or '(harness default)'}",
        f"- **network:** {readiness.get('network') or '(harness default)'}",
        "",
        "## Success signal",
        "",
        str(signal),
        "",
        "## Failure modes",
        "",
        "- **connection refused / wrong env** → fix staging; do not reject finding yet",
        "- **PoC crashes before asserting** → `poc_broken` (re-run develop_poc)",
        "- **clean run, no signal** → `signal_absent` (soft disprove; human decides)",
        "",
        "## Constraints",
        "",
        "- Do not write to application source (target is read-only for audits)",
        "- Prefer non-destructive probes over destructive exploits",
        "- Report: ran | signal | stderr | residual doubt",
        "- Automation never sets `confirmed` — human review owns acceptance",
        "",
        "## Readiness",
        "",
        f"- **issues:** {', '.join(issues) if issues else '_(none)_'}",
        f"- **warnings:** {', '.join(warnings) if warnings else '_(none)_'}",
        "",
        "---",
        "",
        f"_Exported {utc_now_iso()}. Bundle is evidence for validation — not exploit proof._",
        "",
    ]
    return "\n".join(parts)


def _safe_copy_tree(src: Path, dst: Path) -> list[str]:
    """Copy files from src into dst; return relative paths copied."""
    copied: list[str] = []
    if not src.is_dir():
        return copied
    dst.mkdir(parents=True, exist_ok=True)
    for p in sorted(src.rglob("*")):
        if not p.is_file() or p.name.endswith(".tmp"):
            continue
        try:
            rel = p.relative_to(src)
        except ValueError:
            continue
        # skip huge binaries over 2MB
        try:
            if p.stat().st_size > 2_000_000:
                continue
        except OSError:
            continue
        out = dst / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(p, out)
            copied.append(str(rel).replace("\\", "/"))
        except OSError:
            continue
    return copied


def _write_citation_slices(
    target: Path,
    citations: list[dict],
    out_dir: Path,
    *,
    max_chars: int = 8000,
) -> list[dict[str, Any]]:
    written: list[dict[str, Any]] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, c in enumerate(citations or []):
        if not isinstance(c, dict) or not c.get("path"):
            continue
        rel = str(c["path"]).replace("\\", "/").lstrip("/")
        if ".." in rel.split("/"):
            continue
        src = target / rel
        if not src.is_file():
            written.append({"path": rel, "error": "missing"})
            continue
        try:
            text = src.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            written.append({"path": rel, "error": str(e)})
            continue
        start = c.get("start_line")
        end = c.get("end_line")
        if start is not None:
            lines = text.splitlines()
            s = max(1, int(start)) - 1
            e = int(end) if end is not None else s + 40
            e = min(len(lines), max(s + 1, e))
            text = "\n".join(lines[s:e])
            header = f"# {rel} L{s + 1}-{e}\n"
        else:
            header = f"# {rel}\n"
        if len(text) > max_chars:
            text = text[:max_chars] + "\n…[truncated]"
        safe_name = re.sub(r"[^\w.\-]+", "_", rel)[:80]
        fname = f"{i:02d}_{safe_name}.txt"
        (out_dir / fname).write_text(header + text, encoding="utf-8")
        written.append({"path": rel, "file": fname, "start_line": start, "end_line": end})
    return written


def export_validation_job(
    run_dir: Path,
    finding: Any,
    *,
    target_path: str = "",
    run_id: str = "",
    out_dir: Optional[Path] = None,
    as_zip: bool = True,
    include_citations: bool = True,
) -> dict[str, Any]:
    """Build a self-contained validation job directory (and optional zip).

    Layout::

        finding.json
        HANDOFF.md
        meta.json
        evidence/<files>
        citations/*   (optional slices)
    """
    from vulnforge.tools.evidence_write import InvalidEvidenceId, sanitize_evidence_id

    body = dict(getattr(finding, "body", None) or {})
    fid = int(finding.id)
    eid_raw = getattr(finding, "evidence_id", None) or body.get("evidence_id") or f"human-{fid}"
    try:
        eid = sanitize_evidence_id(str(eid_raw))
    except InvalidEvidenceId as e:
        return {"ok": False, "error": f"invalid_evidence_id:{e}"}

    pack_src = Path(run_dir) / "evidence" / eid
    hub_text = ""
    hub_path = pack_src / POC_DEVELOP_RELPATH
    if hub_path.is_file():
        try:
            hub_text = hub_path.read_text(encoding="utf-8")
        except OSError:
            hub_text = ""

    readiness = assess_poc_readiness(
        finding_body=body,
        pack_dir=pack_src if pack_src.is_dir() else None,
        hub_text=hub_text,
        finding_state=str(getattr(finding, "state", "") or ""),
    )

    if out_dir is None:
        out_dir = Path(run_dir) / "exports" / f"validation-job-finding-{fid}"
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    finding_payload = {
        "id": fid,
        "state": getattr(finding, "state", None),
        "stable_key": getattr(finding, "stable_key", None),
        "evidence_id": eid,
        "body": body,
        "severity": getattr(finding, "severity", None),
    }
    (out_dir / "finding.json").write_text(
        json.dumps(finding_payload, indent=2), encoding="utf-8"
    )

    handoff = build_handoff_markdown(
        finding_id=fid,
        finding_body=body,
        state=str(getattr(finding, "state", "") or ""),
        stable_key=str(getattr(finding, "stable_key", "") or ""),
        evidence_id=eid,
        readiness=readiness,
        target_path=target_path,
        run_id=run_id,
    )
    (out_dir / HANDOFF_RELPATH).write_text(handoff, encoding="utf-8")

    ev_out = out_dir / "evidence"
    copied = _safe_copy_tree(pack_src, ev_out) if pack_src.is_dir() else []

    citations_meta: list[dict[str, Any]] = []
    if include_citations and target_path:
        tpath = Path(target_path)
        if tpath.exists():
            cites = body.get("citations") if isinstance(body.get("citations"), list) else []
            citations_meta = _write_citation_slices(
                tpath, cites, out_dir / "citations"
            )

    meta = {
        "exported_at": utc_now_iso(),
        "finding_id": fid,
        "evidence_id": eid,
        "run_id": run_id,
        "target_path": target_path,
        "run_dir": str(run_dir),
        "readiness": readiness,
        "evidence_files": copied,
        "citations": citations_meta,
        "disclaimer": (
            "needs_human = mech gates; confirmed = human accepted "
            "(not exploit proven). PoC run results are evidence only."
        ),
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    zip_path: Optional[Path] = None
    if as_zip:
        zip_path = out_dir.with_suffix(".zip")
        if zip_path.is_file():
            zip_path.unlink()
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for p in sorted(out_dir.rglob("*")):
                if p.is_file():
                    zf.write(p, arcname=str(p.relative_to(out_dir)).replace("\\", "/"))

    return {
        "ok": True,
        "finding_id": fid,
        "evidence_id": eid,
        "out_dir": str(out_dir),
        "zip_path": str(zip_path) if zip_path else None,
        "readiness": readiness,
        "evidence_files": copied,
        "handoff_relpath": HANDOFF_RELPATH,
    }

"""
Deterministic tool-gap analysis from run transcripts, events, and task results.

Mines signals that the model wanted or tried tools we do not have, or failed
to use well. Writes projection-style reports under run_dir/project/.

Authority remains harness.db + transcripts; project/* is regenerate-friendly.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Optional

from vulnforge.profiles.code_static import CodeStaticProfile
from vulnforge.util import utc_now_iso, write_json

# Allowlist for code_static (so profile tools are not false gaps).
KNOWN_TOOLS: frozenset[str] = frozenset(CodeStaticProfile().allowed_tools())

# Free-text / wishlist keywords -> capability id (not necessarily a tool name).
# First matching group wins per keyword hit; multiple keywords may map to same cap.
WISHLIST_KEYWORDS: dict[str, str] = {
    # shell / process
    "shell": "exec_job",
    "bash": "exec_job",
    "sh ": "exec_job",
    "powershell": "exec_job",
    "cmd.exe": "exec_job",
    "run_shell": "exec_job",
    "execute": "exec_job",
    "exec": "exec_job",
    "subprocess": "exec_job",
    "terminal": "exec_job",
    # network / browser
    "browser": "http_fetch",
    "curl": "http_fetch",
    "wget": "http_fetch",
    "http_fetch": "http_fetch",
    "fetch url": "http_fetch",
    "http request": "http_fetch",
    "web request": "http_fetch",
    "playwright": "http_fetch",
    "selenium": "http_fetch",
    # scanners
    "sqlmap": "security_scanners",
    "nmap": "security_scanners",
    "nikto": "security_scanners",
    "burp": "security_scanners",
    "zap": "security_scanners",
    "nuclei": "security_scanners",
    # debugger / binary
    "debugger": "debugger",
    "gdb": "debugger",
    "lldb": "debugger",
    "strace": "debugger",
    "ltrace": "debugger",
    "windbg": "debugger",
    # package / env
    "pip install": "package_manager",
    "npm install": "package_manager",
    "docker": "container_runtime",
    # write / patch target
    "edit file": "write_target",
    "patch file": "write_target",
    "write_file": "write_target",
    "apply_patch": "write_target",
}

# Tool result error substrings -> bucket
_ERROR_BUCKETS = (
    ("unknown tool", "unknown_tool"),
    ("not_found", "not_found"),
    ("not found", "not_found"),
    ("denied", "denied"),
    ("permission", "denied"),
    ("path escape", "denied"),
    ("failed", "failed"),
    ("bad args", "failed"),
    ("timeout", "failed"),
)

_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

# Max evidence snippets kept per gap key
_MAX_EVIDENCE = 12
_MAX_SNIP_LEN = 240


def analyze_run(run_dir: Path) -> dict[str, Any]:
    """
    Analyze one run directory. Returns structured analysis dict.

    Does not require harness.db (transcripts alone are enough); DB notes and
    task results are used when present.
    """
    run_dir = Path(run_dir)
    gaps_acc: dict[str, dict[str, Any]] = {}
    stats = {
        "transcripts_scanned": 0,
        "tool_calls": 0,
        "tool_results": 0,
        "notes_scanned": 0,
        "tasks_scanned": 0,
        "events_scanned": 0,
        "freetext_hits": 0,
    }

    # --- transcripts ---
    tdir = run_dir / "transcripts"
    if tdir.is_dir():
        for path in sorted(tdir.glob("task-*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            stats["transcripts_scanned"] += 1
            task_id = data.get("task_id")
            try:
                task_id = int(task_id) if task_id is not None else None
            except (TypeError, ValueError):
                task_id = None
            kind = str(data.get("kind") or "")
            _scan_messages(
                data.get("messages") or [],
                gaps_acc,
                stats,
                source=f"transcript task-{path.stem}",
                task_id=task_id,
                task_kind=kind,
            )

    # --- DB notes + task results ---
    db_path = run_dir / "harness.db"
    if db_path.is_file():
        try:
            from vulnforge.db import Database

            db = Database.open(db_path)
            try:
                for n in db.list_notes():
                    stats["notes_scanned"] += 1
                    _scan_note(n, gaps_acc, stats)
                for t in db.list_tasks(limit=2000):
                    stats["tasks_scanned"] += 1
                    _scan_task_result(t, gaps_acc, stats)
            finally:
                db.close()
        except Exception as e:
            stats["db_error"] = str(e)[:200]

    # --- events.jsonl ---
    events_path = run_dir / "events.jsonl"
    if events_path.is_file():
        try:
            with events_path.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    stats["events_scanned"] += 1
                    _scan_event(ev, gaps_acc, stats)
        except OSError as e:
            stats["events_error"] = str(e)[:200]

    gaps = sorted(
        gaps_acc.values(),
        key=lambda g: (
            -_SEVERITY_RANK.get(str(g.get("severity") or "info"), 0),
            -int(g.get("count") or 0),
            str(g.get("tool_or_capability") or ""),
        ),
    )
    for g in gaps:
        g.setdefault("source", "mech")

    return {
        "schema_version": 2,
        "mode": "mechanical",
        "generated_at": utc_now_iso(),
        "run_dir": str(run_dir.resolve()),
        "known_tools": sorted(KNOWN_TOOLS),
        "stats": stats,
        "gap_count": len(gaps),
        "gaps": gaps,
    }


def write_reports(run_dir: Path, analysis: Optional[dict[str, Any]] = None) -> list[str]:
    """Write project/TOOL_GAPS.md and project/tool_gaps.json. Returns paths written."""
    run_dir = Path(run_dir)
    if analysis is None:
        analysis = analyze_run(run_dir)
    proj = run_dir / "project"
    proj.mkdir(parents=True, exist_ok=True)
    json_path = proj / "tool_gaps.json"
    md_path = proj / "TOOL_GAPS.md"
    write_json(json_path, analysis)
    md_path.write_text(format_markdown(analysis), encoding="utf-8")
    return [str(json_path), str(md_path)]


def format_markdown(analysis: dict[str, Any]) -> str:
    """ASCII-friendly projection report."""
    stats = analysis.get("stats") or {}
    gaps = analysis.get("gaps") or []
    mode = analysis.get("mode") or "mechanical"
    lines = [
        "# Tool gaps",
        "",
        f"Generated: {analysis.get('generated_at') or utc_now_iso()}",
        f"Run dir: {analysis.get('run_dir') or ''}",
        f"Mode: {mode}",
        "",
        "Scan of transcripts, notes, task results, and events.jsonl.",
        "Mechanical rules plus optional AI synthesis (operator roadmap - not proof).",
        "",
        "## Scan stats",
        "",
        f"- transcripts: {stats.get('transcripts_scanned', 0)}",
        f"- tool_calls: {stats.get('tool_calls', 0)}",
        f"- tool_results: {stats.get('tool_results', 0)}",
        f"- notes: {stats.get('notes_scanned', 0)}",
        f"- tasks: {stats.get('tasks_scanned', 0)}",
        f"- events: {stats.get('events_scanned', 0)}",
        f"- free-text hits: {stats.get('freetext_hits', 0)}",
        f"- analysis mode: {mode}",
        "",
        f"## Gaps ({len(gaps)})",
        "",
    ]
    if not gaps:
        lines.append("_No tool-gap signals detected._")
        lines.append("")
    else:
        lines.extend(
            [
                "| Severity | Capability | Count | Suggestion |",
                "|----------|------------|------:|------------|",
            ]
        )
        for g in gaps:
            cap = _md_cell(g.get("tool_or_capability"))
            sev = _md_cell(g.get("severity"))
            sug = _md_cell(g.get("suggestion"))
            cnt = int(g.get("count") or 0)
            lines.append(f"| {sev} | `{cap}` | {cnt} | {sug} |")
        lines.append("")
        lines.append("## Evidence detail")
        lines.append("")
        for g in gaps:
            cap = g.get("tool_or_capability") or "?"
            lines.append(f"### `{cap}` ({g.get('severity')}, n={g.get('count')})")
            lines.append("")
            if g.get("suggestion"):
                lines.append(f"**Suggestion:** {g['suggestion']}")
                lines.append("")
            for ev in (g.get("evidence") or [])[:_MAX_EVIDENCE]:
                if isinstance(ev, dict):
                    src = ev.get("source") or ""
                    snip = ev.get("snippet") or ""
                    tid = ev.get("task_id")
                    tid_s = f" task={tid}" if tid is not None else ""
                    lines.append(f"- [{src}{tid_s}] {snip}")
                else:
                    lines.append(f"- {ev}")
            lines.append("")

    lines.extend(
        [
            "## Known tools (code_static)",
            "",
            ", ".join(f"`{t}`" for t in (analysis.get("known_tools") or sorted(KNOWN_TOOLS))),
            "",
            "_This file is a projection. Re-run `vf tool-gaps` to regenerate._",
            "",
        ]
    )
    return "\n".join(lines)


def _md_cell(val: Any) -> str:
    s = str(val if val is not None else "").replace("|", "/").replace("\n", " ")
    return s[:180]


def _bump(
    gaps: dict[str, dict[str, Any]],
    key: str,
    *,
    severity: str,
    suggestion: str,
    evidence: dict[str, Any],
    category: str = "",
) -> None:
    if key not in gaps:
        gaps[key] = {
            "tool_or_capability": key,
            "category": category or _category_for(key),
            "count": 0,
            "severity": severity,
            "suggestion": suggestion,
            "evidence": [],
        }
    g = gaps[key]
    g["count"] = int(g["count"]) + 1
    # escalate severity
    if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(str(g.get("severity")), 0):
        g["severity"] = severity
    if suggestion and (not g.get("suggestion") or len(suggestion) > len(str(g.get("suggestion") or ""))):
        g["suggestion"] = suggestion
    evs = g["evidence"]
    if len(evs) < _MAX_EVIDENCE:
        evs.append(evidence)


def _category_for(key: str) -> str:
    if key.startswith("unknown:"):
        return "unknown_tool"
    if key.startswith("error:"):
        return "tool_error"
    if key.startswith("thrash:"):
        return "thrash"
    if key.startswith("submit:"):
        return "submit"
    if key.startswith("wishlist:") or key.startswith("note:"):
        return "wishlist"
    if key.startswith("freetext:"):
        return "freetext"
    return "other"


def _snip(text: Any, n: int = _MAX_SNIP_LEN) -> str:
    s = str(text if text is not None else "")
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > n:
        return s[: n - 3] + "..."
    return s


def _parse_tool_content(content: Any) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    if not isinstance(content, str):
        return {}
    s = content.strip()
    if not s:
        return {}
    try:
        data = json.loads(s)
        return data if isinstance(data, dict) else {"_raw": data}
    except json.JSONDecodeError:
        return {"_text": s}


def _tool_name_from_call(tc: Any) -> Optional[str]:
    if not isinstance(tc, dict):
        return None
    # OpenAI-style: function.name
    fn = tc.get("function")
    if isinstance(fn, dict) and fn.get("name"):
        return str(fn["name"])
    if tc.get("name"):
        return str(tc["name"])
    return None


def _scan_messages(
    messages: list,
    gaps: dict[str, dict[str, Any]],
    stats: dict[str, Any],
    *,
    source: str,
    task_id: Optional[int],
    task_kind: str,
) -> None:
    # Track empty-result thrash per tool within one transcript
    empty_by_tool: dict[str, int] = defaultdict(int)
    submit_fail = 0
    saw_submit_ok = False
    is_llm_stage = task_kind in ("hunt", "recon", "validate_llm")

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role")

        if role == "assistant":
            # free text / reasoning
            for field in ("content", "reasoning_content"):
                text = msg.get(field)
                if isinstance(text, str) and text.strip():
                    _scan_freetext(
                        text,
                        gaps,
                        stats,
                        source=f"{source}:{field}",
                        task_id=task_id,
                    )
            tcs = msg.get("tool_calls") or []
            if isinstance(tcs, list):
                for tc in tcs:
                    name = _tool_name_from_call(tc)
                    if not name:
                        continue
                    stats["tool_calls"] = int(stats["tool_calls"]) + 1
                    if name not in KNOWN_TOOLS:
                        _bump(
                            gaps,
                            f"unknown:{name}",
                            severity="high",
                            suggestion=(
                                f"Model invoked non-allowlisted tool `{name}`. "
                                "Extend profile tools or tighten tool schema / preamble."
                            ),
                            evidence={
                                "source": source,
                                "task_id": task_id,
                                "snippet": _snip(f"tool_call name={name}"),
                                "kind": "unknown_tool",
                            },
                            category="unknown_tool",
                        )

        if role == "tool":
            stats["tool_results"] = int(stats["tool_results"]) + 1
            name = str(msg.get("name") or "")
            body = _parse_tool_content(msg.get("content"))
            _handle_tool_result(
                name,
                body,
                gaps,
                empty_by_tool,
                source=source,
                task_id=task_id,
            )
            if name in ("submit_candidate", "submit_none", "submit_architecture"):
                if body.get("ok") is True:
                    saw_submit_ok = True
                elif body.get("ok") is False:
                    submit_fail += 1
                    err = body.get("error") or "submit failed"
                    _bump(
                        gaps,
                        f"submit:failure:{name}",
                        severity="medium",
                        suggestion=(
                            f"`{name}` returned ok=false. Check body validation gates "
                            "and evidence requirements."
                        ),
                        evidence={
                            "source": source,
                            "task_id": task_id,
                            "snippet": _snip(err),
                            "kind": "submit_failure",
                        },
                        category="submit",
                    )
            if name == "note":
                # notes also appear as tool results with payload in args; content may echo
                kind = body.get("kind")
                if kind in ("wishlist", "sibling_seed"):
                    payload = body.get("payload", body)
                    _scan_note_payload(
                        str(kind),
                        payload,
                        gaps,
                        stats,
                        source=source,
                        task_id=task_id,
                    )

        if role == "user":
            text = msg.get("content")
            # only scan short operator notes, not huge packets
            if isinstance(text, str) and 0 < len(text) < 4000:
                # skip system-like packets
                if not text.lstrip().startswith("#"):
                    _scan_freetext(
                        text,
                        gaps,
                        stats,
                        source=f"{source}:user",
                        task_id=task_id,
                    )

    # thrash: many empty results for same tool
    for tool, n in empty_by_tool.items():
        if n >= 3:
            _bump(
                gaps,
                f"thrash:empty:{tool}",
                severity="medium",
                suggestion=(
                    f"Repeated empty results from `{tool}` ({n}x in one task). "
                    "Improve path hints, inventory, or grep preindex."
                ),
                evidence={
                    "source": source,
                    "task_id": task_id,
                    "snippet": _snip(f"{tool} empty_result_count={n}"),
                    "kind": "empty_thrash",
                },
                category="thrash",
            )
            # count once as the thrash event (already counted empties separately)

    if is_llm_stage and task_kind == "hunt" and not saw_submit_ok:
        # only if there were assistant turns (real attempt)
        if any(
            isinstance(m, dict) and m.get("role") == "assistant" for m in messages
        ):
            _bump(
                gaps,
                "submit:no_submit",
                severity="medium",
                suggestion=(
                    "Hunt transcript ended without successful submit_candidate/submit_none. "
                    "This typically indicates one of: (1) LLM called non-submit tools too many times and hit max_tool_rounds, "
                    "(2) LLM did not call any submit_* tool due to non-compliance, or (3) Network/infra failure during LLM call. "
                    "Recommended actions: 1) Check the transcript file at <run_dir>/transcripts/task-<id>.json for details, "
                    "2) Verify your model supports the expected tool schema (submit_candidate/submit_none), "
                    "3) Consider increasing max_tool_rounds in config/default.yaml if the LLM is making many tool calls before submitting, "
                    "4) Try a different model known to comply with VulnForge tool contracts."
                ),
                evidence={
                    "source": source,
                    "task_id": task_id,
                    "snippet": "no successful submit_* in transcript",
                    "kind": "no_submit",
                },
                category="submit",
            )


def _handle_tool_result(
    name: str,
    body: dict[str, Any],
    gaps: dict[str, dict[str, Any]],
    empty_by_tool: dict[str, int],
    *,
    source: str,
    task_id: Optional[int],
) -> None:
    err = body.get("error")
    ok = body.get("ok")

    if isinstance(err, str) and err:
        low = err.lower()
        bucket = "failed"
        for needle, b in _ERROR_BUCKETS:
            if needle in low:
                bucket = b
                break
        if bucket == "unknown_tool" or "unknown tool" in low:
            # extract tool name if present
            m = re.search(r"unknown tool\s+(\S+)", err, re.I)
            tname = m.group(1) if m else (name or "unknown")
            _bump(
                gaps,
                f"unknown:{tname}",
                severity="high",
                suggestion=(
                    f"Handler rejected tool `{tname}`. Align model schema with "
                    "code_static allowlist or add the tool."
                ),
                evidence={
                    "source": source,
                    "task_id": task_id,
                    "snippet": _snip(err),
                    "kind": "unknown_tool",
                },
                category="unknown_tool",
            )
            return
        sev = "high" if bucket == "denied" else "medium"
        tool_label = name or "tool"
        _bump(
            gaps,
            f"error:{bucket}:{tool_label}",
            severity=sev,
            suggestion=_error_suggestion(bucket, tool_label),
            evidence={
                "source": source,
                "task_id": task_id,
                "snippet": _snip(err),
                "kind": f"error_{bucket}",
            },
            category="tool_error",
        )
        return

    if ok is False and not err:
        tool_label = name or "tool"
        _bump(
            gaps,
            f"error:failed:{tool_label}",
            severity="medium",
            suggestion=_error_suggestion("failed", tool_label),
            evidence={
                "source": source,
                "task_id": task_id,
                "snippet": _snip(body),
                "kind": "error_failed",
            },
            category="tool_error",
        )
        return

    # empty-ish success results
    if name and ok is not False:
        if _is_empty_result(name, body):
            empty_by_tool[name] += 1


def _is_empty_result(name: str, body: dict[str, Any]) -> bool:
    if name == "grep":
        matches = body.get("matches")
        if matches is not None and len(matches) == 0:
            return True
        if body.get("count") == 0:
            return True
    if name == "list_dir":
        entries = body.get("entries") or body.get("items")
        if isinstance(entries, list) and len(entries) == 0:
            return True
    if name == "read_file":
        content = body.get("content")
        if content == "" or content is None:
            if body.get("ok") is True:
                return True
    return False


def _error_suggestion(bucket: str, tool: str) -> str:
    if bucket == "not_found":
        return (
            f"`{tool}` hit not_found. Path hints or inventory may be stale; "
            "re-run recon or fix operator path selection."
        )
    if bucket == "denied":
        return (
            f"`{tool}` denied (jail/scope). Model may be probing outside target; "
            "tighten packet scope or document boundaries."
        )
    return f"`{tool}` returned errors. Inspect transcripts for bad args or infra issues."


def _scan_note(n: dict[str, Any], gaps: dict, stats: dict) -> None:
    kind = str(n.get("kind") or "")
    if kind not in ("wishlist", "sibling_seed"):
        return
    _scan_note_payload(
        kind,
        n.get("payload"),
        gaps,
        stats,
        source="db:notes",
        task_id=n.get("task_id"),
    )


def _scan_note_payload(
    kind: str,
    payload: Any,
    gaps: dict,
    stats: dict,
    *,
    source: str,
    task_id: Optional[int],
) -> None:
    text_bits: list[str] = []
    if isinstance(payload, str):
        text_bits.append(payload)
    elif isinstance(payload, dict):
        text_bits.append(json.dumps(payload, ensure_ascii=True))
        for k in ("tool", "tools", "capability", "want", "request", "name"):
            v = payload.get(k)
            if isinstance(v, str) and v.strip():
                text_bits.append(v)
            elif isinstance(v, list):
                text_bits.extend(str(x) for x in v)
    else:
        text_bits.append(str(payload))

    blob = " ".join(text_bits).lower()
    matched_caps: set[str] = set()
    for kw, cap in WISHLIST_KEYWORDS.items():
        if kw in blob:
            matched_caps.add(cap)
    # explicit tool-like tokens not in allowlist
    for tok in re.findall(r"\b([a-z][a-z0-9_]{2,32})\b", blob):
        if tok in KNOWN_TOOLS:
            continue
        if tok in (
            "wishlist",
            "sibling_seed",
            "codemap",
            "tool",
            "tools",
            "need",
            "want",
            "path",
            "area",
            "class",
            "true",
            "false",
            "none",
            "null",
        ):
            continue
        # only treat as tool-ish if looks like verb_noun or known wishlist word
        if tok in WISHLIST_KEYWORDS:
            matched_caps.add(WISHLIST_KEYWORDS[tok])
        elif any(
            tok.startswith(p)
            for p in ("run_", "exec_", "fetch_", "http_", "shell_", "scan_")
        ):
            matched_caps.add(tok)

    if not matched_caps:
        # still record generic wishlist/sibling note as low signal
        key = f"note:{kind}"
        _bump(
            gaps,
            key,
            severity="low",
            suggestion=(
                f"Agent left a `{kind}` note. Review payload for capability requests."
            ),
            evidence={
                "source": source,
                "task_id": task_id,
                "snippet": _snip(payload),
                "kind": kind,
            },
            category="wishlist",
        )
        return

    for cap in sorted(matched_caps):
        _bump(
            gaps,
            f"wishlist:{cap}",
            severity="high" if kind == "wishlist" else "medium",
            suggestion=_capability_suggestion(cap),
            evidence={
                "source": source,
                "task_id": task_id,
                "snippet": _snip(f"{kind}: {payload}"),
                "kind": kind,
            },
            category="wishlist",
        )


def _capability_suggestion(cap: str) -> str:
    hints = {
        "exec_job": "Consider code_exec profile or a jailed exec_job tool (off by default).",
        "http_fetch": "Add optional http_fetch tool for live endpoints (scoped allowlist).",
        "security_scanners": "Out-of-band scanners are out of scope for code_static; run offline.",
        "debugger": "Debugger attach is out of scope; use static evidence and notes.",
        "package_manager": "Do not install packages mid-audit; document deps in notes.",
        "container_runtime": "Container runtime not allowlisted; keep target read-only.",
        "write_target": "Target is read-only; use write_evidence for artifacts only.",
    }
    return hints.get(
        cap,
        f"Capability `{cap}` is not in code_static allowlist. "
        "Document residual or extend tools carefully.",
    )


def _scan_freetext(
    text: str,
    gaps: dict,
    stats: dict,
    *,
    source: str,
    task_id: Optional[int],
) -> None:
    low = text.lower()
    # require toolish context to reduce noise from prompts that mention curl etc.
    context_ok = any(
        c in low
        for c in (
            "tool",
            "cannot",
            "can't",
            "unable",
            "need to run",
            "wish",
            "if i had",
            "would use",
            "no way to",
            "missing",
            "not available",
            "not allowed",
            "instead of",
            "without ",
            "i would",
            "let me run",
            "try to run",
            "execute",
        )
    )
    hits: set[str] = set()
    for kw, cap in WISHLIST_KEYWORDS.items():
        if kw in low:
            hits.add(cap)
    if not hits:
        return
    if not context_ok:
        # still count very explicit tool names often used as function calls in prose
        strong = {"run_shell", "sqlmap", "nmap", "http_fetch", "write_file", "apply_patch"}
        if not any(s in low for s in strong):
            return
    stats["freetext_hits"] = int(stats["freetext_hits"]) + 1
    for cap in sorted(hits):
        if cap in KNOWN_TOOLS:
            continue
        _bump(
            gaps,
            f"freetext:{cap}",
            severity="low",
            suggestion=_capability_suggestion(cap),
            evidence={
                "source": source,
                "task_id": task_id,
                "snippet": _snip(text),
                "kind": "freetext",
            },
            category="freetext",
        )


def _scan_task_result(task: Any, gaps: dict, stats: dict) -> None:
    """Inspect harness task rows for no_submit / abort thrash."""
    try:
        result = task.result if hasattr(task, "result") else None
        tid = task.id if hasattr(task, "id") else None
        kind = task.kind if hasattr(task, "kind") else ""
        state = task.state if hasattr(task, "state") else ""
    except Exception:
        return
    if not isinstance(result, dict):
        result = {}
    err = str(result.get("error") or "")
    if err in ("no_submit", "max_tool_rounds", "aborted_scope") or result.get(
        "aborted_scope"
    ):
        key = f"submit:{err or 'aborted_scope'}"
        _bump(
            gaps,
            key,
            severity="medium",
            suggestion=(
                f"Task result error `{err or 'aborted_scope'}`. "
                "Often tool thrash or missing submit_*; review transcript."
            ),
            evidence={
                "source": "db:tasks",
                "task_id": tid,
                "snippet": _snip(f"kind={kind} state={state} error={err}"),
                "kind": "task_abort",
            },
            category="submit",
        )


def _scan_event(ev: dict[str, Any], gaps: dict, stats: dict) -> None:
    event = str(ev.get("event") or "")
    if event in ("failed_task", "deadletter", "not_implemented"):
        err = str(ev.get("error") or event)
        low = err.lower()
        if "unknown tool" in low or "no_submit" in low or "max_tool_rounds" in low:
            _bump(
                gaps,
                f"event:{event}",
                severity="low",
                suggestion="See events.jsonl and matching task transcript.",
                evidence={
                    "source": "events.jsonl",
                    "task_id": ev.get("task_id"),
                    "snippet": _snip(err),
                    "kind": event,
                },
                category="event",
            )


def discover_run_dirs(runs_root: Path) -> list[Path]:
    """Find runs/*/run-*/ with harness.db or transcripts/."""
    runs_root = Path(runs_root)
    out: list[Path] = []
    if not runs_root.is_dir():
        return out
    for target_dir in sorted(runs_root.iterdir()):
        if not target_dir.is_dir():
            continue
        for run in sorted(target_dir.iterdir()):
            if not run.is_dir():
                continue
            if (run / "harness.db").is_file() or (run / "transcripts").is_dir():
                out.append(run.resolve())
    return out


# ---------------------------------------------------------------------------
# AI / hybrid analysis + cross-run aggregation
# ---------------------------------------------------------------------------

_MAX_LLM_TRANSCRIPT_CHARS = 12000
_MAX_LLM_MECH_GAPS = 25
_MAX_LLM_SNIPPETS = 40


def _prompts_root() -> Path:
    return Path(__file__).resolve().parents[1] / "prompts" / "v1"


def _normalize_mode(mode: Optional[str]) -> str:
    m = (mode or "mechanical").strip().lower()
    if m in ("mech", "mechanical", "deterministic", "rules"):
        return "mechanical"
    if m in ("llm", "ai"):
        return "llm"
    if m in ("hybrid", "both"):
        return "hybrid"
    return "mechanical"


def _compact_mech_for_llm(mech: dict[str, Any]) -> dict[str, Any]:
    gaps_out = []
    for g in (mech.get("gaps") or [])[:_MAX_LLM_MECH_GAPS]:
        ev = []
        for e in (g.get("evidence") or [])[:3]:
            if isinstance(e, dict):
                ev.append(
                    {
                        "task_id": e.get("task_id"),
                        "snippet": _snip(e.get("snippet"), 160),
                        "source": e.get("source"),
                    }
                )
        gaps_out.append(
            {
                "tool_or_capability": g.get("tool_or_capability"),
                "category": g.get("category"),
                "severity": g.get("severity"),
                "count": g.get("count"),
                "suggestion": g.get("suggestion"),
                "evidence": ev,
            }
        )
    return {
        "known_tools": mech.get("known_tools") or sorted(KNOWN_TOOLS),
        "stats": mech.get("stats") or {},
        "mechanical_gaps": gaps_out,
    }


def _transcript_digest(run_dir: Path, max_chars: int = _MAX_LLM_TRANSCRIPT_CHARS) -> str:
    """Pack assistant free-text + tool names from recent transcripts for the model."""
    tdir = Path(run_dir) / "transcripts"
    if not tdir.is_dir():
        return ""
    chunks: list[str] = []
    used = 0
    for path in sorted(tdir.glob("task-*.json"), reverse=True):
        if used >= max_chars:
            break
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        tid = data.get("task_id")
        kind = data.get("kind") or ""
        parts = [f"### task {tid} kind={kind}"]
        for msg in data.get("messages") or []:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role")
            if role == "assistant":
                for field in ("content", "reasoning_content"):
                    text = msg.get(field)
                    if isinstance(text, str) and text.strip():
                        parts.append(f"assistant.{field}: {_snip(text, 400)}")
                for tc in msg.get("tool_calls") or []:
                    name = _tool_name_from_call(tc)
                    if name:
                        parts.append(f"tool_call: {name}")
            if role == "tool":
                name = msg.get("name") or ""
                body = _parse_tool_content(msg.get("content"))
                err = body.get("error")
                if err:
                    parts.append(f"tool_result {name} error: {_snip(err, 200)}")
        block = "\n".join(parts)
        if used + len(block) > max_chars:
            remain = max_chars - used
            if remain > 80:
                chunks.append(block[:remain] + "\n...[truncated]...")
            break
        chunks.append(block)
        used += len(block) + 2
    return "\n\n".join(reversed(chunks))


def _parse_llm_gaps_json(content: Optional[str]) -> list[dict[str, Any]]:
    if not content or not str(content).strip():
        return []
    text = str(content).strip()
    # strip optional markdown fences
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    # try whole, then first { ... }
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []
    if not isinstance(data, dict):
        return []
    raw = data.get("gaps")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw[:20]:
        if not isinstance(item, dict):
            continue
        cap = str(item.get("tool_or_capability") or item.get("capability") or "").strip()
        if not cap:
            continue
        sev = str(item.get("severity") or "medium").lower()
        if sev not in _SEVERITY_RANK:
            sev = "medium"
        evidence = []
        for e in item.get("evidence") or []:
            if isinstance(e, dict):
                evidence.append(
                    {
                        "source": e.get("source") or "llm",
                        "task_id": e.get("task_id"),
                        "snippet": _snip(e.get("snippet") or e.get("text") or "", 200),
                        "kind": e.get("kind") or "llm",
                    }
                )
            elif isinstance(e, str) and e.strip():
                evidence.append(
                    {"source": "llm", "task_id": None, "snippet": _snip(e, 200), "kind": "llm"}
                )
            if len(evidence) >= _MAX_EVIDENCE:
                break
        out.append(
            {
                "tool_or_capability": cap[:120],
                "category": str(item.get("category") or "other")[:40],
                "count": max(1, int(item.get("count") or 1)),
                "severity": sev,
                "suggestion": str(item.get("suggestion") or "")[:500],
                "evidence": evidence,
                "source": "llm",
            }
        )
    return out


def _capability_key(g: dict[str, Any]) -> str:
    """Normalize for merge: strip known prefixes where possible."""
    raw = str(g.get("tool_or_capability") or "")
    for prefix in (
        "unknown:",
        "wishlist:",
        "freetext:",
        "error:",
        "thrash:empty:",
        "submit:",
        "note:",
        "event:",
    ):
        if raw.startswith(prefix):
            rest = raw[len(prefix) :]
            # error:bucket:tool -> tool or capability
            if prefix == "error:" and ":" in rest:
                rest = rest.split(":", 1)[-1]
            return rest.lower()
    return raw.lower()


def _merge_gaps(
    mech_gaps: list[dict[str, Any]], llm_gaps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for g in mech_gaps:
        gg = dict(g)
        gg["source"] = gg.get("source") or "mech"
        by_key[_capability_key(gg) or str(gg.get("tool_or_capability"))] = gg
    for g in llm_gaps:
        key = _capability_key(g) or str(g.get("tool_or_capability"))
        if key in by_key:
            existing = by_key[key]
            existing["source"] = "hybrid"
            existing["count"] = max(int(existing.get("count") or 0), int(g.get("count") or 0))
            if _SEVERITY_RANK.get(str(g.get("severity")), 0) > _SEVERITY_RANK.get(
                str(existing.get("severity")), 0
            ):
                existing["severity"] = g.get("severity")
            if g.get("suggestion") and (
                not existing.get("suggestion")
                or len(str(g["suggestion"])) > len(str(existing.get("suggestion") or ""))
            ):
                existing["suggestion"] = g["suggestion"]
            evs = list(existing.get("evidence") or [])
            for e in g.get("evidence") or []:
                if len(evs) >= _MAX_EVIDENCE:
                    break
                evs.append(e)
            existing["evidence"] = evs
        else:
            by_key[key] = dict(g)
            by_key[key]["source"] = "llm"
    gaps = sorted(
        by_key.values(),
        key=lambda g: (
            -_SEVERITY_RANK.get(str(g.get("severity") or "info"), 0),
            -int(g.get("count") or 0),
            str(g.get("tool_or_capability") or ""),
        ),
    )
    return gaps


def analyze_run_llm(
    run_dir: Path,
    cfg: Optional[dict[str, Any]] = None,
    *,
    client: Any = None,
    mech: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    LLM synthesis of tool gaps. Uses mechanical analysis as context.
    Returns analysis dict (mode=llm). Caller should write_reports.
    """
    from vulnforge.llm import make_client
    from vulnforge.packet import load_prompt_slice

    run_dir = Path(run_dir)
    cfg = cfg or {}
    mech = mech if mech is not None else analyze_run(run_dir)
    digest = _transcript_digest(run_dir)
    compact = _compact_mech_for_llm(mech)

    try:
        system = load_prompt_slice(_prompts_root(), "tool_gaps.md")
    except (OSError, FileNotFoundError, PermissionError):
        system = (
            "Identify missing tools/capabilities from the audit packet. "
            "Reply with JSON only: {\"gaps\":[...], \"notes\":\"...\"}."
        )

    user = (
        "Analyze this campaign for tool/capability gaps.\n\n"
        f"## Mechanical pre-scan\n```json\n{json.dumps(compact, indent=2)[:8000]}\n```\n\n"
        f"## Transcript digest\n{digest or '_no transcripts_'}\n\n"
        "Return JSON only with ranked gaps."
    )

    own_client = client is None
    if client is None:
        client = make_client(cfg)
    model_id = None
    content = None
    llm_error = None
    try:
        try:
            model_id = client.fingerprint_model()
        except Exception as e:
            llm_error = f"fingerprint: {e}"
        if not llm_error:
            temp = float((cfg.get("llm") or {}).get("temperature_recon", 0.2))
            result = client.chat(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                tools=None,
                temperature=temp,
            )
            try:
                from vulnforge.llm import estimate_usage_from_messages
                from vulnforge.usage import record_llm_result

                if result.usage is None or getattr(result.usage, "source", "none") == "none":
                    result.usage = estimate_usage_from_messages(
                        [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        result.content,
                        result.tool_calls,
                    )
                record_llm_result(
                    run_dir,
                    task_id=None,
                    kind="tool_gaps",
                    model_id=model_id or result.model_id,
                    result=result,
                )
            except Exception:
                pass
            if not result.ok:
                llm_error = result.error or result.classification.value
            else:
                content = result.content
                model_id = result.model_id or model_id
    finally:
        if own_client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass

    llm_gaps = _parse_llm_gaps_json(content) if content else []
    stats = dict(mech.get("stats") or {})
    stats["llm_model"] = model_id
    if llm_error:
        stats["llm_error"] = str(llm_error)[:300]
    stats["llm_gaps_parsed"] = len(llm_gaps)

    # Pure LLM mode still includes mechanical as fallback when parse empty
    gaps = llm_gaps if llm_gaps else list(mech.get("gaps") or [])
    for g in gaps:
        g.setdefault("source", "llm" if llm_gaps else "mech")

    return {
        "schema_version": 2,
        "mode": "llm",
        "generated_at": utc_now_iso(),
        "run_dir": str(run_dir.resolve()),
        "known_tools": sorted(KNOWN_TOOLS),
        "stats": stats,
        "gap_count": len(gaps),
        "gaps": gaps,
        "llm_notes": None,
        "llm_error": llm_error,
    }


def analyze_run_hybrid(
    run_dir: Path,
    cfg: Optional[dict[str, Any]] = None,
    *,
    client: Any = None,
) -> dict[str, Any]:
    """Mechanical baseline + LLM refinement merged."""
    run_dir = Path(run_dir)
    mech = analyze_run(run_dir)
    llm = analyze_run_llm(run_dir, cfg, client=client, mech=mech)
    merged = _merge_gaps(list(mech.get("gaps") or []), list(llm.get("gaps") or []))
    stats = dict(mech.get("stats") or {})
    stats.update({k: v for k, v in (llm.get("stats") or {}).items() if k.startswith("llm")})
    return {
        "schema_version": 2,
        "mode": "hybrid",
        "generated_at": utc_now_iso(),
        "run_dir": str(run_dir.resolve()),
        "known_tools": sorted(KNOWN_TOOLS),
        "stats": stats,
        "gap_count": len(merged),
        "gaps": merged,
        "llm_error": llm.get("llm_error"),
    }


def analyze_run_mode(
    run_dir: Path,
    mode: str = "mechanical",
    cfg: Optional[dict[str, Any]] = None,
    *,
    client: Any = None,
) -> dict[str, Any]:
    """Dispatch by mode: mechanical | llm | hybrid."""
    m = _normalize_mode(mode)
    if m == "llm":
        return analyze_run_llm(run_dir, cfg, client=client)
    if m == "hybrid":
        return analyze_run_hybrid(run_dir, cfg, client=client)
    return analyze_run(run_dir)


def load_or_analyze(
    run_dir: Path,
    *,
    force: bool = False,
    mode: Optional[str] = None,
    cfg: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Return cached tool_gaps.json unless force or missing.

    When mode is llm/hybrid and force is False, still prefer cache if present.
    """
    run_dir = Path(run_dir)
    cached = run_dir / "project" / "tool_gaps.json"
    if not force and cached.is_file():
        try:
            data = json.loads(cached.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "gaps" in data:
                return data
        except (OSError, json.JSONDecodeError):
            pass
    m = _normalize_mode(mode or (cfg or {}).get("run", {}).get("tool_gaps_mode") or "mechanical")
    analysis = analyze_run_mode(run_dir, m, cfg)
    write_reports(run_dir, analysis)
    return analysis


def aggregate_tool_gaps(
    runs_root: Path,
    *,
    analyze_missing: bool = False,
    mode: str = "mechanical",
    cfg: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Roll up tool_gaps.json across all runs for the Home page.

    Returns capability-centric summary + per-run stats.
    """
    runs_root = Path(runs_root)
    run_dirs = discover_run_dirs(runs_root)
    by_cap: dict[str, dict[str, Any]] = {}
    per_run: list[dict[str, Any]] = []
    total_gaps = 0

    for rd in run_dirs:
        cached = rd / "project" / "tool_gaps.json"
        analysis: Optional[dict[str, Any]] = None
        if cached.is_file():
            try:
                analysis = json.loads(cached.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                analysis = None
        if analysis is None and analyze_missing:
            try:
                analysis = analyze_run_mode(rd, mode, cfg)
                write_reports(rd, analysis)
            except Exception as e:
                per_run.append(
                    {
                        "run_dir": str(rd),
                        "target_id": rd.parent.name,
                        "run_id": rd.name,
                        "error": str(e)[:200],
                        "gap_count": 0,
                    }
                )
                continue
        if not analysis:
            per_run.append(
                {
                    "run_dir": str(rd),
                    "target_id": rd.parent.name,
                    "run_id": rd.name,
                    "gap_count": 0,
                    "cached": False,
                }
            )
            continue

        gaps = analysis.get("gaps") or []
        total_gaps += len(gaps)
        per_run.append(
            {
                "run_dir": str(rd),
                "target_id": rd.parent.name,
                "run_id": rd.name,
                "gap_count": len(gaps),
                "mode": analysis.get("mode") or "mechanical",
                "generated_at": analysis.get("generated_at"),
                "cached": True,
            }
        )
        for g in gaps:
            cap = str(g.get("tool_or_capability") or "?")
            key = cap
            if key not in by_cap:
                by_cap[key] = {
                    "tool_or_capability": cap,
                    "category": g.get("category") or "",
                    "severity": g.get("severity") or "info",
                    "count": 0,
                    "runs_hit": 0,
                    "suggestion": g.get("suggestion") or "",
                    "sources": set(),
                    "run_keys": [],
                }
            entry = by_cap[key]
            entry["count"] += int(g.get("count") or 1)
            entry["runs_hit"] += 1
            entry["run_keys"].append(f"{rd.parent.name}/{rd.name}")
            src = g.get("source") or analysis.get("mode") or "mech"
            if isinstance(entry["sources"], set):
                entry["sources"].add(str(src))
            if _SEVERITY_RANK.get(str(g.get("severity")), 0) > _SEVERITY_RANK.get(
                str(entry.get("severity")), 0
            ):
                entry["severity"] = g.get("severity")
            sug = g.get("suggestion") or ""
            if sug and len(sug) > len(str(entry.get("suggestion") or "")):
                entry["suggestion"] = sug

    capabilities = []
    for entry in by_cap.values():
        sources = entry.pop("sources", set())
        if isinstance(sources, set):
            entry["source"] = "+".join(sorted(sources)) if sources else "mech"
        else:
            entry["source"] = str(sources)
        entry["run_keys"] = entry["run_keys"][:20]
        capabilities.append(entry)

    capabilities.sort(
        key=lambda c: (
            -_SEVERITY_RANK.get(str(c.get("severity") or "info"), 0),
            -int(c.get("runs_hit") or 0),
            -int(c.get("count") or 0),
            str(c.get("tool_or_capability") or ""),
        )
    )

    return {
        "schema_version": 1,
        "generated_at": utc_now_iso(),
        "runs_root": str(runs_root.resolve()),
        "runs_scanned": len(run_dirs),
        "total_gap_rows": total_gaps,
        "capability_count": len(capabilities),
        "capabilities": capabilities,
        "per_run": per_run,
    }

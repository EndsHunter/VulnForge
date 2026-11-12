"""SARIF 2.1.0 findings export (GitHub code scanning, IDEs, other SARIF consumers).

Registered as format ``sarif`` in ``vulnforge.export_findings.EXPORT_FORMATS``
(the registry wrapper there calls :func:`build_sarif`).

- One ``rule`` per weakness class (hunt skill); one ``result`` per finding.
- ``stable_key`` is the result's ``partialFingerprints`` so code scanning dedupes
  across runs. It is line-independent, so it is also used as
  ``primaryLocationLineHash`` (the key GitHub matches alerts on).
- VulnForge state goes in ``result.properties``. Exporting never changes state.
- Default filter: ``confirmed`` only. ``needs_human`` is opt-in; ``rejected_*``
  and ``superseded`` are opt-in. ``candidate`` only through an explicit state list.
- Paths are relative to the run's target root. A finding without a target-relative
  path and start line is not emitted as a result; it is listed in
  ``invocations[0].toolExecutionNotifications`` instead, so nothing vanishes silently.

needs_human = mechanical gates passed; confirmed = human accepted. Neither is exploit proof.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any, Iterable
from urllib.parse import quote, unquote

from vulnforge.findings.severity import normalize_severity_claim
from vulnforge.hunt_profiles.store import CLASS_ALIASES

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_MEDIA_TYPE = "application/sarif+json"

# Fingerprint keys. GitHub matches alerts on primaryLocationLineHash; the
# namespaced key keeps the VulnForge identity readable for other consumers.
FINGERPRINT_KEY = "vulnforge/stableKey/v1"
GITHUB_FINGERPRINT_KEY = "primaryLocationLineHash"

NO_LOCATION_ID = "vulnforge/no-location"

DEFAULT_STATES: tuple[str, ...] = ("confirmed",)
REJECTED_STATES: tuple[str, ...] = (
    "rejected_mech",
    "rejected_llm",
    "rejected_human",
    "superseded",
)

_LEVELS = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFORMATIONAL": "note",
}

# First sentence of message.text is the code-scanning alert title, so the
# state leads for anything a human has not accepted.
_STATE_NOTES = {
    "confirmed": "Human accepted in VulnForge review; not exploit proven.",
    "needs_human": "Mechanical gates passed; not a confirmed vulnerability.",
    "candidate": "Unvalidated hunt candidate; not a confirmed vulnerability.",
}

_MAX_NAME = 255
_MAX_DESC = 1024
_SLUG_RE = re.compile(r"[^a-z0-9._-]+")
_WIN_ABS_RE = re.compile(r"^[A-Za-z]:/")


def selected_states(
    *,
    include_needs_human: bool = False,
    include_rejected: bool = False,
    states: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """States a SARIF export includes. An explicit ``states`` list wins over the flags."""
    if states is not None:
        picked = [str(s).strip().lower() for s in states if str(s).strip()]
        return tuple(dict.fromkeys(picked))
    out = list(DEFAULT_STATES)
    if include_needs_human:
        out.append("needs_human")
    if include_rejected:
        out.extend(REJECTED_STATES)
    return tuple(out)


def rule_id_for_class(weakness_class: Any) -> str:
    """Rule id for a weakness class: slug plus the static hunt-skill aliases (sqli → injection).

    Uses only the code-level ``CLASS_ALIASES`` table, not the operator profile
    collection, so a rule id does not change when Settings change.
    """
    raw = str(weakness_class or "").strip().lower().replace("_", "-").replace(" ", "-")
    raw = CLASS_ALIASES.get(raw, raw)
    slug = _SLUG_RE.sub("-", raw).strip("-.")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug or "unclassified"


def _clip(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _rule_name(rule_id: str) -> str:
    parts = [p for p in re.split(r"[^a-z0-9]+", rule_id) if p]
    return _clip("".join(p[:1].upper() + p[1:] for p in parts) or "Unclassified", _MAX_NAME)


def _target_root(target_path: str) -> PurePosixPath | None:
    raw = str(target_path or "").replace("\\", "/").rstrip("/")
    if not raw:
        return None
    return PurePosixPath(raw)


def artifact_uri(path: Any, target_root: PurePosixPath | None) -> str | None:
    """Target-relative, percent-encoded POSIX URI, or None when not representable.

    Absolute paths outside the target root and paths that climb above it
    return None. Absolute local paths are never written to the SARIF file.
    """
    p = str(path or "").replace("\\", "/").strip()
    if not p or "://" in p:
        return None
    if p.startswith("/") or _WIN_ABS_RE.match(p):
        if target_root is None:
            return None
        try:
            p = PurePosixPath(p).relative_to(target_root).as_posix()
        except ValueError:
            return None
    parts: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(seg)
    if not parts:
        return None
    return quote("/".join(parts), safe="/")


def _line(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n >= 1 else None


def _physical_location(cit: dict, target_root: PurePosixPath | None) -> dict | None:
    uri = artifact_uri(cit.get("path"), target_root)
    start = _line(cit.get("start_line"))
    if uri is None or start is None:
        return None
    region: dict[str, Any] = {"startLine": start}
    end = _line(cit.get("end_line"))
    if end is not None and end >= start:
        region["endLine"] = end
    return {"artifactLocation": {"uri": uri}, "region": region}


def _locations(body: dict, target_root: PurePosixPath | None) -> tuple[dict | None, list[dict]]:
    """(primary location, related locations) from citations that have a path and line."""
    usable: list[tuple[dict, dict]] = []
    for c in body.get("citations") or []:
        if not isinstance(c, dict):
            continue
        phys = _physical_location(c, target_root)
        if phys is not None:
            usable.append((c, phys))
    if not usable:
        return None, []
    sink_uri = artifact_uri(body.get("sink_path"), target_root)
    sink_symbol = str(body.get("sink_symbol") or "").strip()
    primary_idx = 0
    if sink_uri:
        same_file = [
            i for i, (_c, phys) in enumerate(usable)
            if phys["artifactLocation"]["uri"] == sink_uri
        ]
        if same_file:
            primary_idx = same_file[0]
            # Several citations in the sink file: the one naming the sink symbol wins.
            if sink_symbol:
                for i in same_file:
                    if str(usable[i][0].get("symbol") or "").strip() == sink_symbol:
                        primary_idx = i
                        break
    c0, phys0 = usable[primary_idx]
    primary: dict[str, Any] = {"physicalLocation": phys0}
    symbol = str(c0.get("symbol") or body.get("sink_symbol") or "").strip()
    if symbol:
        primary["logicalLocations"] = [{"name": symbol}]
    related: list[dict] = []
    seen = {repr(phys0)}
    for i, (c, phys) in enumerate(usable):
        key = repr(phys)
        if i == primary_idx or key in seen:
            continue
        seen.add(key)
        loc: dict[str, Any] = {"id": len(related) + 1, "physicalLocation": phys}
        sym = str(c.get("symbol") or "").strip()
        loc["message"] = {"text": sym or _location_label(phys)}
        related.append(loc)
    return primary, related


def _location_label(phys: dict) -> str:
    return f"{unquote(phys['artifactLocation']['uri'])}:{phys['region']['startLine']}"


def _escape_links(text: str) -> str:
    """Escape brackets only where plain text would read as a SARIF embedded link."""
    if re.search(r"\]\(", text):
        return re.sub(r"([\\\[\]])", r"\\\1", text)
    return text


def _message(state: str, title: str, summary: str, related: list[dict]) -> str:
    title = _escape_links(str(title or "").strip().rstrip(".")) or "Untitled finding"
    note = _STATE_NOTES.get(state) or "Not a confirmed vulnerability."
    head = f"{title}. {note}" if state == "confirmed" else f"{state}: {title}. {note}"
    parts = [head]
    summary = _escape_links(str(summary or "").strip())
    if summary:
        parts.append(summary)
    if related:
        # Code scanning only shows a related location the message links to.
        links = ", ".join(
            "[{}]({})".format(
                re.sub(r"([\\\[\]])", r"\\\1", _location_label(loc["physicalLocation"])),
                loc["id"],
            )
            for loc in related
        )
        parts.append(f"Related locations: {links}.")
    return "\n\n".join(parts)


def _rule(rule_id: str, weakness_class: str, disclaimer: str) -> dict[str, Any]:
    label = str(weakness_class or "").strip() or "unclassified"
    return {
        "id": rule_id,
        "name": _rule_name(rule_id),
        "shortDescription": {"text": _clip(f"VulnForge {label} finding", _MAX_DESC)},
        "fullDescription": {
            "text": _clip(
                f"Finding reported by the VulnForge '{label}' hunt skill. {disclaimer}",
                _MAX_DESC,
            )
        },
        "help": {
            "text": (
                f"VulnForge hunt class '{label}'. Check the cited code and the "
                "finding's evidence pack (evidence/<evidence_id>) before acting. "
                "The result's vulnforge/state property says how far it got: "
                "needs_human = mechanical gates passed; confirmed = human accepted. "
                "Neither is exploit proof."
            )
        },
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": list(dict.fromkeys(["security", "vulnforge", rule_id]))},
    }


def build_sarif(
    rows: list[dict[str, Any]],
    *,
    states: Iterable[str],
    target_path: str = "",
    run_id: str = "",
    profile: str = "",
    exported_at: str = "",
    tool_version: str = "",
    disclaimer: str = "",
    weakness_class: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF 2.1.0 log (dict) from ``findings_to_rows`` rows.

    ``states`` is the allow-list of finding states. ``weakness_class`` optionally
    keeps only rows whose class maps to the same rule id.
    """
    allowed = {str(s).lower() for s in states}
    want_rule = rule_id_for_class(weakness_class) if weakness_class else None
    root = _target_root(target_path)

    rules: dict[str, dict[str, Any]] = {}
    pending: list[tuple[str, dict[str, Any]]] = []
    notifications: list[dict[str, Any]] = []
    counts: dict[str, int] = {}

    for r in sorted(rows, key=lambda x: (x.get("id") is None, x.get("id") or 0)):
        state = str(r.get("state") or "").lower()
        if state not in allowed:
            continue
        body = r.get("_body") if isinstance(r.get("_body"), dict) else {}
        wc = str(r.get("weakness_class") or body.get("weakness_class") or "")
        rid = rule_id_for_class(wc)
        if want_rule is not None and rid != want_rule:
            continue
        fid = r.get("id")
        primary, related = _locations(body, root)
        if primary is None:
            notifications.append(
                {
                    "descriptor": {"id": NO_LOCATION_ID, "index": 0},
                    "level": "warning",
                    "message": {
                        "text": (
                            f"Finding #{fid} ({state}) has no target-relative path "
                            "with a start line; not emitted as a result."
                        )
                    },
                    "properties": {"vulnforge/finding_id": fid, "vulnforge/state": state},
                }
            )
            continue
        rules.setdefault(rid, _rule(rid, wc, disclaimer))
        counts[state] = counts.get(state, 0) + 1
        sev = normalize_severity_claim(body.get("severity_claim"))
        hr = r.get("_human_review") if isinstance(r.get("_human_review"), dict) else {}
        result: dict[str, Any] = {
            "ruleId": rid,
            "level": _LEVELS.get(sev or "", "warning"),
            "message": {
                "text": _message(state, r.get("title") or "", r.get("summary") or "", related)
            },
            "locations": [primary],
        }
        if related:
            result["relatedLocations"] = related
        stable = str(r.get("stable_key") or "")
        if stable:
            result["partialFingerprints"] = {
                GITHUB_FINGERPRINT_KEY: stable,
                FINGERPRINT_KEY: stable,
            }
        props: dict[str, Any] = {
            "vulnforge/finding_id": fid,
            "vulnforge/state": state,
            "vulnforge/confirmed": state == "confirmed",
            "vulnforge/weakness_class": wc,
            "vulnforge/severity_claim": sev or "",
            "vulnforge/evidence_id": str(r.get("evidence_id") or ""),
            "tags": list(dict.fromkeys(["security", state])),
        }
        if stable:
            props["vulnforge/stable_key"] = stable
        if hr.get("action"):
            props["vulnforge/human_review_action"] = str(hr.get("action"))
        result["properties"] = props
        pending.append((rid, result))

    rule_ids = sorted(rules)
    index = {rid: i for i, rid in enumerate(rule_ids)}
    results = []
    for rid, result in pending:
        result["ruleIndex"] = index[rid]
        results.append(result)

    driver: dict[str, Any] = {
        "name": "VulnForge",
        "rules": [rules[rid] for rid in rule_ids],
        "notifications": [
            {
                "id": NO_LOCATION_ID,
                "name": "NoLocation",
                "shortDescription": {
                    "text": "Finding has no target-relative location; not emitted as a result."
                },
            }
        ],
    }
    if tool_version:
        driver["version"] = tool_version
        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+].*)?", tool_version):
            driver["semanticVersion"] = tool_version

    invocation: dict[str, Any] = {"executionSuccessful": True}
    if exported_at:
        invocation["endTimeUtc"] = exported_at
    if notifications:
        invocation["toolExecutionNotifications"] = notifications

    run_props: dict[str, Any] = {
        "vulnforge/run_id": run_id,
        "vulnforge/profile": profile,
        "vulnforge/states_included": sorted(allowed),
        "vulnforge/result_counts": counts,
        "vulnforge/skipped_no_location": len(notifications),
    }
    if weakness_class:
        run_props["vulnforge/weakness_class_filter"] = want_rule
    if disclaimer:
        run_props["vulnforge/disclaimer"] = disclaimer

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": driver},
                "invocations": [invocation],
                "results": results,
                "properties": run_props,
            }
        ],
    }


def tool_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("vulnforge")
    except PackageNotFoundError:
        return ""


__all__ = [
    "DEFAULT_STATES",
    "REJECTED_STATES",
    "SARIF_MEDIA_TYPE",
    "SARIF_VERSION",
    "artifact_uri",
    "build_sarif",
    "rule_id_for_class",
    "selected_states",
    "tool_version",
]

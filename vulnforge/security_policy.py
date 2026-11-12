"""Operator-owned security policy (``vulnforge/security-policy@1``).

The policy is declarative operator input stored in ``harness.db`` (never in the
read-only target tree). It feeds recon / hunt / disprove packets as guidance and
drives two mechanical, demote-only effects in ``validate_mech``:

* ``exclusions`` / ``out_of_scope`` → ``rejected_mech`` with the rule cited
  (``policy_excluded:<id>`` / ``policy_out_of_scope:<id>``) and a durable
  ``policy_match`` record on the finding body, so nothing is suppressed silently.
* ``severity_rubric`` rules with ``max_severity`` → cap ``severity_claim``
  (original kept under ``severity_claim_original``). Never raises severity.

The policy never promotes a finding and never sets ``confirmed``. ``in_scope`` is
packet guidance only (no gate). See ``docs/harness/validate/POLICY.md``.
"""

from __future__ import annotations

import posixpath
import re
from pathlib import Path
from typing import Any

from vulnforge.findings.severity import ALLOWED_SEVERITY_CLAIMS, normalize_severity_claim
from vulnforge.util import normalize_relpath

POLICY_SCHEMA = "vulnforge/security-policy@1"

# Explicit rank — string order would put HIGH below LOW.
SEVERITY_RANK: dict[str, int] = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

MAX_NOTES_CHARS = 8000
MAX_RULES_PER_LIST = 200

# list key -> (id prefix, allowed keys, required non-empty paths, required text field)
_LISTS: dict[str, tuple[str, frozenset[str], bool, str | None]] = {
    "trust_boundaries": (
        "tb",
        frozenset({"id", "name", "description", "paths"}),
        False,
        None,
    ),
    "attacker_controlled": (
        "src",
        frozenset({"id", "description", "paths"}),
        False,
        "description",
    ),
    "trusted_inputs": (
        "trust",
        frozenset({"id", "description", "paths"}),
        False,
        "description",
    ),
    "in_scope": ("scope", frozenset({"id", "paths", "note"}), True, None),
    "out_of_scope": ("oos", frozenset({"id", "paths", "reason"}), True, "reason"),
    "exclusions": (
        "ex",
        frozenset({"id", "paths", "weakness_class", "reason"}),
        True,
        "reason",
    ),
    "severity_rubric": (
        "sev",
        frozenset({"id", "max_severity", "weakness_class", "paths", "criteria"}),
        False,
        None,
    ),
}

_TOP_KEYS = frozenset({"schema", "notes", *_LISTS})
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
# Only * and ? are wildcards; "[" is literal (Next.js-style "app/[id]" dirs).
_GLOB_CHARS = frozenset("*?")


class PolicyError(ValueError):
    """Raised by :func:`require_policy` when a document does not validate."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = list(errors)


def empty_policy() -> dict[str, Any]:
    out: dict[str, Any] = {"schema": POLICY_SCHEMA, "notes": ""}
    for key in _LISTS:
        out[key] = []
    return out


# Body keys only the harness may write. validate_mech strips candidate-supplied
# copies before the gates so a hunt cannot fake a prior cap or an exclusion.
HARNESS_OWNED_KEYS: tuple[str, ...] = (
    "policy_match",
    "severity_rubric",
    "severity_claim_original",
)


def strip_harness_owned(body: dict) -> tuple[dict, list[str]]:
    """Return (body without harness-owned policy keys, dropped key names)."""
    if not isinstance(body, dict):
        return body, []
    dropped = [k for k in HARNESS_OWNED_KEYS if k in body]
    if not dropped:
        return body, []
    return {k: v for k, v in body.items() if k not in HARNESS_OWNED_KEYS}, dropped


def is_empty_policy(policy: dict | None) -> bool:
    if not isinstance(policy, dict):
        return True
    if str(policy.get("notes") or "").strip():
        return False
    return not any(policy.get(k) for k in _LISTS)


# ---------------------------------------------------------------------------
# Globs
# ---------------------------------------------------------------------------


def normalize_glob(raw: Any) -> tuple[str | None, str | None]:
    """Return (glob, error). Globs are relative to the target root."""
    if not isinstance(raw, str):
        return None, "path glob must be a string"
    g = raw.strip().replace("\\", "/")
    while g.startswith("./"):
        g = g[2:]
    if not g:
        return None, "empty path glob"
    if g.startswith("/") or re.match(r"^[A-Za-z]:", g):
        return None, f"path glob must be relative: {raw!r}"
    if ".." in g.split("/"):
        return None, f"path glob must not contain '..': {raw!r}"
    return g, None


def _glob_regex(glob: str) -> re.Pattern[str]:
    g = glob
    if g.endswith("/"):
        g = g + "**"
    out: list[str] = []
    i = 0
    while i < len(g):
        if g.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif g.startswith("**", i):
            out.append(".*")
            i += 2
        elif g[i] == "*":
            out.append("[^/]*")
            i += 1
        elif g[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(g[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def path_matches(glob: str, relpath: str) -> bool:
    """Full-path glob match (case-sensitive).

    ``*`` stays inside one segment, ``**`` crosses segments (may be empty), a
    trailing ``/`` means the whole directory, and a glob with no wildcard also
    matches everything under it as a directory (``vendor`` ≡ ``vendor/**``).
    """
    p = normalize_relpath(str(relpath or ""))
    if not p or not glob:
        return False
    if not (_GLOB_CHARS & set(glob)) and not glob.endswith("/"):
        return p == glob or p.startswith(glob + "/")
    rx = _REGEX_CACHE.get(glob)
    if rx is None:
        rx = _glob_regex(glob)
        _REGEX_CACHE[glob] = rx
    return bool(rx.match(p))


def _glob_literal_prefix(glob: str) -> str:
    """Directory prefix before the first wildcard (``src/api/*.py`` → ``src/api``)."""
    cut = len(glob)
    for i, ch in enumerate(glob):
        if ch in _GLOB_CHARS:
            cut = i
            break
    head = glob[:cut]
    if cut < len(glob):
        head = head.rsplit("/", 1)[0] if "/" in head else ""
    return head.rstrip("/")


def glob_overlaps_hint(glob: str, hint: str) -> bool:
    """Loose overlap for packet slicing (not used for gating)."""
    h = normalize_relpath(str(hint or "")).rstrip("/")
    if not h:
        return True
    if path_matches(glob, h):
        return True
    prefix = _glob_literal_prefix(glob)
    if not prefix:
        return True  # e.g. "**/*.py" — applies everywhere
    return prefix == h or prefix.startswith(h + "/") or h.startswith(prefix + "/")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def normalize_policy(raw: Any) -> tuple[dict[str, Any], list[str]]:
    """Validate + normalize a policy document. Returns (policy, errors).

    Strict: unknown keys (top-level or inside a rule) are errors so a typo such
    as ``max_sevrity`` never silently turns a cap into prose.
    """
    errors: list[str] = []
    out = empty_policy()
    if raw is None:
        return out, errors
    if not isinstance(raw, dict):
        return out, ["policy must be a JSON object"]

    for key in raw:
        if key not in _TOP_KEYS:
            errors.append(f"unknown top-level key: {key!r}")
    schema = raw.get("schema")
    if schema not in (None, "", POLICY_SCHEMA):
        errors.append(f"unsupported schema: {schema!r} (expected {POLICY_SCHEMA})")

    notes = raw.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append("notes must be a string")
    else:
        n = str(notes or "")
        if len(n) > MAX_NOTES_CHARS:
            errors.append(f"notes longer than {MAX_NOTES_CHARS} characters")
        out["notes"] = n

    seen_ids: set[str] = set()
    pending_auto: list[tuple[str, dict]] = []

    for list_key, (prefix, allowed, need_paths, need_text) in _LISTS.items():
        items = raw.get(list_key)
        if items is None:
            continue
        if not isinstance(items, list):
            errors.append(f"{list_key} must be a list")
            continue
        if len(items) > MAX_RULES_PER_LIST:
            errors.append(f"{list_key}: more than {MAX_RULES_PER_LIST} rules")
            continue
        for idx, item in enumerate(items):
            where = f"{list_key}[{idx}]"
            if not isinstance(item, dict):
                errors.append(f"{where} must be an object")
                continue
            for k in item:
                if k not in allowed:
                    errors.append(f"{where}: unknown key {k!r}")
            rule: dict[str, Any] = {}
            rid = item.get("id")
            if rid is not None and str(rid).strip():
                rid_s = str(rid).strip()
                if not _RULE_ID_RE.match(rid_s):
                    errors.append(f"{where}: bad id {rid!r} (letters, digits, _ . -)")
                elif rid_s in seen_ids:
                    errors.append(f"{where}: duplicate id {rid_s!r}")
                else:
                    seen_ids.add(rid_s)
                rule["id"] = rid_s
            else:
                pending_auto.append((prefix, rule))

            if "paths" in allowed:
                raw_paths = item.get("paths")
                paths: list[str] = []
                if raw_paths is None:
                    raw_paths = []
                if not isinstance(raw_paths, list):
                    errors.append(f"{where}: paths must be a list of globs")
                    raw_paths = []
                for rp in raw_paths:
                    g, err = normalize_glob(rp)
                    if err:
                        errors.append(f"{where}: {err}")
                    elif g not in paths:
                        paths.append(g)
                if need_paths and not paths:
                    # Empty paths + "every cited path matches" would match everything.
                    errors.append(f"{where}: paths must list at least one glob")
                rule["paths"] = paths

            for text_key in ("name", "description", "reason", "note", "criteria"):
                if text_key not in allowed:
                    continue
                val = item.get(text_key)
                if val is not None and not isinstance(val, str):
                    errors.append(f"{where}: {text_key} must be a string")
                    val = ""
                rule[text_key] = str(val or "").strip()[:2000]
            if need_text and not rule.get(need_text):
                errors.append(f"{where}: {need_text} is required")
            if list_key == "trust_boundaries" and not (
                rule.get("name") or rule.get("description")
            ):
                errors.append(f"{where}: name or description is required")

            if "weakness_class" in allowed:
                wc = item.get("weakness_class")
                if wc is not None and not isinstance(wc, str):
                    errors.append(f"{where}: weakness_class must be a string")
                    wc = ""
                rule["weakness_class"] = str(wc or "*").strip().lower() or "*"

            if list_key == "severity_rubric":
                ms = item.get("max_severity")
                if ms is None or (isinstance(ms, str) and not ms.strip()):
                    rule["max_severity"] = None
                else:
                    canon = normalize_severity_claim(ms)
                    if canon is None or canon not in ALLOWED_SEVERITY_CLAIMS:
                        errors.append(
                            f"{where}: max_severity must be one of "
                            "CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL"
                        )
                        rule["max_severity"] = None
                    else:
                        rule["max_severity"] = canon
                if not rule.get("max_severity") and not rule.get("criteria"):
                    errors.append(f"{where}: max_severity or criteria is required")

            out[list_key].append(rule)

    # Auto-assign ids after explicit ones so they never collide.
    counters: dict[str, int] = {}
    for prefix, rule in pending_auto:
        n = counters.get(prefix, 0)
        while True:
            n += 1
            cand = f"{prefix}-{n}"
            if cand not in seen_ids:
                break
        counters[prefix] = n
        seen_ids.add(cand)
        rule["id"] = cand
        # keep id first for readability
        items = dict(rule)
        rule.clear()
        rule["id"] = cand
        rule.update({k: v for k, v in items.items() if k != "id"})

    return out, errors


def require_policy(raw: Any) -> dict[str, Any]:
    policy, errors = normalize_policy(raw)
    if errors:
        raise PolicyError(errors)
    return policy


def load_current(db, *, context: str = "security_policy.load") -> dict[str, Any] | None:
    """Current policy record ``{revision, policy, ...}`` from ``db``, or None when
    missing / empty. Never raises (policy is optional guidance for LLM stages)."""
    getter = getattr(db, "get_security_policy", None)
    if getter is None:
        return None
    try:
        cur = getter()
    except Exception as exc:  # noqa: BLE001
        from vulnforge.errors import note_swallowed

        note_swallowed(exc, context=context)
        return None
    if not cur or is_empty_policy(cur.get("policy")):
        return None
    return cur


def rule_ids(policy: dict | None) -> set[str]:
    out: set[str] = set()
    if not isinstance(policy, dict):
        return out
    for key in _LISTS:
        for r in policy.get(key) or []:
            if isinstance(r, dict) and r.get("id"):
                out.add(str(r["id"]))
    return out


# ---------------------------------------------------------------------------
# Matching (mechanical, demote-only)
# ---------------------------------------------------------------------------


def cited_paths(body: dict | None) -> list[str]:
    out: list[str] = []
    if not isinstance(body, dict):
        return out
    cites = body.get("citations")
    if not isinstance(cites, list):
        return out
    for c in cites:
        if not isinstance(c, dict):
            continue
        p = _resolve_relpath(str(c.get("path") or ""))
        if p and p not in out:
            out.append(p)
    return out


def _resolve_relpath(raw: str) -> str:
    """Lexically resolve ``.``/``..`` so ``lib/../vendor/a.py`` matches as
    ``vendor/a.py`` (the citation gate resolves the same way). A path that still
    escapes the root is returned with its leading ``..`` so no rule matches it."""
    p = normalize_relpath(raw)
    if not p:
        return ""
    norm = posixpath.normpath(p)
    return "" if norm == "." else norm


def _class_matches(rule: dict, body: dict) -> bool:
    wc = str(rule.get("weakness_class") or "*").strip().lower()
    if wc in ("", "*"):
        return True
    return str(body.get("weakness_class") or "").strip().lower() == wc


def _all_paths_match(globs: list[str], paths: list[str]) -> bool:
    if not globs or not paths:
        return False
    return all(any(path_matches(g, p) for g in globs) for p in paths)


def match_exclusion(
    policy: dict | None,
    body: dict | None,
    *,
    revision: int | None = None,
) -> dict[str, Any] | None:
    """Return the first exclusion / out-of-scope rule that covers **every** cited path.

    A finding with one citation inside the rule and another outside it is not
    excluded. No citations → no match (the schema gate owns that).
    """
    if not isinstance(policy, dict) or not isinstance(body, dict):
        return None
    paths = cited_paths(body)
    if not paths:
        return None
    for kind, list_key in (("excluded", "exclusions"), ("out_of_scope", "out_of_scope")):
        for rule in policy.get(list_key) or []:
            if not isinstance(rule, dict):
                continue
            if list_key == "exclusions" and not _class_matches(rule, body):
                continue
            globs = [g for g in (rule.get("paths") or []) if isinstance(g, str) and g]
            if _all_paths_match(globs, paths):
                return {
                    "kind": kind,
                    "rule_id": str(rule.get("id") or ""),
                    "reason": str(rule.get("reason") or ""),
                    "weakness_class": rule.get("weakness_class") if kind == "excluded" else None,
                    "rule_paths": list(globs),
                    "matched_paths": list(paths),
                    "policy_revision": revision,
                }
    return None


def exclusion_reason_code(match: dict) -> str:
    prefix = "policy_excluded" if match.get("kind") == "excluded" else "policy_out_of_scope"
    return f"{prefix}:{match.get('rule_id')}"


def apply_severity_rubric(
    policy: dict | None,
    body: dict,
    *,
    revision: int | None = None,
) -> tuple[dict, dict | None]:
    """Cap ``severity_claim`` by the tightest matching rubric rule (demote-only).

    Returns (new_body, record_or_None). ``record`` is what was written under
    ``body["severity_rubric"]``. An existing ``capped`` record is never replaced.
    """
    if not isinstance(policy, dict) or not isinstance(body, dict):
        return body, None
    claim = normalize_severity_claim(body.get("severity_claim"))
    if claim is None or claim not in SEVERITY_RANK:
        return body, None
    prior = body.get("severity_rubric")
    if isinstance(prior, dict) and prior.get("action") == "capped":
        return body, None
    if body.get("severity_claim_original"):
        return body, None
    paths = cited_paths(body)
    best: dict | None = None
    for rule in policy.get("severity_rubric") or []:
        if not isinstance(rule, dict):
            continue
        ms = rule.get("max_severity")
        if ms not in SEVERITY_RANK:
            continue
        if not _class_matches(rule, body):
            continue
        globs = [g for g in (rule.get("paths") or []) if isinstance(g, str) and g]
        if globs and not _all_paths_match(globs, paths):
            continue
        if best is None or SEVERITY_RANK[ms] < SEVERITY_RANK[best["max_severity"]]:
            best = rule
    if best is None:
        return body, None
    new = dict(body)
    cap = best["max_severity"]
    if SEVERITY_RANK[claim] > SEVERITY_RANK[cap]:
        new["severity_claim_original"] = claim
        new["severity_claim"] = cap
        rec = {
            "rule_id": str(best.get("id") or ""),
            "action": "capped",
            "from": claim,
            "to": cap,
            "criteria": str(best.get("criteria") or "")[:500],
            "policy_revision": revision,
        }
    else:
        rec = {
            "rule_id": str(best.get("id") or ""),
            "action": "within",
            "max_severity": cap,
            "policy_revision": revision,
        }
    new["severity_rubric"] = rec
    return new, rec


# ---------------------------------------------------------------------------
# Packet text (guidance for LLM stages)
# ---------------------------------------------------------------------------

_FRAMING = {
    "recon": (
        "Operator-declared ground truth. Listed trust boundaries and attacker-controlled "
        "sources override conflicting inferences in your map. Anything not listed is "
        "**not** implied trusted. Keep mapping excluded / out-of-scope areas normally; "
        "the harness applies exclusions to findings later and records each match."
    ),
    "hunt": (
        "Operator-declared. Treat listed trust boundaries and attacker-controlled sources "
        "as facts that override conflicting architecture entries; anything not listed is "
        "**not** implied trusted. Exclusions and out-of-scope rules are applied by the "
        "harness after you submit and the match is recorded in the report — do not skip "
        "submit_candidate because a rule might match. Grade severity_claim against the "
        "severity rubric."
    ),
    "disprove": (
        "Operator-declared. Listed trust boundaries and attacker-controlled sources are "
        "facts; anything not listed is not implied trusted. A policy rule can support "
        "`reject` or `needs_human`, never `stand`. If a rule decides your verdict, add a "
        "line `POLICY_RULE=<id>` (for a path rule, only when every cited path falls under "
        "that rule). Flag severity_claim above the rubric cap as overclaim."
    ),
}


def _fmt_paths(paths: list[str]) -> str:
    return ", ".join(f"`{p}`" for p in paths) if paths else "(any path)"


def format_policy_for_packet(
    policy: dict | None,
    *,
    stage: str = "hunt",
    revision: int | None = None,
    path_hints: list | None = None,
    max_chars: int = 1800,
) -> str:
    """Markdown block for a packet, or "" when the policy is empty.

    With ``path_hints`` (hunt), path rules are sliced to those overlapping the
    hints; rules without paths and the rubric are always kept.
    """
    if is_empty_policy(policy):
        return ""
    assert isinstance(policy, dict)
    hints = [str(h) for h in (path_hints or []) if str(h or "").strip()]

    def keep(rule: dict) -> bool:
        globs = rule.get("paths") or []
        if not hints or not globs:
            return True
        return any(glob_overlaps_hint(g, h) for g in globs for h in hints)

    rev = f" rev {revision}" if revision is not None else ""
    head = (
        f"\n## Operator security policy ({stage}{rev}"
        + (", area slice" if hints else "")
        + ")\n"
        + _FRAMING.get(stage, _FRAMING["hunt"])
        + "\n"
    )
    lines: list[str] = []
    notes = str(policy.get("notes") or "").strip()
    if notes:
        lines.append("Notes: " + notes[:600] + ("…" if len(notes) > 600 else ""))

    def section(title: str, key: str, fmt) -> None:
        rows = [r for r in policy.get(key) or [] if isinstance(r, dict) and keep(r)]
        if not rows:
            return
        lines.append(f"{title}:")
        for r in rows:
            lines.append(f"- [{r.get('id')}] " + fmt(r))

    section(
        "Trust boundaries",
        "trust_boundaries",
        lambda r: " — ".join(x for x in (r.get("name"), r.get("description")) if x)
        + f" paths={_fmt_paths(r.get('paths') or [])}",
    )
    section(
        "Attacker-controlled sources",
        "attacker_controlled",
        lambda r: f"{r.get('description')} paths={_fmt_paths(r.get('paths') or [])}",
    )
    section(
        "Trusted inputs (operator-declared)",
        "trusted_inputs",
        lambda r: f"{r.get('description')} paths={_fmt_paths(r.get('paths') or [])}",
    )
    section(
        "In scope (focus guidance; not a gate)",
        "in_scope",
        lambda r: _fmt_paths(r.get("paths") or [])
        + (f" — {r.get('note')}" if r.get("note") else ""),
    )
    section(
        "Out of scope (harness rejects when every cited path matches)",
        "out_of_scope",
        lambda r: f"{_fmt_paths(r.get('paths') or [])} — {r.get('reason')}",
    )
    section(
        "Exclusions (harness rejects when class matches and every cited path matches)",
        "exclusions",
        lambda r: f"class={r.get('weakness_class') or '*'} "
        f"{_fmt_paths(r.get('paths') or [])} — {r.get('reason')}",
    )
    rubric = [r for r in policy.get("severity_rubric") or [] if isinstance(r, dict)]
    if rubric:
        lines.append("Severity rubric (harness caps severity_claim at max_severity):")
        for r in rubric:
            bits = []
            if r.get("max_severity"):
                bits.append(f"max={r['max_severity']}")
            bits.append(f"class={r.get('weakness_class') or '*'}")
            bits.append(f"paths={_fmt_paths(r.get('paths') or [])}")
            if r.get("criteria"):
                bits.append(f"— {r['criteria']}")
            lines.append(f"- [{r.get('id')}] " + " ".join(bits))

    body = "\n".join(lines)
    suffix = "\n…[policy truncated; full policy on run]"
    budget = max(200, int(max_chars) - len(head) - 1)  # trailing newline
    if len(body) > budget:
        body = body[: max(0, budget - len(suffix))].rstrip() + suffix
    return head + body + "\n"


_POLICY_RULE_RE = re.compile(r"POLICY_RULE\s*=\s*([A-Za-z0-9][A-Za-z0-9_.-]{0,63})")


def parse_policy_citations(content: str | None, policy: dict | None) -> list[str]:
    """Rule ids a disprover cited via ``POLICY_RULE=<id>`` that exist in the policy."""
    known = rule_ids(policy)
    if not known or not content:
        return []
    out: list[str] = []
    for m in _POLICY_RULE_RE.finditer(str(content)):
        rid = m.group(1).rstrip(".")
        if rid in known and rid not in out:
            out.append(rid)
    return out


# ---------------------------------------------------------------------------
# Seeding from the target's SECURITY.md (read-only; never saved automatically)
# ---------------------------------------------------------------------------

_SECURITY_MD_CANDIDATES = (
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
    "security.md",
)


def draft_from_security_md(target_path: str | Path) -> dict[str, Any] | None:
    """Draft policy with ``notes`` from the target's SECURITY.md, or None.

    Only prose is copied; no mechanical rules are invented. The caller must save
    the draft explicitly.
    """
    target = Path(target_path)
    root = target if target.is_dir() else target.parent
    try:
        root_r = root.resolve()
    except OSError:
        return None
    for rel in _SECURITY_MD_CANDIDATES:
        p = root / rel
        try:
            rp = p.resolve()
            rp.relative_to(root_r)
        except (OSError, ValueError):
            continue
        if not rp.is_file():
            continue
        try:
            text = rp.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if not text:
            continue
        if len(text) > MAX_NOTES_CHARS:
            text = text[: MAX_NOTES_CHARS - 40].rstrip() + "\n…[SECURITY.md truncated]"
        policy = empty_policy()
        policy["notes"] = text
        return {"policy": policy, "source_path": rel}
    return None

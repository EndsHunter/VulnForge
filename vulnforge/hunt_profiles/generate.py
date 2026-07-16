"""LLM-backed generation of custom hunt skill profiles."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

from vulnforge.hunt_profiles.store import (
    MAX_BODY_BYTES,
    PROFILE_ID_RE,
    HuntProfileError,
    all_class_ids,
    save_profile,
)
from vulnforge.llm import make_client

# Cloudflare-style section detection (seed + generated skills).
# Mission: **Mission:** or ## Mission
_MISSION_RE = re.compile(r"(?im)(\*\*mission\b|##\s*mission\b)")
# Principles: Cloudflare bar (acceptable alternative to Mission)
_PRINCIPLES_RE = re.compile(r"(?im)##\s*principles\b")
# Method, Hunt workflow, or Workflow
_METHOD_RE = re.compile(r"(?im)##\s*(method|hunt\s+workflow|workflow)\b")
# Rules quick reference (Cloudflare tables) — recommended in author template
_RULES_RE = re.compile(r"(?im)##\s*rules(\s+quick\s+reference)?\b")
# Anti-patterns
_ANTI_RE = re.compile(r"(?im)##\s*anti-?patterns?\b")
# Submit / Submit checklist
_SUBMIT_RE = re.compile(r"(?im)##\s*submit(\s+checklist)?\b")
# Markdown table row (Rules / Anti-patterns tables)
_TABLE_ROW_RE = re.compile(r"(?m)^\s*\|.+\|\s*$")
_SLUG_RE = re.compile(r"[^a-z0-9-]+")


class GenerateSkillError(ValueError):
    """LLM output or validation failed for skill generation."""


def slugify_profile_id(raw: str, *, fallback: str = "custom-hunt") -> str:
    """Normalize free text into a PROFILE_ID_RE-compatible slug."""
    s = str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")
    s = _SLUG_RE.sub("-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    if not s:
        s = fallback
    if not s[0].isalpha():
        s = f"hunt-{s}"
    s = s[:64].rstrip("-")
    if not PROFILE_ID_RE.match(s):
        s = fallback if PROFILE_ID_RE.match(fallback) else "custom-hunt"
    return s


def allocate_free_id(preferred: str) -> str:
    """Return preferred id or preferred-2 / -3 / short-hash if taken."""
    base = slugify_profile_id(preferred)
    try:
        existing = set(all_class_ids())
    except HuntProfileError:
        existing = set()
    if base not in existing:
        return base
    for n in range(2, 100):
        suffix = f"-{n}"
        # Keep under 64 chars total for PROFILE_ID_RE
        stem = base[: max(1, 64 - len(suffix))].rstrip("-")
        cand = f"{stem}{suffix}"
        if PROFILE_ID_RE.match(cand) and cand not in existing:
            return cand
    h = hashlib.sha256(base.encode("utf-8")).hexdigest()[:6]
    suffix = f"-{h}"
    stem = base[: max(1, 64 - len(suffix))].rstrip("-")
    cand = f"{stem}{suffix}"
    if PROFILE_ID_RE.match(cand) and cand not in existing:
        return cand
    # Last resort: pure hash slug
    for i in range(16):
        cand = f"gen-{hashlib.sha256(f'{base}:{i}'.encode()).hexdigest()[:10]}"
        if cand not in existing:
            return cand
    raise GenerateSkillError("could not allocate a free profile id")


def required_sections_missing(body_md: str) -> list[str]:
    """Return names of required Cloudflare-style sections missing from body_md.

    Required (aligned with prompts/v1/generate_skill.md):
      Mission **or** Principles,
      Method | Hunt workflow | Workflow,
      Anti-patterns,
      Submit | Submit checklist.

    Strongly expected for Cloudflare bar (also enforced for generated skills):
      Rules quick reference, and at least one markdown table row (Rules/Anti-patterns).
    """
    text = body_md or ""
    missing: list[str] = []
    if not (_MISSION_RE.search(text) or _PRINCIPLES_RE.search(text)):
        missing.append("Mission or Principles")
    if not _METHOD_RE.search(text):
        missing.append("Method or Hunt workflow")
    if not _ANTI_RE.search(text):
        missing.append("Anti-patterns")
    if not _SUBMIT_RE.search(text):
        missing.append("Submit")
    # Cloudflare bar: Rules table + any table syntax in body
    if not _RULES_RE.search(text):
        missing.append("Rules")
    if text and not _TABLE_ROW_RE.search(text):
        missing.append("Tables")
    return missing


def validate_skill_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize LLM skill JSON into the return shape."""
    if not isinstance(data, dict):
        raise GenerateSkillError("skill payload must be an object")

    body_md = data.get("body_md")
    if body_md is None or not str(body_md).strip():
        raise GenerateSkillError("body_md is required and must be non-empty")
    body_md = str(body_md)
    if len(body_md.encode("utf-8")) > MAX_BODY_BYTES:
        raise GenerateSkillError(f"body_md exceeds {MAX_BODY_BYTES} bytes")

    missing = required_sections_missing(body_md)
    if missing:
        raise GenerateSkillError(
            "body_md missing required sections: " + ", ".join(missing)
        )

    raw_id = data.get("id") or data.get("profile_id") or ""
    if not str(raw_id).strip():
        # try title line from body
        for line in body_md.splitlines()[:5]:
            s = line.strip()
            if s.lower().startswith("#"):
                t = s.lstrip("#").strip()
                if ":" in t:
                    t = t.split(":", 1)[1].strip()
                raw_id = t
                break
    if not str(raw_id).strip():
        raw_id = "custom-hunt"

    pid = slugify_profile_id(str(raw_id))
    if not PROFILE_ID_RE.match(pid):
        raise GenerateSkillError(f"invalid profile id after slugify: {raw_id!r}")

    title = str(data.get("title") or "").strip()
    if not title:
        for line in body_md.splitlines():
            s = line.strip()
            if s.startswith("#"):
                t = s.lstrip("#").strip()
                if ":" in t:
                    t = t.split(":", 1)[1].strip() or t
                title = t[:120]
                break
        title = title or pid.replace("-", " ").title()

    description = str(data.get("description") or "").strip()[:500]

    def _str_list(key: str, *, cap: int = 24) -> list[str]:
        raw = data.get(key)
        if raw is None:
            return []
        if isinstance(raw, str):
            raw = [raw]
        if not isinstance(raw, list):
            return []
        out: list[str] = []
        for x in raw[:cap]:
            s = str(x).strip()
            if s:
                out.append(s[:80])
        return out

    def _int_list(key: str, *, cap: int = 12) -> list[int]:
        raw = data.get(key)
        if raw is None:
            return []
        if isinstance(raw, (int, float)):
            raw = [raw]
        if isinstance(raw, str):
            raw = [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]
        if not isinstance(raw, list):
            return []
        out: list[int] = []
        seen: set[int] = set()
        for x in raw[:cap]:
            try:
                n = int(x)
            except (TypeError, ValueError):
                continue
            if 1 <= n <= 12 and n not in seen:
                seen.add(n)
                out.append(n)
        return out

    return {
        "id": pid,
        "title": title[:120],
        "description": description,
        "body_md": body_md,
        "tags": _str_list("tags"),
        "cwe": _str_list("cwe"),
        "angle_ids": _int_list("angle_ids"),
        "sink_families": _str_list("sink_families"),
    }


def _strip_json_fences(text: str) -> str:
    text = str(text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _parse_json_object(content: Optional[str]) -> dict[str, Any]:
    if not content or not str(content).strip():
        raise GenerateSkillError("empty LLM response")
    text = _strip_json_fences(content)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            raise GenerateSkillError("LLM response is not valid JSON") from None
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError as e:
            raise GenerateSkillError(f"LLM JSON parse failed: {e}") from e
    if not isinstance(data, dict):
        raise GenerateSkillError("LLM JSON root must be an object")
    return data


def parse_skill_response(content: Optional[str]) -> dict[str, Any]:
    """Parse model content (JSON, optionally fenced) into a validated skill dict."""
    data = _parse_json_object(content)
    # Batch envelope with a single skill
    if "body_md" not in data and isinstance(data.get("skills"), list) and data["skills"]:
        first = data["skills"][0]
        if isinstance(first, dict):
            data = first
    skill = validate_skill_payload(data)
    skill["id"] = allocate_free_id(skill["id"])
    return skill


def parse_skills_response(content: Optional[str], *, count: int) -> list[dict[str, Any]]:
    """Parse multi-skill JSON into up to ``count`` validated skill dicts."""
    n = clamp_skill_count(count)
    data = _parse_json_object(content)
    raw_list: list[Any]
    if isinstance(data.get("skills"), list):
        raw_list = data["skills"]
    elif data.get("body_md") is not None:
        raw_list = [data]
    else:
        raise GenerateSkillError("expected skills array or a single skill object")

    out: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for item in raw_list:
        if len(out) >= n:
            break
        if not isinstance(item, dict):
            continue
        try:
            skill = validate_skill_payload(item)
        except GenerateSkillError:
            continue
        # Prefer uniqueness within this batch before allocate_free_id
        base = skill["id"]
        if base in seen_ids:
            skill["id"] = allocate_free_id(f"{base}-x")
        else:
            skill["id"] = allocate_free_id(base)
        seen_ids.add(skill["id"])
        out.append(skill)
    if not out:
        raise GenerateSkillError("no valid skills in LLM response")
    return out


def _load_author_prompt() -> str:
    """Operator override (config/prompts/) then package seed, then fallback."""
    from vulnforge.hunt_profiles.author_prompt import load_author_prompt

    return load_author_prompt()


def _signals_json(signals: Any, *, max_chars: int = 6000) -> Optional[str]:
    if signals is None:
        return None
    try:
        sig_txt = json.dumps(signals, indent=2, default=str)
    except (TypeError, ValueError):
        sig_txt = str(signals)
    if len(sig_txt) > max_chars:
        sig_txt = sig_txt[: max_chars - 40] + "\n...[signals truncated]...\n"
    return sig_txt


def _build_user_message(
    brief: str,
    *,
    signals: Any = None,
    suggested_id: Optional[str] = None,
) -> str:
    parts = [
        "Generate a custom hunt skill for this operator brief.",
        "",
        "## Operator brief",
        str(brief).strip(),
        "",
    ]
    if suggested_id and str(suggested_id).strip():
        parts.extend(
            [
                f"## Suggested id",
                slugify_profile_id(str(suggested_id)),
                "(Use this id if it fits; still return a valid slug.)",
                "",
            ]
        )
    sig_txt = _signals_json(signals)
    if sig_txt is not None:
        parts.extend(["## Signals / context", "```json", sig_txt, "```", ""])
    parts.extend(
        [
            "Return JSON only with id, title, description, body_md.",
            "body_md MUST use the Cloudflare-style template from the system prompt:",
            "Principles, Mission, Rules quick reference table, Hunt workflow/Method,",
            "Anti-patterns table, Submit checklist — plus at least one markdown table.",
        ]
    )
    return "\n".join(parts)


def _build_batch_user_message(
    *,
    count: int,
    architecture: Any = None,
    signals: Any = None,
    operator_brief: str = "",
    existing_class_ids: Optional[list[str]] = None,
) -> str:
    n = clamp_skill_count(count)
    parts = [
        f"Produce exactly {n} distinct custom hunt skills tailored to this target.",
        "Each skill must be a focused hunt class (not a generic restatement of stock classes).",
        "Prefer stack-specific or surface-specific ids (e.g. jwt-kid-injection, graphql-batch-authz).",
        "",
        f"## Required count: {n}",
        "",
    ]
    brief = str(operator_brief or "").strip()
    if brief:
        parts.extend(["## Operator brief", brief[:4000], ""])
    if architecture is not None:
        try:
            arch_txt = json.dumps(architecture, indent=2, default=str)
        except (TypeError, ValueError):
            arch_txt = str(architecture)
        if len(arch_txt) > 8000:
            arch_txt = arch_txt[:7960] + "\n...[architecture truncated]...\n"
        parts.extend(["## Architecture", "```json", arch_txt, "```", ""])
    sig_txt = _signals_json(signals, max_chars=5000)
    if sig_txt is not None:
        parts.extend(["## Signals / inventory", "```json", sig_txt, "```", ""])
    if existing_class_ids:
        ids = [str(x) for x in existing_class_ids if str(x).strip()][:40]
        if ids:
            parts.extend(
                [
                    "## Existing class ids (avoid exact duplicates; specialize instead)",
                    ", ".join(ids),
                    "",
                ]
            )
    parts.extend(
        [
            "Return JSON only:",
            f'{{"skills":[{{"id","title","description","body_md",...}}, ...]}}',
            f"with length {n} (or fewer only if you cannot invent more solid angles).",
            "Each body_md MUST follow the Cloudflare-style template (Principles,",
            "Rules quick reference table, Anti-patterns table, Hunt workflow, Submit).",
        ]
    )
    return "\n".join(parts)


def clamp_skill_count(raw: Any, *, default: int = 3) -> int:
    """Normalize dynamic skill count to at least 1 (no upper cap)."""
    try:
        n = int(raw)
    except (TypeError, ValueError):
        n = default
    return max(1, n)


def generate_hunt_skill(
    cfg: dict,
    *,
    brief: str,
    signals: Any = None,
    suggested_id: Optional[str] = None,
    client: Any = None,
    run_dir: Optional[Path | str] = None,
    task_id: Optional[int] = None,
) -> dict[str, Any]:
    """
    Call the LLM to author a hunt skill; validate and resolve id collisions.

    Returns dict with keys: id, title, description, body_md, and optional
    tags, cwe, angle_ids, sink_families. May include model_id and usage fields
    when recording is available.

    Does **not** write to prompts/v1. Persistence is via save_generated_profile
    / save_profile (callers).
    """
    brief_s = str(brief or "").strip()
    if not brief_s:
        raise GenerateSkillError("brief is required")

    system = _load_author_prompt()
    user = _build_user_message(
        brief_s, signals=signals, suggested_id=suggested_id
    )

    own_client = client is None
    if client is None:
        client = make_client(cfg)

    model_id: Optional[str] = None
    usage_fields: dict[str, Any] = {}
    try:
        try:
            model_id = client.fingerprint_model()
        except Exception as e:
            raise GenerateSkillError(f"model fingerprint failed: {e}") from e

        temp = float((cfg.get("llm") or {}).get("temperature_recon", 0.3))
        result = client.chat(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            tools=None,
            temperature=temp,
        )

        if run_dir is not None:
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
                usage_fields = record_llm_result(
                    run_dir,
                    task_id=task_id,
                    kind="generate_skill",
                    model_id=model_id or getattr(result, "model_id", None),
                    result=result,
                )
            except Exception:
                usage_fields = {}

        if not result.ok:
            err = result.error or (
                result.classification.value
                if getattr(result, "classification", None)
                else "llm_failed"
            )
            raise GenerateSkillError(f"LLM failed: {err}")

        skill = parse_skill_response(result.content)
        skill["model_id"] = model_id or getattr(result, "model_id", None)
        if usage_fields:
            skill["usage"] = usage_fields
        return skill
    finally:
        if own_client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass


def generate_hunt_skills_batch(
    cfg: dict,
    *,
    count: int,
    architecture: Any = None,
    signals: Any = None,
    operator_brief: str = "",
    existing_class_ids: Optional[list[str]] = None,
    client: Any = None,
    run_dir: Optional[Path | str] = None,
    task_id: Optional[int] = None,
) -> list[dict[str, Any]]:
    """
    Author up to ``count`` hunt skills from architecture/signals in one LLM call.

    On multi-skill parse failure, falls back to sequential single-skill calls
    using architecture-derived briefs.
    """
    n = clamp_skill_count(count)
    system = _load_author_prompt()
    user = _build_batch_user_message(
        count=n,
        architecture=architecture,
        signals=signals,
        operator_brief=operator_brief,
        existing_class_ids=existing_class_ids,
    )

    own_client = client is None
    if client is None:
        client = make_client(cfg)

    model_id: Optional[str] = None
    try:
        try:
            model_id = client.fingerprint_model()
        except Exception as e:
            raise GenerateSkillError(f"model fingerprint failed: {e}") from e

        temp = float((cfg.get("llm") or {}).get("temperature_recon", 0.3))
        result = client.chat(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            tools=None,
            temperature=temp,
        )

        if run_dir is not None:
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
                    task_id=task_id,
                    kind="generate_run_skills",
                    model_id=model_id or getattr(result, "model_id", None),
                    result=result,
                )
            except Exception:
                pass

        if result.ok:
            try:
                skills = parse_skills_response(result.content, count=n)
                for s in skills:
                    s["model_id"] = model_id or getattr(result, "model_id", None)
                return skills
            except GenerateSkillError:
                pass  # sequential fallback below
        # Fallback path: sequential single skills
        return _sequential_skills_from_arch(
            cfg,
            count=n,
            architecture=architecture,
            signals=signals,
            operator_brief=operator_brief,
            client=client,
            run_dir=run_dir,
            task_id=task_id,
            model_id=model_id,
        )
    finally:
        if own_client and hasattr(client, "close"):
            try:
                client.close()
            except Exception:
                pass


def _brief_slices_from_architecture(
    architecture: Any,
    *,
    count: int,
    operator_brief: str = "",
) -> list[str]:
    """Build N short operator briefs from architecture for sequential fallback."""
    n = clamp_skill_count(count)
    arch = architecture if isinstance(architecture, dict) else {}
    summary = str(arch.get("summary") or "").strip()
    foci = arch.get("hunt_focus") if isinstance(arch.get("hunt_focus"), list) else []
    surfaces = (
        arch.get("input_surfaces")
        if isinstance(arch.get("input_surfaces"), list)
        else []
    )
    components = (
        arch.get("components") if isinstance(arch.get("components"), list) else []
    )
    op = str(operator_brief or "").strip()
    seeds: list[str] = []
    for f in foci:
        if isinstance(f, dict):
            seeds.append(
                f"Hunt class for area={f.get('area')!r} class-hint={f.get('class')!r} "
                f"paths={f.get('path_hints')!r}. Architecture: {summary[:800]}"
            )
        elif f is not None:
            seeds.append(f"Hunt angle: {f}. Architecture: {summary[:800]}")
    for s in surfaces:
        if isinstance(s, dict):
            seeds.append(
                f"Threats on input surface {json.dumps(s, default=str)[:400]}. "
                f"{summary[:600]}"
            )
        else:
            seeds.append(f"Threats on surface {s!r}. {summary[:600]}")
    for c in components:
        if isinstance(c, dict):
            seeds.append(
                f"Hunt skill for component {json.dumps(c, default=str)[:400]}. "
                f"{summary[:600]}"
            )
        else:
            seeds.append(f"Hunt skill for component {c!r}. {summary[:600]}")
    if not seeds and summary:
        seeds = [
            f"Custom hunt skill #{i + 1} for this project. {summary[:1200]}"
            for i in range(n)
        ]
    if not seeds:
        base = op or "Author a focused custom hunt class for this codebase."
        seeds = [f"{base} (variant {i + 1})" for i in range(n)]
    # Pad / trim
    while len(seeds) < n:
        seeds.append(
            f"Additional specialized hunt skill #{len(seeds) + 1}. "
            f"{summary[:800] or op or 'residual trust edges'}"
        )
    if op:
        seeds = [f"{s}\n\nOperator notes: {op[:500]}" for s in seeds[:n]]
    return seeds[:n]


def _sequential_skills_from_arch(
    cfg: dict,
    *,
    count: int,
    architecture: Any = None,
    signals: Any = None,
    operator_brief: str = "",
    client: Any = None,
    run_dir: Optional[Path | str] = None,
    task_id: Optional[int] = None,
    model_id: Optional[str] = None,
) -> list[dict[str, Any]]:
    briefs = _brief_slices_from_architecture(
        architecture, count=count, operator_brief=operator_brief
    )
    out: list[dict[str, Any]] = []
    for brief in briefs:
        try:
            skill = generate_hunt_skill(
                cfg,
                brief=brief,
                signals=signals,
                client=client,
                run_dir=run_dir,
                task_id=task_id,
            )
            if model_id and not skill.get("model_id"):
                skill["model_id"] = model_id
            out.append(skill)
        except GenerateSkillError:
            continue
    if not out:
        raise GenerateSkillError("batch and sequential skill generation both failed")
    return out


def origin_from_run_dir(
    run_dir: Optional[Path | str],
) -> tuple[Optional[str], Optional[str]]:
    """
    Parse ``.../runs/{target_id}/{run_id}`` into origin provenance.

    Returns ``(origin_target_id, origin_run_id)`` or ``(None, None)`` when the
    path does not look like a VulnForge run directory.
    """
    if run_dir is None:
        return None, None
    try:
        parts = Path(run_dir).resolve().parts
    except (OSError, RuntimeError, ValueError, TypeError):
        try:
            parts = Path(str(run_dir)).parts
        except (TypeError, ValueError):
            return None, None
    if len(parts) < 2:
        return None, None

    # Prefer explicit .../runs/{target_id}/{run_id}/...
    for i, part in enumerate(parts):
        if part == "runs" and i + 2 < len(parts):
            target_id = str(parts[i + 1]).strip()
            run_id = str(parts[i + 2]).strip()
            if (
                target_id
                and run_id
                and target_id not in (".", "..")
                and run_id not in (".", "..")
            ):
                return target_id, run_id

    # Fallback: last two components when they resemble target/run
    target_id = str(parts[-2]).strip()
    run_id = str(parts[-1]).strip()
    if (
        target_id
        and run_id
        and target_id not in (".", "..")
        and run_id not in (".", "..")
        and re.match(r"^run-\d+", run_id, re.I)
    ):
        return target_id, run_id
    return None, None


def save_generated_profile(
    skill: dict[str, Any],
    *,
    active: bool = False,
    origin_target_id: Optional[str] = None,
    origin_run_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Persist a generated skill via save_profile.

    source=\"generated\", active=False by default. Never writes package prompts.
    Optional origin_* stamps which run authored the skill.
    """
    pid = skill.get("id")
    body = skill.get("body_md")
    if not pid or body is None:
        raise GenerateSkillError("skill missing id or body_md")
    # Re-resolve if collection changed since generate
    free = allocate_free_id(str(pid))
    if free != pid:
        skill = dict(skill)
        skill["id"] = free
        pid = free
    kwargs: dict[str, Any] = {
        "body_md": str(body),
        "title": skill.get("title"),
        "description": skill.get("description"),
        "active": bool(active),
        "source": "generated",
        "tags": skill.get("tags"),
        "cwe": skill.get("cwe"),
        "angle_ids": skill.get("angle_ids"),
        "sink_families": skill.get("sink_families"),
        "create": True,
    }
    if origin_target_id is not None:
        kwargs["origin_target_id"] = origin_target_id
    if origin_run_id is not None:
        kwargs["origin_run_id"] = origin_run_id
    return save_profile(pid, **kwargs)

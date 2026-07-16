---
name: drone-py
description: >
  Use when hunting a single file that appears empty, contains only stubs/placeholders,
  or is explicitly documented as part of an uninitialized/empty repository. Also when
  the operator needs to verify no hidden functionality, dynamic imports, or side-effect
  loading exists in a minimal codebase. Prefer this skill when the architecture context
  confirms zero functional code, sinks, or trust boundaries. Do not use when the file
  contains actual implementation, data handling, network calls, or user input processing.
---

# Hunt class: drone-py

## Mission

Verify whether `drone.py` is a true empty/stub or contains hidden functionality; if truly empty, submit `none` — there is no vulnerability to find.

## Principles

- **Verify emptiness.** Check for hidden content, comments that imply logic, or imports that load external code.
- **One concrete check.** Confirm line count and content type (empty vs stub).
- **Honest none.** If truly empty, submit `none` — there is no vulnerability to find.
- **Respect scope.** Do not expand into unrelated modules unless explicitly required for minimal context.

## When to use

- Single-file repositories with 0 lines or placeholder content.
- Architecture context explicitly states "no code to analyze" or "empty Python repository".
- Operator needs to confirm absence of sinks/surfaces before proceeding.

## When not to use

- Files containing actual implementation, sinks, or trust boundaries.
- Multi-file repositories where functionality exists elsewhere.
- When the file contains user input, network calls, or data processing.

## Rules quick reference

| Rule | Summary |
|------|---------|
| Check line count. | Confirm file is exactly 0 lines or contains only whitespace/comments. |
| Check imports. | Ensure no dynamic imports, `importlib`, or side-effect loading exists. |
| No sinks. | If empty, no sinks exist; do not fabricate a vulnerability. |
| Respect scope. | Do not expand into unrelated modules except for minimal context. |

## Focus

- Empty/stub file verification.
- Absence of sinks, surfaces, and trust edges.
- Confirmation of placeholder status.

## Hunt workflow

1. Inventory `drone.py` — check line count and raw content.
2. Walk for hidden logic — look for comments, placeholders, or dynamic loading.
3. Prove emptiness — confirm no sinks, surfaces, or trust edges exist.
4. Submit `none` — if truly empty, submit `none` with evidence of emptiness.

## Stack cues

    0 lines|placeholder|# stub|empty file|no code

## Required evidence

- File content (showing empty or stub state).
- Line count confirmation.
- Absence of sinks/surfaces documentation.

## False positives

- Fabricating a vulnerability in an empty file (vacuous LOW / rejected_mech).
- Expanding scope to unrelated modules without justification.
- Assuming hidden functionality without evidence.

## Anti-patterns

| Anti-pattern | Why it matters |
|--------------|----------------|
| Fabricating a vulnerability in an empty file | Vacuous LOW / rejected_mech — no code means no exploit path. |
| Expanding into unrelated modules | Scope violation — brief restricts to `drone.py` only. |
| Skipping emptiness verification | Wastes hunter effort on non-existent attack surfaces. |

## Scope

This skill covers empty/stub file verification for single-file repositories. Related registered classes (do not invent ids):

- **`injection`** — when actual input processing exists.
- **`access-control`** — when authentication/authorization code is present.
- Prefer `submit_none` over dual-filing the same path+sink.

## Submit checklist

1. write_evidence: Show file content (empty or stub) and line count.
2. submit_candidate with weakness_class: `drone-py`, threat_model, citations (or submit `none`).
3. Good: Concrete evidence of emptiness.
4. Bad: Fabricated vulnerability in empty file.
5. Or honest submit_none after real work.
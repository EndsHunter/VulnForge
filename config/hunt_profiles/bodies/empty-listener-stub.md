---
name: empty-listener-stub
description: Audits empty files named like network listeners to ensure they aren't being dynamically loaded or executed in deployment.
---

# Hunt class: empty-listener-stub

## Mission

Verify that files named like network listeners (e.g., `HttpListener.py`, `Server.py`) which contain zero lines of code are not being dynamically loaded, imported, or executed by deployment scripts, preventing false confidence in security posture.

## When to use

- You encounter a file named `*Listener.py`, `*Server.py`, or `*Handler.py` that is 0 lines.
- The repository appears to be a stub or placeholder.
- You suspect deployment might execute these files via `python -m` or dynamic imports.

## When not to use

- The file contains functional code (use other classes).
- The file is clearly a macOS metadata artifact (`.DS_Store`).
- There is no network-facing intent in the filename.

## Decision tree

1. Identify files matching `*Listener.py` or `*Server.py`.
2. Check line count. If > 0, skip (use other classes).
3. If 0 lines, check if the file is imported by any other module.
4. If not imported and no framework/manifest exists, verify deployment scripts don't reference it.
5. If safe → submit_none. If found executing → file finding.

## Focus

- Empty Python files with network-related names.
- Dynamic import mechanisms (`importlib`).
- Deployment scripts (Dockerfiles, shell scripts) that might execute empty stubs.

## Method

1. **Inventory:** List all `.py` files. Filter for names containing `Listener`, `Server`, `Handler`.
2. **Check Content:** Read each candidate. If 0 lines, flag as "Empty Stub".
3. **Trace Imports:** Search for `import` or `from ... import` statements referencing the empty stub.
4. **Check Deployment:** Look for Dockerfiles, `docker-compose.yml`, or shell scripts that might run the file (e.g., `python HttpListener.py`).
5. **Submit:** If no execution path found, submit_none with note on stub existence.

## Stack cues

    Listener\.py$
    Server\.py$
    importlib
    docker-compose\.yml

## Required evidence

- File path of the empty stub.
- Proof that it is not imported or executed (or proof that it is).

## False positives

- Files intentionally left empty as placeholders (common in scaffolding).
- `.DS_Store` files (ignore these).

## Anti-patterns

- Do not flag functional listeners as "empty".
- Do not assume empty files are safe without checking deployment scripts.

## Submit checklist

1. write_evidence: Cite the empty file path and confirm 0 lines.
2. submit_candidate with weakness_class: `empty-listener-stub`, threat_model, citations.
3. Good: Concrete proof of execution or safe confirmation via deployment audit.
4. Bad: Vague claim about "potential" risk without evidence.
5. Or honest submit_none after verifying no execution path exists.
"""Bench-side finding, mech, and disprove adapters.

These checks score model output. They do not call harness stages.
"""

from __future__ import annotations

import json
from pathlib import Path

STAGES = ("hunt_raw", "mech_formed", "mech_reproduced", "disprove")
KILL = {"kill", "reject"}
SURVIVE = {"survive", "keep"}
POC_PREFIXES = ("poc/", "exploit/", "harness/")


def stable_key(finding: dict) -> str:
    cwe = str(finding.get("cwe") or "").upper()
    return "|".join(
        [
            str(finding.get("path") or ""),
            str(finding.get("line") or ""),
            str(finding.get("symbol") or ""),
            cwe,
        ]
    )


def normalize_finding(raw: dict) -> dict:
    path = str(raw.get("path") or "").replace("\\", "/").lstrip("./")
    line = raw.get("line")
    try:
        line_no = int(line)
    except (TypeError, ValueError):
        line_no = None
    confidence = raw.get("confidence", 0)
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        conf = 0.0
    contract = raw.get("path_contract")
    if not isinstance(contract, list):
        contract = []
    return {
        "path": path,
        "line": line_no,
        "symbol": str(raw.get("symbol") or ""),
        "cwe": str(raw.get("cwe") or ""),
        "confidence": conf,
        "evidence": str(raw.get("evidence") or ""),
        "path_contract": [str(hop) for hop in contract],
        "severity": str(raw.get("severity") or ""),
    }


def read_tree_file(root: Path, rel: str) -> str | None:
    if not rel or rel.startswith("/") or ".." in Path(rel).parts:
        return None
    path = (root / rel).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return None
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def apply_mech(finding: dict, root: Path, oracle: dict | None) -> dict:
    text = read_tree_file(root, finding["path"])
    lines = text.splitlines() if text is not None else []
    line_no = finding["line"]
    quote = finding["evidence"]
    reasons: list[str] = []
    formed = True
    if text is None:
        formed = False
        reasons.append("missing-file")
    elif not isinstance(line_no, int) or line_no < 1 or line_no > len(lines):
        formed = False
        reasons.append("bad-line")
    elif len(quote) < 8 or quote not in text:
        formed = False
        reasons.append("quote-not-in-file")
    elif quote not in lines[line_no - 1]:
        formed = False
        reasons.append("quote-not-on-line")

    poc_signal = finding["path"].startswith(POC_PREFIXES)
    contract = finding["path_contract"]
    path_contract_valid = bool(
        contract
        and text is not None
        and all(hop and hop in text for hop in contract)
    )
    oracle_hit = False
    if oracle and text is not None and quote:
        oracle_hit = (
            finding["path"] == oracle["path"]
            and line_no == oracle["line"]
            and oracle["quote"] in quote
            and oracle["quote"] in text
        )
    cwe = (finding.get("cwe") or "").upper()
    oracle_cwe = (oracle or {}).get("cwe", "")
    cwe_ok = (not cwe) or (not oracle_cwe) or cwe == oracle_cwe.upper()
    contract_ok = bool(contract) and bool(oracle) and contract[-1] == oracle["symbol"]
    reproduced = bool(
        formed and oracle_hit and contract_ok and cwe_ok and not poc_signal
    )
    if formed and not reproduced:
        reasons.append("not-reproduced")
    return {
        "formed": formed,
        "reproduced": reproduced,
        "oracle_hit": oracle_hit,
        "poc_signal": poc_signal,
        "path_contract_valid": path_contract_valid,
        "reasons": reasons,
    }


def parse_disprove(payload: dict | None) -> str:
    """Errors, timeouts, and unparsed verdicts are inconclusive, never survive."""
    if not payload:
        return "inconclusive"
    if payload.get("error") or payload.get("timed_out"):
        return "inconclusive"
    text = str(payload.get("verdict_text") or "").strip()
    if not text:
        return "inconclusive"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "inconclusive"
    if not isinstance(data, dict):
        return "inconclusive"
    verdict = str(data.get("verdict") or "").strip().lower()
    if verdict in KILL:
        return "kill"
    if verdict in SURVIVE:
        return "survive"
    return "inconclusive"


def survives(finding: dict, stage: str) -> bool:
    if stage == "hunt_raw":
        return True
    if stage == "mech_formed":
        return bool(finding["mech"]["formed"])
    if stage == "mech_reproduced":
        return bool(finding["mech"]["reproduced"])
    if stage == "disprove":
        return bool(finding["mech"]["formed"]) and finding["verdict"] == "survive"
    raise KeyError(stage)


def annotate(raw_findings: list[dict], root: Path, oracle: dict | None) -> list[dict]:
    annotated = []
    for raw in raw_findings:
        finding = normalize_finding(raw)
        finding["stable_key"] = stable_key(finding)
        finding["mech"] = apply_mech(finding, root, oracle)
        payload = raw.get("disprove") or {}
        finding["verdict"] = parse_disprove(payload)
        finding["disprove_tokens"] = int(payload.get("tokens") or 0)
        finding["disprove_latency_s"] = float(payload.get("latency_s") or 0)
        finding["disprove_error"] = bool(payload.get("error"))
        finding["disprove_timeout"] = bool(payload.get("timed_out"))
        finding["disprove_unparsed"] = finding["verdict"] == "inconclusive" and not (
            finding["disprove_error"] or finding["disprove_timeout"]
        )
        annotated.append(finding)
    return annotated


def extract_json(text: str) -> object:
    body = text.strip()
    if body.startswith("```"):
        lines = body.splitlines()
        lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        body = "\n".join(lines).strip()
    return json.loads(body)


def parse_model_findings(text: str) -> list[dict] | None:
    try:
        data = extract_json(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict):
        findings = data.get("findings")
    elif isinstance(data, list):
        findings = data
    else:
        return None
    if not isinstance(findings, list):
        return None
    if not all(isinstance(item, dict) for item in findings):
        return None
    return findings

"""Frozen VulnGym slice: class map, oracle freeze, git checkout."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from vulnforge.eval.recall import parse_line_number
from vulnforge.paths import PROJECT_ROOT
from vulnforge.util import normalize_relpath

UPSTREAM = PROJECT_ROOT / ".audit" / "vulngym" / "upstream"
ENTRIES_JSONL = UPSTREAM / "data" / "entries.jsonl"
SLICE_PATH = PROJECT_ROOT / "fixtures" / "vulngym" / "slice.json"
TREES = PROJECT_ROOT / ".audit" / "vulngym" / "trees"

# Frozen eval set. Distinct repos, verified rows, mixed hunt classes.
SLICE_IDS = (
    "entry-00319",  # nltk unauth shutdown
    "entry-00080",  # WeKnora MCP command injection
    "entry-00310",  # fastmcp JWT audience
    "entry-00462",  # onnx path/TOCTOU write
    "entry-00114",  # typescript-sdk shared transport race
    "entry-00447",  # paperclip cross-tenant IDOR
)

LINE_SLOP = 5


def map_hunt_class(l1: str, l2: str) -> str:
    blob = f"{l1} {l2}".lower()
    checks = (
        ("bl-agent", "ai-llm"),
        ("agent能力", "ai-llm"),
        ("bl-auth-bypass", "web-protocol-auth"),
        ("bl-origin-integrity", "web-protocol-auth"),
        ("oauth", "web-protocol-auth"),
        ("jwt", "web-protocol-auth"),
        ("认证绕过", "web-protocol-auth"),
        ("bl-authz", "access-control"),
        ("bl-priv-esc", "access-control"),
        ("bl-multi-tenant", "access-control"),
        ("bl-mass-assignment", "access-control"),
        ("bl-trust-boundary", "access-control"),
        ("idor", "access-control"),
        ("权限绕过", "access-control"),
        ("授权", "access-control"),
        ("bl-workflow", "business-logic"),
        ("bl-race", "business-logic"),
        ("竞争", "business-logic"),
        ("ssrf", "feature-abuse"),
        ("xss", "client-side"),
        ("供应链", "supply-chain"),
        ("命令注入", "injection"),
        ("代码注入", "injection"),
        ("os 命令", "injection"),
        ("os命令", "injection"),
        ("路径穿越", "injection"),
        ("路径遍历", "injection"),
        ("反序列化", "injection"),
        ("模板注入", "injection"),
        ("任意模块", "injection"),
        ("toctou", "injection"),
        ("符号链接", "injection"),
        ("文件操作", "injection"),
        ("注入", "injection"),
        ("bl-insecure-default", "feature-abuse"),
    )
    for needle, cls in checks:
        if needle in blob:
            return cls
    return "wildcard"


def load_entries(path: Path | None = None) -> list[dict[str, Any]]:
    src = path or ENTRIES_JSONL
    if not src.is_file():
        raise FileNotFoundError(src)
    out = []
    for line in src.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def _loc_line(node: Any) -> int | None:
    if not isinstance(node, dict):
        return None
    return parse_line_number(node.get("line"))


def entry_to_oracle(entry: dict[str, Any]) -> dict[str, Any]:
    co = entry.get("critical_operation") if isinstance(entry.get("critical_operation"), dict) else {}
    ep = entry.get("entry_point") if isinstance(entry.get("entry_point"), dict) else {}
    co_path = normalize_relpath(str(co.get("file") or ""))
    ep_path = normalize_relpath(str(ep.get("file") or ""))
    co_line = _loc_line(co)
    cls = map_hunt_class(str(entry.get("vuln_category_l1") or ""), str(entry.get("vuln_category_l2") or ""))
    eid = str(entry.get("entry_id") or "")
    return {
        "id": eid,
        "class": cls,
        "report_id": str(entry.get("report_id") or ""),
        "project": str(entry.get("project") or ""),
        "repo_url": str(entry.get("repo_url") or ""),
        "commit": str(entry.get("commit") or ""),
        "verify": entry.get("verify"),
        "l1": entry.get("vuln_category_l1"),
        "l2": entry.get("vuln_category_l2"),
        "title": str(entry.get("vuln_title") or "")[:200],
        "trace_len": len(entry.get("trace") or []) if isinstance(entry.get("trace"), list) else 0,
        "sink_path": co_path,
        "sink_line": co_line,
        "entry_path": ep_path,
        "entry_line": _loc_line(ep),
        "co_code": str(co.get("code") or "")[:240],
        "match": {
            "path_suffix": co_path,
            "start_line": co_line,
            "line_slop": LINE_SLOP,
        },
    }


def freeze_slice(entries: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = entries if entries is not None else load_entries()
    by_id = {str(e.get("entry_id")): e for e in rows}
    findings = []
    missing = []
    for eid in SLICE_IDS:
        raw = by_id.get(eid)
        if not raw:
            missing.append(eid)
            continue
        findings.append(entry_to_oracle(raw))
    if missing:
        raise KeyError(f"slice ids missing from VulnGym dump: {missing}")
    data = {
        "target": "fixtures/vulngym/slice.json",
        "description": (
            "Frozen VulnGym verified slice. Hunt the critical_operation file. "
            "Score path plus line ±5. Do not put the GHSA body in the hunt packet."
        ),
        "upstream": "https://github.com/Tencent/VulnGym",
        "findings": findings,
    }
    SLICE_PATH.parent.mkdir(parents=True, exist_ok=True)
    SLICE_PATH.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data


def tree_dir(oracle: dict[str, Any]) -> Path:
    eid = str(oracle.get("id") or "entry")
    return TREES / eid


def checkout_oracle(oracle: dict[str, Any], timeout: int = 180) -> Path:
    dest = tree_dir(oracle)
    url = str(oracle.get("repo_url") or "")
    commit = str(oracle.get("commit") or "")
    if not url or not commit:
        raise ValueError(f"oracle {oracle.get('id')} missing repo_url/commit")
    dest.parent.mkdir(parents=True, exist_ok=True)
    marker = dest / ".vf_commit"
    if marker.is_file() and marker.read_text(encoding="utf-8").strip() == commit:
        return dest
    if dest.exists() and not (dest / ".git").exists():
        raise RuntimeError(f"{dest} exists without git")
    if not (dest / ".git").exists():
        subprocess.run(["git", "init", str(dest)], check=True, capture_output=True, text=True)
        subprocess.run(
            ["git", "-C", str(dest), "remote", "add", "origin", url],
            check=True,
            capture_output=True,
            text=True,
        )
    fetch = subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", commit],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if fetch.returncode != 0:
        fetch = subprocess.run(
            ["git", "-C", str(dest), "fetch", "--filter=blob:none", "origin", commit],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    if fetch.returncode != 0:
        raise RuntimeError(f"git fetch {url}@{commit}: {fetch.stderr or fetch.stdout}")
    co = subprocess.run(
        ["git", "-C", str(dest), "checkout", "--force", "FETCH_HEAD"],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if co.returncode != 0:
        raise RuntimeError(f"git checkout {commit}: {co.stderr or co.stdout}")
    marker.write_text(commit + "\n", encoding="utf-8")
    return dest


def prepare_trees(oracles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for o in oracles:
        dest = checkout_oracle(o)
        rel = str(o.get("sink_path") or "")
        hit = dest / rel
        out.append(
            {
                "id": o.get("id"),
                "tree": str(dest),
                "sink_exists": hit.is_file(),
                "sink_path": rel,
            }
        )
        if not hit.is_file():
            raise FileNotFoundError(f"{o.get('id')} missing {rel} under {dest}")
    return out

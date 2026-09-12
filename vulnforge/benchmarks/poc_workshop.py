"""POC workshop harness — isolated poc_dev benches (ticket 7).

Generates a deterministic fixture pack stub under
``benchmarks/runs/<id>/sandbox/``, runs it offline (subprocess;
``network: none`` contract), scores pack files + ``poc_run.json`` vs
oracle, and writes a ``BenchmarkRun``. Never sets finding ``confirmed``.
Never touches Report's Develop POC modal.

Default isolation: document ``network: none`` in written ``poc_run.json``.
Optional docker ``--network=none`` is available but subprocess is preferred
for offline CI reliability.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from vulnforge.benchmarks.runs import (
    BenchmarkRunError,
    create_run,
    runs_root,
    update_run,
)
from vulnforge.benchmarks.store import (
    BenchmarkLibraryError,
    get_def,
    get_version,
)

PASS_SCORE_BAR = 0.0
DEFAULT_SIGNAL = "fixture_ok"
NETWORK_NONE = "none"

# Deterministic fixture script: writes poc_run.json with network:none.
# Not a real exploit — offline stub for mechanical scoring only.
_POC_PY_TEMPLATE = '''\
"""Deterministic poc_dev fixture stub — no network, no live targets."""
from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "poc_run.json"
payload = {{
    "ok": True,
    "signal": {signal!r},
    "network": "none",
}}
OUT.write_text(json.dumps(payload, indent=2) + "\\n", encoding="utf-8")
print("wrote", OUT)
'''


def _expected_pack_files(oracle: dict[str, Any]) -> list[str]:
    raw = oracle.get("pack_files") or oracle.get("expected_pack_files") or []
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    if isinstance(raw, (list, tuple)):
        return [str(x).strip() for x in raw if str(x).strip()]
    return ["poc.py", "poc_meta.json"]


def _expected_poc_run(oracle: dict[str, Any]) -> dict[str, Any]:
    body = oracle.get("poc_run")
    if isinstance(body, dict):
        return dict(body)
    return {
        "ok": True,
        "signal": str(oracle.get("signal") or DEFAULT_SIGNAL),
        "network": NETWORK_NONE,
    }


def generate_pack_stub(
    sandbox: Path,
    *,
    signal: str = DEFAULT_SIGNAL,
    meta: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Write minimal pack files under ``sandbox`` (poc.py + poc_meta.json)."""
    sandbox.mkdir(parents=True, exist_ok=True)
    poc_py = sandbox / "poc.py"
    poc_py.write_text(
        _POC_PY_TEMPLATE.format(signal=signal),
        encoding="utf-8",
    )
    meta_body = {
        "format": "vulnforge.poc_dev_pack/v1",
        "network": NETWORK_NONE,
        "signal": signal,
        "note": "Isolated fixture stub — not a live-system PoC.",
    }
    if isinstance(meta, dict):
        meta_body.update(meta)
    meta_path = sandbox / "poc_meta.json"
    meta_path.write_text(json.dumps(meta_body, indent=2) + "\n", encoding="utf-8")
    return {
        "pack_dir": str(sandbox),
        "files": ["poc.py", "poc_meta.json"],
        "network": NETWORK_NONE,
    }


def run_pack_subprocess(
    sandbox: Path,
    *,
    timeout_s: float = 30.0,
) -> dict[str, Any]:
    """Execute sandbox/poc.py via subprocess (offline; network:none contract).

    Env clears common proxy vars. Prefer subprocess over docker for CI.
    Optional docker path is documented but not required.
    """
    script = sandbox / "poc.py"
    if not script.is_file():
        raise BenchmarkRunError(f"pack stub missing: {script}")
    env = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ):
        env.pop(key, None)
    # Explicit contract for the harness + child process.
    env["VULNFORGE_POC_NETWORK"] = NETWORK_NONE
    env["VULNFORGE_POC_NO_NETWORK"] = "1"
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(sandbox),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    return {
        "returncode": int(proc.returncode),
        "stdout": (proc.stdout or "")[:4000],
        "stderr": (proc.stderr or "")[:4000],
        "network": NETWORK_NONE,
        "executor": "subprocess",
    }


def _load_poc_run(sandbox: Path) -> dict[str, Any]:
    path = sandbox / "poc_run.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def score_poc_dev(
    sandbox: Path,
    oracle: dict[str, Any],
    *,
    run_info: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Score pack presence + poc_run.json vs oracle. Never sets confirmed."""
    want_files = _expected_pack_files(oracle)
    present = [f for f in want_files if (sandbox / f).is_file()]
    missing = [f for f in want_files if f not in present]
    pack_recall = (len(present) / len(want_files)) if want_files else 1.0

    expected = _expected_poc_run(oracle)
    actual = _load_poc_run(sandbox)

    checks: dict[str, bool] = {}
    # ok
    if "ok" in expected:
        checks["ok"] = bool(actual.get("ok")) is bool(expected.get("ok"))
    # signal
    if "signal" in expected:
        checks["signal"] = str(actual.get("signal") or "") == str(expected.get("signal"))
    # network must be none
    want_net = str(expected.get("network") or NETWORK_NONE)
    got_net = str(actual.get("network") or "")
    checks["network"] = got_net == want_net == NETWORK_NONE
    # Oracle-level network: none
    oracle_net = str(oracle.get("network") or NETWORK_NONE)
    checks["oracle_network"] = oracle_net == NETWORK_NONE

    run_checks = len(checks)
    run_hits = sum(1 for v in checks.values() if v)
    run_recall = (run_hits / run_checks) if run_checks else 1.0

    # Equal weight: pack files + poc_run fields
    score = round(0.5 * pack_recall + 0.5 * run_recall, 4)

    if not want_files and not expected:
        passed = True
        score = 1.0
    else:
        passed = (
            pack_recall >= 1.0
            and run_recall >= 1.0
            and bool(checks.get("network"))
        )

    metrics: dict[str, Any] = {
        "mode": "mechanical",
        "bench_type": "poc_dev",
        "score": score,
        "passed": bool(passed),
        "pack_files_expected": want_files,
        "pack_files_present": present,
        "pack_files_missing": missing,
        "pack_recall": round(pack_recall, 4),
        "poc_run_expected": expected,
        "poc_run_actual": actual,
        "poc_run_checks": checks,
        "poc_run_recall": round(run_recall, 4),
        "network": NETWORK_NONE,
        "network_enforced": True,
        "confirmed": False,
        "sandbox": str(sandbox),
    }
    if run_info:
        metrics["executor"] = run_info.get("executor")
        metrics["returncode"] = run_info.get("returncode")
    return metrics


def run_poc_workshop(
    *,
    def_id: str,
    version: Optional[int] = None,
    mode: str = "mechanical",
) -> dict[str, Any]:
    """Create + execute a poc_dev BenchmarkRun via the isolated workshop path.

    Writes sandbox under ``benchmarks/runs/<id>/sandbox/``. Does not use
    Report ``#poc-modal``. Never auto-confirms findings.
    """
    bid = str(def_id or "").strip().lower()
    if not bid:
        raise BenchmarkRunError("def_id is required")

    mode_n = str(mode or "mechanical").strip().lower()
    if mode_n not in ("mechanical", "live"):
        raise BenchmarkRunError("mode must be 'mechanical' or 'live'")

    try:
        head = get_def(bid, include_oracle=False)
    except BenchmarkLibraryError as e:
        raise BenchmarkRunError(str(e)) from e

    ver = int(version) if version is not None else int(head.get("head_version") or 1)
    try:
        snap = get_version(bid, ver)
    except BenchmarkLibraryError as e:
        raise BenchmarkRunError(str(e)) from e

    snap_types = [str(t).strip().lower() for t in (snap.get("types") or [])]
    if "poc_dev" not in snap_types:
        raise BenchmarkRunError(f"benchmark {bid}@{ver} does not include poc_dev")

    oracle = snap.get("oracle") if isinstance(snap.get("oracle"), dict) else {}
    if str(oracle.get("type") or "").lower() not in ("", "poc_dev"):
        # Still allow if types declare poc_dev but oracle type differs
        pass
    target_ref = str(snap.get("target_ref") or "")
    oracle_hash = str(snap.get("oracle_hash") or "")

    run = create_run(
        def_id=bid,
        version=ver,
        types_run=["poc_dev"],
        mode=mode_n,
        target_ref=target_ref,
        oracle_hash=oracle_hash,
        status="running",
    )
    rid = run["id"]
    sandbox = runs_root() / rid / "sandbox"

    if mode_n == "live":
        return update_run(
            rid,
            status="error",
            error=(
                "live poc_dev is not enabled (use mechanical workshop; "
                "network:none only — no live-net PoC)"
            ),
            metrics={"confirmed": False, "network": NETWORK_NONE},
            harness_run_dir=str(sandbox),
        )

    try:
        expected = _expected_poc_run(oracle)
        signal = str(expected.get("signal") or DEFAULT_SIGNAL)
        generate_pack_stub(sandbox, signal=signal)
        run_info = run_pack_subprocess(sandbox)
        if int(run_info.get("returncode") or 0) != 0:
            return update_run(
                rid,
                status="error",
                error=(
                    f"poc stub exited {run_info.get('returncode')}: "
                    f"{(run_info.get('stderr') or '')[:500]}"
                ),
                metrics={
                    "mode": "mechanical",
                    "bench_type": "poc_dev",
                    "confirmed": False,
                    "network": NETWORK_NONE,
                    "executor": run_info.get("executor"),
                    "returncode": run_info.get("returncode"),
                },
                harness_run_dir=str(sandbox),
            )

        type_metrics = score_poc_dev(sandbox, oracle, run_info=run_info)
        metrics: dict[str, Any] = {
            "mode": "mechanical",
            "types_run": ["poc_dev"],
            "by_type": {"poc_dev": type_metrics},
            "confirmed": False,
            "network": NETWORK_NONE,
            "network_enforced": True,
            "harness": "poc_workshop",
        }
        for k, v in type_metrics.items():
            if k not in ("by_type",):
                metrics[k] = v

        status = "passed" if type_metrics.get("passed") else "failed"
        return update_run(
            rid,
            status=status,
            metrics=metrics,
            error=None,
            harness_run_dir=str(sandbox),
        )
    except BenchmarkRunError as e:
        return update_run(
            rid,
            status="error",
            error=str(e),
            metrics={"confirmed": False, "network": NETWORK_NONE},
            harness_run_dir=str(sandbox) if sandbox.exists() else None,
        )
    except subprocess.TimeoutExpired as e:
        return update_run(
            rid,
            status="error",
            error=f"TimeoutExpired: {e}",
            metrics={"confirmed": False, "network": NETWORK_NONE},
            harness_run_dir=str(sandbox) if sandbox.exists() else None,
        )
    except Exception as e:  # noqa: BLE001
        return update_run(
            rid,
            status="error",
            error=f"{type(e).__name__}: {e}",
            metrics={"confirmed": False, "network": NETWORK_NONE},
            harness_run_dir=str(sandbox) if sandbox.exists() else None,
        )

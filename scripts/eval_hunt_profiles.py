#!/usr/bin/env python3
"""Live hunt-profile recall eval plus HTML progress dashboard.

Frozen ruler:
  python scripts/eval_hunt_profiles.py --sensitivity
  python scripts/eval_hunt_profiles.py --live --label baseline
  python scripts/eval_hunt_profiles.py --dashboard

Metric is recall vs fixtures/profile_eval/ground_truth.json.
Any finding body that matches an oracle counts as a hit, regardless of state.
Extras are recorded and do not fail the run.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vulnforge.eval.recall import load_ground_truth, score_findings
from vulnforge.paths import PROJECT_ROOT

GT_PATH = PROJECT_ROOT / "fixtures" / "profile_eval" / "ground_truth.json"
TREE = PROJECT_ROOT / "fixtures" / "profile_eval" / "tree"
AUDIT = PROJECT_ROOT / ".audit" / "hunt-profile-hillclimb"
RESULTS_DIR = AUDIT / "results"
DASHBOARD = AUDIT / "index.html"
EVAL_RUNS = AUDIT / "eval_runs"
VF = PROJECT_ROOT / ".venv" / "bin" / "python"
RALPH = PROJECT_ROOT / "scripts" / "ralph.py"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_catalog() -> dict[str, Any]:
    return load_ground_truth(GT_PATH)


def synthetic_perfect(oracles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bodies = []
    for o in oracles:
        path = str(o.get("sink_path") or "")
        sym = str(o.get("sink_symbol") or "")
        bodies.append(
            {
                "sink_path": path,
                "sink_symbol": sym,
                "citations": [{"path": path, "symbol": sym, "start_line": 1}],
            }
        )
    return bodies


def sensitivity() -> dict[str, Any]:
    gt = load_catalog()
    oracles = list(gt.get("findings") or [])
    empty = score_findings([], oracles)
    perfect = score_findings(synthetic_perfect(oracles), oracles)
    present = sorted(p.name for p in TREE.iterdir() if p.is_file()) if TREE.is_dir() else []
    want = sorted({str(o.get("sink_path")) for o in oracles})
    files_ok = want == present or set(want).issubset(set(present))
    return {
        "empty_recall": empty["recall"],
        "perfect_recall": perfect["recall"],
        "oracle_count": len(oracles),
        "files": present,
        "files_ok": files_ok,
        "ok": empty["recall"] == 0.0 and perfect["recall"] == 1.0 and files_ok,
    }


def _write_overlay_yaml(path: Path) -> None:
    src = PROJECT_ROOT / "config" / "default.yaml"
    text = src.read_text(encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Keep default.yaml intact; append eval-only overrides that YAML merge
    # cannot do, so we rewrite stages.validate_llm in a sidecar full copy.
    lines = []
    in_stages = False
    for line in text.splitlines(True):
        if line.startswith("stages:"):
            in_stages = True
            lines.append(line)
            continue
        if in_stages and line.startswith("  validate_llm:"):
            lines.append("  validate_llm: false\n")
            in_stages = False
            continue
        if in_stages and line and not line.startswith(" ") and not line.startswith("\t"):
            in_stages = False
        lines.append(line)
    path.write_text("".join(lines), encoding="utf-8")


def _vf(*args: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env.setdefault("VF_VALIDATE_LLM", "0")
    if extra_env:
        env.update(extra_env)
    exe = str(VF if VF.is_file() else sys.executable)
    cmd = [exe, "-m", "vulnforge.cli", *args]
    return subprocess.run(cmd, cwd=str(PROJECT_ROOT), env=env, capture_output=True, text=True)


def _find_run_dir(runs_root: Path, after_ts: float) -> Path:
    candidates = sorted(runs_root.glob("*/run-*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in candidates:
        if p.is_dir() and (p / "harness.db").is_file():
            if p.stat().st_mtime >= after_ts - 2:
                return p
    if candidates:
        return candidates[0]
    raise FileNotFoundError(f"no run under {runs_root}")


def run_live(label: str, task_timeout: int, max_tasks: int | None) -> dict[str, Any]:
    from vulnforge.control.ops import hunt_from_selection
    from vulnforge.db import Database

    gt = load_catalog()
    oracles = list(gt.get("findings") or [])
    if not TREE.is_dir():
        raise FileNotFoundError(TREE)

    AUDIT.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    EVAL_RUNS.mkdir(parents=True, exist_ok=True)
    overlay = AUDIT / "eval_overlay.yaml"
    _write_overlay_yaml(overlay)

    started = datetime.now().timestamp()
    init = _vf(
        "--config",
        str(overlay),
        "init",
        "--target",
        str(TREE),
        "--strategy",
        "file_by_file",
        "--no-enqueue-hunts",
        "--runs-root",
        str(EVAL_RUNS),
        "--hunt-skill-mode",
        "all_active",
    )
    if init.returncode != 0:
        raise RuntimeError(f"vf init failed: {init.stderr or init.stdout}")
    run_dir = _find_run_dir(EVAL_RUNS, started)

    enqueued = []
    for o in oracles:
        r = hunt_from_selection(
            run_dir,
            path=str(o.get("sink_path") or ""),
            attack_class=str(o.get("class") or "wildcard"),
            area="eval",
        )
        enqueued.append({"id": o.get("id"), "ok": r.get("ok"), "task_id": r.get("task_id"), "error": r.get("error")})
        if not r.get("ok"):
            raise RuntimeError(f"enqueue failed for {o.get('id')}: {r}")

    n = len(oracles)
    budget = max_tasks if max_tasks is not None else n * 3
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env.setdefault("VF_VALIDATE_LLM", "0")
    exe = str(VF if VF.is_file() else sys.executable)
    ralph = subprocess.run(
        [
            exe,
            str(RALPH),
            "--run-dir",
            str(run_dir),
            "--config",
            str(overlay),
            "--task-timeout",
            str(task_timeout),
            "--max-tasks",
            str(budget),
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )

    db = Database(run_dir / "harness.db")
    try:
        findings = db.list_findings()
        tasks = []
        try:
            rows = db.conn.execute(
                "SELECT id, kind, state, payload_json FROM tasks ORDER BY id"
            ).fetchall()
        except Exception:
            rows = []
        for row in rows:
            tasks.append(
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "state": row["state"],
                    "payload": json.loads(row["payload_json"] or "{}"),
                }
            )
    finally:
        db.close()

    bodies = [f.body for f in findings]
    scored = score_findings(bodies, oracles)
    by_class: dict[str, dict[str, int]] = {}
    for o in oracles:
        cls = str(o.get("class") or "?")
        bucket = by_class.setdefault(cls, {"oracles": 0, "hits": 0})
        bucket["oracles"] += 1
        if str(o.get("id")) in scored["hits"]:
            bucket["hits"] += 1
    for cls, bucket in by_class.items():
        bucket["recall"] = (bucket["hits"] / bucket["oracles"]) if bucket["oracles"] else 1.0

    result = {
        "ts": utc_now(),
        "label": label,
        "run_dir": str(run_dir),
        "recall": scored["recall"],
        "hits": scored["hits"],
        "misses": scored["misses"],
        "hit_count": scored["hit_count"],
        "oracle_count": scored["oracle_count"],
        "finding_count": scored["finding_count"],
        "extras": scored["extras"],
        "finding_states": [{"id": f.id, "state": f.state, "sink_path": f.body.get("sink_path")} for f in findings],
        "by_class": by_class,
        "enqueued": enqueued,
        "ralph_returncode": ralph.returncode,
        "ralph_tail": (ralph.stdout or "")[-4000:],
        "ralph_err_tail": (ralph.stderr or "")[-2000:],
        "tasks": [
            {"id": t["id"], "kind": t["kind"], "state": t["state"]} for t in tasks
        ],
        "task_timeout": task_timeout,
        "max_tasks": budget,
    }
    out = RESULTS_DIR / f"{utc_now().replace(':', '')}_{label}.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["result_path"] = str(out)
    write_dashboard()
    return result


def _load_history() -> list[dict[str, Any]]:
    if not RESULTS_DIR.is_dir():
        return []
    rows = []
    for p in sorted(RESULTS_DIR.glob("*.json")):
        try:
            rows.append(json.loads(p.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError):
            continue
    return rows


def write_dashboard() -> Path:
    history = _load_history()
    AUDIT.mkdir(parents=True, exist_ok=True)
    points = [
        {
            "ts": r.get("ts"),
            "label": r.get("label"),
            "recall": r.get("recall"),
            "hits": r.get("hit_count"),
            "oracles": r.get("oracle_count"),
            "extras": r.get("extras"),
            "misses": r.get("misses") or [],
        }
        for r in history
        if isinstance(r.get("recall"), (int, float))
    ]
    latest = history[-1] if history else {}
    html = _dashboard_html(points, latest)
    DASHBOARD.write_text(html, encoding="utf-8")
    return DASHBOARD


def _dashboard_html(points: list[dict[str, Any]], latest: dict[str, Any]) -> str:
    data = json.dumps(points)
    latest_json = json.dumps(latest, indent=2)
    recall_pct = f"{100 * float(latest.get('recall') or 0):.0f}%" if latest else "—"
    baseline = next((p for p in points if p.get("label") == "baseline"), points[0] if points else None)
    base_pct = f"{100 * float(baseline['recall']):.0f}%" if baseline else "—"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>Hunt profile recall</title>
<style>
  :root {{ color-scheme: dark; --bg:#111; --fg:#eee; --muted:#9aa; --acc:#6cf; --miss:#f86; --hit:#6c6; }}
  body {{ font: 15px/1.4 ui-sans-serif, system-ui, sans-serif; margin: 24px; background: var(--bg); color: var(--fg); }}
  h1 {{ font-size: 22px; font-weight: 600; }}
  .row {{ display: flex; gap: 16px; flex-wrap: wrap; }}
  .card {{ background: #1b1b1b; border: 1px solid #2a2a2a; border-radius: 8px; padding: 16px; min-width: 160px; }}
  .num {{ font-size: 32px; font-weight: 650; }}
  canvas {{ width: 100%; max-width: 920px; height: 280px; background: #181818; border-radius: 8px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #333; }}
  .miss {{ color: var(--miss); }}
  .hit {{ color: var(--hit); }}
  pre {{ overflow: auto; background: #181818; padding: 12px; border-radius: 8px; }}
</style>
</head>
<body>
<h1>Hunt profile recall</h1>
<p>Live hunts on the frozen 8-file snippet set. Recall is oracle hits over oracles. Extras do not fail the metric.</p>
<div class="row">
  <div class="card"><div>Latest recall</div><div class="num" id="latest">{recall_pct}</div></div>
  <div class="card"><div>Baseline</div><div class="num" id="base">{base_pct}</div></div>
  <div class="card"><div>Hits / oracles</div><div class="num" id="frac">{latest.get("hit_count", "—")}/{latest.get("oracle_count", "—")}</div></div>
  <div class="card"><div>Extras</div><div class="num">{latest.get("extras", "—")}</div></div>
</div>
<p>Target is 85% or better, and strictly above baseline. Model is ornith-ai-ornith-1.5-35b-a3b-mtplx at 10.0.0.232:8000.</p>
<canvas id="chart" width="920" height="280"></canvas>
<h2>Runs</h2>
<table>
<thead><tr><th>When</th><th>Label</th><th>Recall</th><th>Hits</th><th>Misses</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<h2>Latest miss list</h2>
<pre id="misses"></pre>
<h2>Latest raw</h2>
<pre id="raw"></pre>
<script>
const points = {data};
const latest = {latest_json};
function draw() {{
  const c = document.getElementById('chart');
  const ctx = c.getContext('2d');
  const w = c.width, h = c.height;
  ctx.clearRect(0,0,w,h);
  ctx.strokeStyle = '#333';
  ctx.beginPath();
  for (let i=0;i<=4;i++) {{
    const y = 20 + i*(h-40)/4;
    ctx.moveTo(40,y); ctx.lineTo(w-10,y);
  }}
  ctx.stroke();
  ctx.fillStyle = '#9aa';
  ctx.fillText('0%', 8, h-16);
  ctx.fillText('100%', 2, 24);
  ctx.strokeStyle = '#444';
  ctx.setLineDash([4,4]);
  const y85 = 20 + (1-0.85)*(h-40);
  ctx.beginPath(); ctx.moveTo(40,y85); ctx.lineTo(w-10,y85); ctx.stroke();
  ctx.setLineDash([]);
  ctx.fillText('85%', w-40, y85-4);
  if (!points.length) return;
  ctx.strokeStyle = '#6cf';
  ctx.lineWidth = 2;
  ctx.beginPath();
  points.forEach((p,i) => {{
    const x = 40 + i*((w-60)/Math.max(points.length-1,1));
    const y = 20 + (1-(p.recall||0))*(h-40);
    if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
  }});
  ctx.stroke();
  ctx.fillStyle = '#6cf';
  points.forEach((p,i) => {{
    const x = 40 + i*((w-60)/Math.max(points.length-1,1));
    const y = 20 + (1-(p.recall||0))*(h-40);
    ctx.beginPath(); ctx.arc(x,y,4,0,Math.PI*2); ctx.fill();
  }});
  const tb = document.getElementById('rows');
  tb.innerHTML = points.map(p => {{
    const miss = (p.misses||[]).join(', ') || 'none';
    const cls = (p.recall||0) >= 0.85 ? 'hit' : 'miss';
    return `<tr><td>${{p.ts||''}}</td><td>${{p.label||''}}</td><td class="${{cls}}">${{((p.recall||0)*100).toFixed(0)}}%</td><td>${{p.hits}}/${{p.oracles}}</td><td class="miss">${{miss}}</td></tr>`;
  }}).join('');
  document.getElementById('misses').textContent = (latest.misses||[]).join('\\n') || 'none';
  document.getElementById('raw').textContent = JSON.stringify(latest, null, 2);
}}
draw();
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Hunt profile live recall eval")
    ap.add_argument("--sensitivity", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--dashboard", action="store_true")
    ap.add_argument("--label", default="run")
    ap.add_argument("--task-timeout", type=int, default=900)
    ap.add_argument("--max-tasks", type=int, default=None)
    args = ap.parse_args()
    if args.sensitivity:
        s = sensitivity()
        print(json.dumps(s, indent=2))
        return 0 if s["ok"] else 1
    if args.dashboard:
        p = write_dashboard()
        print(p)
        return 0
    if args.live:
        r = run_live(args.label, args.task_timeout, args.max_tasks)
        print(
            f"{r['label']}: recall={r['recall']:.0%} "
            f"hits={r['hit_count']}/{r['oracle_count']} extras={r['extras']}"
        )
        if r.get("misses"):
            print("  misses:", ", ".join(r["misses"]))
        print("  dashboard:", DASHBOARD)
        print("  result:", r.get("result_path"))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

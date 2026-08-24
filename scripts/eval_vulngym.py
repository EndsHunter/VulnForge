#!/usr/bin/env python3
"""Live VulnGym hunt-profile recall + HTML dashboard.

  python scripts/eval_vulngym.py --freeze
  python scripts/eval_vulngym.py --prepare
  python scripts/eval_vulngym.py --sensitivity
  python scripts/eval_vulngym.py --live --label baseline
  python scripts/eval_vulngym.py --dashboard

Metric is line-tolerant recall vs fixtures/vulngym/slice.json.
Endpoint is pinned to 10.0.0.232:8000 ornith-ai-ornith-1.5-35b-a3b-mtplx.
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
from vulnforge.eval.vulngym import (
    SLICE_PATH,
    checkout_oracle,
    freeze_slice,
    prepare_trees,
    tree_dir,
)
from vulnforge.paths import PROJECT_ROOT

AUDIT = PROJECT_ROOT / ".audit" / "vulngym"
RESULTS_DIR = AUDIT / "results"
DASHBOARD = AUDIT / "index.html"
EVAL_RUNS = AUDIT / "eval_runs"
DECISIONS = AUDIT / "decisions.tsv"
VF = PROJECT_ROOT / ".venv" / "bin" / "python"
RALPH = PROJECT_ROOT / "scripts" / "ralph.py"
MODEL_HOST = "10.0.0.232"
MODEL_PORT = "8000"
MODEL_ID = "ornith-ai-ornith-1.5-35b-a3b-mtplx"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_catalog() -> dict[str, Any]:
    return load_ground_truth(SLICE_PATH)


def log_decision(phase: str, decision: str, why: str, evidence: str, result: str) -> None:
    AUDIT.mkdir(parents=True, exist_ok=True)
    if not DECISIONS.is_file():
        DECISIONS.write_text(
            "ts\tphase\tdecision\twhy\tevidence\tresult\n", encoding="utf-8"
        )
    def cell(s: str) -> str:
        t = str(s).replace("\t", " ").replace("\n", " ").strip()
        if t[:1] in "=+-@":
            t = "'" + t
        return t
    line = "\t".join(
        [utc_now(), cell(phase), cell(decision), cell(why), cell(evidence), cell(result)]
    )
    with DECISIONS.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def synthetic_perfect(oracles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bodies = []
    for o in oracles:
        path = str(o.get("sink_path") or "")
        line = (o.get("match") or {}).get("start_line")
        bodies.append(
            {
                "sink_path": path,
                "citations": [{"path": path, "start_line": line}],
            }
        )
    return bodies


def sensitivity() -> dict[str, Any]:
    gt = load_catalog()
    oracles = list(gt.get("findings") or [])
    empty = score_findings([], oracles)
    perfect = score_findings(synthetic_perfect(oracles), oracles)
    return {
        "empty_recall": empty["recall"],
        "perfect_recall": perfect["recall"],
        "oracle_count": len(oracles),
        "ok": empty["recall"] == 0.0 and perfect["recall"] == 1.0 and len(oracles) == 6,
    }


def _eval_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(PROJECT_ROOT)
    env["VF_VALIDATE_LLM"] = "0"
    env["VF_HOST"] = MODEL_HOST
    env["VF_PORT"] = MODEL_PORT
    env["VF_MODEL"] = MODEL_ID
    if extra:
        env.update(extra)
    return env


def _write_overlay_yaml(path: Path) -> None:
    src = PROJECT_ROOT / "config" / "default.yaml"
    text = src.read_text(encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    in_stages = False
    in_llm = False
    for line in text.splitlines(True):
        if line.startswith("stages:"):
            in_stages = True
            in_llm = False
            lines.append(line)
            continue
        if line.startswith("llm:"):
            in_llm = True
            in_stages = False
            lines.append(line)
            continue
        if in_stages and line.startswith("  validate_llm:"):
            lines.append("  validate_llm: false\n")
            in_stages = False
            continue
        if in_llm and line.startswith("  base_url:"):
            lines.append(f'  base_url: "http://{MODEL_HOST}:{MODEL_PORT}/v1"\n')
            continue
        if in_llm and line.startswith("  model:"):
            lines.append(f'  model: "{MODEL_ID}"\n')
            continue
        if in_llm and line.startswith("  timeout_seconds:"):
            lines.append("  timeout_seconds: 600\n")
            continue
        if (in_stages or in_llm) and line and not line.startswith(" ") and not line.startswith("\t"):
            in_stages = False
            in_llm = False
        lines.append(line)
    path.write_text("".join(lines), encoding="utf-8")


def _vf(*args: str) -> subprocess.CompletedProcess:
    env = _eval_env()
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


def _hunt_one(
    oracle: dict[str, Any],
    overlay: Path,
    task_timeout: int,
    max_tasks: int,
) -> dict[str, Any]:
    from vulnforge.control.ops import hunt_from_selection
    from vulnforge.db import Database

    tree = tree_dir(oracle)
    if not tree.is_dir():
        checkout_oracle(oracle)
    started = datetime.now().timestamp()
    init = _vf(
        "--config",
        str(overlay),
        "init",
        "--target",
        str(tree),
        "--strategy",
        "file_by_file",
        "--no-enqueue-hunts",
        "--runs-root",
        str(EVAL_RUNS / str(oracle.get("id"))),
        "--hunt-skill-mode",
        "all_active",
    )
    if init.returncode != 0:
        raise RuntimeError(
            f"vf init {oracle.get('id')} failed: {init.stderr or init.stdout}"
        )
    run_dir = _find_run_dir(EVAL_RUNS / str(oracle.get("id")), started)
    hunt_path = str(oracle.get("sink_path") or "")
    r = hunt_from_selection(
        run_dir,
        path=hunt_path,
        attack_class=str(oracle.get("class") or "wildcard"),
        area="eval",
    )
    if not r.get("ok"):
        raise RuntimeError(f"enqueue {oracle.get('id')}: {r}")
    env = _eval_env()
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
            str(max_tasks),
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    db = Database(run_dir / "harness.db")
    try:
        findings = db.list_findings()
        bodies = [f.body for f in findings]
        states = [
            {"id": f.id, "state": f.state, "sink_path": f.body.get("sink_path")}
            for f in findings
        ]
    finally:
        db.close()
    one = score_findings(bodies, [oracle])
    return {
        "id": oracle.get("id"),
        "class": oracle.get("class"),
        "run_dir": str(run_dir),
        "hit": one["hit_count"] == 1,
        "finding_count": len(bodies),
        "finding_states": states,
        "bodies": bodies,
        "ralph_returncode": ralph.returncode,
        "ralph_err_tail": (ralph.stderr or "")[-1500:],
        "enqueued": r.get("task_id"),
    }


def run_live(
    label: str,
    task_timeout: int,
    max_tasks: int,
    only: list[str] | None = None,
) -> dict[str, Any]:
    gt = load_catalog()
    oracles = list(gt.get("findings") or [])
    if only:
        want = {x.strip() for x in only if x.strip()}
        oracles = [o for o in oracles if str(o.get("id")) in want]
        if not oracles:
            raise ValueError(f"no oracles matched --only {sorted(want)}")
    AUDIT.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    EVAL_RUNS.mkdir(parents=True, exist_ok=True)
    overlay = AUDIT / "eval_overlay.yaml"
    _write_overlay_yaml(overlay)
    prepare_trees(oracles)
    per: list[dict[str, Any]] = []
    all_bodies: list[dict[str, Any]] = []
    for o in oracles:
        row = _hunt_one(o, overlay, task_timeout, max_tasks)
        per.append({k: v for k, v in row.items() if k != "bodies"})
        all_bodies.extend(row["bodies"])
        write_dashboard_partial(label, oracles, all_bodies, per)
    scored = score_findings(all_bodies, oracles)
    by_class: dict[str, dict[str, int | float]] = {}
    for o in oracles:
        cls = str(o.get("class") or "?")
        bucket = by_class.setdefault(cls, {"oracles": 0, "hits": 0})
        bucket["oracles"] = int(bucket["oracles"]) + 1
        if str(o.get("id")) in scored["hits"]:
            bucket["hits"] = int(bucket["hits"]) + 1
    for cls, bucket in by_class.items():
        n = int(bucket["oracles"])
        bucket["recall"] = (int(bucket["hits"]) / n) if n else 1.0
    result = {
        "ts": utc_now(),
        "label": label,
        "recall": scored["recall"],
        "hits": scored["hits"],
        "misses": scored["misses"],
        "hit_count": scored["hit_count"],
        "oracle_count": scored["oracle_count"],
        "finding_count": scored["finding_count"],
        "extras": scored["extras"],
        "by_class": by_class,
        "per_oracle": per,
        "task_timeout": task_timeout,
        "max_tasks": max_tasks,
        "model": MODEL_ID,
        "endpoint": f"http://{MODEL_HOST}:{MODEL_PORT}/v1",
        "only": only or [],
    }
    out = RESULTS_DIR / f"{utc_now().replace(':', '')}_{label}.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    result["result_path"] = str(out)
    write_dashboard()
    return result


def write_dashboard_partial(
    label: str,
    oracles: list[dict[str, Any]],
    bodies: list[dict[str, Any]],
    per: list[dict[str, Any]],
) -> None:
    scored = score_findings(bodies, oracles)
    stub = {
        "ts": utc_now(),
        "label": f"{label}-partial-{len(per)}/{len(oracles)}",
        "recall": scored["recall"],
        "hits": scored["hits"],
        "misses": scored["misses"],
        "hit_count": scored["hit_count"],
        "oracle_count": len(oracles),
        "finding_count": scored["finding_count"],
        "extras": scored["extras"],
        "by_class": {},
        "per_oracle": per,
    }
    AUDIT.mkdir(parents=True, exist_ok=True)
    DASHBOARD.write_text(_dashboard_html(_load_history() + [stub], stub), encoding="utf-8")


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
    latest = history[-1] if history else {}
    html = _dashboard_html(history, latest)
    AUDIT.mkdir(parents=True, exist_ok=True)
    DASHBOARD.write_text(html, encoding="utf-8")
    return DASHBOARD


def _dashboard_html(history: list[dict[str, Any]], latest: dict[str, Any]) -> str:
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
        and "partial" not in str(r.get("label") or "")
    ]
    data = json.dumps(points)
    latest_json = json.dumps(latest, indent=2)
    by_class = json.dumps(latest.get("by_class") or {})
    recall_pct = f"{100 * float(latest.get('recall') or 0):.0f}%" if latest else "—"
    baseline = next((p for p in points if p.get("label") == "baseline"), points[0] if points else None)
    base_pct = f"{100 * float(baseline['recall']):.0f}%" if baseline else "—"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>VulnGym hunt recall</title>
<style>
  :root {{ color-scheme: dark; --bg:#111; --fg:#eee; --muted:#9aa; --acc:#6cf; --miss:#f86; --hit:#6c6; }}
  body {{ font: 15px/1.4 ui-sans-serif, system-ui, sans-serif; margin: 24px; background: var(--bg); color: var(--fg); }}
  h1 {{ font-size: 22px; font-weight: 600; }}
  .row {{ display: flex; gap: 16px; flex-wrap: wrap; }}
  .card {{ background: #1b1b1b; border: 1px solid #2a2a2a; border-radius: 8px; padding: 16px; min-width: 160px; }}
  .num {{ font-size: 32px; font-weight: 650; }}
  canvas {{ width: 100%; max-width: 920px; height: 280px; background: #181818; border-radius: 8px; }}
  #bars {{ height: 360px; max-width: 920px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #333; }}
  .miss {{ color: var(--miss); }}
  .hit {{ color: var(--hit); }}
  pre {{ overflow: auto; background: #181818; padding: 12px; border-radius: 8px; }}
</style>
</head>
<body>
<h1>VulnGym hunt recall</h1>
<p>Frozen 6-entry verified slice. One hunt per critical_operation file. Recall is path plus line plus or minus 5. GHSA text is not in the packet. Model is ornith-ai-ornith-1.5-35b-a3b-mtplx at 10.0.0.232:8000.</p>
<div class="row">
  <div class="card"><div>Latest recall</div><div class="num" id="latest">{recall_pct}</div></div>
  <div class="card"><div>Baseline</div><div class="num" id="base">{base_pct}</div></div>
  <div class="card"><div>Hits / oracles</div><div class="num" id="frac">{latest.get("hit_count", "—")}/{latest.get("oracle_count", "—")}</div></div>
  <div class="card"><div>Extras</div><div class="num">{latest.get("extras", "—")}</div></div>
</div>
<p>Stop when recall is strictly above the frozen baseline. Target is 100 percent.</p>
<canvas id="chart" width="920" height="280"></canvas>
<h2>Per-class (latest run)</h2>
<canvas id="bars" width="920" height="360"></canvas>
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
    const cls = (p.recall||0) > (points[0].recall||0) ? 'hit' : 'miss';
    return `<tr><td>${{p.ts||''}}</td><td>${{p.label||''}}</td><td class="${{cls}}">${{((p.recall||0)*100).toFixed(0)}}%</td><td>${{p.hits}}/${{p.oracles}}</td><td class="miss">${{miss}}</td></tr>`;
  }}).join('');
  document.getElementById('misses').textContent = (latest.misses||[]).join('\\n') || 'none';
  document.getElementById('raw').textContent = JSON.stringify(latest, null, 2);
  const byClass = {by_class};
  const bc = document.getElementById('bars');
  const bctx = bc.getContext('2d');
  bctx.clearRect(0,0,bc.width,bc.height);
  const keys = Object.keys(byClass);
  if (keys.length) {{
    const bw = (bc.width-80)/keys.length;
    keys.forEach((k,i) => {{
      const rec = byClass[k].recall || 0;
      const hits = byClass[k].hits || 0;
      const n = byClass[k].oracles || 0;
      const barh = rec*(bc.height-50);
      const x = 50 + i*bw;
      bctx.fillStyle = rec >= 1 ? '#6c6' : rec > 0 ? '#6cf' : '#f86';
      bctx.fillRect(x+8, bc.height-30-barh, Math.max(bw-16, 8), barh);
      bctx.fillStyle = '#9aa';
      bctx.save();
      bctx.translate(x+bw/2, bc.height-8);
      bctx.rotate(-0.4);
      bctx.fillText(k, -20, 0);
      bctx.restore();
      bctx.fillText(hits+'/'+n, x+8, bc.height-32-barh);
    }});
  }}
}}
draw();
</script>
</body>
</html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="VulnGym hunt-profile live recall")
    ap.add_argument("--freeze", action="store_true")
    ap.add_argument("--prepare", action="store_true")
    ap.add_argument("--sensitivity", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--dashboard", action="store_true")
    ap.add_argument("--label", default="run")
    ap.add_argument("--task-timeout", type=int, default=600)
    ap.add_argument("--max-tasks", type=int, default=3)
    ap.add_argument("--only", action="append", default=[])
    args = ap.parse_args()
    if args.freeze:
        data = freeze_slice()
        print(json.dumps({"ok": True, "n": len(data["findings"]), "path": str(SLICE_PATH)}, indent=2))
        return 0
    if args.prepare:
        if not SLICE_PATH.is_file():
            freeze_slice()
        prep = prepare_trees(list(load_catalog().get("findings") or []))
        print(json.dumps({"ok": True, "trees": prep}, indent=2))
        return 0
    if args.sensitivity:
        if not SLICE_PATH.is_file():
            freeze_slice()
        s = sensitivity()
        print(json.dumps(s, indent=2))
        return 0 if s["ok"] else 1
    if args.dashboard:
        p = write_dashboard()
        print(p)
        return 0
    if args.live:
        if not SLICE_PATH.is_file():
            freeze_slice()
        result = run_live(
            args.label,
            args.task_timeout,
            args.max_tasks,
            only=args.only,
        )
        print(json.dumps({k: result[k] for k in ("ts", "label", "recall", "hits", "misses", "hit_count", "oracle_count", "result_path") if k in result}, indent=2))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

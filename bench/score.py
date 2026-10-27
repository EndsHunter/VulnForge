"""Scorecard math: pairs, stages, disprove, cost. No LLM judge."""

from __future__ import annotations

from collections import defaultdict

from bench.adapters import STAGES, apply_mech, normalize_finding, survives
from bench.tasks import SEED_DIR, Task, load_canaries

T_CRIT = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
}
BINARY = 1e-9
YOUDEN_FEW_NEGATIVES = "equals VD-S (fewer than 200 negatives)"
MIN_NEGATIVES_FOR_YOUDEN = 200
PAIR_KEYS = ("paired_correct", "both_vulnerable", "both_benign", "reversed", "error")
SCALE_UP = (
    "Next: grow toward about 30 vulnerable/fixed pairs and 10 benign tasks "
    "from CASTLE-style cases or dated CVE pairs with hand-checked sinks, "
    "and refresh held_out quarterly. Do not import BigVul or Devign labels."
)


def ci95(values: list[float]) -> dict | None:
    usable = [value for value in values if value is not None]
    n = len(usable)
    if n < 2:
        return None
    mean = sum(usable) / n
    var = sum((value - mean) ** 2 for value in usable) / (n - 1)
    std = var ** 0.5
    margin = T_CRIT.get(n - 1, 1.96) * std / (n ** 0.5)
    return {"n": n, "mean": mean, "low": mean - margin, "high": mean + margin, "std": std}


def _mean(values: list[float | None]) -> float | None:
    usable = [value for value in values if value is not None]
    if not usable:
        return None
    return sum(usable) / len(usable)


def _rate(part: int, whole: int) -> float | None:
    if whole == 0:
        return None
    return part / whole


def _confusion(positives: list[dict], negatives: list[dict], threshold: float) -> dict:
    tp = sum(
        1
        for item in positives
        if item["score"] >= threshold and item["companion"] < threshold
    )
    fp = sum(1 for item in negatives if item["score"] >= threshold)
    n_pos = len(positives)
    n_neg = len(negatives)
    fn = n_pos - tp
    tn = n_neg - fp
    tpr = _rate(tp, n_pos)
    fpr = _rate(fp, n_neg)
    precision = _rate(tp, tp + fp)
    youden = None if tpr is None or fpr is None else tpr - fpr
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": tpr,
        "fpr": fpr,
        "youden": youden,
    }


def _sweep(positives: list[dict], negatives: list[dict], fpr_cap: float) -> dict:
    scores = [item["score"] for item in positives] + [item["score"] for item in negatives]
    cuts = sorted({score for score in scores if score > 0}, reverse=True)
    cuts.append(float("inf"))
    ranked = []
    for cut in cuts:
        row = _confusion(positives, negatives, cut)
        row["threshold"] = None if cut == float("inf") else cut
        ranked.append(row)
    eligible = [
        row
        for row in ranked
        if row["fpr"] is not None and row["recall"] is not None and row["fpr"] <= fpr_cap
    ]
    if not eligible:
        chosen = ranked[-1]
    else:
        best_recall = max(row["recall"] for row in eligible)
        pool = [row for row in eligible if row["recall"] == best_recall]
        best_fpr = min(row["fpr"] for row in pool)
        pool = [row for row in pool if row["fpr"] == best_fpr]
        chosen = pool[0]
    youden_pool = [
        row
        for row in ranked
        if row["youden"] is not None and row["fpr"] is not None and row["fpr"] <= fpr_cap
    ]
    best_youden = max(youden_pool, key=lambda row: row["youden"]) if youden_pool else None
    return {
        "recall_at_fpr_le_0.5pct": chosen["recall"],
        # PrimeVul VD-S: same operating point as the headline, not Youden's J.
        "vd_s": chosen["recall"],
        "precision_at_fpr_cap": chosen["precision"],
        "fpr_at_operating_point": chosen["fpr"],
        "youden": 0.0 if best_youden is None else best_youden["youden"],
        "youden_threshold": None if best_youden is None else best_youden["threshold"],
    }


def _oracle_for(task: Task) -> dict | None:
    if task.oracle is None:
        return None
    return {
        "path": task.oracle.path,
        "line": task.oracle.line,
        "symbol": task.oracle.symbol,
        "quote": task.oracle.quote,
        "cwe": task.oracle.cwe,
    }


def _side_score(attempt: dict, stage: str, *, oracle_only: bool) -> float:
    best = 0.0
    for finding in attempt["findings"]:
        if not survives(finding, stage):
            continue
        if oracle_only and not finding["mech"]["oracle_hit"]:
            continue
        best = max(best, float(finding["confidence"]))
    return best


def _dedup_precision(attempts: list[dict], stage: str) -> float | None:
    matched: set[str] = set()
    keys: set[str] = set()
    for attempt in attempts:
        if attempt["error"]:
            continue
        for finding in attempt["findings"]:
            if not survives(finding, stage):
                continue
            keys.add(finding["stable_key"])
            if finding["mech"]["oracle_hit"]:
                matched.add(finding["stable_key"])
    return _rate(len(matched), len(keys))


def _dup_rate(attempts: list[dict]) -> float | None:
    keys = []
    for attempt in attempts:
        if attempt["error"]:
            continue
        for finding in attempt["findings"]:
            keys.append(finding["stable_key"])
    if not keys:
        return 0.0
    return 1.0 - (len(set(keys)) / len(keys))


def _gate_rates(rows: list[dict]) -> dict:
    """rows: is_real, rejected, inconclusive."""
    conclusive = [row for row in rows if not row["inconclusive"]]
    real = [row for row in conclusive if row["is_real"]]
    fake = [row for row in conclusive if not row["is_real"]]
    return {
        "false_reject_rate": _rate(sum(1 for row in real if row["rejected"]), len(real)),
        "false_pass_rate": _rate(sum(1 for row in fake if not row["rejected"]), len(fake)),
        "real_conclusive": len(real),
        "false_conclusive": len(fake),
        "inconclusive": sum(1 for row in rows if row["inconclusive"]),
    }


def _pair_outcome(pos: float, companion: float) -> str:
    if pos > 0 and companion == 0:
        return "paired_correct"
    if pos > 0 and companion > 0:
        return "both_vulnerable"
    if pos == 0 and companion == 0:
        return "both_benign"
    return "reversed"


def _subset_view(pairs: list[dict], negatives: list[dict]) -> dict:
    tp = sum(1 for item in pairs if item["outcome"] == "paired_correct")
    fp = sum(1 for item in negatives if item["score"] > 0)
    return {
        "pairs": len(pairs),
        "recall": _rate(tp, len(pairs)),
        "fpr": _rate(fp, len(negatives)),
    }


def score_repeat(
    attempts: list[dict],
    tasks: list[Task],
    *,
    fpr_cap: float,
    cutoff: str,
    workers: int,
) -> dict:
    by_task: dict[str, dict[str, dict]] = defaultdict(dict)
    for attempt in attempts:
        by_task[attempt["task_id"]][attempt["side"]] = attempt
    stages: dict[str, dict] = {}
    for stage in STAGES:
        positives = []
        negatives = []
        outcomes = {key: 0 for key in PAIR_KEYS}
        for task in tasks:
            if task.kind != "pair":
                continue
            vuln = by_task[task.id]["vulnerable"]
            fixed = by_task[task.id]["fixed"]
            if vuln["error"] or fixed["error"]:
                outcomes["error"] += 1
                if not fixed["error"]:
                    negatives.append(
                        {
                            "score": _side_score(fixed, stage, oracle_only=False),
                            "split": task.split,
                            "date": task.disclosure_date,
                            "task_id": task.id,
                        }
                    )
                continue
            pos = _side_score(vuln, stage, oracle_only=True)
            companion = _side_score(fixed, stage, oracle_only=False)
            outcome = _pair_outcome(pos, companion)
            outcomes[outcome] += 1
            positives.append(
                {
                    "score": pos,
                    "companion": companion,
                    "cwe": task.cwe,
                    "split": task.split,
                    "date": task.disclosure_date,
                    "task_id": task.id,
                    "outcome": outcome,
                }
            )
            negatives.append(
                {
                    "score": companion,
                    "split": task.split,
                    "date": task.disclosure_date,
                    "task_id": task.id,
                }
            )
        for task in tasks:
            if task.kind != "benign":
                continue
            attempt = by_task[task.id]["benign"]
            if attempt["error"]:
                continue
            negatives.append(
                {
                    "score": _side_score(attempt, stage, oracle_only=False),
                    "split": task.split,
                    "date": None,
                    "task_id": task.id,
                }
            )
        binary = _confusion(positives, negatives, BINARY)
        ranked = _sweep(positives, negatives, fpr_cap)
        if len(negatives) < MIN_NEGATIVES_FOR_YOUDEN:
            ranked["youden"] = YOUDEN_FEW_NEGATIVES
            ranked["youden_threshold"] = None
        recall_per_class: dict[str, float | None] = {}
        for cwe in sorted({item["cwe"] for item in positives if item["cwe"]}):
            group = [item for item in positives if item["cwe"] == cwe]
            hits = sum(1 for item in group if item["outcome"] == "paired_correct")
            recall_per_class[cwe] = _rate(hits, len(group))
        stages[stage] = {
            **binary,
            **ranked,
            "pair_outcomes": outcomes,
            "precision_oracle_matched_dedup": _dedup_precision(attempts, stage),
            "recall_per_class": recall_per_class,
            "_positives": positives,
            "_negatives": negatives,
        }

    headline = stages["disprove"]
    formed_rows = []
    reproduced_rows = []
    disprove_rows = []
    health = {
        "inconclusive": 0,
        "timeouts": 0,
        "errors": 0,
        "zero_verdicts": 0,
        "survived": 0,
        "killed": 0,
    }
    disagreement_num = 0
    disagreement_den = 0
    contract_ok = 0
    contract_n = 0
    poc_n = 0
    finding_n = 0
    for attempt in attempts:
        if attempt["error"]:
            continue
        for finding in attempt["findings"]:
            finding_n += 1
            mech = finding["mech"]
            is_real = bool(mech["oracle_hit"])
            formed_rows.append(
                {"is_real": is_real, "rejected": not mech["formed"], "inconclusive": False}
            )
            if mech["formed"]:
                disagreement_den += 1
                if finding["verdict"] == "kill":
                    disagreement_num += 1
                reproduced_rows.append(
                    {
                        "is_real": is_real,
                        "rejected": not mech["reproduced"],
                        "inconclusive": False,
                    }
                )
                inconclusive = finding["verdict"] == "inconclusive"
                disprove_rows.append(
                    {
                        "is_real": is_real,
                        "rejected": finding["verdict"] == "kill",
                        "inconclusive": inconclusive,
                    }
                )
            if finding["verdict"] == "survive":
                health["survived"] += 1
            elif finding["verdict"] == "kill":
                health["killed"] += 1
            else:
                health["inconclusive"] += 1
                if finding["disprove_timeout"]:
                    health["timeouts"] += 1
                elif finding["disprove_error"]:
                    health["errors"] += 1
                else:
                    health["zero_verdicts"] += 1
            contract_n += 1
            contract_ok += int(mech["path_contract_valid"])
            poc_n += int(mech["poc_signal"])

    hunt_tokens = sum(attempt["tokens"] for attempt in attempts)
    disprove_tokens = sum(
        finding["disprove_tokens"]
        for attempt in attempts
        for finding in attempt["findings"]
    )
    tokens = hunt_tokens + disprove_tokens
    active = sum(attempt["latency_s"] for attempt in attempts) + sum(
        finding["disprove_latency_s"]
        for attempt in attempts
        for finding in attempt["findings"]
    )
    true_findings = headline["pair_outcomes"]["paired_correct"]
    misses = headline["pair_outcomes"]["both_benign"] + headline["pair_outcomes"]["reversed"]
    hunt_errors = sum(1 for attempt in attempts if attempt["error"])
    error_tasks = sorted(
        {attempt["task_id"] for attempt in attempts if attempt.get("error")}
    )
    attempt_errors = sorted(
        (
            {
                "task_id": attempt["task_id"],
                "side": attempt["side"],
                "error": attempt["error"],
                "error_kind": attempt.get("error_kind"),
            }
            for attempt in attempts
            if attempt.get("error")
        ),
        key=lambda row: (row["task_id"], row["side"], row["error"] or ""),
    )
    miss_tasks = sorted(
        item["task_id"]
        for item in headline["_positives"]
        if item["outcome"] != "paired_correct"
    )
    first_true = None
    for task in tasks:
        if task.kind != "pair":
            continue
        vuln = by_task[task.id]["vulnerable"]
        fixed = by_task[task.id]["fixed"]
        if vuln["error"] or fixed["error"]:
            continue
        pos = _side_score(vuln, "disprove", oracle_only=True)
        companion = _side_score(fixed, "disprove", oracle_only=False)
        if _pair_outcome(pos, companion) == "paired_correct":
            known_at = max(vuln["t_offset_s"], fixed["t_offset_s"])
            first_true = known_at if first_true is None else min(first_true, known_at)

    pre_pos = [
        item
        for item in headline["_positives"]
        if item["date"] is not None and item["date"] < cutoff
    ]
    post_pos = [
        item
        for item in headline["_positives"]
        if item["date"] is not None and item["date"] >= cutoff
    ]
    pre_neg = [
        item
        for item in headline["_negatives"]
        if item["date"] is not None and item["date"] < cutoff
    ]
    post_neg = [
        item
        for item in headline["_negatives"]
        if item["date"] is not None and item["date"] >= cutoff
    ]
    splits = {}
    for name in ("train", "dev", "held_out"):
        splits[name] = _subset_view(
            [item for item in headline["_positives"] if item["split"] == name],
            [item for item in headline["_negatives"] if item["split"] == name],
        )

    mech_precision = stages["mech_formed"]["precision"]
    dis_precision = stages["disprove"]["precision"]
    dis_gate = _gate_rates(disprove_rows)
    lift = None
    if mech_precision is not None and dis_precision is not None:
        lift = dis_precision - mech_precision
    frr = dis_gate["false_reject_rate"]
    net = None if lift is None or frr is None else lift - frr
    per_true_tokens = _rate(tokens, true_findings)
    per_true_hunt = _rate(hunt_tokens, true_findings)
    per_true_disprove = _rate(disprove_tokens, true_findings)

    public_stages = {}
    for stage, body in stages.items():
        public_stages[stage] = {
            key: value
            for key, value in body.items()
            if not key.startswith("_")
        }

    return {
        "stages": public_stages,
        "dup_rate": _dup_rate(attempts),
        "gates": {
            "mech_formed": _gate_rates(formed_rows),
            "mech_reproduced": _gate_rates(reproduced_rows),
            "disprove": dis_gate,
            "human": None,
        },
        "disagreement_rate": _rate(disagreement_num, disagreement_den),
        "llm_lift": {
            "precision_mech_formed": mech_precision,
            "precision_disprove": dis_precision,
            "lift": lift,
            "false_reject_cost": frr,
            "net_of_false_reject": net,
        },
        "disprove_health": health,
        "path_contract_validity_rate": _rate(contract_ok, contract_n) if contract_n else 1.0,
        "poc_false_signal_rate": _rate(poc_n, finding_n) if finding_n else 0.0,
        "efficiency": {
            "tokens": tokens,
            "hunt_tokens": hunt_tokens,
            "disprove_tokens": disprove_tokens,
            "mech_tokens": 0,
            "active_seconds": active,
            "wall_seconds": active / workers,
            "errors": hunt_errors + health["errors"] + health["timeouts"],
            "hunt_errors": hunt_errors,
            "misses": misses,
            "true_findings": true_findings,
            "findings_per_1k_tokens": (true_findings / tokens * 1000) if tokens else None,
            "tokens_per_true_finding": {
                "total": per_true_tokens,
                "hunt": per_true_hunt,
                "disprove": per_true_disprove,
                "mech": 0 if true_findings else None,
            },
            "tokens_per_candidate": _rate(tokens, finding_n),
            "active_seconds_per_true_finding": _rate(active, true_findings),
            "time_to_first_true": first_true,
        },
        "cutoff": {
            "pre": _subset_view(pre_pos, pre_neg),
            "post": _subset_view(post_pos, post_neg),
        },
        "splits": splits,
        "error_task_ids": error_tasks,
        "attempt_errors": attempt_errors,
        "miss_task_ids": miss_tasks,
    }


def union_from_hits(hit_sets: list[set[str]], pair_ids: list[str]) -> dict[str, float | None]:
    out: dict[str, float | None] = {}
    if not pair_ids:
        return out
    seen: set[str] = set()
    for index, hits in enumerate(hit_sets, start=1):
        seen |= hits
        out[str(index)] = len(seen & set(pair_ids)) / len(pair_ids)
    return out


def flip_rate(verdict_map: dict[tuple, list[str]]) -> float | None:
    considered = 0
    flipped = 0
    for verdicts in verdict_map.values():
        conclusive = [verdict for verdict in verdicts if verdict in {"kill", "survive"}]
        if len(conclusive) < 2:
            continue
        considered += 1
        if len(set(conclusive)) > 1:
            flipped += 1
    return _rate(flipped, considered)


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def average_tree(rows: list[dict]) -> dict:
    """Mean a list of repeat dicts.

    Keys are the union across repeats. A missing count is zero for that
    repeat. A missing rate, or a rate that is None because the denominator
    was zero, is left out of that key's mean. ``_contributed`` on each
    averaged node records how many repeats entered each numeric mean.
    """
    if not rows:
        return {}
    keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                keys.append(key)
    merged: dict = {}
    contributed: dict[str, int] = {}
    for key in keys:
        present = [row[key] for row in rows if key in row]
        if not present:
            continue
        if all(isinstance(value, dict) for value in present):
            filled = [
                row[key] if key in row and isinstance(row[key], dict) else {}
                for row in rows
            ]
            merged[key] = average_tree(filled)
            continue
        if any(isinstance(value, (list, dict)) for value in present):
            continue
        if all(value is None or isinstance(value, (int, float)) for value in present):
            if all(_is_count(value) for value in present):
                nums: list[float | None] = [float(value) for value in present]
                nums.extend([0.0] * (len(rows) - len(present)))
                merged[key] = _mean(nums)
                contributed[key] = len(rows)
            else:
                nums = [None if value is None else float(value) for value in present]
                merged[key] = _mean(nums)
                contributed[key] = sum(value is not None for value in nums)
            continue
        merged[key] = present[0]
    if contributed:
        merged["_contributed"] = contributed
    return merged


def score_calibration() -> dict:
    raw = load_canaries()
    root = SEED_DIR / raw["tree"]
    oracle = raw["oracle"]
    cases = []
    bad_ok = 0
    bad_n = 0
    true_pass = True
    for case in raw["cases"]:
        finding = normalize_finding(case["finding"])
        actual = apply_mech(finding, root, oracle)
        expect = case["expect"]
        match = all(actual[key] == expect[key] for key in expect)
        if case["role"] == "bad":
            bad_n += 1
            bad_ok += int(match and actual["reproduced"] is False)
        elif case["role"] == "true":
            true_pass = match and actual["reproduced"] is True
        cases.append(
            {
                "id": case["id"],
                "role": case["role"],
                "match": match,
                "formed": actual["formed"],
                "reproduced": actual["reproduced"],
                "oracle_hit": actual["oracle_hit"],
                "poc_signal": actual["poc_signal"],
            }
        )
    return {
        "canary_catch_rate": _rate(bad_ok, bad_n),
        "canary_true_pass": true_pass,
        "target": 1.0,
        "cases": cases,
    }


def is_infra_failure(attempt: dict) -> bool:
    """Transport, timeout, HTTP, and stored cache failures.

    A parsed miss is not one of these. A from-cache hole (``missing cache entry``)
    is a cache miss, not an infrastructure error.
    """
    if attempt.get("cached_failure"):
        return True
    if attempt.get("error_kind") == "cache_miss":
        return False
    if attempt.get("timed_out"):
        return True
    error = attempt.get("error")
    if not error or error in {"unparsed hunt response", "missing cache entry"}:
        return False
    return True


def row_infra_excluded(attempts: list[dict]) -> bool:
    """All calls failed, or a strict majority failed, for this model×difficulty row."""
    count = len(attempts)
    if count == 0:
        return False
    infra = sum(1 for attempt in attempts if is_infra_failure(attempt))
    return infra == count or infra * 2 > count


def pareto(points: list[dict]) -> dict:
    frontier = []
    for point in points:
        dominated = False
        for other in points:
            if other is point:
                continue
            better_or_eq = (
                other["score"] >= point["score"] and other["tokens"] <= point["tokens"]
            )
            strict = other["score"] > point["score"] or other["tokens"] < point["tokens"]
            if better_or_eq and strict:
                dominated = True
                break
        frontier.append({**point, "on_frontier": not dominated})
    return {"objective": "maximize recall_at_fpr_le_0.5pct, minimize tokens", "points": frontier}


def pareto_markdown(table: dict) -> str:
    lines = [
        "# Score vs cost",
        "",
        "| model | difficulty | recall_at_fpr_le_0.5pct | tokens | on_frontier |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for point in table["points"]:
        lines.append(
            "| {model} | {difficulty} | {score:.6f} | {tokens:.1f} | {flag} |".format(
                model=point["model"],
                difficulty=point["difficulty"],
                score=point["score"],
                tokens=point["tokens"],
                flag="yes" if point["on_frontier"] else "no",
            )
        )
    for point in table.get("excluded") or []:
        lines.append(
            f"| {point['model']} | {point['difficulty']} | excluded |  | no |"
        )
    lines.append("")
    return "\n".join(lines)


def build_scorecard(
    attempts: list[dict],
    tasks: list[Task],
    *,
    mode: str,
    k: int,
    workers: int,
    fpr_cap: float,
    false_reject_max: float,
    on_breach: str,
    cache_hits: int,
    cache_misses: int,
    cache_misses_by_side: dict | None = None,
    job_count: int | None = None,
    from_cache: bool = False,
) -> dict:
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for attempt in attempts:
        grouped[(attempt["model"], attempt["difficulty"], attempt["repeat"])].append(attempt)
    models = []
    for attempt in attempts:
        if attempt["model"] not in models:
            models.append(attempt["model"])
    difficulties = []
    for attempt in attempts:
        if attempt["difficulty"] not in difficulties:
            difficulties.append(attempt["difficulty"])
    pair_ids = [task.id for task in tasks if task.kind == "pair"]
    calibration = score_calibration()
    model_body: dict = {}
    warnings: list[str] = []
    gate_rows = []
    if k < 3:
        warnings.append(f"k={k} is below 3; confidence intervals need at least 3 repeats")
    if calibration["canary_catch_rate"] != 1.0 or not calibration["canary_true_pass"]:
        warnings.append("canary catch rate is below the 100% target")
    side_misses = {"vulnerable": 0, "fixed": 0, "benign": 0}
    for side, count in (cache_misses_by_side or {}).items():
        if side in side_misses:
            side_misses[side] = int(count)
    holes = cache_misses if from_cache else 0
    stored_failures = sum(1 for attempt in attempts if attempt.get("cached_failure"))
    if job_count:
        coverage = (job_count - holes) / job_count if from_cache else cache_hits / job_count
    else:
        coverage = None
    partial = bool(from_cache and holes > 0)
    if partial:
        warnings.append(
            "INCOMPLETE CACHE: "
            f"{holes} cache misses, coverage {coverage:.6f}, "
            f"vulnerable={side_misses['vulnerable']}, fixed={side_misses['fixed']}, "
            f"benign={side_misses['benign']}. Scorecard is partial."
        )

    for model in models:
        cutoff = next(item["knowledge_cutoff"] for item in attempts if item["model"] == model)
        diff_body = {}
        for difficulty in difficulties:
            repeats = []
            hit_sets = []
            flips: dict[tuple, list[str]] = defaultdict(list)
            for repeat in range(k):
                rows = grouped[(model, difficulty, repeat)]
                scored = score_repeat(
                    rows, tasks, fpr_cap=fpr_cap, cutoff=cutoff, workers=workers
                )
                scored["repeat"] = repeat
                repeats.append(scored)
                hits = set()
                outcomes = scored["stages"]["disprove"]["pair_outcomes"]
                del outcomes
                by_task: dict[str, dict[str, dict]] = defaultdict(dict)
                for attempt in rows:
                    by_task[attempt["task_id"]][attempt["side"]] = attempt
                    for finding in attempt["findings"]:
                        flips[
                            (attempt["task_id"], attempt["side"], finding["stable_key"])
                        ].append(finding["verdict"])
                for task_id in pair_ids:
                    vuln = by_task[task_id]["vulnerable"]
                    fixed = by_task[task_id]["fixed"]
                    if vuln["error"] or fixed["error"]:
                        continue
                    pos = _side_score(vuln, "disprove", oracle_only=True)
                    companion = _side_score(fixed, "disprove", oracle_only=False)
                    if _pair_outcome(pos, companion) == "paired_correct":
                        hits.add(task_id)
                hit_sets.append(hits)
            mean = average_tree([{key: value for key, value in row.items() if key != "repeat"} for row in repeats])
            # average_tree skips lists; surface ids from repeat 0 only via repeats.
            youden_values = [row["stages"]["disprove"]["youden"] for row in repeats]
            youden_ci = (
                ci95(youden_values)
                if all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in youden_values)
                else None
            )
            ci = {
                "recall_at_fpr_le_0.5pct": ci95(
                    [row["stages"]["disprove"]["recall_at_fpr_le_0.5pct"] for row in repeats]
                ),
                "youden": youden_ci,
                "findings_per_1k_tokens": ci95(
                    [row["efficiency"]["findings_per_1k_tokens"] for row in repeats]
                ),
            }
            frr = mean["gates"]["disprove"]["false_reject_rate"]
            status = "ok"
            if frr is not None and frr > false_reject_max:
                status = on_breach
                warnings.append(
                    f"{model} {difficulty} disprove false-reject rate {frr:.4f} "
                    f"exceeds {false_reject_max:.4f} ({on_breach})"
                )
            gate_rows.append(
                {
                    "model": model,
                    "difficulty": difficulty,
                    "false_reject_rate": frr,
                    "status": status,
                }
            )
            diff_body[difficulty] = {
                "repeats": repeats,
                "mean": mean,
                "ci95": ci,
                "union_at_n": union_from_hits(hit_sets, pair_ids),
                "verdict_flip_rate": flip_rate(flips),
            }
        model_body[model] = {"knowledge_cutoff": cutoff, "difficulties": diff_body}

    points = []
    operating_fprs: dict[tuple[str, str], float | None] = {}
    excluded_points = []
    for model, body in model_body.items():
        for difficulty, diff in body["difficulties"].items():
            row_attempts = [
                attempt
                for attempt in attempts
                if attempt["model"] == model and attempt["difficulty"] == difficulty
            ]
            mean = diff["mean"]
            if row_infra_excluded(row_attempts):
                infra = sum(1 for attempt in row_attempts if is_infra_failure(attempt))
                diff["excluded"] = True
                diff["exclude_reason"] = "infra_errors"
                warnings.append(
                    f"{model} {difficulty} excluded: infrastructure errors on "
                    f"{infra}/{len(row_attempts)} calls"
                )
                excluded_points.append(
                    {
                        "model": model,
                        "difficulty": difficulty,
                        "tokens": mean["efficiency"]["tokens"],
                        "wall_seconds": mean["efficiency"]["wall_seconds"],
                        "errors": mean["efficiency"]["errors"],
                        "misses": mean["efficiency"]["misses"],
                    }
                )
                continue
            diff["excluded"] = False
            diff["exclude_reason"] = None
            recall = mean["stages"]["disprove"]["recall_at_fpr_le_0.5pct"]
            operating_fpr = mean["stages"]["disprove"]["fpr_at_operating_point"]
            if recall is None:
                recall = 0.0
            operating_fprs[(model, difficulty)] = operating_fpr
            points.append(
                {
                    "model": model,
                    "difficulty": difficulty,
                    "score": recall,
                    "tokens": mean["efficiency"]["tokens"] or 0.0,
                    "wall_seconds": mean["efficiency"]["wall_seconds"],
                    "findings_per_1k_tokens": mean["efficiency"]["findings_per_1k_tokens"],
                }
            )
    frontier = pareto(points)
    frontier["excluded"] = [
        {
            "model": point["model"],
            "difficulty": point["difficulty"],
            "reason": "infra_errors",
        }
        for point in excluded_points
    ]
    leaderboard_rows = []
    for point in sorted(
        frontier["points"],
        key=lambda item: (item["difficulty"], -item["score"], item["tokens"], item["model"]),
    ):
        diff = model_body[point["model"]]["difficulties"][point["difficulty"]]
        mean = diff["mean"]
        youden = mean["stages"]["disprove"]["youden"]
        leaderboard_rows.append(
            {
                "model": point["model"],
                "difficulty": point["difficulty"],
                "recall_at_fpr_le_0.5pct": point["score"],
                "vd_s": point["score"],
                "youden": youden,
                "youden_in_ranking": youden != YOUDEN_FEW_NEGATIVES,
                "precision": mean["stages"]["disprove"]["precision"],
                "fpr": operating_fprs[(point["model"], point["difficulty"])],
                "tokens": point["tokens"],
                "wall_seconds": point["wall_seconds"],
                "findings_per_1k_tokens": point["findings_per_1k_tokens"],
                "errors": mean["efficiency"]["errors"],
                "misses": mean["efficiency"]["misses"],
                "false_reject_rate": mean["gates"]["disprove"]["false_reject_rate"],
                "on_frontier": point["on_frontier"],
                "excluded": False,
                "exclude_reason": None,
            }
        )
    for index, row in enumerate(leaderboard_rows, start=1):
        row["rank"] = index
    for point in excluded_points:
        leaderboard_rows.append(
            {
                "model": point["model"],
                "difficulty": point["difficulty"],
                "recall_at_fpr_le_0.5pct": None,
                "vd_s": None,
                "youden": None,
                "youden_in_ranking": False,
                "precision": None,
                "fpr": None,
                "tokens": point["tokens"],
                "wall_seconds": point["wall_seconds"],
                "findings_per_1k_tokens": None,
                "errors": point["errors"],
                "misses": point["misses"],
                "false_reject_rate": None,
                "on_frontier": False,
                "excluded": True,
                "exclude_reason": "infra_errors",
                "rank": None,
            }
        )

    breach = any(row["status"] == "fail" for row in gate_rows)
    return {
        "scorecard_version": 1,
        "mode": mode,
        "scores_are_synthetic": mode == "stub",
        "llm_judge": None,
        "headline_metric": "recall_at_fpr_le_0.5pct",
        "fpr_cap": fpr_cap,
        "k": k,
        "workers": workers,
        "wrote_results": False,
        "cache_hits": cache_hits,
        "cache_misses": cache_misses,
        "cache_coverage": coverage,
        "stored_failure_count": stored_failures,
        "partial": partial,
        "seed": {
            "pairs": sum(1 for task in tasks if task.kind == "pair"),
            "benign": sum(1 for task in tasks if task.kind == "benign"),
            "label_source": "hand-verified-oracle",
            "excluded_label_sets": ["BigVul", "Devign"],
            "scale_up": SCALE_UP,
            "tasks": [
                {
                    "id": task.id,
                    "kind": task.kind,
                    "cwe": task.cwe,
                    "component": task.component,
                    "disclosure_date": task.disclosure_date,
                    "split": task.split,
                    "difficulty_levels": list(task.difficulty_levels),
                    "content_hash": task.content_hash,
                    "oracle_sink": None
                    if task.oracle is None
                    else {
                        "path": task.oracle.path,
                        "line": task.oracle.line,
                        "symbol": task.oracle.symbol,
                    },
                }
                for task in tasks
            ],
        },
        "warnings": warnings,
        "disprove_gate": {
            "false_reject_max": false_reject_max,
            "on_breach": on_breach,
            "failed": breach,
            "rows": gate_rows,
        },
        "calibration": calibration,
        "models": model_body,
        "leaderboard": {
            "headline_metric": "recall_at_fpr_le_0.5pct",
            "llm_judge": None,
            "scored_row_count": sum(1 for row in leaderboard_rows if not row["excluded"]),
            "infra_error_row_count": sum(1 for row in leaderboard_rows if row["excluded"]),
            "infra_error_count": sum(1 for attempt in attempts if is_infra_failure(attempt)),
            "cache_miss_count": holes,
            "cache_misses_by_side": side_misses,
            "cache_coverage": coverage,
            "stored_failure_count": stored_failures,
            "partial": partial,
            "rows": leaderboard_rows,
        },
        "pareto": frontier,
        "pareto_markdown": pareto_markdown(frontier),
        "not_measured": [
            "human_accept_rate",
            "inbox_precision",
            "pending_llm_dwell",
            "gpu_seconds",
            "recon_component_recall",
        ],
    }


def freeze(obj: object) -> object:
    if isinstance(obj, bool) or obj is None or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return round(obj, 6)
    if isinstance(obj, dict):
        return {key: freeze(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [freeze(value) for value in obj]
    return obj

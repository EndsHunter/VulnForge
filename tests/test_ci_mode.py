"""Headless CI mode (#188): budgets, thresholds, outcome codes, e2e offline."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from vulnforge.ci import exit_codes as ci_codes
from vulnforge.ci.budget import (
    CostGuard,
    Price,
    PriceTable,
    estimate_cost,
    parse_duration,
)
from vulnforge.ci.outcome import (
    Threshold,
    classify_ralph_stop,
    confirmed_integrity_errors,
    matched_findings,
    parse_fail_on_states,
    parse_min_severity,
    task_integrity_errors,
)
from vulnforge.ci.runner import CIOptions, last_ralph_stop_event, load_ralph_module, run_ci
from vulnforge.control import exit_codes as protocol_codes
from vulnforge.db import Database
from vulnforge.paths import PROJECT_ROOT


# exit codes ------------------------------------------------------------------


def test_outcome_codes_are_separate_from_protocol_codes():
    assert (ci_codes.CI_PASS, ci_codes.CI_THRESHOLD, ci_codes.CI_ERROR) == (0, 1, 2)
    protocol = {
        protocol_codes.EXIT_IDLE,
        protocol_codes.EXIT_BUSY,
        protocol_codes.EXIT_INFRA,
        protocol_codes.EXIT_CONFIG,
    }
    assert not protocol & {ci_codes.CI_THRESHOLD, ci_codes.CI_ERROR}


# durations -------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,secs",
    [("3600", 3600), ("90s", 90), ("45m", 2700), ("2h", 7200), ("1h30m", 5400), (60, 60)],
)
def test_parse_duration(raw, secs):
    assert parse_duration(raw) == secs


@pytest.mark.parametrize("raw", ["abc", "0", "-5", "1h1h", "1h30", "m", "5d"])
def test_parse_duration_rejects(raw):
    with pytest.raises(ValueError):
        parse_duration(raw)


def test_parse_duration_blank_is_none():
    assert parse_duration(None) is None
    assert parse_duration("  ") is None


# cost ------------------------------------------------------------------------


def _summary(by_model: dict, **totals) -> dict:
    out = {"by_model": by_model}
    for k in ("prompt_tokens", "completion_tokens", "cache_read_tokens", "cache_creation_tokens", "llm_calls"):
        out[k] = totals.get(k, sum(int(r.get(k) or 0) for r in by_model.values()))
    return out


def test_cost_bills_cache_tokens_as_input():
    """Anthropic cache tokens sit outside input_tokens; the cap must count them."""
    prices = PriceTable(by_model={"m": Price(3.0, 15.0)})
    s = _summary(
        {"m": {"prompt_tokens": 1_000_000, "cache_read_tokens": 1_000_000,
               "cache_creation_tokens": 0, "completion_tokens": 100_000, "llm_calls": 3}}
    )
    est = estimate_cost(s, prices)
    assert est.usd == pytest.approx(3.0 * 2 + 1.5)
    assert not est.unpriced_models and not est.unmeasured


def test_cost_default_price_covers_other_models_and_unattributed():
    prices = PriceTable(default=Price(1.0, 2.0))
    s = _summary(
        {"a": {"prompt_tokens": 500_000, "completion_tokens": 0, "llm_calls": 1}},
        prompt_tokens=1_500_000,
        completion_tokens=1_000_000,
        llm_calls=2,
    )
    est = estimate_cost(s, prices)
    # a: 0.5 ; unattributed: 1.0 input + 2.0 output
    assert est.usd == pytest.approx(0.5 + 1.0 + 2.0)


def test_cost_unpriced_model_reported():
    prices = PriceTable(by_model={"a": Price(1, 1)})
    s = _summary({"b": {"prompt_tokens": 10, "completion_tokens": 5, "llm_calls": 1}})
    est = estimate_cost(s, prices)
    assert est.unpriced_models == ["b"]
    assert est.unpriced_tokens == 15


def test_cost_counts_only_delta_since_baseline():
    prices = PriceTable(default=Price(1.0, 1.0))
    base = _summary({"m": {"prompt_tokens": 9_000_000, "completion_tokens": 0, "llm_calls": 9}})
    cur = _summary({"m": {"prompt_tokens": 10_000_000, "completion_tokens": 0, "llm_calls": 10}})
    assert estimate_cost(cur, prices, baseline=base).usd == pytest.approx(1.0)


def test_cost_calls_without_tokens_is_unmeasured():
    prices = PriceTable(default=Price(1.0, 1.0))
    s = _summary({"m": {"prompt_tokens": 0, "completion_tokens": 0, "llm_calls": 4}})
    assert estimate_cost(s, prices).unmeasured


def test_price_table_sources(tmp_path: Path):
    cfg = {"ci": {"pricing": {"m": {"input_per_mtok": 2, "output_per_mtok": 4},
                              "default": {"input_per_mtok": 0, "output_per_mtok": 0}}}}
    t = PriceTable.from_sources(cfg)
    assert t.for_model("m") == Price(2, 4)
    assert t.for_model("other") == Price(0, 0)
    t2 = PriceTable.from_sources(cfg, default_input=1, default_output=1)
    assert t2.for_model("other") == Price(1, 1)
    assert t2.for_model("m") == Price(2, 4)
    with pytest.raises(ValueError):
        PriceTable.from_sources({}, default_input=1)
    with pytest.raises(ValueError):
        PriceTable.from_sources({"ci": {"pricing": {"m": {"input_per_mtok": "x"}}}})


def _write_usage(run_dir: Path, summary: dict) -> None:
    (run_dir / "llm_usage_summary.json").write_text(json.dumps(summary), encoding="utf-8")


def test_cost_guard_stops_at_cap_and_fails_closed(tmp_path: Path):
    _write_usage(tmp_path, _summary({"m": {"prompt_tokens": 1_000_000, "completion_tokens": 0, "llm_calls": 1}}))
    guard = CostGuard(tmp_path, 1.0, PriceTable(default=Price(1.0, 1.0)))
    assert guard() is None  # baseline excludes prior spend
    _write_usage(tmp_path, _summary({"m": {"prompt_tokens": 2_000_000, "completion_tokens": 0, "llm_calls": 2}}))
    hit = guard()
    assert hit and hit["reason"] == "budget_cost" and hit["estimate_usd"] == pytest.approx(1.0)

    guard2 = CostGuard(tmp_path, 100.0, PriceTable(by_model={"x": Price(1, 1)}))
    _write_usage(tmp_path, _summary({"m": {"prompt_tokens": 3_000_000, "completion_tokens": 0, "llm_calls": 3}}))
    assert guard2()["reason"] == "cost_unpriced"

    (tmp_path / "llm_usage_summary.json").write_text("{not json", encoding="utf-8")
    assert guard2()["reason"] == "cost_unmeasured"


# thresholds ------------------------------------------------------------------


def _f(fid: int, state: str, sev=None, **body):
    b = {"title": f"finding {fid}", **body}
    if sev is not None:
        b["severity_claim"] = sev
    return SimpleNamespace(id=fid, state=state, body=b, stable_key=f"k{fid}")


def test_parse_threshold_flags():
    assert parse_fail_on_states(["needs_human,confirmed"]) == {"needs_human", "confirmed"}
    with pytest.raises(ValueError):
        parse_fail_on_states(["rejected_llm"])
    assert parse_min_severity("high") == "HIGH"
    with pytest.raises(ValueError):
        parse_min_severity("spicy")


def test_threshold_state_only():
    t = Threshold(states=frozenset({"needs_human"}))
    fs = [_f(1, "needs_human"), _f(2, "rejected_llm"), _f(3, "confirmed"), _f(4, "candidate")]
    assert [m["id"] for m in matched_findings(fs, t)] == [1]


def test_threshold_severity_at_or_above_and_unrated_fail_closed():
    t = Threshold(min_severity="HIGH")
    fs = [
        _f(1, "needs_human", "critical"),
        _f(2, "needs_human", "high"),
        _f(3, "needs_human", "medium"),
        _f(4, "confirmed"),  # unrated → meets
        _f(5, "rejected_mech", "critical"),  # never live
    ]
    got = {m["id"]: m for m in matched_findings(fs, t)}
    assert sorted(got) == [1, 2, 4]
    assert got[4]["severity"] is None and "severity_unrated" in got[4]["reasons"]


def test_threshold_both_flags_are_and():
    t = Threshold(states=frozenset({"confirmed"}), min_severity="MEDIUM")
    fs = [_f(1, "needs_human", "critical"), _f(2, "confirmed", "low"), _f(3, "confirmed", "high")]
    assert [m["id"] for m in matched_findings(fs, t)] == [3]


def test_no_threshold_never_matches():
    assert matched_findings([_f(1, "needs_human", "critical")], Threshold()) == []


def test_needs_human_match_says_needs_review():
    m = matched_findings([_f(1, "needs_human")], Threshold(states=frozenset({"needs_human"})))
    assert "not proven" in m[0]["meaning"]


# integrity -------------------------------------------------------------------


def test_confirmed_without_human_review_is_integrity_error():
    reviewed = _f(2, "confirmed", human_review_latest={"to_state": "confirmed"})
    fs = [_f(1, "confirmed"), reviewed, _f(3, "confirmed")]
    errs = confirmed_integrity_errors(fs, confirmed_before=[3])
    assert errs == ["confirmed_without_human_review: finding 1"]


def test_task_integrity_only_when_drained():
    assert task_integrity_errors({"deadletter": 3}, completed=True)
    assert not task_integrity_errors({"deadletter": 3, "succeeded": 1}, completed=True)
    assert not task_integrity_errors({"failed_task": 2, "queued": 5}, completed=False)
    assert not task_integrity_errors({}, completed=True)


@pytest.mark.parametrize(
    "code,event,reason,is_err",
    [
        (10, {"event": "idle"}, "idle", False),
        (40, {"event": "budget_wall"}, "budget_wall", False),
        (40, {"event": "budget_iterations"}, "budget_iterations", False),
        (40, {"event": "budget_cost", "reason": "budget_cost"}, "budget_cost", False),
        (40, {"event": "budget_cost", "reason": "cost_unpriced"}, "cost_unpriced", True),
        (40, {"event": "budget_cost", "reason": "cost_unmeasured"}, "cost_unmeasured", True),
        (0, {"event": "stop_file"}, "stop_file", False),
        (20, {"event": "infra_give_up"}, "infra_give_up", True),
        (30, {"event": "config_halt"}, "config_halt", True),
        (130, None, "interrupted", True),
        (99, None, "unknown", True),
    ],
)
def test_classify_ralph_stop(code, event, reason, is_err):
    got_reason, err = classify_ralph_stop(code, event)
    assert got_reason == reason
    assert bool(err) is is_err


def test_last_ralph_stop_event_respects_offset(tmp_path: Path):
    ev = tmp_path / "events.jsonl"
    ev.write_text(json.dumps({"source": "ralph", "event": "idle"}) + "\n", encoding="utf-8")
    off = ev.stat().st_size
    with ev.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"source": "ralph", "event": "run_once"}) + "\n")
        f.write(json.dumps({"source": "ralph", "event": "budget_wall"}) + "\n")
    assert last_ralph_stop_event(tmp_path, off)["event"] == "budget_wall"
    assert last_ralph_stop_event(tmp_path, ev.stat().st_size) is None


# Ralph budget hook -----------------------------------------------------------


def test_ralph_budget_check_stops_before_lease(tmp_path: Path, monkeypatch):
    ralph = load_ralph_module()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    calls = {"run_once": 0, "check": 0}

    def fake_invoke(cfg):
        calls["run_once"] += 1
        return ralph.EXIT_PROGRESS

    def check():
        calls["check"] += 1
        return {"event": "budget_cost", "reason": "budget_cost"} if calls["check"] > 2 else None

    monkeypatch.setattr(ralph, "invoke_run_once", fake_invoke)
    monkeypatch.setattr(ralph, "project_on_stop", lambda cfg, reason: None)
    monkeypatch.setattr(ralph, "_release_own_runner_meta", lambda cfg: None)
    cfg = ralph.RalphConfig(
        run_dir=run_dir, max_iterations=50, max_infra_retries=3, sleep_seconds=0,
        infra_backoff_base=0, vf_command=["vf"], stop_file=run_dir / "STOP",
        config_path=None, dry_run=False, verbose=False, task_timeout=None,
        max_wall_seconds=None, max_tasks=None, budget_check=check,
    )
    assert ralph.run_loop(cfg) == ralph.RALPH_BUDGET
    assert calls["run_once"] == 2  # third check stopped the third lease
    assert last_ralph_stop_event(run_dir)["reason"] == "budget_cost"


def test_ralph_config_without_budget_check_still_constructs():
    ralph = load_ralph_module()
    cfg = ralph.RalphConfig(
        run_dir=None, max_iterations=1, max_infra_retries=1, sleep_seconds=0,
        infra_backoff_base=0, vf_command=["vf"], stop_file=None, config_path=None,
        dry_run=True, verbose=False, task_timeout=None, max_wall_seconds=None,
        max_tasks=None,
    )
    assert cfg.budget_check is None


# end-to-end (offline, FakeLLMClient) -----------------------------------------


def _fake_tool(name: str, arguments: dict):
    from vulnforge.llm import LLMResult, ResponseClass

    return LLMResult(
        ok=True,
        classification=ResponseClass.OK,
        content="",
        tool_calls=[{"id": "1", "name": name, "arguments": arguments}],
        raw=None,
        model_id="fake",
    )


_ARCH = {
    "summary": "Tiny vulnerable SQLi toy app",
    "trust_boundaries": ["user input"],
    "components": [{"name": "app", "path_hints": ["app.py"]}],
    "input_surfaces": ["search q param"],
    "hunt_focus": [{"area": "app", "class": "injection", "path_hints": ["app.py"]}],
}

_CANDIDATE = {
    "title": "SQL injection in search_users",
    "summary": "User input q is interpolated into a SQL string in search_users.",
    "weakness_class": "injection",
    "severity_claim": "HIGH",
    "sink_path": "app.py",
    "sink_symbol": "search_users",
    "citations": [{"path": "app.py", "start_line": 9, "end_line": 12, "symbol": "search_users"}],
    "threat_model": {
        "attacker": "remote unauthenticated user",
        "boundary": "HTTP request into the database",
        "impact": "read or modify application rows",
    },
}


def _tool_names(tools) -> set[str]:
    names = set()
    for t in tools or []:
        if isinstance(t, dict):
            fn = t.get("function") if isinstance(t.get("function"), dict) else t
            if fn.get("name"):
                names.add(str(fn["name"]))
        elif getattr(t, "name", None):
            names.add(str(t.name))
    return names


def _scripted_chat(mode: str, tokens: int = 0):
    """FakeLLMClient.chat that answers by the stage's tool set (fresh per task).

    ``tokens`` > 0 attaches provider-style usage to each reply so the cost
    cap sees real spend.
    """
    from vulnforge.llm import LLMResult, ResponseClass, TokenUsage

    def chat(self, messages, tools=None, temperature=0.3, max_tokens=None, timeout=None):
        r = _answer(self, tools)
        if tokens and r.ok:
            r.usage = TokenUsage(prompt_tokens=tokens, completion_tokens=0,
                                 total_tokens=tokens, source="provider")
        return r

    def _answer(self, tools):
        names = _tool_names(tools)
        step = self._i
        self._i += 1
        if mode == "dead":
            return LLMResult(ok=False, classification=ResponseClass.INFRA, content=None,
                             tool_calls=[], raw=None, model_id="fake", error="connection refused")
        if "submit_architecture" in names:
            return _fake_tool("submit_architecture", _ARCH)
        if "submit_candidate" in names and mode == "vuln":
            if step == 0:
                return _fake_tool("write_evidence", {"relpath": "notes.md",
                                                     "content": "search_users builds SQL with an f-string from q."})
            return _fake_tool("submit_candidate", _CANDIDATE)
        if "submit_none" in names:
            return _fake_tool("submit_none", {"reason": "no issue after review of app.py"})
        return LLMResult(ok=False, classification=ResponseClass.EMPTY, content=None,
                         tool_calls=[], raw=None, model_id="fake", error="unscripted")

    return chat


@pytest.fixture
def offline_ci(monkeypatch, tmp_path: Path):
    """Real Ralph loop + in-process vf run-once + FakeLLMClient (no network)."""
    import vulnforge.cli as cli_mod
    from vulnforge.llm import FakeLLMClient

    base = yaml.safe_load((PROJECT_ROOT / "config" / "default.yaml").read_text(encoding="utf-8"))

    def make_cfg(mode: str) -> dict:
        cfg = json.loads(json.dumps(base))
        llm = cfg.setdefault("llm", {})
        llm.update({"fake": True, "fake_responses": [], "model": "fake",
                    "max_tool_rounds": 4, "recon_orchestrator": "inprocess",
                    "architecture_llm_merge": False, "retry_infra": 0})
        cfg.setdefault("stages", {})["validate_llm"] = False
        run = cfg.setdefault("run", {})
        run.update({"runs_root": str(tmp_path / "runs"), "max_task_attempts": 2,
                    "architecture_llm_merge": False})
        return cfg

    state = {"mode": "clean"}
    monkeypatch.setattr(cli_mod, "load_config", lambda path=None: make_cfg(state["mode"]))

    def install(mode: str, tokens: int = 0):
        state["mode"] = mode
        monkeypatch.setattr(FakeLLMClient, "chat", _scripted_chat(mode, tokens))

    ralph = load_ralph_module()

    def invoke(cfg):
        return cli_mod.main(["run-once", "--run-dir", str(cfg.run_dir)])

    monkeypatch.setattr(ralph, "invoke_run_once", invoke)
    monkeypatch.setattr(ralph, "project_on_stop", lambda cfg, reason: None)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    return SimpleNamespace(install=install, make_cfg=make_cfg, cli=cli_mod, tmp=tmp_path)


def _ci(env, *extra: str) -> int:
    return env.cli.main(["ci", "--runs-root", str(env.tmp / "runs"), *extra])


def _result(env) -> dict:
    out = env.tmp / "out" / "ci_result.json"
    return json.loads(out.read_text(encoding="utf-8"))


def test_e2e_clean_run_passes(offline_ci, toy_sqli: Path):
    offline_ci.install("clean")
    code = _ci(offline_ci, "--target", str(toy_sqli), "--fail-on-state", "needs_human",
               "--output-dir", str(offline_ci.tmp / "out"), "-q")
    rec = _result(offline_ci)
    assert code == ci_codes.CI_PASS, rec
    assert rec["outcome"] == "pass" and rec["completed"] is True
    assert rec["ralph"]["stop_reason"] == "idle"
    assert (offline_ci.tmp / "out" / "report" / "REPORT.md").is_file()
    assert (Path(rec["run_dir"]) / "ci_result.json").is_file()


def test_e2e_needs_human_meets_threshold_and_never_confirms(offline_ci, toy_sqli: Path):
    offline_ci.install("vuln")
    out = offline_ci.tmp / "out"
    code = _ci(offline_ci, "--target", str(toy_sqli), "--fail-on-state", "needs_human",
               "--fail-on-severity", "high", "--output-dir", str(out), "-q")
    rec = _result(offline_ci)
    assert code == ci_codes.CI_THRESHOLD, rec
    assert rec["findings"].get("needs_human", 0) >= 1
    assert rec["findings"].get("confirmed", 0) == 0
    m = rec["matched_findings"][0]
    assert m["state"] == "needs_human" and m["severity"] == "high"
    assert "not proven" in m["meaning"]
    assert "never sets confirmed" in rec["honesty"]

    # Same run without a threshold: pass. Resume path, no init.
    code2 = _ci(offline_ci, "--run-dir", rec["run_dir"], "--output-dir", str(out), "-q")
    assert code2 == ci_codes.CI_PASS
    assert _result(offline_ci)["mode"] == "resume"


def test_e2e_dead_endpoint_is_integrity_error(offline_ci, toy_sqli: Path):
    offline_ci.install("dead")
    code = _ci(offline_ci, "--target", str(toy_sqli), "--output-dir",
               str(offline_ci.tmp / "out"), "-q")
    rec = _result(offline_ci)
    assert code == ci_codes.CI_ERROR, rec
    assert rec["outcome"] == "error"


def test_e2e_time_budget_stop_is_not_failure(offline_ci, toy_sqli: Path, monkeypatch):
    """A budget stop leaves a coverage gap; with no threshold met it exits 0."""
    offline_ci.install("clean")
    ralph = load_ralph_module()
    clock = {"t": 0.0}

    def mono():
        clock["t"] += 1000.0
        return clock["t"]

    monkeypatch.setattr(ralph.time, "monotonic", mono)
    code = _ci(offline_ci, "--target", str(toy_sqli), "--max-time", "1s",
               "--output-dir", str(offline_ci.tmp / "out"), "-q")
    rec = _result(offline_ci)
    assert code == ci_codes.CI_PASS, rec
    assert rec["ralph"]["stop_reason"] == "budget_wall"
    assert rec["completed"] is False
    assert any("coverage gap" in w for w in rec["warnings"])
    assert rec["coverage_gaps"].get("queued", 0) >= 1


def test_e2e_cost_cap_stops_leasing_and_passes(offline_ci, toy_sqli: Path):
    """Recon spends 1M tokens at $1/Mtok; a $0.50 cap stops before the next lease."""
    offline_ci.install("clean", tokens=1_000_000)
    code = _ci(offline_ci, "--target", str(toy_sqli), "--max-cost-usd", "0.5",
               "--price-input-per-mtok", "1", "--price-output-per-mtok", "1",
               "--output-dir", str(offline_ci.tmp / "out"), "-q")
    rec = _result(offline_ci)
    assert code == ci_codes.CI_PASS, rec
    assert rec["ralph"]["stop_reason"] == "budget_cost"
    assert rec["cost"]["estimate_usd"] >= 0.5
    assert rec["coverage_gaps"].get("queued", 0) >= 1  # hunts left unleased
    assert any("coverage gap" in w for w in rec["warnings"])


def test_e2e_unpriced_model_under_cost_cap_is_error(offline_ci, toy_sqli: Path):
    """Spend on a model with no price: the cap can't hold, stop and exit 2."""
    offline_ci.install("clean", tokens=1_000)
    cfg = offline_ci.make_cfg("clean")
    cfg["ci"] = {"pricing": {"some-other-model": {"input_per_mtok": 1, "output_per_mtok": 1}}}
    opts = CIOptions(init_args=SimpleNamespace(**_init_ns(toy_sqli, offline_ci.tmp)),
                     max_cost_usd=100.0, output_dir=offline_ci.tmp / "out", verbose=False)
    res = run_ci(opts, cfg)
    assert res.exit_code == ci_codes.CI_ERROR, res.record
    assert res.record["ralph"]["stop_reason"] == "cost_unpriced"
    assert res.record["cost"]["unpriced_models"]


def _init_ns(target: Path, tmp: Path) -> dict:
    return dict(
        target=target, profile=None, runs_root=tmp / "runs", strategy="discovery",
        docs_path=None, agent_ids=None, operator_notes="", dynamic_skills=False,
        dynamic_skill_count=3, hunt_skill_mode=None, hunt_skill_ids=None,
        model_validate=None, sandbox_poc_validate=False, enqueue_hunts=True,
    )


def test_cost_cap_without_prices_is_config_error(offline_ci, toy_sqli: Path):
    code = _ci(offline_ci, "--target", str(toy_sqli), "--max-cost-usd", "5",
               "--output-dir", str(offline_ci.tmp / "out"), "-q")
    rec = _result(offline_ci)
    assert code == ci_codes.CI_ERROR
    assert rec["run_dir"] is None  # refused before init
    assert any("needs prices" in e for e in rec["errors"])


def test_preexisting_stop_file_is_error(offline_ci, toy_sqli: Path):
    offline_ci.install("clean")
    cfg = offline_ci.make_cfg("clean")
    run_dir = offline_ci.tmp / "r"
    run_dir.mkdir()
    db = Database.create(run_dir / "harness.db")
    db.insert_run("r1", str(toy_sqli), "code_static", "pin", {})
    db.close()
    (run_dir / "STOP").write_text("", encoding="utf-8")
    res = run_ci(CIOptions(run_dir=run_dir, verbose=False), cfg)
    assert res.exit_code == ci_codes.CI_ERROR
    assert any("STOP" in e for e in res.record["errors"])


def test_ci_target_and_run_dir_conflict(offline_ci, toy_sqli: Path, tmp_path: Path):
    assert _ci(offline_ci, "--target", str(toy_sqli), "--run-dir", str(tmp_path)) == ci_codes.CI_ERROR
    assert _ci(offline_ci) == ci_codes.CI_ERROR


def test_ci_bad_flag_values_exit_2(offline_ci, toy_sqli: Path):
    for extra in (["--fail-on-state", "rejected_llm"], ["--fail-on-severity", "spicy"],
                  ["--max-time", "soon"]):
        code = _ci(offline_ci, "--target", str(toy_sqli), "--output-dir",
                   str(offline_ci.tmp / "out"), *extra)
        assert code == ci_codes.CI_ERROR, extra


def test_github_step_summary_written(offline_ci, toy_sqli: Path, monkeypatch):
    offline_ci.install("vuln")
    summary = offline_ci.tmp / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    code = _ci(offline_ci, "--target", str(toy_sqli), "--fail-on-state", "needs_human",
               "--output-dir", str(offline_ci.tmp / "out"), "-q")
    assert code == ci_codes.CI_THRESHOLD
    text = summary.read_text(encoding="utf-8")
    assert "VulnForge CI: threshold" in text
    assert "never sets confirmed" in text

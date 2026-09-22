"""Hunt MoA resolve + merge proof (spike #68). Never emits confirmed."""

from __future__ import annotations

from pathlib import Path

import yaml

from vulnforge.findings.identity import compute_stable_key
from vulnforge.findings.merge import merge_key
from vulnforge.stages import hunt_moa
from vulnforge.stages.hunt_moa import (
    EMIT_STATE,
    build_hunt_moa_body,
    hunt_moa_enabled,
    merge_hunt_candidates,
    resolve_hunt_perspectives,
    result_emits_confirmed,
)


def _cand(
    *,
    title: str,
    path: str = "app.py",
    symbol: str = "search_users",
    weakness: str = "injection",
    citations: int = 1,
    evidence_id: str | None = "ev-1",
    summary: str = "User input reaches a concatenated SQL query.",
    extra: dict | None = None,
) -> dict:
    body = {
        "title": title,
        "summary": summary,
        "weakness_class": weakness,
        "sink_path": path,
        "sink_symbol": symbol,
        "citations": [
            {"path": path, "start_line": 10 + i, "end_line": 12 + i, "symbol": symbol}
            for i in range(citations)
        ],
        "threat_model": {
            "attacker": "unauthenticated web user",
            "impact": "read or modify database rows",
        },
    }
    if evidence_id is not None:
        body["evidence_id"] = evidence_id
    if extra:
        body.update(extra)
    return body


def _slot(pid: str, body: dict | None, *, outcome: str | None = None) -> dict:
    if body is None:
        return {
            "perspective_id": pid,
            "outcome": outcome or "none",
            "none_reason": "no sink in scope",
        }
    return {
        "perspective_id": pid,
        "outcome": outcome or "candidate",
        "candidate": body,
    }


def _assert_never_confirmed(result: dict) -> None:
    assert result_emits_confirmed(result) is False
    assert result.get("cell_outcome") != "confirmed"
    for item in result.get("candidates") or []:
        assert item.get("state") == EMIT_STATE
        assert item.get("state") != "confirmed"
        assert (item.get("body") or {}).get("state") != "confirmed"


def test_hunt_moa_flag_defaults_off():
    assert hunt_moa_enabled({}) is False
    assert hunt_moa_enabled({"stages": {}}) is False
    assert hunt_moa_enabled({"stages": {"hunt_moa": False}}) is False
    assert hunt_moa_enabled({"stages": {"hunt_moa": True}}) is True


def test_resolve_hunt_perspectives_defaults():
    v = resolve_hunt_perspectives({})
    assert len(v) >= 2
    assert v[0]["id"] == "sink_driven"
    assert v[0]["prompt"] == "hunt_sink.md"
    ids = [x["id"] for x in v]
    assert "dataflow" in ids
    assert "authz" in ids


def test_resolve_hunt_perspectives_custom_and_model():
    custom = resolve_hunt_perspectives(
        {
            "llm": {
                "hunt_perspectives": [
                    {"id": "a", "prompt": "hunt_sink.md"},
                    {"id": "b", "prompt": "hunt_dataflow.md", "model": "other"},
                    {"id": "skip_me"},
                    "not-a-dict",
                ]
            }
        }
    )
    assert len(custom) == 2
    assert custom[1]["model"] == "other"
    assert custom[0]["id"] == "a"


def test_merge_both_none():
    result = merge_hunt_candidates(
        [
            _slot("sink_driven", None),
            _slot("dataflow", None),
        ]
    )
    _assert_never_confirmed(result)
    assert result["candidates"] == []
    assert result["cell_outcome"] == "none"
    assert result["all_none"] is True
    assert result["requeue_note"]
    assert "all_perspectives_none" in result["requeue_note"]


def test_merge_one_candidate():
    body = _cand(title="SQL injection in search")
    result = merge_hunt_candidates(
        [
            _slot("sink_driven", body),
            _slot("dataflow", None),
        ]
    )
    _assert_never_confirmed(result)
    assert result["cell_outcome"] == "candidate"
    assert result["all_none"] is False
    assert len(result["candidates"]) == 1
    item = result["candidates"][0]
    assert item["state"] == "candidate"
    assert item["agree_count"] == 1
    assert item["perspectives"] == ["sink_driven"]
    assert item["body"]["title"] == "SQL injection in search"
    assert "state" not in item["body"]
    assert result["requeue_note"]
    assert "partial_none" in result["requeue_note"]


def test_merge_two_near_dupes():
    a = _cand(title="SQLi via search_users", citations=1)
    b = _cand(title="Concatenated SQL at search_users", citations=2, evidence_id="ev-2")
    assert merge_key(a) == merge_key(b)
    result = merge_hunt_candidates(
        [
            _slot("sink_driven", a),
            _slot("dataflow", b),
        ]
    )
    _assert_never_confirmed(result)
    assert len(result["candidates"]) == 1
    item = result["candidates"][0]
    assert item["agree_count"] == 2
    assert set(item["perspectives"]) == {"sink_driven", "dataflow"}
    assert item["state"] == "candidate"
    # Richer body (more citations + evidence) is keeper.
    assert item["body"]["title"] == "Concatenated SQL at search_users"
    extras = item["body"].get("near_dup_titles") or []
    assert "SQLi via search_users" in extras


def test_merge_rank_prefers_multi_agree():
    """A lone rich candidate ranks below two perspectives that agree on a sink."""
    rich_alone = _cand(
        title="Rich but single-perspective XSS",
        path="views.py",
        symbol="render_page",
        weakness="client-side",
        citations=8,
        evidence_id="ev-rich",
        summary="Unescaped user HTML is written into the response body in several templates.",
        extra={"poc_relpath": "poc.py"},
    )
    agree_a = _cand(title="SQLi A", citations=1, evidence_id=None, summary="short")
    agree_b = _cand(title="SQLi B", citations=1, evidence_id=None, summary="short")
    result = merge_hunt_candidates(
        [
            _slot("sink_driven", rich_alone),
            _slot("dataflow", agree_a),
            _slot("authz", agree_b),
        ]
    )
    _assert_never_confirmed(result)
    assert len(result["candidates"]) == 2
    top = result["candidates"][0]
    assert top["agree_count"] == 2
    assert top["merge_key"] == merge_key(agree_a)
    assert result["candidates"][1]["agree_count"] == 1
    assert result["candidates"][1]["body"]["title"] == "Rich but single-perspective XSS"


def test_merge_never_emits_confirmed_even_if_input_claims_it():
    poisoned = _cand(title="Poisoned", extra={"state": "confirmed"})
    result = merge_hunt_candidates([_slot("sink_driven", poisoned)])
    _assert_never_confirmed(result)
    assert result["candidates"][0]["state"] == "candidate"
    assert result["candidates"][0]["body"].get("state") != "confirmed"
    assert "confirmed" not in {result["cell_outcome"], result["candidates"][0]["state"]}


def test_merge_empty_and_stable_identity():
    empty = merge_hunt_candidates([])
    _assert_never_confirmed(empty)
    assert empty["cell_outcome"] == "none"
    assert empty["candidates"] == []

    body = _cand(title="Identity")
    result = merge_hunt_candidates([_slot("sink_driven", body)])
    expected = compute_stable_key("code_static", body)
    assert result["candidates"][0]["stable_key"] == expected
    assert result["candidates"][0]["identity"] == expected


def test_build_hunt_moa_body_contract_shape():
    """#71 write / #73 read. Agreement label is not a confirm."""
    slots = [
        {
            "perspective_id": "sink_driven",
            "outcome": "candidate",
            "candidate": _cand(title="SQL injection in search"),
        },
        {
            "perspective_id": "dataflow",
            "outcome": "candidate",
            "candidate": _cand(title="Concatenated SQL"),
        },
        {"perspective_id": "authz", "outcome": "none", "none_reason": "boundary holds"},
    ]
    merged = merge_hunt_candidates(slots)
    record = build_hunt_moa_body(
        slots,
        n_perspectives=3,
        agree_count=merged["candidates"][0]["agree_count"],
        cell_outcome=merged["cell_outcome"],
    )
    assert set(record) == {
        "perspectives",
        "agree_count",
        "label",
        "cell_outcome",
        "requeue_note",
        "none_perspectives",
    }
    assert record["cell_outcome"] == "candidate"
    assert record["agree_count"] == 2
    assert record["label"] == "2/3 hunt agree"
    assert record["requeue_note"] == "partial_none"
    assert record["none_perspectives"] == ["authz"]
    assert [p["id"] for p in record["perspectives"]] == [
        "sink_driven",
        "dataflow",
        "authz",
    ]
    assert record["perspectives"][2]["outcome"] == "none"
    assert "boundary holds" in record["perspectives"][2]["reason"]
    assert result_emits_confirmed(record) is False
    assert record["cell_outcome"] != "confirmed"

    none_slots = [
        {"perspective_id": "sink_driven", "outcome": "none", "none_reason": "no sink"},
        {"perspective_id": "dataflow", "outcome": "none", "none_reason": "no flow"},
    ]
    none_rec = build_hunt_moa_body(
        none_slots, n_perspectives=2, agree_count=9, cell_outcome="none"
    )
    assert none_rec["agree_count"] == 0
    assert none_rec["label"] == "0/2 hunt agree"
    assert none_rec["cell_outcome"] == "none"
    assert none_rec["requeue_note"] == "all_perspectives_none"
    assert none_rec["none_perspectives"] == ["sink_driven", "dataflow"]

    skipped = [
        {"perspective_id": "sink_driven", "outcome": "candidate", "title": "Only one"},
        {"perspective_id": "dataflow", "outcome": "skipped", "none_reason": "shared_round_budget_exhausted"},
    ]
    skipped_rec = build_hunt_moa_body(
        skipped, n_perspectives=2, agree_count=1, cell_outcome="candidate"
    )
    assert skipped_rec["requeue_note"] is None
    assert skipped_rec["label"] == "1/2 hunt agree"
    assert skipped_rec["none_perspectives"] == ["dataflow"]
    assert skipped_rec["perspectives"][1]["outcome"] == "none"
    assert result_emits_confirmed(skipped_rec) is False


def test_default_yaml_hunt_moa_off():
    root = Path(__file__).resolve().parents[1]
    cfg = yaml.safe_load((root / "config" / "default.yaml").read_text(encoding="utf-8"))
    assert cfg["stages"].get("hunt_moa") is False
    assert hunt_moa_enabled(cfg) is False
    pers = resolve_hunt_perspectives(cfg)
    assert len(pers) >= 2
    assert all("id" in p and "prompt" in p for p in pers)


def test_every_public_merge_path_refuses_confirmed():
    """Fixture matrix: none/none, one candidate, near-dupes, multi-agree, poison."""
    cases = [
        [_slot("a", None), _slot("b", None)],
        [_slot("a", _cand(title="one")), _slot("b", None)],
        [
            _slot("a", _cand(title="dup-1")),
            _slot("b", _cand(title="dup-2", citations=3)),
        ],
        [
            _slot("a", _cand(title="agree-1")),
            _slot("b", _cand(title="agree-2")),
            _slot(
                "c",
                _cand(
                    title="other",
                    path="other.py",
                    symbol="other_fn",
                    weakness="access-control",
                ),
            ),
        ],
        [_slot("a", _cand(title="poison", extra={"state": "confirmed"}))],
        None,
        [],
    ]
    for raw in cases:
        result = merge_hunt_candidates(raw)
        _assert_never_confirmed(result)
        assert hunt_moa.result_emits_confirmed(result) is False
        for item in result["candidates"]:
            assert item["state"] == "candidate"

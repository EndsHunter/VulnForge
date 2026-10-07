"""Copy checks for dual-disprove historical docs and the same-model hint.

No stage defaults change. Aggregation stays unanimous reject.
"""

from __future__ import annotations

from vulnforge.paths import PROJECT_ROOT


def test_design_doc_is_historical_and_followups_are_honest():
    text = (
        PROJECT_ROOT / "docs/superpowers/specs/2026-07-18-dual-llm-disprove-design.md"
    ).read_text(encoding="utf-8")
    assert "**Status:** Implemented (historical)" in text
    assert "seeds/system/disprove.md" in text
    assert "seeds/system/disprove_threat.md" in text
    assert "seeds/system/disprove_code.md" in text
    assert "Multi-model validation in Settings" in text
    assert "**Done**" in text
    assert "Operator UI to choose a model per verifier slot | Open" in text
    assert "Parallel dual chat (wall-clock) | Open" in text
    assert text.count("# Dual LLM Disprove Verify — Design") == 1


def test_consensus_is_stand_annotation_in_operator_docs():
    readme = (PROJECT_ROOT / "docs/harness/validate/README.md").read_text(encoding="utf-8")
    assert "multi-model **stand** annotation" in readme
    assert "every** model×perspective slot to return `reject`" in readme
    assert "does not confirm" in readme
    validate = (PROJECT_ROOT / "docs/system/VALIDATE.md").read_text(encoding="utf-8")
    assert "llm.validate_consensus" in validate
    assert "annotates multi-model stand only" in validate
    assert "validate README" in validate


def test_stage_defaults_unchanged():
    cfg = (PROJECT_ROOT / "config/default.yaml").read_text(encoding="utf-8")
    assert "validate_llm: true" in cfg
    assert "validate_models: []" in cfg
    assert "validate_consensus: majority" in cfg


def test_report_and_settings_surface_same_model_hint():
    report = (PROJECT_ROOT / "vulnforge/ui/static/report.js").read_text(encoding="utf-8")
    assert 'data-llm-weak-signal="same-model"' in report
    assert "sameModelOnBothPerspectives" in report
    assert "SAME_MODEL_WEAK_SIGNAL" in report
    settings = (PROJECT_ROOT / "vulnforge/ui/static/settings.js").read_text(encoding="utf-8")
    empty, _, _rest = settings.partition("if (!available.length)")
    assert empty
    branch = settings.split("if (!available.length)", 1)[1].split("available.forEach", 1)[0]
    assert "updateValidateWarn()" in branch
    assert "same-model dual disprove is a weak signal" in settings
    assert "One validation model is a weaker signal than two" in settings

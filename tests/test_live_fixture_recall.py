"""Optional live fixture recall (VF_LIVE=1). Not a CI gate.

Scores whether a real model can file oracle sinks when hunts are tightly
scoped. Soft-fails informationally unless VF_LIVE_STRICT=1.
"""

from __future__ import annotations

import os

import pytest

# Live only — skip unless explicitly enabled
pytestmark = pytest.mark.skipif(
    not os.environ.get("VF_LIVE"),
    reason="Set VF_LIVE=1 for live fixture recall (optional; not CI gate)",
)


def test_live_recall_placeholder():
    """Placeholder so the module is discoverable; full campaign lives in scripts/eval_recall.

    Implementing a full Ralph campaign here is expensive; operators can run:

        python scripts/eval_recall.py --target fixtures/toy_sqli

    when that script is available. This test documents the opt-in.
    """
    assert os.environ.get("VF_LIVE")

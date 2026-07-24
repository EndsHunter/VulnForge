"""Shared task-queue priority bands (lower int = sooner).

See lease_next_task ORDER BY priority ASC, id ASC.
"""

from __future__ import annotations

from typing import Any, Optional

# Init / first-pass recon — ahead of generate (20–25), develop_poc (30), hunts (35–50).
RECON_INIT_PRIORITY = 5

# Operator re-run uses dynamic front-of-queue; floor when queue is empty.
RECON_OPERATOR_PRIORITY_FLOOR = 1

# Internal recon child / fan-out still ahead of hunts.
RECON_CHILD_PRIORITY = 8

# Operator-facing tiers (also in control.ops.PRIORITY_TIERS for UI).
PRIORITY_HIGH = 30
PRIORITY_NORMAL = 50
PRIORITY_LOW = 90


def recon_front_priority(db: Any) -> int:
    """Priority for operator-started recon: strictly ahead of current queue head.

    Uses min(queued) - 1 when the queue is non-empty (may go negative — ASC still
    works). Empty queue → RECON_OPERATOR_PRIORITY_FLOOR.
    """
    mn: Optional[int] = None
    try:
        mn = db.min_queued_priority()
    except Exception:
        mn = None
    if mn is None:
        return int(RECON_OPERATOR_PRIORITY_FLOOR)
    return int(mn) - 1

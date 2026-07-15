"""PROTOCOL exit codes for vf run-once and Ralph."""

EXIT_PROGRESS = 0
EXIT_IDLE = 10
# Multi-worker: no lease this turn (cap full or others still working) — keep looping
# but do NOT count toward Ralph --max-tasks progress budget.
EXIT_BUSY = 11
EXIT_INFRA = 20
EXIT_CONFIG = 30

# Known deferred stage kinds (if enqueued → failed_task + progress, not CONFIG)
DEFERRED_TASK_KINDS = frozenset({"gapfill", "dedup", "feedback"})

"""Near-duplicate merge (mechanical, no LLM). Not a leased stage."""

from __future__ import annotations

from vulnforge.stages.dedup import (
    class_rank,
    merge_key,
    merge_near_duplicate,
    primary_sink,
)

__all__ = [
    "class_rank",
    "merge_key",
    "merge_near_duplicate",
    "primary_sink",
]

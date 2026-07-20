"""Finding identity and near-dup merge (not leased stages)."""

from vulnforge.findings.identity import compute_stable_key
from vulnforge.findings.merge import (
    cluster_findings,
    merge_findings,
    merge_near_duplicate,
)
from vulnforge.findings.severity import (
    ALLOWED_SEVERITY_CLAIMS,
    apply_severity_claim,
    normalize_severity_claim,
)

__all__ = [
    "ALLOWED_SEVERITY_CLAIMS",
    "apply_severity_claim",
    "cluster_findings",
    "compute_stable_key",
    "merge_findings",
    "merge_near_duplicate",
    "normalize_severity_claim",
]

"""OUTCOME exit codes for ``vf ci`` (headless CI mode).

These describe the *audit outcome* for a CI job. They are deliberately a
separate namespace from the Ralph loop protocol codes in
``vulnforge/control/exit_codes.py`` (0/10/11/20/30) and Ralph's own process
codes in ``scripts/ralph.py`` (0/10/20/30/40/130). ``vf ci`` never returns a
protocol code.

  0  pass       campaign finished (or stopped early on a budget) and no
                finding meets the --fail-on-* threshold. Coverage gaps
                alone do not fail.
  1  threshold  at least one finding meets the --fail-on-* threshold.
                A ``needs_human`` hit means "needs review", not "proven".
  2  error      infra or integrity failure: the run cannot vouch for its
                result (init failed, Ralph gave up, render/export failed,
                cost cap unenforceable, ``confirmed`` without a human review).
"""

CI_PASS = 0
CI_THRESHOLD = 1
CI_ERROR = 2

OUTCOME_NAMES = {CI_PASS: "pass", CI_THRESHOLD: "threshold", CI_ERROR: "error"}

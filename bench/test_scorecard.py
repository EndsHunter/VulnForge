from bench.selftest import run_checks


def test_stub_scorecard_invariants():
    failures = run_checks()
    assert failures == []

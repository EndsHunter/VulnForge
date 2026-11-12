"""Per-alternative positives/negatives for sink preindex regexes (issue #169)."""

from __future__ import annotations

import pytest

from vulnforge.tools.sink_preindex import _SINK_PATTERNS


def _kinds(line: str) -> set[str]:
    return {kind for kind, rx in _SINK_PATTERNS if rx.search(line)}


@pytest.mark.parametrize(
    "line",
    [
        "eval(user_input)",
        "exec(code)",
        "system(cmd);",
        'popen(cmd, "r")',
        "child_process.exec(x)",
        "child_process.spawn(cmd)",
        "os.system(x)",
        "os.popen(x)",
        "subprocess.run(args, shell=True)",
        "Runtime.getRuntime().exec(cmd)",
        "new ProcessBuilder(cmd)",
        "shell_exec($c)",
        "passthru($c)",
        "posix_spawnp(&pid, file, NULL, NULL, argv, envp)",
        "CreateProcessW(NULL, cmd, ...)",
        "ShellExecuteA(NULL, op, file, ...)",
    ],
)
def test_exec_sinks_match(line: str) -> None:
    assert "exec" in _kinds(line)


@pytest.mark.parametrize(
    "line",
    ["filesystem(x)", "my_evaluate(x)", "executor.submit(job)"],
)
def test_exec_no_false_match_inside_identifiers(line: str) -> None:
    assert "exec" not in _kinds(line)


@pytest.mark.parametrize(
    "line",
    [
        "db.query(sql)",
        "$pdo->prepare($q)",
        "mysqli_query($c, $q)",
        "mysql_query($q)",
        "pg_query($c, $q)",
        "cursor.execute(q)",
        "cur.executemany(q, rows)",
        "Model.objects.raw(q)",
        "jdbcTemplate.update(sql)",
        "em.createNativeQuery(sql)",
        "DBI->connect($dsn)",
        "sqlite3_exec(db, sql, 0, 0, &err)",
        "q = 'SELECT name FROM users WHERE id=' + uid",
    ],
)
def test_sql_sinks_match(line: str) -> None:
    assert "sql" in _kinds(line)

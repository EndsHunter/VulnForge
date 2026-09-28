"""Portable file locks: Unix flock stays, Windows never imports fcntl."""

from __future__ import annotations

import ast
import errno
import os
import subprocess
import sys
import textwrap
import threading
import time
import types
from pathlib import Path

import pytest

from vulnforge import file_lock
from vulnforge.file_lock import acquire_exclusive, release_exclusive

_ROOT = Path(__file__).resolve().parents[1]


def _no_toplevel_fcntl(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
            assert "fcntl" not in names, path
        elif isinstance(node, ast.ImportFrom):
            assert node.module != "fcntl", path


def test_start_path_modules_have_no_toplevel_fcntl_import() -> None:
    for rel in (
        "vulnforge/file_lock.py",
        "vulnforge/live_task.py",
        "vulnforge/poc_session.py",
    ):
        _no_toplevel_fcntl(_ROOT / rel)


def test_unix_acquire_release_uses_flock_and_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import fcntl

    calls: list[int] = []
    real = fcntl.flock

    def spy(fd: int, op: int) -> None:
        calls.append(op)
        real(fd, op)

    monkeypatch.setattr(fcntl, "flock", spy)
    path = tmp_path / "lock"
    path.touch()
    held = threading.Event()
    release = threading.Event()
    second = threading.Event()

    def hold() -> None:
        fd = os.open(path, os.O_RDWR)
        try:
            acquire_exclusive(fd, path=path)
            held.set()
            assert release.wait(5)
            release_exclusive(fd, path=path)
        finally:
            os.close(fd)

    def wait() -> None:
        assert held.wait(5)
        fd = os.open(path, os.O_RDWR)
        try:
            acquire_exclusive(fd, path=path)
            second.set()
            release_exclusive(fd, path=path)
        finally:
            os.close(fd)

    first = threading.Thread(target=hold)
    other = threading.Thread(target=wait)
    first.start()
    other.start()
    assert held.wait(2)
    time.sleep(0.2)
    assert not second.is_set()
    release.set()
    first.join(5)
    other.join(5)
    assert not first.is_alive()
    assert not other.is_alive()
    assert second.is_set()
    assert calls.count(fcntl.LOCK_EX) == 2
    assert calls.count(fcntl.LOCK_UN) == 2


def test_windows_backend_locks_without_fcntl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    calls: list[tuple[int, int]] = []

    def _forbid_fcntl(name: str, *args: object, **kwargs: object):
        if name == "fcntl":
            raise ModuleNotFoundError("No module named 'fcntl'")
        return real_import(name, *args, **kwargs)

    import builtins

    real_import = builtins.__import__
    monkeypatch.setattr(builtins, "__import__", _forbid_fcntl)
    monkeypatch.delitem(sys.modules, "fcntl", raising=False)

    msvcrt = types.ModuleType("msvcrt")
    msvcrt.LK_NBLCK = 2
    msvcrt.LK_UNLCK = 0
    state = {"fails": 2, "held": False}

    def locking(fd: int, mode: int, nbytes: int) -> None:
        if mode == msvcrt.LK_NBLCK and state["fails"]:
            state["fails"] -= 1
            raise PermissionError(errno.EACCES, "locked")
        if mode == msvcrt.LK_NBLCK:
            if state["held"]:
                raise PermissionError(errno.EACCES, "locked")
            state["held"] = True
        elif mode == msvcrt.LK_UNLCK:
            state["held"] = False
        else:
            raise OSError(errno.EBADF, "bad")
        calls.append((mode, nbytes))

    msvcrt.locking = locking
    monkeypatch.setitem(sys.modules, "msvcrt", msvcrt)
    monkeypatch.setattr(file_lock, "_RETRY_S", 0)

    path = tmp_path / "lock"
    path.touch()
    fd = os.open(path, os.O_RDWR)
    try:
        acquire_exclusive(fd, path=path)
        release_exclusive(fd, path=path)
    finally:
        os.close(fd)
    assert calls == [(msvcrt.LK_NBLCK, 1), (msvcrt.LK_UNLCK, 1)]
    assert "fcntl" not in sys.modules


def test_windows_backend_raises_non_contention_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_lock, "_windows", lambda: True)
    msvcrt = types.ModuleType("msvcrt")
    msvcrt.LK_NBLCK = 2
    msvcrt.LK_UNLCK = 0

    def locking(fd: int, mode: int, nbytes: int) -> None:
        raise OSError(errno.EBADF, "bad fd")

    msvcrt.locking = locking
    monkeypatch.setitem(sys.modules, "msvcrt", msvcrt)
    path = tmp_path / "lock"
    path.touch()
    fd = os.open(path, os.O_RDWR)
    try:
        with pytest.raises(OSError) as raised:
            acquire_exclusive(fd, path=path)
        assert raised.value.errno == errno.EBADF
    finally:
        os.close(fd)


def test_windows_threads_serialize(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(file_lock, "_windows", lambda: True)
    monkeypatch.setattr(file_lock, "_RETRY_S", 0)
    msvcrt = types.ModuleType("msvcrt")
    msvcrt.LK_NBLCK = 2
    msvcrt.LK_UNLCK = 0
    mu = threading.Lock()
    held = False

    def locking(fd: int, mode: int, nbytes: int) -> None:
        nonlocal held
        with mu:
            if mode == msvcrt.LK_NBLCK:
                if held:
                    raise PermissionError(errno.EACCES, "locked")
                held = True
                return
            if mode == msvcrt.LK_UNLCK:
                held = False
                return
        raise OSError(errno.EINVAL, "mode")

    msvcrt.locking = locking
    monkeypatch.setitem(sys.modules, "msvcrt", msvcrt)

    path = tmp_path / "lock"
    path.touch()
    order: list[str] = []
    release = threading.Event()
    started = threading.Event()

    def hold() -> None:
        fd = os.open(path, os.O_RDWR)
        try:
            acquire_exclusive(fd, path=path)
            order.append("first")
            started.set()
            assert release.wait(5)
            release_exclusive(fd, path=path)
        finally:
            os.close(fd)

    def wait() -> None:
        assert started.wait(5)
        fd = os.open(path, os.O_RDWR)
        try:
            acquire_exclusive(fd, path=path)
            order.append("second")
            release_exclusive(fd, path=path)
        finally:
            os.close(fd)

    first = threading.Thread(target=hold)
    other = threading.Thread(target=wait)
    first.start()
    other.start()
    assert started.wait(2)
    time.sleep(0.05)
    assert order == ["first"]
    release.set()
    first.join(5)
    other.join(5)
    assert order == ["first", "second"]


def test_import_and_lock_when_fcntl_is_missing(tmp_path: Path) -> None:
    """Hide stdlib fcntl the way Windows does and exercise both call sites."""
    script = textwrap.dedent(
        """\
        import builtins
        import sys
        import types
        from pathlib import Path

        real_import = builtins.__import__

        def guarded(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "fcntl":
                raise ModuleNotFoundError("No module named 'fcntl'")
            return real_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded
        sys.modules.pop("fcntl", None)

        # Import while fcntl cannot load. Flip platform only after import:
        # stdlib modules such as shutil read sys.platform at import time.
        import vulnforge.poc_session
        from vulnforge.live_task import _live_lock

        assert "fcntl" not in sys.modules
        sys.platform = "win32"

        msvcrt = types.ModuleType("msvcrt")
        msvcrt.LK_NBLCK = 2
        msvcrt.LK_UNLCK = 0
        calls = []

        def locking(fd, mode, nbytes):
            calls.append((mode, nbytes))

        msvcrt.locking = locking
        sys.modules["msvcrt"] = msvcrt

        root = Path(sys.argv[1])
        run = root / "run"
        run.mkdir()
        with _live_lock(run, 7):
            assert (run / "steer" / "task-7.lock").is_file()
        pack = root / "pack"
        fh = vulnforge.poc_session._lock(pack)
        fh.close()
        fh.close()
        assert (pack / "poc_session.lock").is_file()
        assert "fcntl" not in sys.modules
        assert calls
        assert all(nbytes == 1 for _mode, nbytes in calls)
        assert calls[0][0] == msvcrt.LK_NBLCK
        assert msvcrt.LK_UNLCK in {mode for mode, _nbytes in calls}
        print("ok")
        """
    )
    env = os.environ.copy()
    # This worktree only. A shared venv may point PYTHONPATH at another tree.
    env["PYTHONPATH"] = str(_ROOT)
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert completed.stdout.strip().splitlines()[-1] == "ok"


def test_poc_session_lock_serializes_on_unix(tmp_path: Path) -> None:
    from vulnforge.poc_session import LOCK_NAME, _lock

    pack = tmp_path / "pack"
    held = threading.Event()
    release = threading.Event()
    second = threading.Event()

    def hold() -> None:
        fh = _lock(pack)
        try:
            held.set()
            assert release.wait(5)
        finally:
            fh.close()

    def wait() -> None:
        assert held.wait(5)
        fh = _lock(pack)
        try:
            second.set()
        finally:
            fh.close()

    first = threading.Thread(target=hold)
    other = threading.Thread(target=wait)
    first.start()
    other.start()
    assert held.wait(2)
    time.sleep(0.2)
    assert not second.is_set()
    assert (pack / LOCK_NAME).is_file()
    release.set()
    first.join(5)
    other.join(5)
    assert second.is_set()
    assert not first.is_alive()
    assert not other.is_alive()

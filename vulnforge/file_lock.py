"""Exclusive file locks for Unix (``fcntl.flock``) and Windows (``msvcrt``).

``fcntl`` and ``msvcrt`` are imported only when that backend runs, so importing
this module (or callers) does not require a Unix ``fcntl``.
"""

from __future__ import annotations

import errno
import os
import sys
import threading
import time
from typing import Union

PathLike = Union[str, os.PathLike[str]]

# ``msvcrt.locking(..., LK_LOCK)`` gives up after about ten seconds.
# Live and PoC holds can outlast that, so Windows retries a non-blocking
# lock until the byte is free.
_RETRY_S = 0.05

# CRT ``_locking`` reports a busy region as EACCES or EDEADLOCK.
# Windows EDEADLOCK is 36, which is not errno.EDEADLK on every host.
_CONTENTION = frozenset(
    {
        errno.EACCES,
        errno.EAGAIN,
        errno.EDEADLK,
        errno.EWOULDBLOCK,
        36,
    }
)
# Win32 ERROR_LOCK_VIOLATION
_WIN_LOCK_VIOLATION = 33

# Binary fd: Windows rejects os.lseek / msvcrt on text-mode files.
_OPEN_FLAGS = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)

# ``msvcrt`` locks are owned by the process: a second thread in this
# process is not excluded the way ``fcntl.flock`` excludes it. The guard
# serializes those threads. Cross-process exclusion stays with ``msvcrt``.
_guards: dict[str, threading.Lock] = {}
_guards_mu = threading.Lock()


def _windows() -> bool:
    return sys.platform == "win32"


def _path_key(path: PathLike) -> str:
    return os.path.normcase(os.path.abspath(path))


def _guard(path: PathLike) -> threading.Lock:
    key = _path_key(path)
    with _guards_mu:
        lock = _guards.get(key)
        if lock is None:
            lock = threading.Lock()
            _guards[key] = lock
        return lock


def _contended(exc: OSError) -> bool:
    if getattr(exc, "winerror", None) == _WIN_LOCK_VIOLATION:
        return True
    return exc.errno in _CONTENTION


def _lock_windows(fd: int) -> None:
    import msvcrt

    while True:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return
        except OSError as exc:
            if not _contended(exc):
                raise
            time.sleep(_RETRY_S)


def _unlock_windows(fd: int) -> None:
    import msvcrt

    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


def acquire_exclusive(fd: int, *, path: PathLike | None = None) -> None:
    """Block until ``fd`` is exclusively locked.

    On Windows, pass ``path`` so threads in this process serialize on the
    same file. The path must be the file ``fd`` refers to.
    """
    if not _windows():
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX)
        return
    guard = _guard(path) if path is not None else None
    if guard is not None:
        guard.acquire()
    try:
        _lock_windows(fd)
    except BaseException:
        if guard is not None:
            guard.release()
        raise


def release_exclusive(fd: int, *, path: PathLike | None = None) -> None:
    """Release a lock taken by :func:`acquire_exclusive` on this ``fd``."""
    if not _windows():
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    try:
        _unlock_windows(fd)
    finally:
        if path is not None:
            _guard(path).release()


class LockedFile:
    """Open file descriptor whose :meth:`close` releases the exclusive lock."""

    def __init__(self, fd: int, path: PathLike) -> None:
        self._fd = fd
        self._path = path
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            release_exclusive(self._fd, path=self._path)
        finally:
            os.close(self._fd)


def open_exclusive(path: PathLike) -> LockedFile:
    """Open ``path`` (creating it) and take the exclusive lock.

    Binary read/write so Windows ``msvcrt.locking`` can seek to the first
    byte. The file is only a lock token; callers do not write it.
    """
    fd = os.open(os.fspath(path), _OPEN_FLAGS, 0o666)
    try:
        acquire_exclusive(fd, path=path)
    except BaseException:
        os.close(fd)
        raise
    return LockedFile(fd, path)

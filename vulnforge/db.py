"""
SQLite state layer â€” source of truth for runs/tasks/findings.

Crash safety note: write evidence packs with temp+rename first, then SQL commit
finding transitions. Partial project/*.md is disposable (regenerate via render).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from vulnforge.util import normalize_relpath, utc_now_iso


SCHEMA_VERSION = 1


def _sort_coverage_classes(classes: set[str] | Iterable[str]) -> list[str]:
    """Stable column order: active first, then rest of registry, then unknowns."""
    try:
        from vulnforge.hunt_profiles import active_class_ids, all_class_ids

        ordered: list[str] = []
        for c in active_class_ids():
            if c not in ordered:
                ordered.append(c)
        for c in all_class_ids():
            if c not in ordered:
                ordered.append(c)
        order = {c: i for i, c in enumerate(ordered)}
    except Exception:  # pragma: no cover - catalog always available in package
        order = {}
    return sorted({str(c) for c in classes if c}, key=lambda c: (order.get(c, 10_000), c))


@dataclass
class Task:
    id: int
    kind: str
    state: str
    payload: dict
    attempt: int
    priority: int = 100
    lease_owner: Optional[str] = None
    lease_until: Optional[str] = None
    result: Optional[dict] = None


@dataclass
class Finding:
    id: int
    stable_key: str
    state: str
    body: dict
    evidence_id: Optional[str] = None


def _iso_future(seconds: int) -> str:
    return datetime.fromtimestamp(time.time() + seconds, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class Database:
    """Thin wrapper over harness.db."""

    def __init__(self, path: Path, *, create: bool = False):
        self.path = Path(path)
        if create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() and not create:
            raise FileNotFoundError(self.path)
        self.conn = sqlite3.connect(str(self.path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self._apply_pragmas()
        if create:
            self.migrate()
        else:
            self._check_schema()

    @classmethod
    def create(cls, path: Path) -> "Database":
        return cls(path, create=True)

    @classmethod
    def open(cls, path: Path) -> "Database":
        return cls(path, create=False)

    def _apply_pragmas(self) -> None:
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def _check_schema(self) -> None:
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'"
        ).fetchone()
        if not row:
            raise RuntimeError(f"database missing schema: {self.path}")
        ver = self.conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()
        if not ver or int(ver["value"]) != SCHEMA_VERSION:
            raise RuntimeError(
                f"unsupported schema version: {ver['value'] if ver else None}"
            )

    def migrate(self) -> None:
        c = self.conn
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
              id TEXT PRIMARY KEY,
              target_path TEXT NOT NULL,
              profile TEXT NOT NULL,
              prompt_pin TEXT NOT NULL,
              status TEXT NOT NULL,
              config_json TEXT NOT NULL,
              architecture_json TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tasks (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL,
              state TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              priority INTEGER NOT NULL DEFAULT 100,
              attempt INTEGER NOT NULL DEFAULT 0,
              lease_owner TEXT,
              lease_until TEXT,
              result_json TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state);
            CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority, id);

            CREATE TABLE IF NOT EXISTS findings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              stable_key TEXT NOT NULL UNIQUE,
              state TEXT NOT NULL,
              body_json TEXT NOT NULL,
              evidence_id TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);

            CREATE TABLE IF NOT EXISTS coverage_facts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              area TEXT NOT NULL,
              attack_class TEXT NOT NULL,
              path TEXT,
              visit_count INTEGER NOT NULL DEFAULT 0,
              last_depth TEXT,
              UNIQUE(area, attack_class, path)
            );

            CREATE TABLE IF NOT EXISTS notes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              task_id INTEGER,
              created_at TEXT NOT NULL
            );
            """
        )
        c.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        c.commit()

    def insert_run(
        self,
        run_id: str,
        target_path: str,
        profile: str,
        prompt_pin: str,
        config: dict,
    ) -> None:
        now = utc_now_iso()
        self.conn.execute(
            """
            INSERT INTO runs(id, target_path, profile, prompt_pin, status, config_json, created_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?)
            """,
            (
                run_id,
                target_path,
                profile,
                prompt_pin,
                json.dumps(config),
                now,
            ),
        )
        self.conn.commit()

    def get_run(self) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

    def set_architecture(self, architecture: dict) -> None:
        row = self.get_run()
        if not row:
            raise RuntimeError("no run row")
        self.conn.execute(
            "UPDATE runs SET architecture_json=? WHERE id=?",
            (json.dumps(architecture), row["id"]),
        )
        self.conn.commit()

    def get_architecture(self) -> Optional[dict]:
        row = self.get_run()
        if not row or not row["architecture_json"]:
            return None
        return json.loads(row["architecture_json"])

    def enqueue_task(
        self,
        kind: str,
        payload: Optional[dict] = None,
        priority: int = 100,
    ) -> int:
        now = utc_now_iso()
        cur = self.conn.execute(
            """
            INSERT INTO tasks(kind, state, payload_json, priority, attempt, created_at, updated_at)
            VALUES (?, 'queued', ?, ?, 0, ?, ?)
            """,
            (kind, json.dumps(payload or {}), priority, now, now),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def _row_to_task(self, row: sqlite3.Row) -> Task:
        return Task(
            id=row["id"],
            kind=row["kind"],
            state=row["state"],
            payload=json.loads(row["payload_json"] or "{}"),
            attempt=row["attempt"],
            priority=row["priority"],
            lease_owner=row["lease_owner"],
            lease_until=row["lease_until"],
            result=json.loads(row["result_json"]) if row["result_json"] else None,
        )

    def count_leased_tasks(self) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM tasks WHERE state='leased'"
        ).fetchone()
        return int(row["n"] if row else 0)

    def lease_next_task(
        self,
        worker_id: str,
        ttl_seconds: int,
        *,
        max_parallel: int = 1,
    ) -> Optional[Task]:
        """Atomically lease one queued task, respecting concurrent lease cap.

        ``max_parallel`` limits how many tasks may be in ``leased`` at once
        (across all workers). Uses BEGIN IMMEDIATE so multi-process agents
        cannot overshoot the cap under SQLite WAL.
        """
        now = utc_now_iso()
        until = _iso_future(ttl_seconds)
        cap = max(1, int(max_parallel or 1))
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            leased_n = self.conn.execute(
                "SELECT COUNT(*) AS n FROM tasks WHERE state='leased'"
            ).fetchone()["n"]
            if int(leased_n) >= cap:
                self.conn.execute("COMMIT")
                return None
            row = self.conn.execute(
                """
                SELECT * FROM tasks
                WHERE state='queued'
                ORDER BY priority ASC, id ASC
                LIMIT 1
                """
            ).fetchone()
            if not row:
                self.conn.execute("COMMIT")
                return None
            self.conn.execute(
                """
                UPDATE tasks
                SET state='leased', lease_owner=?, lease_until=?,
                    attempt=attempt+1, updated_at=?
                WHERE id=?
                """,
                (worker_id, until, now, row["id"]),
            )
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        refreshed = self.conn.execute(
            "SELECT * FROM tasks WHERE id=?", (row["id"],)
        ).fetchone()
        return self._row_to_task(refreshed)

    def reclaim_expired_leases(self) -> int:
        now = utc_now_iso()
        cur = self.conn.execute(
            """
            UPDATE tasks
            SET state='queued', lease_owner=NULL, lease_until=NULL, updated_at=?
            WHERE state='leased' AND lease_until IS NOT NULL AND lease_until < ?
            """,
            (now, now),
        )
        self.conn.commit()
        return int(cur.rowcount or 0)

    def complete_task(
        self, task_id: int, result: dict, state: str = "succeeded"
    ) -> None:
        now = utc_now_iso()
        self.conn.execute(
            """
            UPDATE tasks
            SET state=?, result_json=?, lease_owner=NULL, lease_until=NULL, updated_at=?
            WHERE id=?
            """,
            (state, json.dumps(result), now, task_id),
        )
        self.conn.commit()

    def fail_task(
        self,
        task_id: int,
        state: str,
        error: str,
        *,
        result_extra: Optional[dict] = None,
    ) -> None:
        now = utc_now_iso()
        body: dict = {"error": error}
        if isinstance(result_extra, dict):
            # Keep stage extras (child_task_id, recon_generation, model_id, …)
            for k, v in result_extra.items():
                if k in ("status",):
                    continue
                if k == "error":
                    continue
                body[k] = v
            body["error"] = error
        self.conn.execute(
            """
            UPDATE tasks
            SET state=?, result_json=?, lease_owner=NULL, lease_until=NULL, updated_at=?
            WHERE id=?
            """,
            (state, json.dumps(body), now, task_id),
        )
        self.conn.commit()

    def update_task_payload(self, task_id: int, payload: dict) -> bool:
        """Replace payload_json for a task (e.g. multi-agent recon fan-out split)."""
        now = utc_now_iso()
        cur = self.conn.execute(
            """
            UPDATE tasks
            SET payload_json=?, updated_at=?
            WHERE id=?
            """,
            (json.dumps(payload or {}), now, int(task_id)),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def set_task_priority(self, task_id: int, priority: int) -> bool:
        """Update priority for a queued task. Returns False if missing or not queued."""
        now = utc_now_iso()
        cur = self.conn.execute(
            """
            UPDATE tasks
            SET priority=?, updated_at=?
            WHERE id=? AND state='queued'
            """,
            (int(priority), now, int(task_id)),
        )
        self.conn.commit()
        return int(cur.rowcount or 0) > 0

    def cancel_queued_task(
        self,
        task_id: int,
        *,
        reason: str = "operator_cancel",
    ) -> bool:
        """Mark a queued task cancelled (terminal). Returns False if missing or not queued."""
        now = utc_now_iso()
        body = {
            "status": "cancelled",
            "error": str(reason or "operator_cancel"),
            "operator_cancelled": True,
        }
        cur = self.conn.execute(
            """
            UPDATE tasks
            SET state='cancelled', result_json=?, lease_owner=NULL, lease_until=NULL, updated_at=?
            WHERE id=? AND state='queued'
            """,
            (json.dumps(body), now, int(task_id)),
        )
        self.conn.commit()
        return int(cur.rowcount or 0) > 0

    def min_queued_priority(self) -> Optional[int]:
        """Lowest priority among queued tasks (sooner), or None if queue empty."""
        row = self.conn.execute(
            "SELECT MIN(priority) AS p FROM tasks WHERE state='queued'"
        ).fetchone()
        if not row or row["p"] is None:
            return None
        return int(row["p"])

    def requeue_task(self, task_id: int, *, error: Optional[str] = None) -> None:
        """Return a leased/failed task to queued for retry (clears lease)."""
        now = utc_now_iso()
        result_json = json.dumps({"error": error}) if error is not None else None
        if result_json is not None:
            self.conn.execute(
                """
                UPDATE tasks
                SET state='queued', result_json=?, lease_owner=NULL, lease_until=NULL,
                    updated_at=?
                WHERE id=?
                """,
                (result_json, now, task_id),
            )
        else:
            self.conn.execute(
                """
                UPDATE tasks
                SET state='queued', lease_owner=NULL, lease_until=NULL, updated_at=?
                WHERE id=?
                """,
                (now, task_id),
            )
        self.conn.commit()

    def deadletter_task(self, task_id: int, error: str) -> None:
        """Terminal poison-task state after max infra attempts (no requeue)."""
        self.fail_task(task_id, "deadletter", error)

    def insert_finding(
        self,
        body: dict,
        state: str = "candidate",
        stable_key: Optional[str] = None,
        evidence_id: Optional[str] = None,
        profile: str = "code_static",
    ) -> int:
        key = stable_key or compute_stable_key(profile, body)
        now = utc_now_iso()
        existing = self.conn.execute(
            "SELECT id, state FROM findings WHERE stable_key=?", (key,)
        ).fetchone()
        if existing:
            self.conn.execute(
                """
                UPDATE findings SET state=?, body_json=?, evidence_id=?, updated_at=?
                WHERE id=?
                """,
                (
                    state,
                    json.dumps(body),
                    evidence_id or body.get("evidence_id"),
                    now,
                    existing["id"],
                ),
            )
            self.conn.commit()
            return int(existing["id"])
        cur = self.conn.execute(
            """
            INSERT INTO findings(stable_key, state, body_json, evidence_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                state,
                json.dumps(body),
                evidence_id or body.get("evidence_id"),
                now,
                now,
            ),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_finding_state(
        self, finding_id: int, state: str, reason: Optional[str] = None
    ) -> None:
        now = utc_now_iso()
        row = self.get_finding(finding_id)
        if not row:
            raise KeyError(finding_id)
        body = dict(row.body)
        if reason is not None:
            body.setdefault("validation_reasons", [])
            if isinstance(body["validation_reasons"], list):
                body["validation_reasons"].append(reason)
        self.conn.execute(
            """
            UPDATE findings SET state=?, body_json=?, updated_at=? WHERE id=?
            """,
            (state, json.dumps(body), now, finding_id),
        )
        self.conn.commit()

    def get_finding(self, finding_id: int) -> Optional[Finding]:
        row = self.conn.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if not row:
            return None
        return Finding(
            id=row["id"],
            stable_key=row["stable_key"],
            state=row["state"],
            body=json.loads(row["body_json"]),
            evidence_id=row["evidence_id"],
        )

    def list_findings(
        self, states: Optional[Iterable[str]] = None
    ) -> list[Finding]:
        if states:
            placeholders = ",".join("?" * len(list(states)))
            state_list = list(states)
            rows = self.conn.execute(
                f"SELECT * FROM findings WHERE state IN ({placeholders}) ORDER BY id",
                state_list,
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM findings ORDER BY id"
            ).fetchall()
        return [
            Finding(
                id=r["id"],
                stable_key=r["stable_key"],
                state=r["state"],
                body=json.loads(r["body_json"]),
                evidence_id=r["evidence_id"],
            )
            for r in rows
        ]

    def upsert_coverage_fact(
        self,
        area: str,
        attack_class: str,
        path: str = "",
        visit_delta: int = 1,
        last_depth: str = "",
    ) -> None:
        path_n = normalize_relpath(path) if path else ""
        row = self.conn.execute(
            """
            SELECT id, visit_count FROM coverage_facts
            WHERE area=? AND attack_class=? AND path=?
            """,
            (area, attack_class, path_n),
        ).fetchone()
        if row:
            self.conn.execute(
                """
                UPDATE coverage_facts
                SET visit_count=?, last_depth=?
                WHERE id=?
                """,
                (row["visit_count"] + visit_delta, last_depth, row["id"]),
            )
        else:
            self.conn.execute(
                """
                INSERT INTO coverage_facts(area, attack_class, path, visit_count, last_depth)
                VALUES (?, ?, ?, ?, ?)
                """,
                (area, attack_class, path_n, visit_delta, last_depth),
            )
        self.conn.commit()

    def insert_note(
        self, kind: str, payload: Any, task_id: Optional[int] = None
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO notes(kind, payload_json, task_id, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (kind, json.dumps(payload), task_id, utc_now_iso()),
        )
        self.conn.commit()

    def list_notes(self, kind: Optional[str] = None) -> list[dict]:
        if kind:
            rows = self.conn.execute(
                "SELECT * FROM notes WHERE kind=? ORDER BY id", (kind,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM notes ORDER BY id").fetchall()
        return [
            {
                "id": r["id"],
                "kind": r["kind"],
                "payload": json.loads(r["payload_json"]),
                "task_id": r["task_id"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def count_tasks_by_state(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT state, COUNT(*) AS n FROM tasks GROUP BY state"
        ).fetchall()
        return {r["state"]: r["n"] for r in rows}

    def count_findings_by_state(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT state, COUNT(*) AS n FROM findings GROUP BY state"
        ).fetchall()
        return {r["state"]: r["n"] for r in rows}

    def has_queued_or_leased(self) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM tasks WHERE state IN ('queued','leased') LIMIT 1"
        ).fetchone()
        return row is not None

    def list_tasks(self, limit: int = 500) -> list[Task]:
        """All tasks ordered by id (for dashboard / status)."""
        rows = self.conn.execute(
            """
            SELECT * FROM tasks
            ORDER BY id ASC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def get_task(self, task_id: int) -> Optional[Task]:
        row = self.conn.execute(
            "SELECT * FROM tasks WHERE id=?", (int(task_id),)
        ).fetchone()
        return self._row_to_task(row) if row else None

    def list_coverage_facts(self) -> list[dict[str, Any]]:
        """All coverage_facts rows for UI matrix / REPORT."""
        rows = self.conn.execute(
            """
            SELECT area, attack_class, path, visit_count, last_depth
            FROM coverage_facts
            ORDER BY area, attack_class, path
            """
        ).fetchall()
        return [
            {
                "area": r["area"],
                "attack_class": r["attack_class"],
                "path": r["path"] or "",
                "visit_count": r["visit_count"],
                "last_depth": r["last_depth"] or "",
            }
            for r in rows
        ]

    def coverage_matrix(self) -> dict[str, Any]:
        """area × class rollup for dashboard (best last_depth / visits).

        Axes include every class/area that appears in coverage_facts **or** hunt
        task payloads so domain packs (and operator-selected classes) always show
        up — not only the short DEFAULT core set when facts are incomplete.
        """
        facts = self.list_coverage_facts()
        cells: dict[str, dict[str, Any]] = {}
        areas: set[str] = set()
        classes: set[str] = set()
        depth_rank = {
            "": 0,
            "planned": 0,
            "shallow": 1,
            "none": 2,
            "aborted": 2,
            "candidate": 3,
            "needs_human": 3,
            "confirmed": 4,
        }
        for f in facts:
            a, c = str(f["area"] or "").strip(), str(f["attack_class"] or "").strip()
            if not a or not c:
                continue
            areas.add(a)
            classes.add(c)
            key = f"{a}\0{c}"
            prev = cells.get(key)
            if not prev:
                cells[key] = {
                    "area": a,
                    "class": c,
                    "visit_count": int(f["visit_count"] or 0),
                    "last_depth": f["last_depth"] or "",
                }
            else:
                prev["visit_count"] += int(f["visit_count"] or 0)
                if depth_rank.get(f["last_depth"] or "", 0) >= depth_rank.get(
                    prev["last_depth"] or "", 0
                ):
                    prev["last_depth"] = f["last_depth"] or prev["last_depth"]

        # Union hunt tasks so used domain packs always become columns/rows even if
        # a fact row was never written (legacy paths, mid-flight queues, etc.).
        try:
            rows = self.conn.execute(
                "SELECT payload_json FROM tasks WHERE kind = 'hunt'"
            ).fetchall()
        except sqlite3.Error:
            rows = []
        for r in rows:
            try:
                p = json.loads(r["payload_json"] or "{}")
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(p, dict):
                continue
            a = str(p.get("area") or "").strip()
            c = str(p.get("class") or p.get("attack_class") or "").strip()
            if a:
                areas.add(a)
            if c:
                classes.add(c)
            if a and c:
                key = f"{a}\0{c}"
                if key not in cells:
                    cells[key] = {
                        "area": a,
                        "class": c,
                        "visit_count": 0,
                        "last_depth": "planned",
                    }

        return {
            "areas": sorted(areas),
            "classes": _sort_coverage_classes(classes),
            "cells": list(cells.values()),
        }

    def summary(self) -> dict[str, Any]:
        run = self.get_run()
        run_dict = None
        if run:
            run_dict = {
                k: run[k]
                for k in run.keys()
                if k != "architecture_json"  # large; fetch via get_architecture
            }
            # keep architecture flag only
            run_dict["has_architecture"] = bool(run["architecture_json"])
        return {
            "run": run_dict,
            "tasks": self.count_tasks_by_state(),
            "findings": self.count_findings_by_state(),
            "has_work": self.has_queued_or_leased(),
        }

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None


# Re-export: canonical home is vulnforge.findings.identity
from vulnforge.findings.identity import compute_stable_key  # noqa: E402


class RunLock:
    """
    Exclusive lock file for a run directory (single writer).

    Uses a lock file with PID; stale if PID is dead (best-effort on Windows/Linux).
    """

    def __init__(self, run_dir: Path, *, stale_seconds: int = 7200):
        self.run_dir = Path(run_dir)
        self.lock_path = self.run_dir / "run.lock"
        self.stale_seconds = stale_seconds
        self._held = False

    def _pid_alive(self, pid: int) -> bool:
        if pid <= 0:
            return False
        try:
            if os.name == "nt":
                import ctypes

                kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
                handle = kernel32.OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION, False, pid
                )
                if handle:
                    kernel32.CloseHandle(handle)
                    return True
                return False
            else:
                os.kill(pid, 0)
                return True
        except OSError:
            return False
        except Exception:
            return False

    def _try_clear_stale(self) -> None:
        if not self.lock_path.is_file():
            return
        try:
            data = json.loads(self.lock_path.read_text(encoding="utf-8"))
            pid = int(data.get("pid", -1))
            ts = float(data.get("ts", 0))
            age = time.time() - ts
            if not self._pid_alive(pid) or age > self.stale_seconds:
                self.lock_path.unlink(missing_ok=True)
        except (OSError, ValueError, json.JSONDecodeError):
            # corrupt lock â€” remove if old enough via mtime
            try:
                age = time.time() - self.lock_path.stat().st_mtime
                if age > self.stale_seconds:
                    self.lock_path.unlink(missing_ok=True)
            except OSError:
                pass

    def acquire(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self._try_clear_stale()
        if self.lock_path.exists():
            raise RuntimeError(f"run locked: {self.lock_path}")
        payload = {
            "pid": os.getpid(),
            "ts": time.time(),
            "created_at": utc_now_iso(),
        }
        # O_EXCL style create
        try:
            fd = os.open(
                str(self.lock_path),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o644,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(payload))
        except FileExistsError as e:
            raise RuntimeError(f"run locked: {self.lock_path}") from e
        self._held = True

    def release(self) -> None:
        if not self._held:
            return
        try:
            if self.lock_path.is_file():
                data = json.loads(self.lock_path.read_text(encoding="utf-8"))
                if int(data.get("pid", -1)) == os.getpid():
                    self.lock_path.unlink(missing_ok=True)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
        self._held = False

    def __enter__(self) -> "RunLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()

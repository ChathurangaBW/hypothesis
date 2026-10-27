"""SQLite run history and tamper-evident chained ledger.

Hashes are integrity indicators, not immutable/WORM storage or legal chain-of-custody.
Production deployments must add independent immutable log export.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from .core import digest


class RunStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL, scenario TEXT NOT NULL,
                payload TEXT NOT NULL, payload_sha TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS ledger (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT UNIQUE NOT NULL, previous_sha TEXT NOT NULL,
                entry_sha TEXT NOT NULL, FOREIGN KEY(run_id) REFERENCES runs(id)
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS workflows (
                id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                payload TEXT NOT NULL, payload_sha TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY, workflow_id TEXT NOT NULL, created_at TEXT NOT NULL,
                payload TEXT NOT NULL, payload_sha TEXT NOT NULL,
                FOREIGN KEY(workflow_id) REFERENCES workflows(id)
            )""")

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=10)

    def save(self, result: dict[str, Any]) -> None:
        payload = json.dumps(result, sort_keys=True, separators=(",", ":"))
        payload_sha = digest(result)
        with self._connect() as db:
            previous = db.execute("SELECT entry_sha FROM ledger ORDER BY sequence DESC LIMIT 1").fetchone()
            previous_sha = previous[0] if previous else "GENESIS"
            ledger_sha = digest({"previous_sha": previous_sha, "run_id": result["id"], "payload_sha": payload_sha})
            db.execute("INSERT INTO runs VALUES (?, ?, ?, ?, ?)",
                       (result["id"], result["created_at"], result["scenario"], payload, payload_sha))
            db.execute("INSERT INTO ledger (run_id, previous_sha, entry_sha) VALUES (?, ?, ?)",
                       (result["id"], previous_sha, ledger_sha))

    def list_runs(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT id, created_at, scenario, payload FROM runs ORDER BY created_at DESC LIMIT 100").fetchall()
        return [
            {"id": row[0], "created_at": row[1], "scenario": row[2], "summary": json.loads(row[3])["summary"]}
            for row in rows
        ]

    def save_workflow(self, record: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute("INSERT INTO workflows VALUES (?, ?, ?, ?)", (
                record["id"], record["created_at"],
                json.dumps(record, sort_keys=True, separators=(",", ":")), digest(record),
            ))

    def list_workflows(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT id, payload, payload_sha FROM workflows "
                              "ORDER BY created_at DESC LIMIT 100").fetchall()
        records = [self._verified_payload(payload, sha, "workflow")
                   for _, payload, sha in rows]
        if any(record.get("id") != row[0] for record, row in zip(records, rows)):
            raise ValueError("Stored workflow failed its integrity check")
        return [{key: record[key] for key in ("id", "created_at", "name", "summary")}
                for record in records]

    def get_workflow(self, workflow_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT payload, payload_sha FROM workflows WHERE id=?", (workflow_id,)).fetchone()
        if row is None:
            return None
        try:
            record = json.loads(row[0])
            valid = digest(record) == row[1] and record["id"] == workflow_id
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise ValueError("Stored workflow failed its integrity check")
        return record

    def save_assessment(self, record: dict[str, Any]) -> None:
        with self._connect() as db:
            db.execute("INSERT INTO assessments VALUES (?, ?, ?, ?, ?)", (
                record["id"], record["workflow_id"], record["created_at"],
                json.dumps(record, sort_keys=True, separators=(",", ":")), digest(record),
            ))

    def list_assessments(self, workflow_id: str | None = None) -> list[dict[str, Any]]:
        with self._connect() as db:
            if workflow_id is None:
                rows = db.execute("SELECT payload, payload_sha FROM assessments "
                                  "ORDER BY created_at DESC LIMIT 100").fetchall()
            else:
                rows = db.execute("SELECT payload, payload_sha FROM assessments "
                                  "WHERE workflow_id=? ORDER BY created_at DESC LIMIT 100",
                                  (workflow_id,)).fetchall()
        records = [self._verified_payload(payload, sha, "assessment") for payload, sha in rows]
        return [{key: record[key] for key in ("id", "workflow_id", "created_at", "summary")}
                for record in records]

    @staticmethod
    def _verified_payload(payload: str, sha: str, kind: str) -> dict[str, Any]:
        try:
            record = json.loads(payload)
            if not isinstance(record, dict) or digest(record) != sha:
                raise ValueError("integrity mismatch")
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Stored {kind} failed its integrity check") from exc
        return record

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT payload, payload_sha FROM assessments WHERE id=?",
                             (assessment_id,)).fetchone()
        if row is None:
            return None
        record = self._verified_payload(row[0], row[1], "assessment")
        if record.get("id") != assessment_id:
            raise ValueError("Stored assessment failed its integrity check")
        return record

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT payload FROM runs WHERE id = ?", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def verify(self, run_id: str) -> dict[str, Any]:
        with self._connect() as db:
            rows = db.execute("""SELECT l.run_id, l.previous_sha, l.entry_sha, r.payload, r.payload_sha
                                  FROM ledger l JOIN runs r ON r.id=l.run_id
                                  ORDER BY l.sequence ASC""").fetchall()
        previous = "GENESIS"
        seen = False
        valid = True
        for row in rows:
            rid, prev_sha, entry_sha, payload, payload_sha = row
            valid = valid and prev_sha == previous
            valid = valid and digest(json.loads(payload)) == payload_sha
            valid = valid and digest({"previous_sha": prev_sha, "run_id": rid, "payload_sha": payload_sha}) == entry_sha
            previous = entry_sha
            if rid == run_id:
                seen = True
        return {
            "run_id": run_id,
            "exists": seen,
            "verified": bool(seen and valid),
            "ledger_entries": len(rows),
            "note": "Hash-chain integrity only; not immutable or legally certified evidence storage",
        }

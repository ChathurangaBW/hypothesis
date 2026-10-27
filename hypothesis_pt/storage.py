"""SQLite workspace history with tamper-evident chained assessment records.

Checksums detect common alterations but do not replace off-host WORM audit logging.
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any
from uuid import uuid4

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
            db.execute("""CREATE TABLE IF NOT EXISTS specs (
                id TEXT PRIMARY KEY, source TEXT NOT NULL,
                operations TEXT NOT NULL, fingerprint TEXT NOT NULL
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
            "run_id": run_id, "exists": seen, "verified": bool(seen and valid),
            "ledger_entries": len(rows),
            "note": "Hash-chain integrity only; not immutable or legally certified evidence storage",
        }

    def save_spec(self, source: str, operations: list[dict[str, Any]]) -> dict[str, Any]:
        spec_id = str(uuid4())
        fingerprint = digest(operations)
        with self._connect() as db:
            db.execute("INSERT INTO specs VALUES (?, ?, ?, ?)",
                       (spec_id, source, json.dumps(operations, sort_keys=True), fingerprint))
        return {"id": spec_id, "source": source, "operation_count": len(operations),
                "fingerprint": fingerprint}

    def get_spec(self, spec_id: str) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT source, operations, fingerprint FROM specs WHERE id=?", (spec_id,)).fetchone()
        if not row:
            return None
        return {"id": spec_id, "source": row[0],
                "operations": json.loads(row[1]), "fingerprint": row[2]}

    def list_specs(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT id, source, operations, fingerprint FROM specs ORDER BY rowid DESC LIMIT 100").fetchall()
        return [{"id": row[0], "source": row[1], "operation_count": len(json.loads(row[2])),
                 "fingerprint": row[3]} for row in rows]

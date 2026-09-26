"""Small SQLite persistence layer for scan history."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parents[1] / "ecdat.db"


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize() -> None:
    with _connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                project_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)


def save_scan(scan: dict[str, Any]) -> None:
    with _connect() as db:
        db.execute(
            "INSERT OR REPLACE INTO scans (id, project_name, created_at, result_json) VALUES (?, ?, ?, ?)",
            (scan["id"], scan["project_name"], scan["created_at"], json.dumps(scan)),
        )


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with _connect() as db:
        row = db.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return json.loads(row["result_json"]) if row else None


def list_scans(limit: int = 20) -> list[dict[str, Any]]:
    with _connect() as db:
        rows = db.execute(
            "SELECT result_json FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    scans = [json.loads(row["result_json"]) for row in rows]
    return [{
        "id": item["id"],
        "project_name": item["project_name"],
        "created_at": item["created_at"],
        "summary": item["summary"],
    } for item in scans]


"""SQLite and append-only JSONL audit logging for DriveMap operations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite

from drivemap.models import AuditRecord

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    tg_user_id INTEGER NOT NULL,
    tg_username TEXT NOT NULL,
    operation TEXT NOT NULL,
    target_sam TEXT NOT NULL,
    target_sid TEXT NOT NULL,
    unc_path TEXT NOT NULL,
    letter TEXT NOT NULL,
    label TEXT NOT NULL,
    gpo_version_before INTEGER NOT NULL,
    gpo_version_after INTEGER NOT NULL,
    backup_path TEXT NOT NULL,
    status TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT ''
);
"""


class AuditRepository:
    """Stores every DriveMap change in SQLite and mirrors to append-only JSONL."""

    def __init__(self, db_path: Path, jsonl_path: Path) -> None:
        self.db_path = db_path
        self.jsonl_path = jsonl_path

    async def init(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(CREATE_TABLE_SQL)
            await db.commit()

    async def record(self, entry: AuditRecord) -> None:
        if not entry.created_at:
            entry.created_at = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO audit_log (
                    tx_id, created_at, tg_user_id, tg_username, operation,
                    target_sam, target_sid, unc_path, letter, label,
                    gpo_version_before, gpo_version_after, backup_path, status, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.tx_id,
                    entry.created_at,
                    entry.tg_user_id,
                    entry.tg_username,
                    entry.operation,
                    entry.target_sam,
                    entry.target_sid,
                    entry.unc_path,
                    entry.letter,
                    entry.label,
                    entry.gpo_version_before,
                    entry.gpo_version_after,
                    entry.backup_path,
                    entry.status,
                    entry.details,
                ),
            )
            await db.commit()

        payload = {
            "tx_id": entry.tx_id,
            "created_at": entry.created_at,
            "tg_user_id": entry.tg_user_id,
            "tg_username": entry.tg_username,
            "operation": entry.operation,
            "target_sam": entry.target_sam,
            "target_sid": entry.target_sid,
            "unc_path": entry.unc_path,
            "letter": entry.letter,
            "label": entry.label,
            "gpo_version_before": entry.gpo_version_before,
            "gpo_version_after": entry.gpo_version_after,
            "backup_path": entry.backup_path,
            "status": entry.status,
            "details": entry.details,
        }
        with self.jsonl_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    async def list_recent(self, limit: int = 10) -> list[AuditRecord]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()
        return [
            AuditRecord(
                tx_id=r["tx_id"],
                created_at=r["created_at"],
                tg_user_id=r["tg_user_id"],
                tg_username=r["tg_username"],
                operation=r["operation"],
                target_sam=r["target_sam"],
                target_sid=r["target_sid"],
                unc_path=r["unc_path"],
                letter=r["letter"],
                label=r["label"],
                gpo_version_before=r["gpo_version_before"],
                gpo_version_after=r["gpo_version_after"],
                backup_path=r["backup_path"],
                status=r["status"],
                details=r["details"],
            )
            for r in rows
        ]

    async def get_by_tx_id(self, tx_id: str) -> Optional[AuditRecord]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT * FROM audit_log WHERE tx_id = ?", (tx_id,)) as cursor:
                r = await cursor.fetchone()
        if not r:
            return None
        return AuditRecord(
            tx_id=r["tx_id"],
            created_at=r["created_at"],
            tg_user_id=r["tg_user_id"],
            tg_username=r["tg_username"],
            operation=r["operation"],
            target_sam=r["target_sam"],
            target_sid=r["target_sid"],
            unc_path=r["unc_path"],
            letter=r["letter"],
            label=r["label"],
            gpo_version_before=r["gpo_version_before"],
            gpo_version_after=r["gpo_version_after"],
            backup_path=r["backup_path"],
            status=r["status"],
            details=r["details"],
        )

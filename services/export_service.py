import asyncio
import csv
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite

from services.db_service import DB_PATH
from services.logger_service import get_logger

logger = get_logger("ExportService")

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value: str) -> str:
    if value and value[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


async def export_audit_csv(days: int = 30) -> str:
    """
    Выгружает записи из audit_logs и offboard_snapshots за последние N дней
    в CSV-файл (UTF-8 с BOM) и возвращает путь к файлу.
    """
    now_utc = datetime.now(timezone.utc)
    since_str = (now_utc - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    filename = f"tauria_audit_{now_utc.strftime('%Y%m%d_%H%M')}_{uuid.uuid4().hex[:8]}.csv"
    export_dir = tempfile.gettempdir()
    os.makedirs(export_dir, exist_ok=True)
    file_path = os.path.join(export_dir, filename)

    rows: list[list[str]] = []

    async with aiosqlite.connect(DB_PATH, timeout=15.0) as db:
        await db.execute("PRAGMA busy_timeout=15000;")
        db.row_factory = aiosqlite.Row

        async with db.execute(
            """
            SELECT timestamp, admin_id, admin_username, action, target, status, details
            FROM audit_logs
            WHERE timestamp >= ?
            ORDER BY timestamp DESC
            """,
            (since_str,),
        ) as cursor:
            audit_rows = await cursor.fetchall()
            for r in audit_rows:
                actor = f"{r['admin_username'] or 'Unknown'} ({r['admin_id']})"
                rows.append([
                    "audit_log",
                    str(r["timestamp"] or ""),
                    actor,
                    str(r["action"] or ""),
                    str(r["target"] or ""),
                    str(r["status"] or ""),
                    str(r["details"] or ""),
                ])

        async with db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='offboard_snapshots'"
        ) as tbl_cur:
            has_snapshots = await tbl_cur.fetchone()

        if has_snapshots:
            async with db.execute(
                """
                SELECT username, dn, groups_json, offboarded_at, offboarded_by, restored_at
                FROM offboard_snapshots
                WHERE offboarded_at >= ?
                ORDER BY offboarded_at DESC
                """,
                (since_str,),
            ) as cursor:
                snap_rows = await cursor.fetchall()
                for r in snap_rows:
                    status = "restored" if r["restored_at"] else "offboarded"
                    details = f"dn={r['dn'] or ''}; groups={r['groups_json'] or ''}; restored_at={r['restored_at'] or ''}"
                    rows.append([
                        "offboard_snapshot",
                        str(r["offboarded_at"] or ""),
                        str(r["offboarded_by"] or ""),
                        "offboard",
                        str(r["username"] or ""),
                        status,
                        details,
                    ])

    def _write_csv():
        with open(file_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow(["source", "timestamp", "actor", "action", "target", "status", "details"])
            for row in rows:
                writer.writerow([_sanitize_csv_cell(c) for c in row])

    await asyncio.to_thread(_write_csv)

    logger.info(f"Exported {len(rows)} audit rows for last {days} days to {file_path}")
    return file_path

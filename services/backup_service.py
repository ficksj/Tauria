import asyncio
import glob
import os
import re
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timedelta
from typing import Any, Dict, List

from aiogram.types import FSInputFile

from config import settings
from services.db_service import DB_PATH
from services.logger_service import log

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SENSITIVE_KEY_PATTERN = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|KEY|PRIVATE|CREDENTIAL)",
    re.IGNORECASE,
)


def _collect_db_targets() -> List[str]:
    candidates = [
        DB_PATH,
        "/opt/tauria/data/tauria.db",
        "/opt/kolins/database.db",
        os.path.join(settings.KOLINS_PATH, "database.db") if getattr(settings, "KOLINS_PATH", "") else "",
    ]
    result = []
    seen = set()
    for p in candidates:
        if p and os.path.exists(p):
            real = os.path.abspath(p)
            if real not in seen:
                seen.add(real)
                result.append(p)
    return result


def _collect_env_targets() -> List[str]:
    candidates = [
        os.path.join(_BASE_DIR, ".env"),
        "/opt/tauria/.env",
        "/opt/kolins/.env",
        os.path.join(settings.KOLINS_PATH, ".env") if getattr(settings, "KOLINS_PATH", "") else "",
    ]
    result = []
    seen = set()
    for p in candidates:
        if p and os.path.exists(p):
            real = os.path.abspath(p)
            if real not in seen:
                seen.add(real)
                result.append(p)
    return result


def _collect_unit_targets() -> List[str]:
    units = []
    if os.path.exists("/etc/systemd/system/tauria-bot.service"):
        units.append("/etc/systemd/system/tauria-bot.service")
    for unit_path in sorted(glob.glob("/etc/systemd/system/kolins-*.service")):
        if os.path.exists(unit_path) and unit_path not in units:
            units.append(unit_path)
    return units


def _mask_env_file_content(env_path: str) -> str:
    """Читает .env и маскирует все секреты/пароли/токены (PASSWORD=***)."""
    masked_lines = [f"# Source: {env_path}"]
    try:
        with open(env_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    masked_lines.append(line)
                    continue
                key, val = line.split("=", 1)
                if SENSITIVE_KEY_PATTERN.search(key):
                    masked_lines.append(f"{key.strip()}=***")
                else:
                    masked_lines.append(f"{key.strip()}={val.strip()}")
    except Exception as e:
        masked_lines.append(f"# Error reading {env_path}: {e}")
    return "\n".join(masked_lines) + "\n"


def _sqlite_hot_backup(src_db: str, dst_db: str) -> None:
    src_conn = sqlite3.connect(src_db, timeout=15.0)
    dst_conn = sqlite3.connect(dst_db, timeout=15.0)
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()


async def create_and_send_backup(bot, target_chat_id: int | str) -> Dict[str, Any]:
    """
    Делает горячий снимок SQLite БД через sqlite3.Connection.backup(),
    формирует безопасный env_manifest.txt с замаскированными паролями (PASSWORD=***)
    без включения сырых .env с открытыми секретами, упаковывает всё в .tar.gz архив,
    отправляет его в target_chat_id и удаляет временные файлы.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    temp_dir = tempfile.gettempdir()
    os.makedirs(temp_dir, exist_ok=True)
    archive_path = os.path.join(temp_dir, f"tauria_backup_{timestamp}.tar.gz")

    db_targets = _collect_db_targets()
    env_targets = _collect_env_targets()
    unit_targets = _collect_unit_targets()
    existing_files = [*db_targets, *env_targets, *unit_targets]
    temp_snapshots: List[str] = []

    if not existing_files:
        return {
            "success": False,
            "archive_path": archive_path,
            "files_included": [],
            "error": "Ни один из файлов для резервного копирования не найден.",
        }

    def _create_archive():
        with tarfile.open(archive_path, "w:gz") as tar:
            # 1. Горячие бэкапы SQLite БД
            for idx, db_path in enumerate(db_targets):
                snap_name = f"snap_{timestamp}_{idx}_{os.path.basename(db_path)}"
                snap_path = os.path.join(temp_dir, snap_name)
                _sqlite_hot_backup(db_path, snap_path)
                temp_snapshots.append(snap_path)
                arcname = os.path.join("databases", os.path.basename(db_path)).replace("\\", "/")
                tar.add(snap_path, arcname=arcname)

            # 2. Замаскированный манифест окружения (env_manifest.txt) вместо сырых .env
            if env_targets:
                manifest_path = os.path.join(temp_dir, f"env_manifest_{timestamp}.txt")
                sections = [
                    f"# Tauria & Testarossa (Kolins) Environment Manifest ({timestamp})",
                    "# Sensitive values (PASSWORD, TOKEN, SECRET, KEY) are masked for security.\n",
                ]
                for env_file in env_targets:
                    sections.append(_mask_env_file_content(env_file))
                with open(manifest_path, "w", encoding="utf-8") as mf:
                    mf.write("\n".join(sections))
                temp_snapshots.append(manifest_path)
                tar.add(manifest_path, arcname="env_manifest.txt")

            # 3. Systemd-юниты
            for unit_path in unit_targets:
                arcname = os.path.join("systemd", os.path.basename(unit_path)).replace("\\", "/")
                tar.add(unit_path, arcname=arcname)

    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _create_archive)

        document = FSInputFile(archive_path)
        await bot.send_document(
            chat_id=target_chat_id,
            document=document,
            caption=f"📦 Резервная копия Tauria & Testarossa ({timestamp})\n🔒 Секреты в env_manifest.txt замаскированы.",
        )
        log.info(f"Backup sent to {target_chat_id}: dbs={db_targets}, envs_masked={len(env_targets)}")
        return {
            "success": True,
            "archive_path": archive_path,
            "files_included": [*db_targets, "env_manifest.txt", *unit_targets],
        }
    except Exception as e:
        log.error(f"Failed to create/send backup: {e}")
        return {
            "success": False,
            "archive_path": archive_path,
            "files_included": existing_files,
            "error": str(e),
        }
    finally:
        for tmp_file in [archive_path, *temp_snapshots]:
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except Exception as e:
                    log.warning(f"Failed to remove temporary file {tmp_file}: {e}")


async def start_backup_scheduler(bot) -> None:
    """Планировщик автоматического ночного бэкапа в 03:00 в settings.LOG_CHAT_ID."""
    log.info("BackupScheduler started (daily at 03:00)")
    while True:
        try:
            now = datetime.now()
            next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)

            wait_seconds = (next_run - now).total_seconds()
            await asyncio.sleep(wait_seconds)

            if settings.LOG_CHAT_ID:
                await create_and_send_backup(bot, settings.LOG_CHAT_ID)
            else:
                log.warning("BackupScheduler: LOG_CHAT_ID не задан, бэкап пропущен")
        except asyncio.CancelledError:
            log.info("BackupScheduler stopped")
            raise
        except Exception as e:
            log.error(f"BackupScheduler error: {e}")
            await asyncio.sleep(60)

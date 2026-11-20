import asyncio
import glob
import os
import re
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from aiogram.exceptions import TelegramBadRequest
from aiogram.types import FSInputFile

from config import settings
from services.db_service import DB_PATH
from services.logger_service import log

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TZ_LOCAL = timezone(timedelta(hours=5))

SENSITIVE_KEY_PATTERN = re.compile(
    r"(PASSWORD|PASSWD|PASS|PWD|AUTH|BEARER|COOKIE|SECRET|TOKEN|KEY|PRIVATE|CREDENTIAL)",
    re.IGNORECASE,
)


def _collect_db_targets() -> List[str]:
    candidates = [
        DB_PATH,
        os.path.join(_BASE_DIR, "data", "drivemap_audit.db"),
        "/opt/tauria/data/tauria.db",
        "/opt/tauria/data/drivemap_audit.db",
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


def _collect_config_targets() -> List[str]:
    candidates = [
        os.path.join(_BASE_DIR, "config", "shares_policy.yaml"),
        "/opt/tauria/config/shares_policy.yaml",
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


def _mask_unit_file_content(unit_path: str) -> str:
    """Читает systemd-юнит и маскирует секреты в Environment= и других директивах."""
    masked_lines = []
    try:
        with open(unit_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\r\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or "=" not in stripped:
                    masked_lines.append(line)
                    continue
                if stripped.startswith("Environment="):
                    prefix, env_val = line.split("=", 1)
                    env_clean = env_val.strip().strip('"').strip("'")
                    if "=" in env_clean:
                        k, _ = env_clean.split("=", 1)
                        if SENSITIVE_KEY_PATTERN.search(k):
                            masked_lines.append(f'{prefix}="{k.strip()}=***"')
                            continue
                key, _ = line.split("=", 1)
                if SENSITIVE_KEY_PATTERN.search(key):
                    masked_lines.append(f"{key.strip()}=***")
                else:
                    masked_lines.append(line)
    except Exception as e:
        masked_lines.append(f"# Error reading {unit_path}: {e}")
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
    timestamp = datetime.now(TZ_LOCAL).strftime("%Y%m%d_%H%M")

    db_targets = _collect_db_targets()
    env_targets = _collect_env_targets()
    unit_targets = _collect_unit_targets()
    config_targets = _collect_config_targets()
    existing_files = [*db_targets, *env_targets, *unit_targets, *config_targets]

    if not existing_files:
        return {
            "success": False,
            "archive_path": "",
            "files_included": [],
            "error": "Ни один из файлов для резервного копирования не найден.",
        }

    with tempfile.TemporaryDirectory(prefix="tauria_backup_") as work_dir:
        try:
            os.chmod(work_dir, 0o700)
        except OSError:
            pass
        archive_path = os.path.join(work_dir, f"tauria_backup_{timestamp}.tar.gz")

        def _create_archive():
            with tarfile.open(archive_path, "w:gz") as tar:
                # 1. Горячие бэкапы SQLite БД
                for idx, db_path in enumerate(db_targets):
                    snap_name = f"snap_{timestamp}_{idx}_{os.path.basename(db_path)}"
                    snap_path = os.path.join(work_dir, snap_name)
                    _sqlite_hot_backup(db_path, snap_path)
                    arcname = os.path.join("databases", os.path.basename(db_path)).replace("\\", "/")
                    tar.add(snap_path, arcname=arcname)

                # 2. Замаскированный манифест окружения (env_manifest.txt) вместо сырых .env
                if env_targets:
                    manifest_path = os.path.join(work_dir, f"env_manifest_{timestamp}.txt")
                    sections = [
                        f"# Tauria & Testarossa (Kolins) Environment Manifest ({timestamp})",
                        "# Sensitive values (PASSWORD, TOKEN, SECRET, KEY, AUTH) are masked for security.\n",
                    ]
                    for env_file in env_targets:
                        sections.append(_mask_env_file_content(env_file))
                    with open(manifest_path, "w", encoding="utf-8") as mf:
                        mf.write("\n".join(sections))
                    tar.add(manifest_path, arcname="env_manifest.txt")

                # 3. Конфигурационные файлы (политики DriveMap и т.д.)
                for cfg_path in config_targets:
                    arcname = os.path.join("config", os.path.basename(cfg_path)).replace("\\", "/")
                    tar.add(cfg_path, arcname=arcname)

                # 4. Systemd-юниты (с маскировкой секретов)
                for idx, unit_path in enumerate(unit_targets):
                    masked_unit_path = os.path.join(work_dir, f"unit_{idx}_{os.path.basename(unit_path)}")
                    with open(masked_unit_path, "w", encoding="utf-8") as uf:
                        uf.write(_mask_unit_file_content(unit_path))
                    arcname = os.path.join("systemd", os.path.basename(unit_path)).replace("\\", "/")
                    tar.add(masked_unit_path, arcname=arcname)

        try:
            await asyncio.to_thread(_create_archive)

            caption = (
                f"📦 Резервная копия Tauria & Testarossa ({timestamp})\n"
                "🔒 Секреты в env_manifest.txt и systemd-юнитах замаскированы."
            )
            sent_chat_id = target_chat_id
            try:
                await bot.send_document(
                    chat_id=target_chat_id,
                    document=FSInputFile(archive_path),
                    caption=caption,
                )
            except TelegramBadRequest as send_err:
                fallback_id = settings.super_admins[0] if settings.super_admins else None
                if fallback_id and str(fallback_id) != str(target_chat_id):
                    log.warning(
                        f"Backup send to {target_chat_id} failed ({send_err}); "
                        f"falling back to super_admin {fallback_id}"
                    )
                    await bot.send_document(
                        chat_id=fallback_id,
                        document=FSInputFile(archive_path),
                        caption=f"{caption}\n⚠️ Fallback: отправка в {target_chat_id} не удалась.",
                    )
                    sent_chat_id = fallback_id
                else:
                    raise

            log.info(
                f"Backup sent to {sent_chat_id}: dbs={db_targets}, "
                f"configs={config_targets}, envs_masked={len(env_targets)}"
            )
            return {
                "success": True,
                "archive_path": archive_path,
                "files_included": [*db_targets, "env_manifest.txt", *config_targets, *unit_targets],
            }
        except Exception as e:
            log.error(f"Failed to create/send backup: {e}")
            return {
                "success": False,
                "archive_path": archive_path,
                "files_included": existing_files,
                "error": str(e),
            }


async def start_backup_scheduler(bot) -> None:
    """Планировщик автоматического ночного бэкапа в 03:00 (UTC+5) в settings.LOG_CHAT_ID."""
    log.info("BackupScheduler started (daily at 03:00 UTC+5)")
    while True:
        try:
            now = datetime.now(TZ_LOCAL)
            next_run = now.replace(hour=3, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)

            wait_seconds = (next_run - now).total_seconds()
            await asyncio.sleep(wait_seconds)

            if settings.LOG_CHAT_ID:
                await create_and_send_backup(bot, settings.LOG_CHAT_ID)
            elif settings.super_admins:
                await create_and_send_backup(bot, settings.super_admins[0])
            else:
                log.warning("BackupScheduler: LOG_CHAT_ID и super_admins не заданы, бэкап пропущен")
        except asyncio.CancelledError:
            log.info("BackupScheduler stopped")
            raise
        except Exception as e:
            log.error(f"BackupScheduler error: {e}")
            await asyncio.sleep(60)

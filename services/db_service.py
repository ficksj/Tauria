from contextlib import asynccontextmanager, contextmanager
import aiosqlite
import sqlite3
import os
import json
from datetime import datetime
from config import settings
from services.logger_service import log

_default_db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "tauria.db")
DB_PATH = settings.SHARED_DB_PATH.strip() if getattr(settings, "SHARED_DB_PATH", "").strip() else _default_db_path


async def _apply_async_pragmas(db: aiosqlite.Connection) -> None:
    await db.execute("PRAGMA synchronous=NORMAL;")
    await db.execute("PRAGMA busy_timeout=15000;")


@asynccontextmanager
async def _get_async_conn(db_path: str | None = None):
    target_path = db_path or DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    async with aiosqlite.connect(target_path, timeout=15.0) as db:
        await _apply_async_pragmas(db)
        yield db


@contextmanager
def _get_conn(db_path: str | None = None):
    """Открывает синхронное SQLite-соединение и закрывает его при выходе из контекста."""
    target_path = db_path or DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    conn = sqlite3.connect(target_path, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=15000;")
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _init_db_sync(db_path: str | None = None):
    """Синхронное создание таблиц и индексов (для безопасного вызова при старте или импорте)."""
    try:
        with _get_conn(db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    admin_id INTEGER NOT NULL,
                    admin_username TEXT,
                    action TEXT NOT NULL,
                    target TEXT,
                    status TEXT NOT NULL,
                    details TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS monitored_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    ip_or_fqdn TEXT NOT NULL,
                    host_type TEXT DEFAULT 'server',
                    is_active INTEGER DEFAULT 1,
                    last_checked DATETIME,
                    last_status TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS jit_grants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    group_name TEXT NOT NULL,
                    granted_at DATETIME NOT NULL,
                    expires_at DATETIME NOT NULL,
                    granted_by INTEGER NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    revoked_at DATETIME
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_pc_sessions (
                    username TEXT PRIMARY KEY,
                    pc_name TEXT NOT NULL,
                    dns_name TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_pc_sessions_pc_name ON user_pc_sessions (pc_name)
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_original_ou (
                    username TEXT PRIMARY KEY,
                    original_ou TEXT NOT NULL,
                    moved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sent_alerts (
                    alert_key TEXT PRIMARY KEY,
                    alert_type TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bot_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS lotus_id_transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pc_name TEXT NOT NULL,
                    dns_name TEXT,
                    win_profile TEXT NOT NULL,
                    ad_username TEXT,
                    original_filename TEXT NOT NULL,
                    original_unc_dir TEXT NOT NULL,
                    storage_filename TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'extracted',
                    admin_id INTEGER,
                    extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    returned_at TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_lotus_pc_status
                ON lotus_id_transfers (pc_name, status)
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS offboard_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    dn TEXT,
                    groups_json TEXT NOT NULL,
                    offboarded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    offboarded_by INTEGER,
                    restored_at DATETIME
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bot_admins (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    role TEXT DEFAULT 'operator',
                    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    except Exception as e:
        log.error(f"Ошибка синхронной инициализации БД: {e}")


async def init_db(db_path: str | None = None):
    async with _get_async_conn(db_path) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                admin_id INTEGER NOT NULL,
                admin_username TEXT,
                action TEXT NOT NULL,
                target TEXT,
                status TEXT NOT NULL,
                details TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS monitored_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                ip_or_fqdn TEXT NOT NULL,
                host_type TEXT DEFAULT 'server',
                is_active INTEGER DEFAULT 1,
                last_checked DATETIME,
                last_status TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS jit_grants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                group_name TEXT NOT NULL,
                granted_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                granted_by INTEGER NOT NULL,
                is_active INTEGER DEFAULT 1,
                revoked_at DATETIME
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS user_pc_sessions (
                username TEXT PRIMARY KEY,
                pc_name TEXT NOT NULL,
                dns_name TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_pc_sessions_pc_name ON user_pc_sessions (pc_name)
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS user_original_ou (
                username TEXT PRIMARY KEY,
                original_ou TEXT NOT NULL,
                moved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sent_alerts (
                alert_key TEXT PRIMARY KEY,
                alert_type TEXT NOT NULL,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS bot_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS lotus_id_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pc_name TEXT NOT NULL,
                dns_name TEXT,
                win_profile TEXT NOT NULL,
                ad_username TEXT,
                original_filename TEXT NOT NULL,
                original_unc_dir TEXT NOT NULL,
                storage_filename TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'extracted',
                admin_id INTEGER,
                extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                returned_at TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_lotus_pc_status
            ON lotus_id_transfers (pc_name, status)
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS offboard_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                dn TEXT,
                groups_json TEXT NOT NULL,
                offboarded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                offboarded_by INTEGER,
                restored_at DATETIME
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS bot_admins (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                role TEXT DEFAULT 'operator',
                added_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()
        log.info(f"Database initialized successfully in WAL mode ({db_path or DB_PATH}).")


async def log_audit_action(
    admin_id: int,
    admin_username: str | None,
    action: str,
    target: str | None,
    status: str,
    details: str | None = None,
):
    try:
        async with _get_async_conn() as db:
            await db.execute(
                """
                INSERT INTO audit_logs (admin_id, admin_username, action, target, status, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (admin_id, admin_username or "Unknown", action, target, status, details),
            )
            await db.commit()
    except Exception as e:
        log.error(f"Failed to log audit action: {e}")


async def get_recent_audit_logs(limit: int = 15):
    async with _get_async_conn() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        ) as cursor:
            return await cursor.fetchall()


async def create_jit_grant(username: str, group_name: str, granted_at: str, expires_at: str, granted_by: int) -> int:
    async with _get_async_conn() as db:
        cursor = await db.execute(
            """
            INSERT INTO jit_grants (username, group_name, granted_at, expires_at, granted_by, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
            """,
            (username, group_name, granted_at, expires_at, granted_by),
        )
        await db.commit()
        return cursor.lastrowid


async def get_active_jit_grants():
    async with _get_async_conn() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM jit_grants WHERE is_active = 1 ORDER BY expires_at ASC"
        ) as cursor:
            return await cursor.fetchall()


async def mark_jit_revoked(grant_id: int, revoked_at: str | None = None):
    if revoked_at is None:
        revoked_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    async with _get_async_conn() as db:
        await db.execute(
            """
            UPDATE jit_grants
            SET is_active = 0, revoked_at = ?
            WHERE id = ?
            """,
            (revoked_at, grant_id),
        )
        await db.commit()


# --- Синхронные функции работы с сессиями пользователей и ПК (совместимость с Kolins / Testarossa) ---

def save_user_pc_session(username: str, pc_name: str, dns_name: str = ""):
    """Сохранение/обновление привязки пользователя к ПК."""
    if not username or not pc_name:
        return
    username_clean = username.strip().lower()
    pc_clean = pc_name.strip().upper()
    try:
        with _get_conn() as conn:
            conn.execute("""
                INSERT INTO user_pc_sessions (username, pc_name, dns_name, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(username) DO UPDATE SET
                    pc_name = excluded.pc_name,
                    dns_name = excluded.dns_name,
                    updated_at = CURRENT_TIMESTAMP
            """, (username_clean, pc_clean, dns_name))
            conn.commit()
        log.debug(f"Сессия сохранена: {username_clean} -> {pc_clean}")
    except Exception as e:
        log.error(f"Ошибка сохранения сессии в БД: {e}")


def get_user_pc_session(username: str) -> dict | None:
    """Получение сохраненного ПК пользователя из БД."""
    if not username:
        return None
    username_clean = username.strip().lower()
    try:
        with _get_conn() as conn:
            row = conn.execute("""
                SELECT pc_name, dns_name, updated_at
                FROM user_pc_sessions
                WHERE username = ?
            """, (username_clean,)).fetchone()
        if row:
            return {
                "pc_name": row["pc_name"],
                "dns_name": row["dns_name"],
                "updated_at": row["updated_at"],
            }
        return None
    except Exception as e:
        log.error(f"Ошибка получения сессии из БД: {e}")
        return None


def get_pc_user_session(pc_name: str) -> dict | None:
    """Получение сохраненного пользователя ПК из БД (обратный поиск по имени ПК)."""
    if not pc_name:
        return None
    pc_clean = pc_name.strip().upper()
    try:
        with _get_conn() as conn:
            row = conn.execute("""
                SELECT username, dns_name, updated_at
                FROM user_pc_sessions
                WHERE pc_name = ? OR UPPER(dns_name) LIKE ?
                ORDER BY updated_at DESC
                LIMIT 1
            """, (pc_clean, f"{pc_clean}.%")).fetchone()
        if row:
            return {
                "username": row["username"],
                "dns_name": row["dns_name"],
                "updated_at": row["updated_at"],
            }
        return None
    except Exception as e:
        log.error(f"Ошибка получения сессии по ПК из БД: {e}")
        return None


def count_user_pc_sessions() -> int:
    """Количество известных связок пользователь <-> ПК в БД."""
    try:
        with _get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM user_pc_sessions").fetchone()
        return int(row["cnt"]) if row else 0
    except Exception as e:
        log.error(f"Ошибка подсчета сессий: {e}")
        return 0


# --- Хранение исходного OU для сертификации ---

def save_original_ou(username: str, original_ou: str):
    """Сохранение исходного OU пользователя."""
    username_clean = username.strip().lower()
    try:
        with _get_conn() as conn:
            conn.execute("""
                INSERT INTO user_original_ou (username, original_ou, moved_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(username) DO UPDATE SET
                    original_ou = excluded.original_ou,
                    moved_at = CURRENT_TIMESTAMP
            """, (username_clean, original_ou))
            conn.commit()
    except Exception as e:
        log.error(f"Ошибка сохранения исходного OU: {e}")


def get_original_ou(username: str) -> str | None:
    """Получение сохраненного исходного OU."""
    username_clean = username.strip().lower()
    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT original_ou FROM user_original_ou WHERE username = ?",
                (username_clean,),
            ).fetchone()
        return row["original_ou"] if row else None
    except Exception as e:
        log.error(f"Ошибка получения исходного OU: {e}")
        return None


def remove_original_ou(username: str):
    """Удаление записи исходного OU после возврата."""
    username_clean = username.strip().lower()
    try:
        with _get_conn() as conn:
            conn.execute("DELETE FROM user_original_ou WHERE username = ?", (username_clean,))
            conn.commit()
    except Exception as e:
        log.error(f"Ошибка удаления исходного OU: {e}")


def list_users_in_cert_ou() -> list[dict]:
    """Список пользователей, перемещенных для выпуска сертификата и ожидающих возврата."""
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT username, original_ou, moved_at
                FROM user_original_ou
                ORDER BY moved_at DESC
            """).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"Ошибка чтения списка cert OU: {e}")
        return []


# --- Алерты и настройки ---

def is_alert_sent(alert_key: str, hours: int = 12) -> bool:
    """Проверяет, отправлялся ли алерт за последние N часов."""
    try:
        with _get_conn() as conn:
            row = conn.execute("""
                SELECT 1 FROM sent_alerts
                WHERE alert_key = ? AND datetime(sent_at) > datetime('now', ?)
            """, (alert_key, f"-{int(hours)} hours")).fetchone()
        return row is not None
    except Exception as e:
        log.error(f"Ошибка проверки алерта: {e}")
        return False


def record_alert_sent(alert_key: str, alert_type: str = "lockout"):
    """Фиксирует факт отправки алерта."""
    try:
        with _get_conn() as conn:
            conn.execute("""
                INSERT INTO sent_alerts (alert_key, alert_type, sent_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(alert_key) DO UPDATE SET
                    sent_at = CURRENT_TIMESTAMP
            """, (alert_key, alert_type))
            conn.commit()
    except Exception as e:
        log.error(f"Ошибка записи отправленного алерта: {e}")


def get_setting(key: str, default: str | None = None) -> str | None:
    """Чтение настройки бота из БД."""
    try:
        with _get_conn() as conn:
            row = conn.execute("SELECT value FROM bot_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    except Exception as e:
        log.error(f"Ошибка чтения настройки {key}: {e}")
        return default


def set_setting(key: str, value: str):
    """Сохранение настройки бота в БД."""
    try:
        with _get_conn() as conn:
            conn.execute("""
                INSERT INTO bot_settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP
            """, (key, str(value)))
            conn.commit()
    except Exception as e:
        log.error(f"Ошибка сохранения настройки {key}: {e}")


# --- IBM Lotus Notes ID Transfers ---

def save_lotus_transfer(
    pc_name: str,
    dns_name: str,
    win_profile: str,
    original_filename: str,
    original_unc_dir: str,
    storage_filename: str,
    ad_username: str | None = None,
    admin_id: int | None = None,
) -> int | None:
    """Сохраняет запись об извлеченном Lotus ID файле (или обновляет активную запись для того же профиля/файла)."""
    pc_clean = pc_name.strip().upper()
    try:
        with _get_conn() as conn:
            conn.execute("""
                UPDATE lotus_id_transfers
                SET status = 'superseded'
                WHERE pc_name = ? AND LOWER(win_profile) = LOWER(?)
                  AND LOWER(original_filename) = LOWER(?) AND status = 'extracted'
            """, (pc_clean, win_profile, original_filename))

            cursor = conn.execute("""
                INSERT INTO lotus_id_transfers (
                    pc_name, dns_name, win_profile, ad_username,
                    original_filename, original_unc_dir, storage_filename,
                    status, admin_id, extracted_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'extracted', ?, CURRENT_TIMESTAMP)
            """, (
                pc_clean, dns_name, win_profile, ad_username,
                original_filename, original_unc_dir, storage_filename, admin_id
            ))
            conn.commit()
            return cursor.lastrowid
    except Exception as e:
        log.error(f"Ошибка сохранения переноса Lotus ID: {e}")
        return None


def get_lotus_transfer_by_id(transfer_id: int) -> dict | None:
    """Возвращает запись о переносе Lotus ID по его ID."""
    try:
        with _get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM lotus_id_transfers WHERE id = ?",
                (transfer_id,),
            ).fetchone()
        return dict(row) if row else None
    except Exception as e:
        log.error(f"Ошибка чтения переноса Lotus ID #{transfer_id}: {e}")
        return None


def get_lotus_transfer(transfer_id: int) -> dict | None:
    """Алиас для получения переноса Lotus ID по ID."""
    return get_lotus_transfer_by_id(transfer_id)


def get_active_lotus_transfers_by_pc(pc_name: str) -> list[dict]:
    """Возвращает все активные (невозвращенные) Lotus ID для указанного ПК."""
    pc_clean = pc_name.strip().upper()
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM lotus_id_transfers
                WHERE pc_name = ? AND status = 'extracted'
                ORDER BY extracted_at DESC
            """, (pc_clean,)).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"Ошибка поиска Lotus ID для ПК {pc_name}: {e}")
        return []


def get_latest_lotus_transfer_by_pc(pc_name: str) -> dict | None:
    """Последняя запись (активная или уже возвращенная) для ПК — чтобы помнить имя файла."""
    pc_clean = pc_name.strip().upper()
    try:
        with _get_conn() as conn:
            row = conn.execute("""
                SELECT * FROM lotus_id_transfers
                WHERE pc_name = ? AND status IN ('extracted', 'returned')
                ORDER BY extracted_at DESC
                LIMIT 1
            """, (pc_clean,)).fetchone()
        return dict(row) if row else None
    except Exception as e:
        log.error(f"Ошибка получения истории Lotus ID для {pc_name}: {e}")
        return None


def list_pending_lotus_transfers() -> list[dict]:
    """Список всех Lotus ID файлов, ожидающих возврата на ПК."""
    try:
        with _get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM lotus_id_transfers
                WHERE status = 'extracted'
                ORDER BY extracted_at DESC
            """).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        log.error(f"Ошибка получения списка ожидающих Lotus ID: {e}")
        return []


def mark_lotus_returned(transfer_id: int):
    """Отмечает Lotus ID как возвращенный на компьютер."""
    try:
        with _get_conn() as conn:
            conn.execute("""
                UPDATE lotus_id_transfers
                SET status = 'returned', returned_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (transfer_id,))
            conn.commit()
    except Exception as e:
        log.error(f"Ошибка обновления статуса Lotus ID #{transfer_id}: {e}")


def mark_lotus_transfer_returned(transfer_id: int):
    """Алиас для mark_lotus_returned."""
    mark_lotus_returned(transfer_id)


def delete_lotus_transfer(transfer_id: int) -> bool:
    """Удаляет запись о переносе Lotus ID из БД."""
    try:
        with _get_conn() as conn:
            cursor = conn.execute(
                "DELETE FROM lotus_id_transfers WHERE id = ?",
                (transfer_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        log.error(f"Ошибка удаления записи Lotus ID #{transfer_id}: {e}")
        return False


# --- Offboarding snapshots & Bot Admins ---

async def save_offboard_snapshot(username: str, dn: str | None, groups: list[str], offboarded_by: int | None = None):
    try:
        async with _get_async_conn() as db:
            await db.execute(
                """
                INSERT INTO offboard_snapshots (username, dn, groups_json, offboarded_by)
                VALUES (?, ?, ?, ?)
                """,
                (username, dn, json.dumps(groups, ensure_ascii=False), offboarded_by),
            )
            await db.commit()
    except Exception as e:
        log.error(f"Ошибка сохранения снапшота увольнения для {username}: {e}")


async def get_offboard_snapshots(username: str) -> list[dict]:
    try:
        async with _get_async_conn() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT id, username, dn, groups_json, offboarded_at, offboarded_by, restored_at
                FROM offboard_snapshots
                WHERE LOWER(username) = LOWER(?)
                ORDER BY id DESC
                """,
                (username,),
            ) as cursor:
                rows = await cursor.fetchall()
                result = []
                for row in rows:
                    try:
                        groups = json.loads(row["groups_json"] or "[]")
                    except Exception:
                        groups = []
                    result.append({
                        "id": row["id"],
                        "username": row["username"],
                        "dn": row["dn"],
                        "groups": groups,
                        "offboarded_at": row["offboarded_at"],
                        "offboarded_by": row["offboarded_by"],
                        "restored_at": row["restored_at"],
                        "restored": row["restored_at"] is not None,
                    })
                return result
    except Exception as e:
        log.error(f"Ошибка получения снапшотов увольнения для {username}: {e}")
        return []


async def mark_snapshot_restored(snapshot_id: int):
    try:
        async with _get_async_conn() as db:
            await db.execute(
                """
                UPDATE offboard_snapshots
                SET restored_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (snapshot_id,),
            )
            await db.commit()
    except Exception as e:
        log.error(f"Ошибка отметки снапшота {snapshot_id} как восстановленного: {e}")


async def add_bot_admin(user_id: int, username: str | None, role: str = "operator") -> None:
    async with _get_async_conn() as db:
        await db.execute(
            """
            INSERT INTO bot_admins (user_id, username, role)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                role = excluded.role
            """,
            (user_id, username, role),
        )
        await db.commit()


async def remove_bot_admin(user_id: int) -> bool:
    async with _get_async_conn() as db:
        cursor = await db.execute("DELETE FROM bot_admins WHERE user_id = ?", (user_id,))
        await db.commit()
        return cursor.rowcount > 0


async def get_bot_admins() -> list[dict]:
    async with _get_async_conn() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT user_id, username, role, added_at FROM bot_admins ORDER BY added_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


async def get_bot_admin_role(user_id: int) -> str | None:
    async with _get_async_conn() as db:
        async with db.execute(
            "SELECT role FROM bot_admins WHERE user_id = ?", (user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None


# Гарантируем создание таблиц при импорте
_init_db_sync()

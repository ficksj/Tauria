import asyncio
import os
import re
import sqlite3
from typing import Dict, Any, List, Optional
from config import settings
from services.logger_service import log


class KolinsManagerService:
    """
    Сервис управления и мониторинга 🏎 Testarossa (Kolins) Support Bot:
    - Управление администраторами (ADMIN_IDS) в /opt/kolins/.env
    - Получение статистики по базе данных (SHARED_DB_PATH или /opt/kolins/database.db)
    - Сбор оперативной статистики по обращениям и сбросам паролей (БД + journalctl)
    """

    def __init__(self, kolins_path: Optional[str] = None):
        self.kolins_path = kolins_path or settings.KOLINS_PATH
        self.env_path = os.path.join(self.kolins_path, ".env")
        shared_db = (getattr(settings, "SHARED_DB_PATH", "") or "").strip()
        self.db_path = shared_db if shared_db else os.path.join(self.kolins_path, "database.db")

    # ==========================================
    # 1. Управление ADMIN_IDS в .env
    # ==========================================

    def _read_env_lines(self) -> List[str]:
        """Чтение строк файла .env"""
        if not os.path.exists(self.env_path):
            raise FileNotFoundError(f"Файл окружения не найден: {self.env_path}")
        with open(self.env_path, "r", encoding="utf-8") as f:
            return f.readlines()

    def _write_env_lines(self, lines: List[str]):
        """Запись строк обратно в .env"""
        with open(self.env_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

    async def get_admin_ids(self) -> List[int]:
        """
        Чтение списка ADMIN_IDS из /opt/kolins/.env
        Возвращает список целочисленных Telegram ID.
        """
        def _get():
            try:
                lines = self._read_env_lines()
                for line in lines:
                    line_str = line.strip()
                    if line_str.startswith("ADMIN_IDS="):
                        val = line_str.split("=", 1)[1].strip()
                        raw_ids = [part.strip() for part in val.split(",") if part.strip()]
                        return [int(x) for x in raw_ids if x.lstrip("-").isdigit()]
                return []
            except Exception as e:
                log.error(f"Failed to read ADMIN_IDS from {self.env_path}: {e}")
                return []

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _get)

    async def add_admin_id(self, new_id: int) -> bool:
        """
        Добавление Telegram ID в ADMIN_IDS в /opt/kolins/.env.
        Если ID уже есть, возвращает True.
        """
        def _add():
            try:
                lines = self._read_env_lines()
                found = False
                updated_lines = []
                for line in lines:
                    if line.strip().startswith("ADMIN_IDS="):
                        found = True
                        val = line.strip().split("=", 1)[1].strip()
                        parts = [p.strip() for p in val.split(",") if p.strip()]
                        id_str = str(new_id)
                        if id_str not in parts:
                            parts.append(id_str)
                        updated_lines.append(f"ADMIN_IDS={', '.join(parts)}\n")
                    else:
                        updated_lines.append(line)

                if not found:
                    updated_lines.append(f"\nADMIN_IDS={new_id}\n")

                self._write_env_lines(updated_lines)
                log.info(f"Added admin ID {new_id} to Testarossa (Kolins) .env")
                return True
            except Exception as e:
                log.error(f"Failed to add admin ID {new_id} to {self.env_path}: {e}")
                return False

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _add)

    async def remove_admin_id(self, target_id: int) -> bool:
        """
        Удаление Telegram ID из ADMIN_IDS в /opt/kolins/.env.
        """
        def _remove():
            try:
                lines = self._read_env_lines()
                found = False
                target_str = str(target_id)
                updated_lines = []
                for line in lines:
                    if line.strip().startswith("ADMIN_IDS="):
                        found = True
                        val = line.strip().split("=", 1)[1].strip()
                        parts = [p.strip() for p in val.split(",") if p.strip()]
                        parts = [p for p in parts if p != target_str]
                        updated_lines.append(f"ADMIN_IDS={', '.join(parts)}\n")
                    else:
                        updated_lines.append(line)

                if not found:
                    return False

                self._write_env_lines(updated_lines)
                log.info(f"Removed admin ID {target_id} from Testarossa (Kolins) .env")
                return True
            except Exception as e:
                log.error(f"Failed to remove admin ID {target_id} from {self.env_path}: {e}")
                return False

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _remove)

    # ==========================================
    # 2. Статистика базы данных и операций
    # ==========================================

    async def get_db_stats(self) -> Dict[str, Any]:
        """
        Получение оперативной статистики из базы данных Testarossa (Kolins):
        - active_sessions: количество привязок ПК (user_pc_sessions)
        - moved_users: количество перемещенных пользователей (user_original_ou)
        - sent_alerts: количество отправленных алертов (sent_alerts)
        - alerts_24h: количество алертов за последние 24 часа
        - lotus_pending: количество активных Lotus ID в хранилище
        - db_size_kb: размер файла БД в КБ
        """
        def _query_db():
            target_db = self.db_path
            if not os.path.exists(target_db):
                from services.db_service import DB_PATH as TAURIA_DB
                if os.path.exists(TAURIA_DB):
                    target_db = TAURIA_DB
                else:
                    return {
                        "exists": False,
                        "error": f"Файл базы данных не найден: {self.db_path}",
                        "active_sessions": 0,
                        "moved_users": 0,
                        "sent_alerts": 0,
                        "alerts_24h": 0,
                        "lotus_pending": 0,
                        "db_size_kb": 0,
                    }

            try:
                db_size = os.path.getsize(target_db) // 1024
                conn = sqlite3.connect(target_db, timeout=15.0)
                cur = conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL;")
                cur.execute("PRAGMA busy_timeout=15000;")

                cur.execute("SELECT COUNT(*) FROM user_pc_sessions")
                sessions = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM user_original_ou")
                moved = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM sent_alerts")
                alerts_total = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM sent_alerts WHERE datetime(sent_at) > datetime('now', '-24 hours')")
                alerts_24h = cur.fetchone()[0]

                lotus_pending = 0
                try:
                    cur.execute("SELECT COUNT(*) FROM lotus_id_transfers WHERE status = 'extracted'")
                    lotus_pending = cur.fetchone()[0]
                except Exception:
                    pass

                cur.execute("SELECT username, pc_name, updated_at FROM user_pc_sessions ORDER BY updated_at DESC LIMIT 5")
                recent_sessions = [{"username": r[0], "pc_name": r[1], "updated_at": r[2]} for r in cur.fetchall()]

                conn.close()
                return {
                    "exists": True,
                    "active_sessions": sessions,
                    "moved_users": moved,
                    "sent_alerts": alerts_total,
                    "alerts_24h": alerts_24h,
                    "lotus_pending": lotus_pending,
                    "db_size_kb": db_size,
                    "recent_sessions": recent_sessions,
                }
            except Exception as e:
                log.error(f"Error querying Testarossa DB ({target_db}): {e}")
                return {
                    "exists": True,
                    "error": str(e),
                    "active_sessions": 0,
                    "moved_users": 0,
                    "sent_alerts": 0,
                    "alerts_24h": 0,
                    "lotus_pending": 0,
                    "db_size_kb": 0,
                }

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _query_db)

    async def get_operational_stats(self, journal_lines: int = 1500) -> Dict[str, Any]:
        """
        Комплексная оперативная статистика Testarossa (Kolins):
        - Данные из БД (сессии ПК, алерты блокировок, активные перемещения).
        - Данные из journalctl kolins-bot.
        """
        db_stats = await self.get_db_stats()

        def _parse_journal():
            stats = {
                "password_resets": 0,
                "user_unlocks": 0,
                "handover_acts": 0,
                "ad_searches": 0,
                "total_requests": 0,
                "lockout_alerts_detected": 0,
            }
            if os.name == "nt":
                return stats
            try:
                import subprocess
                cmd = ["journalctl", "-u", "kolins-bot", "-n", str(journal_lines), "--no-pager"]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
                if res.returncode == 0:
                    text = res.stdout
                    for line in text.splitlines():
                        line_lower = line.lower()
                        if "сброс пароля" in line_lower or "reset_password" in line_lower:
                            stats["password_resets"] += 1
                        if "разблокировк" in line_lower or "unlock_user" in line_lower:
                            stats["user_unlocks"] += 1
                        if "акт приема-передачи" in line_lower or "printservice" in line:
                            stats["handover_acts"] += 1
                        if "anr:" in line_lower or "поиск в ad" in line_lower or "поиск anr" in line_lower:
                            stats["ad_searches"] += 1
                        if "отправлен алерт о блокировке" in line_lower:
                            stats["lockout_alerts_detected"] += 1

                    stats["total_requests"] = (
                        stats["password_resets"]
                        + stats["user_unlocks"]
                        + stats["handover_acts"]
                        + stats["ad_searches"]
                    )
            except Exception as e:
                log.warning(f"Failed to parse journalctl for Kolins operations: {e}")

            return stats

        loop = asyncio.get_running_loop()
        ops_stats = await loop.run_in_executor(None, _parse_journal)

        return {
            "db": db_stats,
            "operations": ops_stats,
        }

    # ==========================================
    # 4. Режим обслуживания (Maintenance Mode)
    # ==========================================

    async def toggle_maintenance(self, enable: bool) -> Dict[str, Any]:
        """
        Включает (останавливает kolins-bot) или выключает (запускает kolins-bot)
        режим обслуживания саппорт-бота.
        """
        action = "stop" if enable else "start"
        cmd = ["sudo", "systemctl", action, "kolins-bot"]

        def _toggle():
            import subprocess
            try:
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15,
                )
                return {
                    "success": res.returncode == 0,
                    "maintenance": enable,
                    "action": action,
                    "service": "kolins-bot",
                    "stdout": res.stdout.strip(),
                    "stderr": res.stderr.strip(),
                }
            except Exception as e:
                log.error(f"Failed to {action} kolins-bot: {e}")
                return {
                    "success": False,
                    "maintenance": enable,
                    "action": action,
                    "service": "kolins-bot",
                    "stdout": "",
                    "stderr": str(e),
                }

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _toggle)


kolins_manager_service = KolinsManagerService()

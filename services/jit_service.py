import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from aiogram import Bot
from config import settings
from services.logger_service import log
from services.ad_service import ad_service
from services.db_service import create_jit_grant, get_active_jit_grants, mark_jit_revoked, log_audit_action
from services.rich_message_service import send_rich_to_chat

class JITService:
    def __init__(self):
        self._checker_task: Optional[asyncio.Task] = None
        self._is_running: bool = False

    async def grant_temporary_access(
        self, 
        username: str, 
        group_name: str, 
        duration_minutes: int, 
        granted_by: int
    ) -> Dict[str, Any]:
        """
        Предоставление Just-In-Time (JIT) временных привилегий:
        - Добавляет пользователя в указанную AD группу (Domain Admins, Enterprise Admins, VPN_Users и т.д.) через ad_service.add_user_to_group.
        - Сохраняет запись в БД (таблица jit_grants: id, username, group_name, granted_at, expires_at, granted_by, is_active, revoked_at).
        - Логирует аудит.
        """
        granted_at_dt = datetime.utcnow()
        expires_at_dt = granted_at_dt + timedelta(minutes=duration_minutes)

        granted_at_str = granted_at_dt.strftime("%Y-%m-%d %H:%M:%S")
        expires_at_str = expires_at_dt.strftime("%Y-%m-%d %H:%M:%S")

        log.info(
            f"Granting JIT access: user={username}, group={group_name}, "
            f"duration={duration_minutes}m, granted_by={granted_by}"
        )

        # 1. Добавляем пользователя в группу AD
        ad_success = await ad_service.add_user_to_group(username, group_name)
        if not ad_success:
            err_msg = f"Не удалось добавить пользователя '{username}' в группу '{group_name}' в AD."
            log.error(err_msg)
            await log_audit_action(
                admin_id=granted_by,
                admin_username="SuperAdmin",
                action="JIT_GRANT_FAILED",
                target=f"{username} -> {group_name}",
                status="FAILED",
                details=f"Duration: {duration_minutes} min. AD modify returned False."
            )
            return {
                "success": False,
                "error": err_msg,
                "username": username,
                "group_name": group_name
            }

        # 2. Записываем в SQLite таблицу jit_grants
        grant_id = await create_jit_grant(
            username=username,
            group_name=group_name,
            granted_at=granted_at_str,
            expires_at=expires_at_str,
            granted_by=granted_by
        )

        # 3. Аудит
        await log_audit_action(
            admin_id=granted_by,
            admin_username="SuperAdmin",
            action="JIT_GRANT",
            target=f"{username} -> {group_name}",
            status="SUCCESS",
            details=f"Grant ID: {grant_id}, Duration: {duration_minutes}m, Expires: {expires_at_str}"
        )

        return {
            "success": True,
            "grant_id": grant_id,
            "username": username,
            "group_name": group_name,
            "duration_minutes": duration_minutes,
            "granted_at": granted_at_str,
            "expires_at": expires_at_str,
            "granted_by": granted_by
        }

    async def check_expired_grants(self, bot: Bot):
        """Проверяет истекшие активные JIT гранты и отзывает привилегии."""
        now = datetime.utcnow()
        active_grants = await get_active_jit_grants()

        for grant in active_grants:
            # Парсим время истечения
            expires_str = grant["expires_at"]
            try:
                # В SQLite хранится в формате "%Y-%m-%d %H:%M:%S" или ISO
                if "T" in expires_str:
                    expires_at = datetime.fromisoformat(expires_str)
                else:
                    expires_at = datetime.strptime(expires_str, "%Y-%m-%d %H:%M:%S")
            except Exception as pe:
                log.error(f"Error parsing expires_at '{expires_str}' for grant {grant['id']}: {pe}")
                continue

            if expires_at <= now:
                grant_id = grant["id"]
                username = grant["username"]
                group_name = grant["group_name"]

                log.info(f"⏳ JIT grant {grant_id} expired for {username} in group {group_name}. Revoking...")

                # 1. Удаляем из группы в AD
                remove_success = await ad_service.remove_user_from_group(username, group_name)
                if not remove_success:
                    log.warning(f"Could not remove {username} from {group_name} in AD (maybe already removed).")

                # 2. Помечаем в БД
                revoked_at_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                await mark_jit_revoked(grant_id, revoked_at_str)

                # 3. Аудит
                await log_audit_action(
                    admin_id=0,
                    admin_username="JIT_WORKER",
                    action="JIT_REVOKED",
                    target=f"{username} -> {group_name}",
                    status="SUCCESS" if remove_success else "PARTIAL",
                    details=f"Grant ID: {grant_id}, Expired: {expires_str}, Revoked: {revoked_at_str}"
                )

                # 4. Отправляем уведомление супер-админам в Telegram
                notify_text = (
                    f"⏳ <b>Срок временных привилегий истек!</b>\n"
                    f"Пользователь <code>{username}</code> успешно удален из группы <b>{group_name}</b>."
                )

                recipients = set(settings.super_admins)
                if settings.LOG_CHAT_ID:
                    recipients.add(settings.LOG_CHAT_ID)

                for chat_id in recipients:
                    try:
                        await send_rich_to_chat(bot, chat_id, notify_text)
                        log.info(f"Sent JIT revoke notification for {username} to {chat_id}")
                    except Exception as ex:
                        log.error(f"Failed to send JIT revoke alert to {chat_id}: {ex}")

    async def _worker_loop(self, bot: Bot, check_interval_sec: int = 30):
        log.info(f"JIT checker background worker started (interval: {check_interval_sec}s).")
        while self._is_running:
            try:
                await self.check_expired_grants(bot)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Unexpected error in JIT checker loop: {e}", exc_info=True)

            try:
                await asyncio.sleep(check_interval_sec)
            except asyncio.CancelledError:
                break
        log.info("JIT checker background worker stopped.")

    def start_jit_checker(self, bot: Bot, check_interval_sec: int = 30) -> asyncio.Task:
        if self._is_running and self._checker_task and not self._checker_task.done():
            log.warning("JIT checker is already running.")
            return self._checker_task

        self._is_running = True
        self._checker_task = asyncio.create_task(
            self._worker_loop(bot, check_interval_sec),
            name="JITCheckerWorker"
        )
        return self._checker_task

    async def stop_jit_checker(self):
        self._is_running = False
        if self._checker_task and not self._checker_task.done():
            self._checker_task.cancel()
            try:
                await self._checker_task
            except asyncio.CancelledError:
                pass

    async def revoke_grant_now(self, grant_id: int) -> dict:
        """Досрочный отзыв активного JIT-гранта по ID."""
        active_grants = await get_active_jit_grants()
        grant = next((g for g in active_grants if g["id"] == grant_id), None)
        if not grant:
            return {"success": False, "error": f"Активный JIT-грант #{grant_id} не найден"}

        username = grant["username"]
        group_name = grant["group_name"]

        remove_success = await ad_service.remove_user_from_group(username, group_name)
        revoked_at_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        await mark_jit_revoked(grant_id, revoked_at_str)

        await log_audit_action(
            admin_id=0,
            admin_username="JIT_MANUAL_REVOKE",
            action="JIT_REVOKED",
            target=f"{username} -> {group_name}",
            status="SUCCESS" if remove_success else "PARTIAL",
            details=f"Manual early revoke. Grant ID: {grant_id}, Revoked: {revoked_at_str}"
        )

        return {
            "success": True,
            "grant_id": grant_id,
            "username": username,
            "group_name": group_name,
            "ad_removed": remove_success,
            "revoked_at": revoked_at_str,
        }

jit_service = JITService()

async def grant_temporary_access(username: str, group_name: str, duration_minutes: int, granted_by: int) -> Dict[str, Any]:
    return await jit_service.grant_temporary_access(username, group_name, duration_minutes, granted_by)

def start_jit_checker(bot: Bot, check_interval_sec: int = 30) -> asyncio.Task:
    return jit_service.start_jit_checker(bot, check_interval_sec)

from typing import Callable, Dict, Any, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message, CallbackQuery
from config import settings
from services.db_service import get_bot_admin_role
from services.logger_service import log

SUPERADMIN_ONLY_CALLBACK_PREFIXES = (
    "killswitch:",
    "ad:offboard",
    "ad:rollback",
    "srv:restart:",
    "docker:restart:",
    "kolins:maint_",
    "menu:rbac",
    "rbac:",
)
SUPERADMIN_ONLY_COMMANDS = ("/exec",)


class SuperAdminMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any]
    ) -> Any:
        user = None
        if isinstance(event, Message):
            user = event.from_user
        elif isinstance(event, CallbackQuery):
            user = event.from_user

        if not user:
            return await handler(event, data)

        if user.id in settings.super_admins:
            role = "superadmin"
        else:
            role = await get_bot_admin_role(user.id)

        if role is None:
            log.warning(f"Unauthorized access attempt by user_id={user.id} (@{user.username})")
            if isinstance(event, Message):
                await event.answer(
                    "⛔️ <b>Доступ запрещен.</b>\nЭтот бот предназначен только для администраторов системы Tauria.",
                    parse_mode="HTML",
                )
            elif isinstance(event, CallbackQuery):
                await event.answer("⛔️ Доступ запрещен: недостаточно прав.", show_alert=True)
            return

        if role == "operator":
            if isinstance(event, CallbackQuery):
                cb_data = event.data or ""
                if any(cb_data.startswith(prefix) for prefix in SUPERADMIN_ONLY_CALLBACK_PREFIXES):
                    await event.answer(
                        "⛔️ Доступ запрещен: эта операция доступна только SuperAdmin.",
                        show_alert=True,
                    )
                    return
            elif isinstance(event, Message):
                msg_text = (event.text or "").strip()
                if any(msg_text.startswith(cmd) for cmd in SUPERADMIN_ONLY_COMMANDS):
                    await event.answer("⛔️ Команда /exec доступна только для роли SuperAdmin.")
                    return

        data["user_role"] = role
        return await handler(event, data)

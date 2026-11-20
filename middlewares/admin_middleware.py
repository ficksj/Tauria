from typing import Callable, Dict, Any, Awaitable
from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, Message, CallbackQuery
from config import settings
from services.db_service import get_bot_admin_role
from services.logger_service import log

# Строгий allowlist (deny-by-default) для роли operator
OPERATOR_ALLOWED_CALLBACK_PREFIXES = (
    "menu:home",
    "home:main",
    "home:user",
    "home:pc",
    "menu:ad",
    "ad:locked",
    "ad:unlock:",
    "user:show:",
    "user:pc:",
    "user:photo:",
    "user:act:",
    "user:unlock:",
    "user:cert:",
    "user:revert:",
    "user:bindpc:",
    "upage:",
    "ppage:",
    "pc:show:",
    "pc:diag:",
    "pc:events:",
    "pc:gpupdate:",
    "pc:move:",
    "pc:move_comp:",
    "lotus:",
    "health:",
    "noop",
    "cancel",
)

OPERATOR_ALLOWED_COMMANDS = ("/start",)

OPERATOR_ALLOWED_FSM_STATES = {
    "UserSearchState:waiting_for_query",
    "PCSearchState:waiting_for_query",
    "PCBindState:waiting_for_pc",
}


class SuperAdminMiddleware(BaseMiddleware):
    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any]
    ) -> Any:
        user = None
        chat = None
        if isinstance(event, Message):
            user = event.from_user
            chat = event.chat
        elif isinstance(event, CallbackQuery):
            user = event.from_user
            chat = event.message.chat if event.message else None

        # Fail-closed: события без пользователя не пропускаем
        if not user:
            log.warning(f"Blocked event without from_user: {type(event).__name__}")
            return

        # Блокируем любые не-приватные чаты (группы, супергруппы, каналы)
        if chat is not None and getattr(chat, "type", None) != "private":
            log.warning(f"Blocked non-private chat access: chat_id={chat.id}, type={chat.type}, user_id={user.id}")
            return

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
                if not any(cb_data.startswith(prefix) for prefix in OPERATOR_ALLOWED_CALLBACK_PREFIXES):
                    await event.answer(
                        "⛔️ Доступ запрещен: эта операция доступна только SuperAdmin.",
                        show_alert=True,
                    )
                    return
            elif isinstance(event, Message):
                msg_text = (event.text or "").strip()
                is_allowed_cmd = any(
                    msg_text == cmd or msg_text.startswith(f"{cmd} ")
                    for cmd in OPERATOR_ALLOWED_COMMANDS
                )
                if not is_allowed_cmd:
                    fsm_state = None
                    state_ctx = data.get("state")
                    if state_ctx is not None:
                        try:
                            fsm_state = await state_ctx.get_state()
                        except Exception:
                            fsm_state = None
                    if fsm_state not in OPERATOR_ALLOWED_FSM_STATES:
                        await event.answer("⛔️ Доступ запрещен: для роли Operator разрешены только /start и поиск.")
                        return

        data["user_role"] = role
        return await handler(event, data)

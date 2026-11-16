"""Strict Telegram User ID allowlist and private-chat enforcement middleware."""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict

from aiogram import BaseMiddleware
from aiogram.types import CallbackQuery, Message, TelegramObject

logger = logging.getLogger("security.auth")


class AdminAllowlistMiddleware(BaseMiddleware):
    """Rejects any update not originating from an allowed admin ID in a private DM."""

    def __init__(self, allowed_user_ids: set[int]) -> None:
        self.allowed_user_ids = allowed_user_ids

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        user = None
        chat_type = None

        if isinstance(event, Message):
            user = event.from_user
            chat_type = event.chat.type
        elif isinstance(event, CallbackQuery):
            user = event.from_user
            chat_type = event.message.chat.type if event.message else None

        if user is None or user.id not in self.allowed_user_ids:
            uid = user.id if user else None
            uname = user.username if user else None
            logger.warning("Unauthorized access blocked: tg_id=%s username=%s chat_type=%s", uid, uname, chat_type)
            return None

        if chat_type != "private":
            logger.warning("Blocked non-private chat interaction from admin tg_id=%s chat_type=%s", user.id, chat_type)
            return None

        return await handler(event, data)

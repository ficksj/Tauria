from aiogram import Bot
from aiogram.types import User
from config import settings
from services.logger_service import get_logger
from services.db_service import log_audit_action
from services.rich_message_service import (
    html_text,
    render_bubble_card,
    send_rich_to_chat,
)

logger = get_logger("AuditService")

async def send_audit_log(bot: Bot, admin: User, action: str, target: str, status: bool = True):
    status_str = "SUCCESS" if status else "FAILED"
    await log_audit_action(
        admin_id=admin.id,
        admin_username=admin.username,
        action=action,
        target=target,
        status=status_str
    )

    if not settings.LOG_CHAT_ID:
        return

    status_badge_text = "✅ УСПЕШНО" if status else "❌ ОШИБКА"
    badge = "SUCCESS" if status else "FAILURE"
    admin_name = html_text(admin.full_name or "Администратор")
    admin_mention = html_text(f"@{admin.username}") if admin.username else f"ID: {admin.id}"

    body = [
        f"<b>Инициатор:</b> {admin_name} ({admin_mention})",
        f"<b>Действие:</b> <code>{html_text(action)}</code>",
        f"<b>Целевой объект:</b> <code>{html_text(target)}</code>",
        f"<b>Итог операции:</b> {status_badge_text}",
    ]

    table_rows = [
        ("Администратор", f"{admin_name} ({admin_mention})"),
        ("Операция", html_text(action)),
        ("Объект", f"<code>{html_text(target)}</code>"),
        ("Статус", status_badge_text),
    ]

    rich_html = render_bubble_card(
        title="🛡️ Аудит действия AD",
        badge=badge,
        body_lines=body,
        table_rows=table_rows,
        footer_note="Автоматический аудит-лог безопасности Tauria"
    )

    try:
        chat_id = int(settings.LOG_CHAT_ID)
        await send_rich_to_chat(bot, chat_id=chat_id, html=rich_html)
        logger.info(f"Аудит-лог отправлен в чат {chat_id}")
    except Exception as e:
        logger.error(f"Не удалось отправить аудит-лог в чат {settings.LOG_CHAT_ID}: {e}")


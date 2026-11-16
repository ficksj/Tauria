from html import escape
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import InputRichMessage, Message

def html_text(value) -> str:
    """Escape dynamic values for Telegram Rich HTML."""
    return escape(str(value if value is not None and value != "" else "—"), quote=True)

def rich_message(html: str) -> InputRichMessage:
    """Create native Bot API rich-message payload."""
    return InputRichMessage(html=html, skip_entity_detection=True)

async def send_rich(message: Message, html: str) -> Message:
    """Send native Rich Message to current chat."""
    return await message.bot.send_rich_message(
        chat_id=message.chat.id,
        rich_message=rich_message(html),
        message_thread_id=getattr(message, "message_thread_id", None),
    )

async def edit_rich(message: Message, html: str):
    """Replace content of message with new Rich Message."""
    try:
        return await message.edit_text(rich_message=rich_message(html), parse_mode=None)
    except TelegramBadRequest as error:
        if "message can't be edited" not in str(error).lower():
            raise
        return await send_rich(message, html)

async def edit_rich_by_ids(bot, chat_id: int | str, message_id: int, html: str):
    """Edit a Rich Message when only its stored chat/message IDs are available."""
    try:
        return await bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            rich_message=rich_message(html),
            parse_mode=None,
        )
    except TelegramBadRequest as error:
        if "message can't be edited" not in str(error).lower():
            raise
        return await send_rich_to_chat(bot, chat_id, html)

async def send_rich_to_chat(bot, chat_id: int | str, html: str):
    """Send native Rich Message directly to chat/channel."""
    return await bot.send_rich_message(chat_id=chat_id, rich_message=rich_message(html))

def callback_button(label: str, data: str, style: str = "primary") -> str:
    """Build callback button with escaped label and payload."""
    if not data or len(data.encode("utf-8")) > 64:
        raise ValueError("Telegram callback_data must be 1-64 UTF-8 bytes")
    return (
        f'<tg-button type="callback_data" style="{style}" '
        f'data="{html_text(data)}">{html_text(label)}</tg-button>'
    )

def button_row(*buttons: str, align: str = "center") -> str:
    return f'<tg-button-row align="{align}">{"".join(buttons)}</tg-button-row>'

def copy_button(label: str, text: str) -> str:
    return f'<tg-button type="copy_text" text="{html_text(text)}">{html_text(label)}</tg-button>'

def render_progress_bar(percent: float, length: int = 10) -> str:
    pct = max(0.0, min(100.0, percent))
    filled_len = int(round((pct / 100.0) * length))
    bar = "█" * filled_len + "░" * (length - filled_len)
    return f"[{bar}] {int(pct)}%"

def render_bubble_card(
    title: str,
    body_lines: list[str] | None = None,
    badge: str = "",
    table_rows: list[tuple[str, str]] | None = None,
    details_title: str | None = None,
    details_content: str | None = None,
    footer_note: str | None = None,
    buttons: list[str] | None = None,
) -> str:
    """
    Генератор нативного Bubble Widget для Telegram Rich Messages:
    - Заголовок с бейджем
    - Блок blockquote (Bubble card)
    - Таблица параметров (bordered compact striped)
    - Сворачиваемые детали details/summary
    - Кнопки tg-button-row
    """
    html_parts = []
    
    # 1. Заголовок
    badge_html = f" · {badge}" if badge else ""
    html_parts.append(f"<h2>{title}{badge_html}</h2>")
    
    # 2. Основной бабл (blockquote)
    if body_lines:
        content = "<br>".join(body_lines)
        html_parts.append(f"<blockquote>{content}</blockquote>")
        
    # 3. Таблица параметров
    if table_rows:
        rows_html = "".join(
            f"<tr><td><b>{html_text(label)}</b></td><td>{val}</td></tr>"
            for label, val in table_rows
        )
        html_parts.append(f"<table bordered compact striped>{rows_html}</table>")
        
    # 4. Сворачиваемый блок
    if details_title and details_content:
        html_parts.append(
            f"<details><summary>{html_text(details_title)}</summary>{details_content}</details>"
        )
        
    # 5. Примечание
    if footer_note:
        html_parts.append(f"<p><small>ℹ️ {html_text(footer_note)}</small></p>")
        
    # 6. Кнопки
    if buttons:
        html_parts.extend(buttons)
        
    return "".join(html_parts)

import asyncio
from html import escape
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.types import InputRichMessage, Message
from services.logger_service import log

MAX_RICH_HTML_BYTES = 32768
_EDIT_FALLBACK_ERRORS = (
    "message can't be edited",
    "message to edit not found",
    "there is no text in the message to edit",
)


def html_text(value) -> str:
    """Escape dynamic values for Telegram Rich HTML."""
    return escape(str(value if value is not None and value != "" else "—"), quote=True)


def _clamp_rich_html(html: str) -> str:
    """Контролирует максимальную длину Rich HTML, чтобы избежать падения API."""
    if not html:
        return ""
    encoded = html.encode("utf-8")
    if len(encoded) <= MAX_RICH_HTML_BYTES:
        return html
    log.warning(
        f"Rich HTML payload exceeds {MAX_RICH_HTML_BYTES} bytes ({len(encoded)} bytes); truncating."
    )
    # Сохраняем блок кнопок в конце, если он есть
    btn_idx = html.find("<tg-button-row")
    if btn_idx != -1:
        buttons_part = html[btn_idx:]
        body_part = html[:btn_idx]
        budget = max(512, MAX_RICH_HTML_BYTES - len(buttons_part.encode("utf-8")) - 128)
        trimmed_body = body_part.encode("utf-8")[:budget].decode("utf-8", errors="ignore")
        return f"{trimmed_body}<p><small>… (вывод сокращён из-за лимита Telegram)</small></p>{buttons_part}"
    trimmed = encoded[: MAX_RICH_HTML_BYTES - 128].decode("utf-8", errors="ignore")
    return f"{trimmed}<p><small>… (вывод сокращён из-за лимита Telegram)</small></p>"


def rich_message(html: str) -> InputRichMessage:
    """Create native Bot API rich-message payload."""
    return InputRichMessage(html=_clamp_rich_html(html), skip_entity_detection=True)


async def send_rich(message: Message, html: str) -> Message:
    """Send native Rich Message to current chat."""
    try:
        return await message.bot.send_rich_message(
            chat_id=message.chat.id,
            rich_message=rich_message(html),
            message_thread_id=getattr(message, "message_thread_id", None),
        )
    except TelegramRetryAfter as error:
        await asyncio.sleep(error.retry_after + 0.5)
        return await message.bot.send_rich_message(
            chat_id=message.chat.id,
            rich_message=rich_message(html),
            message_thread_id=getattr(message, "message_thread_id", None),
        )


async def edit_rich(message: Message, html: str):
    """Replace content of message with new Rich Message."""
    for attempt in range(2):
        try:
            return await message.edit_text(rich_message=rich_message(html), parse_mode=None)
        except TelegramRetryAfter as error:
            if attempt == 0:
                await asyncio.sleep(error.retry_after + 0.5)
                continue
            raise
        except TelegramBadRequest as error:
            err_msg = str(error).lower()
            if "message is not modified" in err_msg:
                return message
            if any(marker in err_msg for marker in _EDIT_FALLBACK_ERRORS):
                return await send_rich(message, html)
            raise


async def edit_rich_by_ids(bot, chat_id: int | str, message_id: int, html: str):
    """Edit a Rich Message when only its stored chat/message IDs are available."""
    for attempt in range(2):
        try:
            return await bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                rich_message=rich_message(html),
                parse_mode=None,
            )
        except TelegramRetryAfter as error:
            if attempt == 0:
                await asyncio.sleep(error.retry_after + 0.5)
                continue
            raise
        except TelegramBadRequest as error:
            err_msg = str(error).lower()
            if "message is not modified" in err_msg:
                return None
            if any(marker in err_msg for marker in _EDIT_FALLBACK_ERRORS):
                return await send_rich_to_chat(bot, chat_id, html)
            raise


async def send_rich_to_chat(bot, chat_id: int | str, html: str):
    """Send native Rich Message directly to chat/channel."""
    try:
        return await bot.send_rich_message(chat_id=chat_id, rich_message=rich_message(html))
    except TelegramRetryAfter as error:
        await asyncio.sleep(error.retry_after + 0.5)
        return await bot.send_rich_message(chat_id=chat_id, rich_message=rich_message(html))


def callback_button(label: str, data: str, style: str = "primary") -> str:
    """Build callback button with escaped label and payload."""
    if not data:
        log.warning(f"Empty callback_data for button '{label}', replacing with 'noop'")
        data = "noop"
    encoded = data.encode("utf-8")
    if len(encoded) > 64:
        log.warning(f"Telegram callback_data exceeds 64 bytes ({len(encoded)}B): {data!r} — truncating")
        data = encoded[:64].decode("utf-8", errors="ignore")
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

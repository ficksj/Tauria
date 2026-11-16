"""Telegram inline keyboards and safe message/markup helpers."""

from __future__ import annotations

from typing import Optional, Sequence

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, Message

from drivemap.models import (
    ACCESS_NONE,
    ADUser,
    AuditRecord,
    EffectiveMapping,
    LetterChoice,
    ShareAccessReport,
    ShareAclEntry,
    ShareInfo,
    UserShareAccessStatus,
)
from drivemap.ui import SERVER_FILTER_LABELS, SERVER_FILTERS, h

__all__ = [
    "h",
    "safe_edit_text",
    "safe_edit_markup",
    "track_panel",
    "clear_tracked_panel",
    "main_menu_keyboard",
    "back_home_keyboard",
    "shares_keyboard",
    "users_keyboard",
    "letters_keyboard",
    "confirm_map_keyboard",
    "map_result_keyboard",
    "user_mappings_keyboard",
    "confirm_unmap_keyboard",
    "audit_keyboard",
    "access_share_keyboard",
    "access_user_grant_keyboard",
    "access_members_keyboard",
    "access_direct_users_keyboard",
    "access_result_keyboard",
]


async def safe_edit_text(
    message: Message,
    text: str,
    reply_markup: Optional[InlineKeyboardMarkup] = None,
) -> Message:
    """Edit message text safely, falling back to a new bubble if original isn't editable."""
    try:
        edited = await message.edit_text(text, reply_markup=reply_markup)
        return edited if isinstance(edited, Message) else message
    except TelegramBadRequest as exc:
        low = str(exc).lower()
        if "message is not modified" in low:
            return message
        if "message can't be edited" in low or "message to edit not found" in low:
            return await message.answer(text, reply_markup=reply_markup)
        raise


async def safe_edit_markup(
    message: Message,
    reply_markup: Optional[InlineKeyboardMarkup] = None,
) -> None:
    """Edit inline markup while ignoring harmless 'message is not modified' errors."""
    try:
        await message.edit_reply_markup(reply_markup=reply_markup)
    except TelegramBadRequest as exc:
        if "message is not modified" not in str(exc).lower():
            raise


async def track_panel(state: FSMContext, msg: Optional[Message]) -> None:
    """Store active bubble message coordinates in FSM state so text inputs can clean stale buttons."""
    if msg is not None:
        await state.update_data(panel_chat_id=msg.chat.id, panel_msg_id=msg.message_id)


async def clear_tracked_panel(bot: Bot, state: FSMContext) -> None:
    """Remove inline buttons from the previous bubble message before posting a new search result."""
    data = await state.get_data()
    chat_id = data.get("panel_chat_id")
    msg_id = data.get("panel_msg_id")
    if chat_id and msg_id:
        try:
            await bot.edit_message_reply_markup(chat_id=chat_id, message_id=msg_id, reply_markup=None)
        except TelegramBadRequest:
            pass


def main_menu_keyboard(dry_run: bool = False) -> InlineKeyboardMarkup:
    mode_badge = " 🧪 [DRY-RUN]" if dry_run else ""
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=f"➕ Подключить диск пользователю{mode_badge}", callback_data="drv:map")],
            [InlineKeyboardButton(text=f"🔐 Доступы к дискам (RO / RW){mode_badge}", callback_data="drv:access")],
            [InlineKeyboardButton(text="👤 Диски пользователя / Отключить", callback_data="drv:user_drives")],
            [InlineKeyboardButton(text="📁 Поиск по шаре (кто подключён)", callback_data="drv:share_users")],
            [
                InlineKeyboardButton(text="📜 Журнал / Откат", callback_data="drv:audit"),
                InlineKeyboardButton(text="🔄 Обновить шары", callback_data="drv:refresh_shares"),
            ],
            [InlineKeyboardButton(text="⬅️ В главное меню Tauria", callback_data="menu:home")],
        ]
    )


def back_home_keyboard(
    back_callback: Optional[str] = None,
    back_text: str = "⬅️ Назад",
) -> InlineKeyboardMarkup:
    row: list[InlineKeyboardButton] = []
    if back_callback:
        row.append(InlineKeyboardButton(text=back_text, callback_data=back_callback))
    row.append(InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"))
    return InlineKeyboardMarkup(inline_keyboard=[row])


def shares_keyboard(
    shares: Sequence[ShareInfo],
    page: int,
    page_size: int = 8,
    prefix: str = "sh",
    server_filter: str = "ALL",
    has_query: bool = False,
    primary_label: str = "",
) -> InlineKeyboardMarkup:
    total = len(shares)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    end = min(total, start + page_size)

    rows: list[list[InlineKeyboardButton]] = []

    filter_row: list[InlineKeyboardButton] = []
    for cat in SERVER_FILTERS:
        lbl = primary_label[:12] if (cat == "PRIMARY" and primary_label) else SERVER_FILTER_LABELS[cat]
        btn_txt = f"• {lbl} •" if cat == server_filter else lbl
        filter_row.append(InlineKeyboardButton(text=btn_txt, callback_data=f"{prefix}:flt:{cat}"))
    rows.append(filter_row)

    for idx in range(start, end):
        s = shares[idx]
        letter_hint = f"[{s.suggested_letter}:] " if s.suggested_letter else ""
        src_icon = "📂" if s.source in ("GPO", "BOTH") else "🖥"
        text = f"{src_icon} {letter_hint}{s.label} ({s.unc_path})"
        if len(text) > 58:
            text = text[:55] + "..."
        rows.append([InlineKeyboardButton(text=text, callback_data=f"{prefix}:sel:{idx}")])

    nav: list[InlineKeyboardButton] = []
    if page > 0:
        nav.append(InlineKeyboardButton(text="⬅️ Назад", callback_data=f"{prefix}:page:{page - 1}"))
    nav.append(InlineKeyboardButton(text=f"Стр. {page + 1}/{total_pages}", callback_data="drv:noop"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton(text="Вперёд ➡️", callback_data=f"{prefix}:page:{page + 1}"))
    if nav:
        rows.append(nav)

    action_btn = (
        InlineKeyboardButton(text="🔄 Сбросить поиск", callback_data=f"{prefix}:reset")
        if has_query
        else InlineKeyboardButton(text="🔄 Обновить список", callback_data=f"{prefix}:refresh")
    )
    rows.append(
        [
            action_btn,
            InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"),
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def users_keyboard(
    users: Sequence[ADUser],
    page: int = 0,
    page_size: int = 8,
    prefix: str = "usr",
    back_callback: Optional[str] = None,
    back_text: str = "⬅️ Назад",
) -> InlineKeyboardMarkup:
    total = len(users)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    end = min(total, start + page_size)

    rows: list[list[InlineKeyboardButton]] = []
    for idx in range(start, end):
        u = users[idx]
        label = f"👤 {u.display_name} ({u.sam_account_name}) · {u.division_label}"
        if len(label) > 58:
            label = label[:55] + "..."
        rows.append([InlineKeyboardButton(text=label, callback_data=f"{prefix}:sel:{idx}")])

    if total_pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton(text="⬅️", callback_data=f"{prefix}:page:{page - 1}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="drv:noop"))
        if page + 1 < total_pages:
            nav.append(InlineKeyboardButton(text="➡️", callback_data=f"{prefix}:page:{page + 1}"))
        rows.append(nav)

    footer: list[InlineKeyboardButton] = []
    if back_callback:
        footer.append(InlineKeyboardButton(text=back_text, callback_data=back_callback))
    footer.append(InlineKeyboardButton(text="❌ Отмена", callback_data="drv:home"))
    rows.append(footer)
    return InlineKeyboardMarkup(inline_keyboard=rows)


def letters_keyboard(
    matrix: Sequence[LetterChoice],
    recommended: str | None,
    back_callback: str = "ltr:back_user",
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if recommended:
        rows.append(
            [
                InlineKeyboardButton(
                    text=f"⭐ Использовать свободную {recommended}:",
                    callback_data=f"ltr:pick:{recommended}",
                )
            ]
        )

    grid: list[InlineKeyboardButton] = []
    for item in matrix:
        if item.status == "PROTECTED":
            continue
        if item.letter == recommended:
            txt = f"⭐ {item.letter}:"
            cb = f"ltr:pick:{item.letter}"
        elif item.status == "FREE":
            txt = f"🟢 {item.letter}:"
            cb = f"ltr:pick:{item.letter}"
        elif item.status == "MAPPED_PER_USER":
            txt = f"👤 {item.letter}:"
            cb = f"ltr:warn:{item.letter}"
        else:
            txt = f"🔒 {item.letter}:"
            cb = f"ltr:locked:{item.letter}"
        grid.append(InlineKeyboardButton(text=txt, callback_data=cb))
        if len(grid) == 4:
            rows.append(grid)
            grid = []
    if grid:
        rows.append(grid)

    rows.append(
        [
            InlineKeyboardButton(text="⬅️ К пользователю", callback_data=back_callback),
            InlineKeyboardButton(text="❌ Отмена", callback_data="drv:home"),
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def confirm_map_keyboard(access_choice: str = ACCESS_NONE) -> InlineKeyboardMarkup:
    def _btn(code: str, label: str) -> InlineKeyboardButton:
        txt = f"• {label} •" if access_choice == code else label
        return InlineKeyboardButton(text=txt, callback_data=f"map:acl:{code}")

    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                _btn("NONE", "Без прав"),
                _btn("RO", "🔒 RO"),
                _btn("RW", "✏️ RW"),
            ],
            [InlineKeyboardButton(text="✅ Подтвердить и применить", callback_data="map:confirm")],
            [
                InlineKeyboardButton(text="✏️ Сменить букву", callback_data="map:change_letter"),
                InlineKeyboardButton(text="❌ Отмена", callback_data="drv:home"),
            ],
        ]
    )


def map_result_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="👤 Диски этого пользователя", callback_data="map:view_user")],
            [
                InlineKeyboardButton(text="➕ Подключить ещё", callback_data="drv:map"),
                InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"),
            ],
        ]
    )


def user_mappings_keyboard(
    mappings: Sequence[EffectiveMapping],
    username: str = "",
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for idx, m in enumerate(mappings):
        if m.removable_by_bot:
            if m.scope_type == "PER_USER_DELETE":
                btn_txt = f"🧹 Убрать delete-маркер {m.letter}:"
            else:
                btn_txt = f"🗑 Отключить {m.letter}: ({m.label or m.path})"
            if len(btn_txt) > 58:
                btn_txt = btn_txt[:55] + "..."
            rows.append([InlineKeyboardButton(text=btn_txt, callback_data=f"umap:ask:{idx}")])
    rows.append(
        [
            InlineKeyboardButton(text="🔄 Обновить", callback_data="umap:refresh"),
            InlineKeyboardButton(text="🔍 Другой", callback_data="drv:user_drives"),
            InlineKeyboardButton(text="🏠 Меню дисков", callback_data="drv:home"),
        ]
    )
    if username:
        rows.append([InlineKeyboardButton(text="👤 В карточку сотрудника", callback_data=f"user:show:{username}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def confirm_unmap_keyboard(mapping_idx: int, is_delete_marker: bool = False) -> InlineKeyboardMarkup:
    if is_delete_marker:
        buttons = [
            [InlineKeyboardButton(text="🧹 Очистить delete-маркер", callback_data=f"umap:do_soft:{mapping_idx}")],
        ]
    else:
        buttons = [
            [InlineKeyboardButton(text="🗑 Снять правило (Unmap)", callback_data=f"umap:do_soft:{mapping_idx}")],
            [InlineKeyboardButton(text="🚫 Отключить жёстко (action=D)", callback_data=f"umap:do_hard:{mapping_idx}")],
        ]
    buttons.append([InlineKeyboardButton(text="⬅️ Назад", callback_data="umap:back")])
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def audit_keyboard(records: Sequence[AuditRecord]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for r in records[:5]:
        if r.status == "SUCCESS" and r.backup_path:
            unit = r.letter if r.operation.startswith("ACCESS_") else f"{r.letter}:"
            btn_txt = f"↩️ Откат {r.tx_id} ({r.operation} {unit} {r.target_sam})"
            if len(btn_txt) > 58:
                btn_txt = btn_txt[:55] + "..."
            rows.append(
                [
                    InlineKeyboardButton(
                        text=btn_txt,
                        callback_data=f"aud:rb:{r.tx_id}",
                    )
                ]
            )
    rows.append(
        [
            InlineKeyboardButton(text="🔄 Обновить", callback_data="drv:audit"),
            InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"),
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def access_share_keyboard(report: ShareAccessReport) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if report.readable:
        rows.append([InlineKeyboardButton(text="👤 Права пользователя (Проверить / Выдать)", callback_data="acl:pick_user")])

    grp_row: list[InlineKeyboardButton] = []
    if report.ro_group is not None:
        txt = f"🔒 {report.ro_group.sam_account_name} ({len(report.ro_group.member_dns)})"
        if len(txt) > 30:
            txt = txt[:27] + "..."
        grp_row.append(InlineKeyboardButton(text=txt, callback_data="acl:grp:RO"))
    if report.rw_group is not None:
        txt = f"✏️ {report.rw_group.sam_account_name} ({len(report.rw_group.member_dns)})"
        if len(txt) > 30:
            txt = txt[:27] + "..."
        grp_row.append(InlineKeyboardButton(text=txt, callback_data="acl:grp:RW"))
    if grp_row:
        rows.append(grp_row)

    direct_users = [e for e in report.entries if e.principal_type == "USER" and not e.is_protected]
    if report.readable and direct_users:
        rows.append([InlineKeyboardButton(text=f"🧾 Прямые NTFS ACE ({len(direct_users)})", callback_data="acl:direct")])

    rows.append(
        [
            InlineKeyboardButton(text="🔄 Обновить ACL", callback_data="acl:refresh_one"),
            InlineKeyboardButton(text="⬅️ К шарам", callback_data="ash:back"),
        ]
    )
    rows.append([InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def access_user_grant_keyboard(
    status: UserShareAccessStatus,
    report: ShareAccessReport,
) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if report.readable:
        rows.append([InlineKeyboardButton(text="🔒 Выдать Только чтение (RO)", callback_data="acl:set:RO")])
        rows.append([InlineKeyboardButton(text="✏️ Выдать Чтение и запись (RW)", callback_data="acl:set:RW")])
        if status.can_revoke_direct or status.direct_level != ACCESS_NONE or status.member_of_manageable_groups:
            rows.append([InlineKeyboardButton(text="🗑 Отозвать доступ у пользователя", callback_data="acl:set:NONE")])

    rows.append(
        [
            InlineKeyboardButton(text="🔄 Перепроверить", callback_data="acl:recheck"),
            InlineKeyboardButton(text="⬅️ К шаре", callback_data="acl:back_share"),
        ]
    )
    rows.append(
        [
            InlineKeyboardButton(text="👤 Другой сотрудник", callback_data="acl:pick_user"),
            InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"),
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def access_members_keyboard(
    members: Sequence[ADUser],
    page: int = 0,
    page_size: int = 8,
) -> InlineKeyboardMarkup:
    total = len(members)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    end = min(total, start + page_size)

    rows: list[list[InlineKeyboardButton]] = []
    for idx in range(start, end):
        u = members[idx]
        label = f"🗑 {u.display_name} ({u.sam_account_name})"
        if len(label) > 58:
            label = label[:55] + "..."
        rows.append([InlineKeyboardButton(text=label, callback_data=f"acl:grm:{idx}")])

    if total_pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton(text="⬅️", callback_data=f"acl:grpg:{page - 1}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="drv:noop"))
        if page + 1 < total_pages:
            nav.append(InlineKeyboardButton(text="➡️", callback_data=f"acl:grpg:{page + 1}"))
        rows.append(nav)

    rows.append([InlineKeyboardButton(text="➕ Добавить сотрудника (поиск)", callback_data="acl:pick_user")])
    rows.append(
        [
            InlineKeyboardButton(text="⬅️ К шаре", callback_data="acl:back_share"),
            InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"),
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def access_direct_users_keyboard(
    entries: Sequence[ShareAclEntry],
    page: int = 0,
    page_size: int = 8,
) -> InlineKeyboardMarkup:
    total = len(entries)
    total_pages = max(1, (total + page_size - 1) // page_size)
    page = max(0, min(page, total_pages - 1))
    start = page * page_size
    end = min(total, start + page_size)

    rows: list[list[InlineKeyboardButton]] = []
    for idx in range(start, end):
        e = entries[idx]
        if e.is_inherited:
            label = f"🔗 {e.display_name} ({e.level}) [унасл.]"
            cb = "acl:inh"
        else:
            label = f"🗑 {e.display_name} ({e.level})"
            cb = f"acl:drm:{idx}"
        if len(label) > 58:
            label = label[:55] + "..."
        rows.append([InlineKeyboardButton(text=label, callback_data=cb)])

    if total_pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton(text="⬅️", callback_data=f"acl:drpg:{page - 1}"))
        nav.append(InlineKeyboardButton(text=f"{page + 1}/{total_pages}", callback_data="drv:noop"))
        if page + 1 < total_pages:
            nav.append(InlineKeyboardButton(text="➡️", callback_data=f"acl:drpg:{page + 1}"))
        rows.append(nav)

    rows.append(
        [
            InlineKeyboardButton(text="⬅️ К шаре", callback_data="acl:back_share"),
            InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"),
        ]
    )
    return InlineKeyboardMarkup(inline_keyboard=rows)


def access_result_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="👤 Ещё сотрудник на этой шаре", callback_data="acl:pick_user")],
            [InlineKeyboardButton(text="🔐 Состояние шары (ACL)", callback_data="acl:back_share")],
            [
                InlineKeyboardButton(text="📜 Журнал / Откат", callback_data="drv:audit"),
                InlineKeyboardButton(text="🏠 В меню дисков", callback_data="drv:home"),
            ],
        ]
    )

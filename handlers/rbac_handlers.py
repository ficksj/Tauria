from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from config import settings
from services.db_service import (
    add_bot_admin,
    remove_bot_admin,
    get_bot_admins,
    log_audit_action,
)
from services.rich_message_service import (
    render_bubble_card,
    button_row,
    callback_button,
    html_text,
    send_rich,
    edit_rich,
    edit_rich_by_ids,
)

rbac_router = Router()
router = rbac_router


class RBACAdminState(StatesGroup):
    waiting_for_user_input = State()


async def _build_rbac_card() -> str:
    root_admins = settings.super_admins or []
    db_admins = await get_bot_admins()

    body_lines = ["<b>👑 Корневые SuperAdmin (.env, защищены от удаления):</b>"]
    if root_admins:
        for uid in root_admins:
            body_lines.append(f"• <code>{uid}</code> — 👑 <b>superadmin</b> (Root)")
    else:
        body_lines.append("• <i>Не заданы в .env</i>")

    body_lines.append("")
    body_lines.append(f"<b>📋 Назначенные пользователи в БД ({len(db_admins)}):</b>")

    buttons = [
        button_row(
            callback_button("➕ Добавить Operator", "rbac:add:operator", "primary"),
            callback_button("👑 Добавить SuperAdmin", "rbac:add:superadmin", "success"),
        )
    ]

    if not db_admins:
        body_lines.append("• <i>Список дополнительных администраторов пуст.</i>")
    else:
        for item in db_admins:
            uid = item["user_id"]
            uname = item.get("username")
            role = item.get("role", "operator")
            added_at = str(item.get("added_at") or "—")[:16]
            role_label = "👑 superadmin" if role == "superadmin" else "🛠 operator"
            uname_str = f"@{html_text(uname.lstrip('@'))}" if uname else "без username"
            body_lines.append(
                f"• <code>{uid}</code> ({uname_str}) — <b>{role_label}</b> · <i>{html_text(added_at)}</i>"
            )
            buttons.append(
                button_row(
                    callback_button(f"🗑 Удалить {uid}", f"rbac:del:{uid}", "danger")
                )
            )

    buttons.append(
        button_row(
            callback_button("🔄 Обновить", "rbac:list", "secondary"),
            callback_button("⬅️ Главное меню", "menu:home", "link"),
        )
    )

    return render_bubble_card(
        title="🔐 Управление доступом (RBAC)",
        badge="Zero Trust",
        body_lines=body_lines,
        footer_note="Operator имеет доступ к операционным задачам; SuperAdmin — полный доступ.",
        buttons=buttons,
    )


@rbac_router.callback_query(F.data.in_(["menu:rbac", "rbac:list"]))
async def show_rbac_menu(call: CallbackQuery, state: FSMContext):
    await state.clear()
    await call.answer()
    card = await _build_rbac_card()
    await edit_rich(call.message, card)


@rbac_router.callback_query(F.data.in_(["rbac:add:operator", "rbac:add:superadmin"]))
async def prompt_add_rbac_user(call: CallbackQuery, state: FSMContext):
    role = call.data.split(":")[2]
    role_title = "👑 SuperAdmin" if role == "superadmin" else "🛠 Operator"

    await state.set_state(RBACAdminState.waiting_for_user_input)
    await state.update_data(
        rbac_target_role=role,
        rich_chat_id=call.message.chat.id,
        rich_message_id=call.message.message_id,
    )

    card = render_bubble_card(
        title=f"➕ Добавление роли: {role_title}",
        badge="RBAC",
        body_lines=[
            f"Вы назначаете роль: <b>{role_title}</b>",
            "",
            "Отправьте сообщением <b>Telegram ID</b> (и опционально <code>@username</code> через пробел):",
            "Пример: <code>123456789 @ivanov</code> или просто <code>123456789</code>",
        ],
        buttons=[button_row(callback_button("❌ Отмена", "menu:rbac", "link"))],
    )
    await edit_rich(call.message, card)
    await call.answer()


@rbac_router.message(RBACAdminState.waiting_for_user_input)
async def process_add_rbac_user(message: Message, state: FSMContext):
    raw = (message.text or "").strip()
    parts = raw.split()
    data = await state.get_data()
    role = data.get("rbac_target_role", "operator")
    rich_chat_id = data.get("rich_chat_id")
    rich_message_id = data.get("rich_message_id")

    if not parts or not parts[0].lstrip("-").isdigit():
        err_card = render_bubble_card(
            title="❌ Некорректный ввод",
            badge="Ошибка RBAC",
            body_lines=[
                "Первым параметром должен быть числовой <b>Telegram ID</b>.",
                "Пример: <code>123456789 @ivanov</code>",
            ],
            buttons=[button_row(callback_button("⬅️ Назад к RBAC", "menu:rbac", "link"))],
        )
        if rich_chat_id and rich_message_id:
            await edit_rich_by_ids(message.bot, rich_chat_id, rich_message_id, err_card)
        else:
            await send_rich(message, err_card)
        return

    uid = int(parts[0])
    uname = parts[1].lstrip("@") if len(parts) > 1 else None
    await state.clear()

    await add_bot_admin(uid, uname, role)
    await log_audit_action(
        admin_id=message.from_user.id,
        admin_username=message.from_user.username,
        action="RBAC_ADD_ADMIN",
        target=f"{uid} (@{uname or 'none'}) -> {role}",
        status="SUCCESS",
    )

    card = await _build_rbac_card()
    if rich_chat_id and rich_message_id:
        await edit_rich_by_ids(message.bot, rich_chat_id, rich_message_id, card)
    else:
        await send_rich(message, card)


@rbac_router.callback_query(F.data.startswith("rbac:del:"))
async def delete_rbac_user(call: CallbackQuery):
    raw_uid = call.data.split(":", 2)[2]
    if not raw_uid.lstrip("-").isdigit():
        await call.answer("❌ Некорректный ID", show_alert=True)
        return

    uid = int(raw_uid)
    if uid in (settings.super_admins or []):
        await call.answer("⛔️ Корневой SuperAdmin из .env защищен от удаления.", show_alert=True)
        return

    removed = await remove_bot_admin(uid)
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="RBAC_REMOVE_ADMIN",
        target=str(uid),
        status="SUCCESS" if removed else "FAILED",
    )

    if removed:
        await call.answer(f"🗑 Пользователь {uid} удален из RBAC", show_alert=False)
    else:
        await call.answer(f"ℹ️ Пользователь {uid} не найден в БД", show_alert=True)

    card = await _build_rbac_card()
    await edit_rich(call.message, card)

from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext

from config import settings
from services.infra_service import get_service_status
from services.kolins_manager_service import kolins_manager_service
from services.db_service import log_audit_action
from services.rich_message_service import (
    render_bubble_card,
    button_row,
    callback_button,
    html_text,
    send_rich,
    edit_rich,
)
from handlers.states import KolinsAdminState

kolins_router = Router()


@kolins_router.callback_query(F.data == "menu:kolins")
async def cb_kolins(call: CallbackQuery):
    kolins_stat = await get_service_status("kolins-bot")
    admins = await kolins_manager_service.get_admin_ids()
    op_stats = await kolins_manager_service.get_operational_stats()
    db = op_stats["db"]
    ops = op_stats["operations"]

    body = [
        f"🏎 <b>Статус службы:</b> {'🟢 Работает' if kolins_stat['active'] else '🔴 Остановлен'}",
        f"👥 <b>Саппортов в .env:</b> <code>{len(admins)} чел.</code>",
        f"💻 <b>Сохраненных ПК-сессий:</b> <code>{db.get('active_sessions', 0)}</code>",
        f"🪪 <b>Lotus ID в ожидании:</b> <code>{db.get('lotus_pending', 0)}</code>",
        f"📊 <b>Сбросов паролей (journalctl):</b> <code>{ops.get('password_resets', 0)}</code>",
        f"🔓 <b>Разблокировок (journalctl):</b> <code>{ops.get('user_unlocks', 0)}</code>",
        f"📁 <b>Размер БД:</b> <code>{db.get('db_size_kb', 0)} KB</code>",
    ]

    table = [
        ("Служба", kolins_stat["status"]),
        ("Путь", settings.KOLINS_PATH),
        ("Алерты блокировок", str(ops.get("lockout_alerts_detected", 0))),
    ]

    maint_cb = "kolins:maint_on" if kolins_stat["active"] else "kolins:maint_off"
    buttons = [
        button_row(
            callback_button("👥 Список саппортов", "kolins:admins", "primary"),
            callback_button("📊 Детальная статистика", "kolins:stats", "primary"),
        ),
        button_row(
            callback_button("🔄 Перезапустить Testarossa", "srv:restart:kolins-bot", "danger"),
            callback_button("📄 Логи бота", "srv:viewlog:kolins-bot", "primary"),
        ),
        button_row(
            callback_button("🚧 Техработы (Вкл/Выкл)", maint_cb, "danger"),
        ),
        button_row(
            callback_button("🔄 Обновить", "menu:kolins", "link"),
            callback_button("⬅️ Главное меню", "menu:home", "link"),
        ),
    ]
    card = render_bubble_card(
        title="🏎 Testarossa (Kolins) Orchestrator",
        badge="HelpDesk v3.0",
        body_lines=body,
        table_rows=table,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


@kolins_router.callback_query(F.data.in_({"kolins:maint_on", "kolins:maint_off"}))
async def cb_kolins_maintenance(call: CallbackQuery):
    enable = call.data == "kolins:maint_on"
    await call.answer("🚧 Переключаю режим техработ...", show_alert=False)
    res = await kolins_manager_service.toggle_maintenance(enable)
    ok = res.get("success", False) if isinstance(res, dict) else bool(res)
    if ok:
        state_text = "включен (kolins-bot остановлен)" if enable else "выключен (kolins-bot запущен)"
        body = [f"✅ Режим техработ <b>{state_text}</b>."]
    else:
        err = res.get("error", "Неизвестная ошибка") if isinstance(res, dict) else str(res)
        body = [f"❌ <b>Ошибка переключения техработ:</b> {html_text(str(err))}"]
    buttons = [button_row(callback_button("⬅️ Назад в Testarossa", "menu:kolins", "link"))]
    card = render_bubble_card(
        title="🚧 Режим техработ Testarossa (Kolins)",
        badge="Maintenance",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)


# Просмотр и управление саппортами Testarossa (Kolins)
@kolins_router.callback_query(F.data == "kolins:admins")
async def cb_kolins_admins(call: CallbackQuery):
    admin_ids = await kolins_manager_service.get_admin_ids()
    body = [
        f"Список авторизованных сотрудников техподдержки в <code>{settings.KOLINS_PATH}/.env</code>:",
        "",
    ]
    table = []
    buttons = []
    if not admin_ids:
        body.append("⚠️ Список саппортов пуст!")
    else:
        for idx, aid in enumerate(admin_ids, 1):
            table.append((f"#{idx} ID: {aid}", "Support Admin"))
            buttons.append(button_row(
                callback_button(f"🗑 Удалить #{idx} ({aid})", f"kolins:deladmin:{aid}", "danger")
            ))

    buttons.append(button_row(
        callback_button("➕ Добавить саппорта", "kolins:addadmin", "success"),
        callback_button("⬅️ Назад в Testarossa", "menu:kolins", "link"),
    ))

    card = render_bubble_card(
        title="👥 Администраторы Testarossa (Kolins)",
        badge=f"{len(admin_ids)} саппортов",
        body_lines=body,
        table_rows=table,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


@kolins_router.callback_query(F.data == "kolins:addadmin")
async def cb_kolins_addadmin_prompt(call: CallbackQuery, state: FSMContext):
    body = [
        "Введите <b>Telegram ID</b> сотрудника поддержки для добавления в ADMIN_IDS:",
        "Например: <code>6133663021</code>",
    ]
    buttons = [button_row(callback_button("❌ Отмена", "kolins:admins", "link"))]
    card = render_bubble_card(
        title="➕ Добавление саппорта",
        badge="Testarossa .env",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await state.set_state(KolinsAdminState.waiting_for_add_id)
    await call.answer()


@kolins_router.message(KolinsAdminState.waiting_for_add_id)
async def process_kolins_add_id(message: Message, state: FSMContext):
    raw_text = (message.text or "").strip()
    if not raw_text.isdigit():
        await send_rich(message, render_bubble_card(
            title="❌ Некорректный ID",
            badge="Ошибка ввода",
            body_lines=["Telegram ID должен состоять только из цифр!"],
            buttons=[button_row(callback_button("⬅️ Назад к саппортам", "kolins:admins", "link"))],
        ))
        await state.clear()
        return

    target_id = int(raw_text)
    success = await kolins_manager_service.add_admin_id(target_id)
    await log_audit_action(
        admin_id=message.from_user.id,
        admin_username=message.from_user.username,
        action="KOLINS_ADD_ADMIN",
        target=str(target_id),
        status="SUCCESS" if success else "FAILED",
    )
    await state.clear()
    body = [f"✅ Пользователь с ID <code>{target_id}</code> успешно добавлен в список администраторов Testarossa (Kolins)!"] if success else [f"❌ Не удалось добавить {target_id}."]
    buttons = [button_row(callback_button("⬅️ К списку саппортов", "kolins:admins", "link"))]
    await send_rich(
        message,
        render_bubble_card(
            title="👥 Результат добавления",
            badge="Успешно" if success else "Ошибка",
            body_lines=body,
            buttons=buttons,
        ),
    )


@kolins_router.callback_query(F.data.startswith("kolins:deladmin:"))
async def cb_kolins_deladmin(call: CallbackQuery):
    target_id = int(call.data.split(":")[2])
    success = await kolins_manager_service.remove_admin_id(target_id)
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="KOLINS_REMOVE_ADMIN",
        target=str(target_id),
        status="SUCCESS" if success else "FAILED",
    )
    if success:
        await call.answer(f"✅ ID {target_id} удален из саппортов!", show_alert=True)
    else:
        await call.answer(f"❌ Ошибка удаления {target_id}", show_alert=True)
    await cb_kolins_admins(call)


# Детальная статистика Testarossa (Kolins)
@kolins_router.callback_query(F.data == "kolins:stats")
async def cb_kolins_stats(call: CallbackQuery):
    op_stats = await kolins_manager_service.get_operational_stats()
    db = op_stats["db"]
    ops = op_stats["operations"]

    body = [
        "<b>Оперативная аналитика 🏎 Testarossa (Kolins) Support Bot:</b>",
        f"• Обращений всего за сессию: <b>{ops.get('total_requests', 0)}</b>",
        f"• Сбросов паролей: <b>{ops.get('password_resets', 0)}</b>",
        f"• Разблокировок пользователей: <b>{ops.get('user_unlocks', 0)}</b>",
        f"• Актов приёма-передачи: <b>{ops.get('handover_acts', 0)}</b>",
        f"• Поисков в Active Directory: <b>{ops.get('ad_searches', 0)}</b>",
        "",
        "<b>База данных (SQLite WAL):</b>",
        f"• Сессий ПК в кэше: <b>{db.get('active_sessions', 0)}</b>",
        f"• Активных Lotus ID в хранилище: <b>{db.get('lotus_pending', 0)}</b>",
        f"• Перемещений OU: <b>{db.get('moved_users', 0)}</b>",
        f"• Отправлено алертов: <b>{db.get('sent_alerts', 0)}</b>",
        f"• Алертов за 24ч: <b>{db.get('alerts_24h', 0)}</b>",
    ]

    buttons = [
        button_row(
            callback_button("🔄 Обновить", "kolins:stats", "primary"),
            callback_button("⬅️ Назад в Testarossa", "menu:kolins", "link"),
        )
    ]

    card = render_bubble_card(
        title="📊 Аналитика 🏎 Testarossa (Kolins)",
        badge="Analytics",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()

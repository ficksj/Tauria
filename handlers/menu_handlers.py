import asyncio
import os
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, FSInputFile
from aiogram.filters import CommandStart
from aiogram.fsm.context import FSMContext

from config import settings
from services.ad_service import ad_service
from services.db_service import get_recent_audit_logs, list_pending_lotus_transfers
from services.export_service import export_audit_csv
from services.rich_message_service import (
    render_bubble_card,
    button_row,
    callback_button,
    html_text,
    send_rich,
    edit_rich
)
from handlers.states import (
    UserSearchState,
    PCSearchState
)

menu_router = Router()

def get_home_card(admin_name: str, ad_ok: bool, pending_lotus: int = 0) -> str:
    ad_badge = "🟢 В сети" if ad_ok else "🔴 Недоступен"
    lotus_label = f"🪪 Lotus ID ({pending_lotus})" if pending_lotus > 0 else "🪪 Lotus ID"
    body = [
        f"👑 <b>Супер-администратор:</b> {html_text(admin_name)}",
        f"🏢 <b>Каталог AD ({settings.AD_DOMAIN}):</b> {ad_badge}",
        f"🖥 <b>Сервер управления:</b> <code>192.168.202.117</code> (Ubuntu Linux)",
    ]
    table = [
        ("Доступ к боту", "Строгий RBAC (SuperAdmin)"),
        ("Модули", "AD · DriveMap · Exchange · Infra"),
        ("Active Directory", settings.AD_SERVER),
    ]
    buttons = [
        button_row(
            callback_button("👤 Пользователи", "home:user", "primary"),
            callback_button("💻 Компьютеры", "home:pc", "primary"),
        ),
        button_row(
            callback_button("🏢 Active Directory", "menu:ad", "primary"),
            callback_button("🗄 Диски & Шары", "menu:drives", "primary"),
        ),
        button_row(
            callback_button("🖥 Инфраструктура", "menu:infra", "primary"),
            callback_button(lotus_label, "lotus:list", "primary"),
        ),
        button_row(
            callback_button("🛡 Kill Switch", "killswitch:prompt", "danger"),
            callback_button("⏳ JIT Права", "jit:menu", "primary"),
        ),
        button_row(
            callback_button("⚡️ Админ-плейбуки", "playbooks:menu", "primary"),
            callback_button("🏎 Бот Testarossa", "menu:kolins", "primary"),
        ),
        button_row(
            callback_button("🌐 Сеть & SSL", "menu:net", "primary"),
            callback_button("📋 Аудит", "menu:audit", "link"),
        ),
        button_row(
            callback_button("🔄 Обновить", "menu:home", "link"),
        )
    ]
    return render_bubble_card(
        title="⚡️ Tauria · SuperAdmin Hub",
        badge="v6.0",
        body_lines=body,
        table_rows=table,
        footer_note="Выберите раздел управления инфраструктурой выше",
        buttons=buttons
    )

@menu_router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    ad_ok, pending = await asyncio.gather(
        ad_service.test_connection(),
        asyncio.to_thread(list_pending_lotus_transfers),
    )
    user_name = message.from_user.full_name or message.from_user.username or "Admin"
    await send_rich(message, get_home_card(user_name, ad_ok, len(pending)))

@menu_router.callback_query(F.data.in_(["menu:home", "home:main"]))
async def cb_home(call: CallbackQuery, state: FSMContext):
    await state.clear()
    ad_ok, pending = await asyncio.gather(
        ad_service.test_connection(),
        asyncio.to_thread(list_pending_lotus_transfers),
    )
    user_name = call.from_user.full_name or call.from_user.username or "Admin"
    await edit_rich(call.message, get_home_card(user_name, ad_ok, len(pending)))
    await call.answer()

@menu_router.callback_query(F.data == "home:user")
async def cb_search_user_prompt(call: CallbackQuery, state: FSMContext):
    await state.update_data(rich_chat_id=call.message.chat.id, rich_message_id=call.message.message_id)
    await state.set_state(UserSearchState.waiting_for_query)
    html_card = render_bubble_card(
        title="🔎 Поиск сотрудника",
        badge="Ввод данных",
        body_lines=[
            "Отправьте сообщением <b>логин</b> или <b>ФИО</b> сотрудника.",
            "<i>Поддерживается частичный поиск через ANR (например: <code>Жанабаева</code> или <code>dzhanab</code>).</i>"
        ],
        buttons=[button_row(callback_button('❌ Отмена', 'menu:ad', 'link'))]
    )
    await edit_rich(call.message, html_card)
    await call.answer()

@menu_router.callback_query(F.data == "home:pc")
async def cb_search_pc_prompt(call: CallbackQuery, state: FSMContext):
    await state.update_data(rich_chat_id=call.message.chat.id, rich_message_id=call.message.message_id)
    await state.set_state(PCSearchState.waiting_for_query)
    html_card = render_bubble_card(
        title="💻 Поиск компьютера",
        badge="Ввод данных",
        body_lines=[
            "Отправьте сообщением <b>сетевое имя</b> или <b>описание ПК</b>.",
            "<i>Пример: <code>7538</code> или <code>N10054</code>.</i>"
        ],
        buttons=[button_row(callback_button('❌ Отмена', 'menu:ad', 'link'))]
    )
    await edit_rich(call.message, html_card)
    await call.answer()

# ==========================================
# 1. Active Directory
# ==========================================

@menu_router.callback_query(F.data == "menu:audit")
async def cb_audit(call: CallbackQuery):
    logs = await get_recent_audit_logs(limit=10)
    if not logs:
        body = ["📋 Записей в журнале аудита пока нет."]
    else:
        body = ["Последние операции суперадминов:"]
        for row in logs:
            time_str = row["timestamp"][:16]
            st = "✅" if row["status"] == "SUCCESS" else "❌"
            body.append(f"{st} <code>{time_str}</code> | <b>{html_text(row['action'])}</b> [{html_text(row['target'])}] by @{html_text(row['admin_username'])}")

    buttons = [
        button_row(callback_button("📥 Выгрузить CSV", "audit:export", "primary")),
        button_row(callback_button("⬅️ Главное меню", "menu:home", "link")),
    ]
    card = render_bubble_card(title="📋 Журнал аудита", badge="Audit DB", body_lines=body, buttons=buttons)
    await edit_rich(call.message, card)
    await call.answer()


@menu_router.callback_query(F.data == "audit:export")
async def cb_audit_export(call: CallbackQuery):
    await call.answer("⏳ Формирую CSV...")
    file_path = await export_audit_csv(days=30)
    try:
        await call.message.answer_document(
            FSInputFile(file_path),
            caption="📋 Журнал аудита за последние 30 дней"
        )
    finally:
        if file_path and os.path.exists(file_path):
            os.remove(file_path)

# ==========================================
# 5. Kolins Support Bot Management
# ==========================================

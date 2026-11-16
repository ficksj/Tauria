import secrets
import string
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext

from config import settings
from services.ad_service import ad_service
from services.db_service import log_audit_action
from services.rich_message_service import (
    render_bubble_card,
    button_row,
    callback_button,
    html_text,
    send_rich,
    edit_rich
)
from handlers.states import (
    ADActionState,
    RollbackOffboardState,
    CreateUserState
)

ad_admin_router = Router()

@ad_admin_router.callback_query(F.data == "menu:ad")
async def cb_ad_menu(call: CallbackQuery):
    body = [
        "Управление безопасностью учетных записей Active Directory DS.",
        "Выберите действие:"
    ]
    table = [
        ("Контроллер AD", settings.AD_SERVER),
        ("Базовый DN", settings.AD_SEARCH_BASE),
    ]
    buttons = [
        button_row(
            callback_button("👤 Поиск пользователя", "home:user", "primary"),
            callback_button("💻 Поиск ПК", "home:pc", "primary"),
        ),
        button_row(
            callback_button("🔒 Заблокированные аккаунты", "ad:locked", "danger"),
            callback_button("🗄 Диски & Шары GPO", "menu:drives", "primary"),
        ),
        button_row(
            callback_button("👑 Привилегированные группы", "ad:priv_groups", "primary"),
            callback_button("🔑 Истекающие пароли", "ad:expiring", "primary"),
        ),
        button_row(
            callback_button("🧹 AD Hygiene", "ad:hygiene", "primary"),
            callback_button("➕ Создать сотрудника", "ad:create_user", "success"),
        ),
        button_row(
            callback_button("🚨 Offboarding (Увольнение)", "ad:offboard", "danger"),
            callback_button("♻️ Откат Offboarding", "ad:rollback", "primary"),
        ),
        button_row(
            callback_button("⬅️ Главное меню", "menu:home", "link")
        )
    ]
    card = render_bubble_card(
        title="🏢 Active Directory Management",
        badge="AD DS",
        body_lines=body,
        table_rows=table,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await call.answer()

@ad_admin_router.callback_query(F.data == "ad:priv_groups")
async def cb_ad_priv_groups(call: CallbackQuery):
    await call.answer("👑 Проверяю привилегированные группы...", show_alert=False)
    res = await ad_service.inspect_privileged_groups()
    if isinstance(res, dict) and not res.get("success", True):
        body = [f"❌ <b>Ошибка:</b> {html_text(res.get('error', 'Не удалось получить данные'))}"]
    else:
        groups = res.get("groups", res) if isinstance(res, dict) else res
        body = ["👑 <b>Состав привилегированных групп AD:</b>"]
        if isinstance(groups, dict):
            for grp, members in groups.items():
                m_list = ", ".join(html_text(str(m)) for m in (members or [])) or "пусто"
                body.append(f"• <b>{html_text(str(grp))}</b> ({len(members or [])}): <code>{m_list}</code>")
        elif isinstance(groups, list):
            for item in groups:
                body.append(f"• {html_text(str(item))}")
        else:
            body.append(html_text(str(groups)))
    buttons = [button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))]
    card = render_bubble_card(
        title="👑 Привилегированные группы",
        badge="AD Security",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

@ad_admin_router.callback_query(F.data == "ad:expiring")
async def cb_ad_expiring(call: CallbackQuery):
    await call.answer("🔑 Ищу истекающие пароли...", show_alert=False)
    res = await ad_service.get_expiring_password_users(days=7)
    users = res.get("users", []) if isinstance(res, dict) else (res or [])
    if not users:
        body = ["✅ Пользователей с истекающим в ближайшие 7 дней паролем не найдено."]
    else:
        body = [f"🔑 <b>Истекающие пароли (7 дней): {len(users)}</b>", ""]
        for u in users[:25]:
            if isinstance(u, dict):
                uname = u.get("username") or u.get("sAMAccountName") or str(u)
                days_left = u.get("days_left", "?")
                body.append(f"• <code>{html_text(str(uname))}</code> — осталось <b>{days_left} дн.</b>")
            else:
                body.append(f"• <code>{html_text(str(u))}</code>")
    buttons = [button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))]
    card = render_bubble_card(
        title="🔑 Истекающие пароли",
        badge="AD Policy",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

@ad_admin_router.callback_query(F.data == "ad:hygiene")
async def cb_ad_hygiene(call: CallbackQuery):
    body = [
        "🧹 <b>AD Hygiene — Аудит учетных записей</b>",
        "Выберите категорию для проверки:"
    ]
    buttons = [
        button_row(
            callback_button("💤 Неактивные 60+ дней", "ad:inactive", "primary"),
            callback_button("♾ PasswordNeverExpires", "ad:never_exp", "primary"),
        ),
        button_row(
            callback_button("⬅️ Назад в AD", "menu:ad", "link")
        )
    ]
    card = render_bubble_card(
        title="🧹 AD Hygiene",
        badge="Audit",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await call.answer()

@ad_admin_router.callback_query(F.data == "ad:inactive")
async def cb_ad_inactive(call: CallbackQuery):
    await call.answer("💤 Ищу неактивные учетные записи...", show_alert=False)
    users = await ad_service.get_inactive_users(days=60)
    if not users:
        body = ["✅ Неактивных учетных записей (60+ дней) не найдено."]
    else:
        body = [f"💤 <b>Неактивные 60+ дней: {len(users)}</b>", ""]
        for u in users[:25]:
            uname = u.get("username", str(u)) if isinstance(u, dict) else str(u)
            last_logon = u.get("last_logon", "N/A") if isinstance(u, dict) else ""
            body.append(f"• <code>{html_text(uname)}</code> ({html_text(str(last_logon))})")
    buttons = [button_row(callback_button("⬅️ Назад в AD Hygiene", "ad:hygiene", "link"))]
    card = render_bubble_card(
        title="💤 Неактивные 60+ дней",
        badge="AD Hygiene",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

@ad_admin_router.callback_query(F.data == "ad:never_exp")
async def cb_ad_never_exp(call: CallbackQuery):
    await call.answer("♾ Проверяю PasswordNeverExpires...", show_alert=False)
    users = await ad_service.get_never_expire_password_users()
    if not users:
        body = ["✅ Учетных записей с флагом PasswordNeverExpires не найдено."]
    else:
        body = [f"♾ <b>PasswordNeverExpires: {len(users)}</b>", ""]
        for u in users[:25]:
            uname = u.get("username", str(u)) if isinstance(u, dict) else str(u)
            body.append(f"• <code>{html_text(uname)}</code>")
    buttons = [button_row(callback_button("⬅️ Назад в AD Hygiene", "ad:hygiene", "link"))]
    card = render_bubble_card(
        title="♾ PasswordNeverExpires",
        badge="AD Hygiene",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

def _translit_ru_to_en(text: str) -> str:
    mapping = {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
        "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
        "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
        "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
        "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya"
    }
    return "".join(mapping.get(ch, ch) for ch in text.lower())

def _generate_ad_username(full_name: str) -> str:
    parts = [p for p in full_name.strip().split() if p]
    if len(parts) >= 2:
        # Поддержка формата "Фамилия Имя ..." или "Имя Фамилия"
        first_initial = _translit_ru_to_en(parts[0][0])
        last_name = _translit_ru_to_en(parts[1])
        raw = f"{first_initial}.{last_name}"
    elif parts:
        raw = _translit_ru_to_en(parts[0])
    else:
        raw = "user"
    return "".join(c for c in raw if c.isalnum() or c in "._-")[:20]

def _generate_temp_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(alphabet) for _ in range(length))

@ad_admin_router.callback_query(F.data == "ad:create_user")
async def cb_ad_create_user(call: CallbackQuery, state: FSMContext):
    await state.set_state(CreateUserState.waiting_for_fullname)
    body = [
        "➕ <b>Создание нового сотрудника в AD</b>",
        "Введите <b>ФИО</b> сотрудника (например: <code>Иван Петров</code>):"
    ]
    buttons = [button_row(callback_button("❌ Отмена", "menu:ad", "link"))]
    card = render_bubble_card(
        title="➕ Новый сотрудник",
        badge="Шаг 1/2",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await call.answer()

DEPARTMENT_TEMPLATES = {
    "it": {"department": "IT", "groups": ["IT", "VPN-Users"]},
    "acc": {"department": "Бухгалтерия", "groups": ["Accounting", "1C-Users"]},
    "back": {"department": "Бэк-офис", "groups": ["BackOffice"]},
}


async def _finish_create_user(
    target_msg: Message,
    admin_user,
    full_name: str,
    department: str,
    groups: list[str] | None = None,
    edit: bool = False,
):
    username = _generate_ad_username(full_name)
    password = _generate_temp_password()
    ou_dn = f"CN=Users,{settings.AD_SEARCH_BASE}" if settings.AD_SEARCH_BASE else "CN=Users"

    res = await ad_service.create_ad_user(
        full_name=full_name,
        username=username,
        password=password,
        ou_dn=ou_dn,
        department=department,
        groups=groups,
    )
    ok = res.get("success", False) if isinstance(res, dict) else bool(res)
    await log_audit_action(
        admin_id=admin_user.id,
        admin_username=admin_user.username,
        action="AD_CREATE_USER",
        target=f"{username} ({department})",
        status="SUCCESS" if ok else "FAILED",
    )
    if ok:
        body = [
            "✅ <b>Сотрудник успешно создан в Active Directory!</b>",
            f"• ФИО: <b>{html_text(full_name)}</b>",
            f"• Отдел: <b>{html_text(department)}</b>",
            f"• Логин: <code>{html_text(username)}</code>",
            f"• Временный пароль: <code>{html_text(password)}</code>",
        ]
    else:
        err = res.get("error", "Неизвестная ошибка") if isinstance(res, dict) else str(res)
        body = [f"❌ <b>Ошибка создания пользователя:</b> {html_text(str(err))}"]

    buttons = [button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))]
    card = render_bubble_card(
        title="➕ Создание сотрудника",
        badge="Готово" if ok else "Ошибка",
        body_lines=body,
        buttons=buttons,
    )
    if edit:
        await edit_rich(target_msg, card)
    else:
        await send_rich(target_msg, card)


@ad_admin_router.message(CreateUserState.waiting_for_fullname)
async def process_create_user_fullname(message: Message, state: FSMContext):
    full_name = message.text.strip()
    await state.update_data(full_name=full_name)
    body = [
        f"👤 ФИО: <b>{html_text(full_name)}</b>",
        "Выберите <b>шаблон отдела</b> или введите его вручную:"
    ]
    buttons = [
        button_row(
            callback_button("💻 IT", "tpl:it", "primary"),
            callback_button("📊 Бухгалтерия", "tpl:acc", "primary"),
        ),
        button_row(
            callback_button("🏢 Бэк-офис", "tpl:back", "primary"),
            callback_button("✏️ Ввести вручную", "tpl:custom", "link"),
        ),
        button_row(callback_button("❌ Отмена", "menu:ad", "link")),
    ]
    card = render_bubble_card(
        title="➕ Новый сотрудник",
        badge="Шаг 2/2",
        body_lines=body,
        buttons=buttons
    )
    await send_rich(message, card)


@ad_admin_router.callback_query(F.data.startswith("tpl:"))
async def cb_create_user_template(call: CallbackQuery, state: FSMContext):
    tpl_key = call.data.split("tpl:", 1)[1]
    if tpl_key == "custom":
        await state.set_state(CreateUserState.waiting_for_department)
        data = await state.get_data()
        full_name = data.get("full_name", "")
        body = [
            f"👤 ФИО: <b>{html_text(full_name)}</b>",
            "Введите <b>отдел</b> (Department) сотрудника:"
        ]
        buttons = [button_row(callback_button("❌ Отмена", "menu:ad", "link"))]
        card = render_bubble_card(
            title="➕ Новый сотрудник",
            badge="Шаг 2/2",
            body_lines=body,
            buttons=buttons
        )
        await edit_rich(call.message, card)
        await call.answer()
        return

    tpl = DEPARTMENT_TEMPLATES.get(tpl_key)
    if not tpl:
        await call.answer("Неизвестный шаблон", show_alert=True)
        return

    data = await state.get_data()
    full_name = data.get("full_name", "")
    await state.clear()
    await call.answer("⏳ Создаю сотрудника...")
    await _finish_create_user(
        target_msg=call.message,
        admin_user=call.from_user,
        full_name=full_name,
        department=tpl["department"],
        groups=tpl["groups"],
        edit=True,
    )


@ad_admin_router.message(CreateUserState.waiting_for_department)
async def process_create_user_department(message: Message, state: FSMContext):
    department = message.text.strip()
    data = await state.get_data()
    full_name = data.get("full_name", "")
    await state.clear()
    await _finish_create_user(
        target_msg=message,
        admin_user=message.from_user,
        full_name=full_name,
        department=department,
        edit=False,
    )

@ad_admin_router.callback_query(F.data == "ad:rollback")
async def cb_ad_rollback(call: CallbackQuery, state: FSMContext):
    await state.set_state(RollbackOffboardState.waiting_for_username)
    body = [
        "♻️ <b>Откат Offboarding</b>",
        "Введите логин пользователя в AD (<code>sAMAccountName</code>) для восстановления:"
    ]
    buttons = [button_row(callback_button("❌ Отмена", "menu:ad", "link"))]
    card = render_bubble_card(
        title="♻️ Откат Offboarding",
        badge="AD Recovery",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await call.answer()

@ad_admin_router.message(RollbackOffboardState.waiting_for_username)
async def process_ad_rollback(message: Message, state: FSMContext):
    username = message.text.strip()
    await state.clear()

    res = await ad_service.rollback_offboard(username)
    ok = res.get("success", False) if isinstance(res, dict) else bool(res)
    await log_audit_action(
        admin_id=message.from_user.id,
        admin_username=message.from_user.username,
        action="AD_ROLLBACK_OFFBOARD",
        target=username,
        status="SUCCESS" if ok else "FAILED"
    )
    if ok:
        body = [f"✅ Учетная запись <code>{html_text(username)}</code> восстановлена."]
    else:
        err = res.get("error", "Неизвестная ошибка") if isinstance(res, dict) else str(res)
        body = [f"❌ <b>Ошибка отката для {html_text(username)}:</b> {html_text(str(err))}"]

    buttons = [button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))]
    card = render_bubble_card(
        title="♻️ Результат отката Offboarding",
        badge="AD Recovery",
        body_lines=body,
        buttons=buttons
    )
    await send_rich(message, card)

@ad_admin_router.callback_query(F.data == "ad:locked")
async def cb_ad_locked(call: CallbackQuery):
    users = await ad_service.get_locked_users()
    if not users:
        body = ["🟢 <b>В данный момент нет заблокированных учетных записей!</b>"]
        buttons = [button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))]
        card = render_bubble_card(
            title="🔒 Заблокированные пользователи",
            badge="Все активно",
            body_lines=body,
            buttons=buttons
        )
        await edit_rich(call.message, card)
        await call.answer()
        return

    body = [f"Найдено заблокированных: <b>{len(users)}</b>"]
    table = []
    buttons = []
    for u in users[:8]:
        table.append((u["username"], f"{u['name']} ({u['department']})"))
        buttons.append(button_row(callback_button(f"🔓 Разблокировать {u['username']}", f"ad:unlock:{u['username']}", "success")))

    buttons.append(button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link")))
    card = render_bubble_card(
        title="🔒 Заблокированные учетные записи",
        badge="Lockout Alert",
        body_lines=body,
        table_rows=table,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await call.answer()

@ad_admin_router.callback_query(F.data.startswith("ad:unlock:"))
async def cb_ad_unlock(call: CallbackQuery):
    username = call.data.split(":")[2]
    res = await ad_service.unlock_user_async(username)
    status_str = "SUCCESS" if res else "FAILED"
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="UNLOCK_USER",
        target=username,
        status=status_str
    )
    if res:
        await call.answer(f"✅ Пользователь {username} успешно разблокирован!", show_alert=True)
    else:
        await call.answer(f"❌ Ошибка при разблокировке {username}", show_alert=True)
    await cb_ad_locked(call)

# Offboarding
@ad_admin_router.callback_query(F.data == "ad:offboard")
async def cb_ad_offboard_prompt(call: CallbackQuery, state: FSMContext):
    body = [
        "⚠️ <b>Процедура Offboarding (Увольнение):</b>",
        "1. Мгновенная блокировка учетной записи (AccountDisabled).",
        "2. Установка префикса [TERMINATED] в Description.",
        "3. Перемещение в защищенный контейнер Disabled Users OU.",
        "",
        "Введите <b>sAMAccountName (логин)</b> сотрудника для увольнения:"
    ]
    buttons = [button_row(callback_button("❌ Отмена", "menu:ad", "link"))]
    card = render_bubble_card(
        title="🚨 Увольнение сотрудника",
        badge="Danger Zone",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await state.set_state(ADActionState.waiting_for_offboard_username)
    await call.answer()

@ad_admin_router.message(ADActionState.waiting_for_offboard_username)
async def process_offboard_username(message: Message, state: FSMContext):
    username = message.text.strip()
    body = [
        f"Вы действительно хотите <b>УВОЛИТЬ</b> сотрудника <code>{html_text(username)}</code>?",
        "Действие заблокирует аккаунт в AD и переместит его в архив!"
    ]
    buttons = [
        button_row(callback_button("⚠️ Да, заблокировать и уволить", f"confirm_offboard:{username}", "danger")),
        button_row(callback_button("❌ Отмена", "menu:ad", "link"))
    ]
    card = render_bubble_card(
        title="⚠️ Подтверждение действия",
        badge="Two-Step Verification",
        body_lines=body,
        buttons=buttons
    )
    await state.clear()
    await send_rich(message, card)

@ad_admin_router.callback_query(F.data.startswith("confirm_offboard:"))
async def cb_confirm_offboard(call: CallbackQuery):
    username = call.data.split(":")[1]
    res = await ad_service.offboard_user(username, offboarded_by=call.from_user.id)
    success = res.get("success", False)
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="OFFBOARD_USER",
        target=username,
        status="SUCCESS" if success else "FAILED",
        details=str(res)
    )
    if success:
        body = [
            f"✅ Сотрудник <code>{html_text(username)}</code> успешно уволен и заблокирован!",
            f"Перемещение в Disabled OU: {'Да' if res.get('moved') else 'Не настроено'}"
        ]
    else:
        body = [f"❌ Не удалось выполнить операцию: {html_text(res.get('error', 'Ошибка'))}"]

    buttons = [button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))]
    card = render_bubble_card(
        title="🚨 Результат увольнения",
        badge="Offboarding",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await call.answer()


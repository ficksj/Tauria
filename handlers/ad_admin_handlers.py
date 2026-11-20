import datetime
import re
import secrets
import string
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext

from config import settings
from services.ad_service import ad_service, TZ_LOCAL
from services.db_service import log_audit_action
from services.rich_message_service import (
    render_bubble_card,
    button_row,
    callback_button,
    copy_button,
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
async def cb_ad_menu(call: CallbackQuery, state: FSMContext):
    await state.clear()
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
            callback_button("🛡 Здоровье AD", "health:main", "primary"),
            callback_button("🗄 Диски & Шары GPO", "menu:drives", "primary"),
        ),
        button_row(
            callback_button("🔒 Заблокированные аккаунты", "ad:locked", "danger"),
            callback_button("🔑 Истекающие пароли", "ad:expiring", "primary"),
        ),
        button_row(
            callback_button("👑 Привилегированные группы", "ad:priv_groups", "primary"),
            callback_button("🧹 AD Hygiene", "ad:hygiene", "primary"),
        ),
        button_row(
            callback_button("➕ Онбординг по СЗ (Штатный / Стажер)", "ad:create_user", "success"),
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
        # Стандартный формат ФИО: "Фамилия Имя [Отчество]" -> i.familiya (например, Сериков Айбек -> a.serikov)
        first_initial = _translit_ru_to_en(parts[1][0])
        last_name = _translit_ru_to_en(parts[0])
        raw = f"{first_initial}.{last_name}"
    elif parts:
        raw = _translit_ru_to_en(parts[0])
    else:
        raw = "user"
    return "".join(c for c in raw if c.isalnum() or c in "._-")[:20]

def _generate_temp_password(length: int = 12) -> str:
    length = max(length, 8)
    specials = "!@#$%"
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(specials),
    ]
    alphabet = string.ascii_letters + string.digits + specials
    rest = [secrets.choice(alphabet) for _ in range(length - len(required))]
    chars = required + rest
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def parse_sz_text(raw_text: str) -> dict:
    """
    Парсит произвольный текст служебной записки (СЗ) для онбординга сотрудника или стажера.
    Возвращает словарь:
    full_name, department, title, sz_number, curator, period, is_intern, expires_days
    """
    text = (raw_text or "").strip()
    low_text = text.lower()

    is_intern = any(k in low_text for k in ("стажер", "стажёр", "практикант", "стажировк", "intern"))
    full_name = ""
    department = ""
    title = "Стажер" if is_intern else "Специалист"
    sz_number = ""
    curator = ""
    period = ""
    expires_days: int | None = 30 if is_intern else None

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        low_l = line.lower()
        if ":" in line:
            key_part, val_part = line.split(":", 1)
            k = key_part.strip().lower().lstrip("•-* ")
            v = val_part.strip()
            if not v:
                continue
            if any(w in k for w in ("фио", "сотрудник", "стажер", "стажёр", "кандидат", "работник")):
                if not full_name:
                    full_name = v
                continue
            if any(w in k for w in ("департамент", "подразделение", "отдел", "управление", "служба")):
                if not department:
                    department = v
                continue
            if "должност" in k or "позици" in k:
                title = v
                if any(w in v.lower() for w in ("стажер", "стажёр", "практикант", "intern")):
                    is_intern = True
                continue
            if any(w in k for w in ("сз", "служебн", "записк", "основани", "приказ", "заявк")):
                if not sz_number:
                    sz_number = v
                continue
            if any(w in k for w in ("куратор", "руководител", "наставник", "ответствен")):
                if not curator:
                    curator = v
                continue
            if any(w in k for w in ("период", "срок", "дата выхода", "выход", "действ")):
                if not period:
                    period = v
                continue

        # Fallback regexes within line if no explicit key matched
        if not sz_number and any(w in low_l for w in ("сз ", "сз№", "служебная записка")):
            m_sz = re.search(r"(?:сз|служебная записка)\s*(?:№|от|#|:)?\s*([^\n,;]+)", line, flags=re.IGNORECASE)
            if m_sz:
                sz_number = m_sz.group(1).strip()

    # Fallback: если ФИО не найдено по ключу "ФИО:", ищем первую строку из 2-3 слов с заглавной буквы
    if not full_name and lines:
        for line in lines:
            if ":" in line:
                continue
            words = line.lstrip("•-* ").split()
            if 2 <= len(words) <= 4 and all(w[0].isupper() for w in words if w):
                full_name = " ".join(words)
                break
        if not full_name and ":" not in lines[0]:
            full_name = lines[0].lstrip("•-* ").strip()

    # Вычисление expires_days из периода или текста
    if period or is_intern:
        search_target = f"{period} {text}".lower()
        m_days = re.search(r"(\d{1,3})\s*(?:дн|дней|дня)", search_target)
        m_months = re.search(r"(\d{1,2})\s*(?:мес|месяц)", search_target)
        m_dates = re.findall(r"(\d{2}\.\d{2}\.\d{4})", period or text)
        if m_days:
            expires_days = int(m_days.group(1))
        elif m_months:
            expires_days = int(m_months.group(1)) * 30
        elif m_dates:
            try:
                last_dt = datetime.datetime.strptime(m_dates[-1], "%d.%m.%Y").replace(tzinfo=TZ_LOCAL)
                now_dt = datetime.datetime.now(TZ_LOCAL)
                delta = (last_dt.date() - now_dt.date()).days
                if delta > 0:
                    expires_days = delta
            except Exception:
                pass
        elif is_intern and expires_days is None:
            expires_days = 30

    return {
        "full_name": full_name,
        "department": department,
        "title": title,
        "sz_number": sz_number,
        "curator": curator,
        "period": period,
        "is_intern": is_intern,
        "expires_days": expires_days,
    }


def format_helpdesk_onboarding_report(
    full_name: str,
    username: str,
    password: str,
    department: str = "—",
    title: str = "Специалист",
    sz_info: str = "По СЗ",
    curator: str = "—",
    period_str: str = "Бессрочно (штат)",
    access_str: str = "Стандартный пакет AD",
) -> str:
    """Формирует готовый текст отчета для HelpDesk строго по стандарту AGENTS.md."""
    dept_val = department.strip() if department and department.strip() else "—"
    title_val = title.strip() if title and title.strip() else "Специалист"
    sz_val = sz_info.strip() if sz_info and sz_info.strip() else "По СЗ"
    curator_val = curator.strip() if curator and curator.strip() else "—"
    period_val = period_str.strip() if period_str and period_str.strip() else "Бессрочно (штат)"
    access_val = access_str.strip() if access_str and access_str.strip() else "Стандартный пакет AD"

    return (
        "Выход сотрудника/стажера / УЗ готова\n\n"
        f"• СЗ: {sz_val}\n"
        f"• ФИО: {full_name}\n"
        f"• Подразделение: {dept_val} ({title_val})\n"
        f"• Руководитель (куратор): {curator_val}\n"
        f"• Период / Дата выхода: {period_val}\n"
        f"• Логин: {username}\n"
        f"• Временный пароль: {password} (смена при первом входе)\n"
        f"• Сетевые папки / Доступы: {access_val}"
    )


DEPARTMENT_TEMPLATES = {
    "it": {"department": "ДАРиТ (IT)", "title": "Специалист IT", "groups": ["IT", "VPN-Users"]},
    "acc": {"department": "Бухгалтерия", "title": "Бухгалтер", "groups": ["Accounting", "1C-Users"]},
    "back": {"department": "Бэк-офис", "title": "Менеджер", "groups": ["BackOffice"]},
    "cred": {"department": "Кредитование", "title": "Кредитный аналитик", "groups": ["CreditDept"]},
    "sec": {"department": "Риски / ИБ", "title": "Специалист ИБ", "groups": ["Security", "RiskManagement"]},
    "intern": {"department": "Стажировка", "title": "Стажер", "groups": []},
}


@ad_admin_router.callback_query(F.data == "ad:create_user")
async def cb_ad_create_user(call: CallbackQuery, state: FSMContext):
    await state.clear()
    await state.set_state(CreateUserState.waiting_for_mode)
    body = [
        "➕ <b>Zero-Touch Онбординг сотрудника по СЗ</b>",
        "Выберите режим создания учетной записи Active Directory:",
        "",
        "• <b>Штатный сотрудник</b> — бессрочная УЗ в <code>AD_DEFAULT_NEW_USER_OU</code>",
        "• <b>Стажер (Intern)</b> — временная УЗ с авто-отключением (<code>accountExpires</code>) в <code>AD_INTERN_OU</code>",
        "• <b>Вставить текст СЗ</b> — автоматический разбор ФИО, отдела, куратора и сроков из текста СЗ",
    ]
    buttons = [
        button_row(
            callback_button("👔 Штатный сотрудник", "onb:mode:staff", "primary"),
            callback_button("🎓 Стажер (Intern)", "onb:mode:intern", "primary"),
        ),
        button_row(
            callback_button("📋 Вставить текст СЗ (Авто-разбор)", "onb:mode:parse", "success"),
        ),
        button_row(callback_button("❌ Отмена", "menu:ad", "link")),
    ]
    card = render_bubble_card(
        title="➕ Новый сотрудник / Стажер",
        badge="Zero-Touch AD",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


@ad_admin_router.callback_query(F.data.startswith("onb:mode:"))
async def cb_onboarding_mode(call: CallbackQuery, state: FSMContext):
    mode = call.data.split("onb:mode:", 1)[1]
    if mode == "parse":
        await state.set_state(CreateUserState.waiting_for_sz_raw_text)
        body = [
            "📋 <b>Авто-разбор текста Служебной записки (СЗ)</b>",
            "Отправьте текст СЗ одним сообщением. Поддерживаются поля:",
            "<code>ФИО: ...</code>",
            "<code>Подразделение: ...</code>",
            "<code>Должность: ...</code>",
            "<code>СЗ: №... от ...</code>",
            "<code>Куратор: ...</code>",
            "<code>Период: 30 дней / до ДД.ММ.ГГГГ</code>",
        ]
        buttons = [button_row(callback_button("⬅️ Назад", "ad:create_user", "link"))]
        card = render_bubble_card(
            title="📋 Авто-разбор СЗ",
            badge="Парсер СЗ",
            body_lines=body,
            buttons=buttons,
        )
        await edit_rich(call.message, card)
        await call.answer()
        return

    is_intern = mode == "intern"
    await state.update_data(
        is_intern=is_intern,
        title="Стажер" if is_intern else "Специалист",
        expires_days=30 if is_intern else None,
        account_expires_dt=None,
        period_str="30 дн." if is_intern else "Бессрочно (штат)",
    )
    await state.set_state(CreateUserState.waiting_for_fullname)
    role_label = "🎓 Стажер (Intern)" if is_intern else "👔 Штатный сотрудник"
    body = [
        f"Режим: <b>{role_label}</b>",
        "Введите <b>ФИО</b> полностью (например: <code>Иванов Иван Иванович</code>):",
    ]
    buttons = [button_row(callback_button("⬅️ Назад", "ad:create_user", "link"))]
    card = render_bubble_card(
        title="➕ Новый сотрудник",
        badge="Шаг 1 · ФИО",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


@ad_admin_router.message(CreateUserState.waiting_for_sz_raw_text)
async def process_onboarding_sz_raw_text(message: Message, state: FSMContext):
    parsed = parse_sz_text(message.text or "")
    full_name = parsed.get("full_name") or ""
    if not full_name:
        body = [
            "⚠️ Не удалось распознать <b>ФИО</b> из текста СЗ.",
            "Укажите строку <code>ФИО: Фамилия Имя Отчество</code> или перейдите в пошаговый режим.",
        ]
        buttons = [button_row(callback_button("⬅️ К выбору режима", "ad:create_user", "link"))]
        card = render_bubble_card(
            title="📋 Авто-разбор СЗ",
            badge="Уточнение",
            body_lines=body,
            buttons=buttons,
        )
        await send_rich(message, card)
        return

    is_intern = bool(parsed.get("is_intern"))
    expires_days = parsed.get("expires_days")
    now_local = datetime.datetime.now(TZ_LOCAL)
    expires_dt = None
    period_str = parsed.get("period") or ("Бессрочно (штат)" if not is_intern else "")
    if is_intern and expires_days:
        expires_dt = now_local + datetime.timedelta(days=int(expires_days))
        if not period_str:
            period_str = f"{expires_days} дн. (до {expires_dt.strftime('%d.%m.%Y')})"
    elif not period_str:
        period_str = f"с {now_local.strftime('%d.%m.%Y')} (бессрочно)"

    sz_info = parsed.get("sz_number") or "По СЗ"
    curator = parsed.get("curator") or "—"
    department = parsed.get("department") or ""
    title = parsed.get("title") or ("Стажер" if is_intern else "Специалист")

    await state.update_data(
        full_name=full_name,
        is_intern=is_intern,
        title=title,
        sz_info=sz_info,
        curator=curator,
        period_str=period_str,
        account_expires_dt=expires_dt.isoformat() if expires_dt else None,
        department=department,
    )

    if department:
        await state.clear()
        await _finish_create_user(
            target_msg=message,
            admin_user=message.from_user,
            full_name=full_name,
            department=department,
            title=title,
            is_intern=is_intern,
            sz_info=sz_info,
            curator=curator,
            period_str=period_str,
            account_expires_dt=expires_dt,
            groups=[],
            edit=False,
        )
    else:
        await _prompt_department_selection(message, state, edit=False)


async def _prompt_sz_info(target_msg: Message, state: FSMContext, edit: bool = False):
    await state.set_state(CreateUserState.waiting_for_sz_info)
    data = await state.get_data()
    full_name = data.get("full_name", "")
    body = [
        f"👤 ФИО: <b>{html_text(full_name)}</b>",
        "Введите <b>номер/дату СЗ и куратора</b> (например: <code>СЗ №142 от 16.11.2026 | Куратор: Оспанов А.</code>)",
        "или нажмите «⏭ Пропустить»:",
    ]
    buttons = [
        button_row(callback_button("⏭ Пропустить", "onb:sz:skip", "primary")),
        button_row(callback_button("❌ Отмена", "menu:ad", "link")),
    ]
    card = render_bubble_card(
        title="➕ Новый сотрудник",
        badge="Данные СЗ",
        body_lines=body,
        buttons=buttons,
    )
    if edit:
        await edit_rich(target_msg, card)
    else:
        await send_rich(target_msg, card)


async def _prompt_department_selection(target_msg: Message, state: FSMContext, edit: bool = False):
    data = await state.get_data()
    full_name = data.get("full_name", "")
    is_intern = data.get("is_intern", False)
    period_str = data.get("period_str", "Бессрочно (штат)")
    sz_info = data.get("sz_info", "По СЗ")
    curator = data.get("curator", "—")

    body = [
        f"👤 ФИО: <b>{html_text(full_name)}</b>",
        f"📋 СЗ: <b>{html_text(sz_info)}</b> · Куратор: <b>{html_text(curator)}</b>",
        f"⏳ Срок: <b>{html_text(period_str)}</b>",
        "",
        "Выберите <b>шаблон подразделения</b> или введите вручную:",
    ]
    buttons = [
        button_row(
            callback_button("💻 IT", "tpl:it", "primary"),
            callback_button("📊 Бухгалтерия", "tpl:acc", "primary"),
        ),
        button_row(
            callback_button("🏢 Бэк-офис", "tpl:back", "primary"),
            callback_button("💼 Кредитование", "tpl:cred", "primary"),
        ),
        button_row(
            callback_button("🛡 Риски / ИБ", "tpl:sec", "primary"),
            callback_button("🎓 Стажер (Базовый)", "tpl:intern", "primary"),
        ),
        button_row(
            callback_button("✏️ Ввести вручную", "tpl:custom", "link"),
            callback_button("❌ Отмена", "menu:ad", "link"),
        ),
    ]
    card = render_bubble_card(
        title="➕ Новый сотрудник",
        badge="Выбор отдела" if not is_intern else "Отдел стажера",
        body_lines=body,
        buttons=buttons,
    )
    if edit:
        await edit_rich(target_msg, card)
    else:
        await send_rich(target_msg, card)


@ad_admin_router.message(CreateUserState.waiting_for_fullname)
async def process_create_user_fullname(message: Message, state: FSMContext):
    full_name = (message.text or "").strip()
    await state.update_data(full_name=full_name)
    data = await state.get_data()
    if data.get("is_intern"):
        await state.set_state(CreateUserState.waiting_for_intern_duration)
        body = [
            f"🎓 Стажер: <b>{html_text(full_name)}</b>",
            "Выберите <b>срок стажировки</b> (дата авто-отключения <code>accountExpires</code>) или введите дату в формате <code>ДД.ММ.ГГГГ</code>:",
        ]
        buttons = [
            button_row(
                callback_button("14 дней", "onb:dur:14", "primary"),
                callback_button("1 месяц (30 дн.)", "onb:dur:30", "primary"),
            ),
            button_row(
                callback_button("2 месяца (60 дн.)", "onb:dur:60", "primary"),
                callback_button("3 месяца (90 дн.)", "onb:dur:90", "primary"),
            ),
            button_row(callback_button("❌ Отмена", "menu:ad", "link")),
        ]
        card = render_bubble_card(
            title="🎓 Срок стажировки",
            badge="Шаг 2 · Срок",
            body_lines=body,
            buttons=buttons,
        )
        await send_rich(message, card)
    else:
        await _prompt_sz_info(message, state, edit=False)


@ad_admin_router.callback_query(F.data.startswith("onb:dur:"))
async def cb_onboarding_intern_duration(call: CallbackQuery, state: FSMContext):
    days = int(call.data.split("onb:dur:", 1)[1])
    now_local = datetime.datetime.now(TZ_LOCAL)
    exp_dt = now_local + datetime.timedelta(days=days)
    period_str = f"с {now_local.strftime('%d.%m.%Y')} по {exp_dt.strftime('%d.%m.%Y')} ({days} дн.)"
    await state.update_data(
        expires_days=days,
        account_expires_dt=exp_dt.isoformat(),
        period_str=period_str,
    )
    await call.answer(f"Срок: {days} дн.")
    await _prompt_sz_info(call.message, state, edit=True)


@ad_admin_router.message(CreateUserState.waiting_for_intern_duration)
async def process_onboarding_intern_duration_text(message: Message, state: FSMContext):
    raw = (message.text or "").strip()
    now_local = datetime.datetime.now(TZ_LOCAL)
    exp_dt = None
    try:
        if "." in raw:
            exp_dt = datetime.datetime.strptime(raw, "%d.%m.%Y").replace(tzinfo=TZ_LOCAL)
        elif raw.isdigit():
            exp_dt = now_local + datetime.timedelta(days=int(raw))
    except Exception:
        exp_dt = None

    if not exp_dt:
        await send_rich(
            message,
            render_bubble_card(
                title="⚠️ Неверный формат даты",
                badge="Ошибка ввода",
                body_lines=["Введите дату окончания в формате <code>ДД.ММ.ГГГГ</code> (например <code>31.12.2026</code>) или число дней:"],
                buttons=[button_row(callback_button("❌ Отмена", "menu:ad", "link"))],
            ),
        )
        return

    days = max(1, (exp_dt.date() - now_local.date()).days)
    period_str = f"с {now_local.strftime('%d.%m.%Y')} по {exp_dt.strftime('%d.%m.%Y')} ({days} дн.)"
    await state.update_data(
        expires_days=days,
        account_expires_dt=exp_dt.isoformat(),
        period_str=period_str,
    )
    await _prompt_sz_info(message, state, edit=False)


@ad_admin_router.callback_query(F.data == "onb:sz:skip")
async def cb_onboarding_sz_skip(call: CallbackQuery, state: FSMContext):
    await state.update_data(sz_info="По СЗ", curator="—")
    await call.answer("Пропущено")
    await _prompt_department_selection(call.message, state, edit=True)


@ad_admin_router.message(CreateUserState.waiting_for_sz_info)
async def process_onboarding_sz_info(message: Message, state: FSMContext):
    raw = (message.text or "").strip()
    sz_info = raw
    curator = "—"
    if "|" in raw:
        parts = [p.strip() for p in raw.split("|", 1)]
        sz_info = parts[0] or "По СЗ"
        curator = re.sub(r"^(?:куратор|руководитель)\s*:\s*", "", parts[1], flags=re.IGNORECASE).strip() or "—"
    else:
        parsed = parse_sz_text(raw)
        if parsed.get("sz_number"):
            sz_info = parsed["sz_number"]
        if parsed.get("curator"):
            curator = parsed["curator"]
    await state.update_data(sz_info=sz_info, curator=curator)
    await _prompt_department_selection(message, state, edit=False)


async def _finish_create_user(
    target_msg: Message,
    admin_user,
    full_name: str,
    department: str,
    title: str = "Специалист",
    is_intern: bool = False,
    sz_info: str = "По СЗ",
    curator: str = "—",
    period_str: str = "Бессрочно (штат)",
    account_expires_dt: datetime.datetime | None = None,
    groups: list[str] | None = None,
    edit: bool = False,
):
    username = _generate_ad_username(full_name)
    password = _generate_temp_password()
    ou_dn = settings.AD_INTERN_OU if is_intern else settings.AD_DEFAULT_NEW_USER_OU
    if not ou_dn:
        ou_dn = f"CN=Users,{settings.AD_SEARCH_BASE}" if settings.AD_SEARCH_BASE else "CN=Users"

    desc_parts = []
    if is_intern:
        desc_parts.append("Стажер")
    if sz_info and sz_info != "По СЗ":
        desc_parts.append(f"СЗ: {sz_info}")
    if curator and curator != "—":
        desc_parts.append(f"Куратор: {curator}")
    if account_expires_dt:
        desc_parts.append(f"до {account_expires_dt.strftime('%d.%m.%Y')}")
    description = " | ".join(desc_parts)

    res = await ad_service.create_ad_user(
        full_name=full_name,
        username=username,
        password=password,
        ou_dn=ou_dn,
        department=department,
        title=title,
        description=description,
        groups=groups,
        account_expires_dt=account_expires_dt,
    )
    ok = res.get("success", False) if isinstance(res, dict) else bool(res)
    actual_username = res.get("username", username) if isinstance(res, dict) else username
    added_groups = res.get("added_groups", []) if isinstance(res, dict) else []
    user_dn = res.get("dn", ou_dn) if isinstance(res, dict) else ou_dn

    await log_audit_action(
        admin_id=admin_user.id,
        admin_username=admin_user.username,
        action="AD_CREATE_INTERN" if is_intern else "AD_CREATE_USER",
        target=f"{actual_username} ({department})",
        status="SUCCESS" if ok else "FAILED",
        details=description or None,
    )

    if ok:
        access_str = ", ".join(added_groups) if added_groups else "Базовые доменные группы (Domain Users)"
        report_plain_text = format_helpdesk_onboarding_report(
            full_name=full_name,
            username=actual_username,
            password=password,
            department=department,
            title=title,
            sz_info=sz_info,
            curator=curator,
            period_str=period_str,
            access_str=access_str,
        )
        body = [
            f"✅ <b>{'Стажер' if is_intern else 'Сотрудник'} успешно создан в Active Directory!</b>",
            f"• ФИО: <b>{html_text(full_name)}</b>",
            f"• Подразделение: <b>{html_text(department)}</b> ({html_text(title)})",
            f"• Логин: <code>{html_text(actual_username)}</code>",
            f"• Временный пароль: <code>{html_text(password)}</code>",
            f"• Контейнер (DN): <code>{html_text(user_dn)}</code>",
            f"• Срок действия: <b>{html_text(period_str)}</b>",
            f"• Группы AD: <code>{html_text(access_str)}</code>",
            "",
            "📋 <b>Готовый ответ для чата HelpDesk:</b>",
            f"<pre>{html_text(report_plain_text)}</pre>",
        ]
        buttons = [
            button_row(copy_button("📋 Скопировать для HelpDesk", report_plain_text)),
            button_row(
                callback_button("🗄 Подключить сетевые диски", f"drv:user:{actual_username}", "primary"),
                callback_button("👤 Карточка сотрудника", f"user:show:{actual_username}", "primary"),
            ),
            button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link")),
        ]
    else:
        err = res.get("error", "Неизвестная ошибка") if isinstance(res, dict) else str(res)
        body = [f"❌ <b>Ошибка создания пользователя:</b> {html_text(str(err))}"]
        buttons = [button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))]

    card = render_bubble_card(
        title="➕ Онбординг завершен" if ok else "➕ Ошибка онбординга",
        badge="Готово" if ok else "Ошибка",
        body_lines=body,
        buttons=buttons,
    )
    if edit:
        await edit_rich(target_msg, card)
    else:
        await send_rich(target_msg, card)


@ad_admin_router.callback_query(F.data.startswith("tpl:"))
async def cb_create_user_template(call: CallbackQuery, state: FSMContext):
    tpl_key = call.data.split("tpl:", 1)[1]
    data = await state.get_data()
    full_name = data.get("full_name", "")

    if tpl_key == "custom":
        await state.set_state(CreateUserState.waiting_for_department)
        body = [
            f"👤 ФИО: <b>{html_text(full_name)}</b>",
            "Введите <b>название подразделения</b> (или <code>Подразделение | Должность</code>):",
        ]
        buttons = [button_row(callback_button("❌ Отмена", "menu:ad", "link"))]
        card = render_bubble_card(
            title="➕ Новый сотрудник",
            badge="Ввод отдела",
            body_lines=body,
            buttons=buttons,
        )
        await edit_rich(call.message, card)
        await call.answer()
        return

    tpl = DEPARTMENT_TEMPLATES.get(tpl_key)
    if not tpl:
        await call.answer("Неизвестный шаблон", show_alert=True)
        return

    is_intern = bool(data.get("is_intern")) or (tpl_key == "intern")
    title = "Стажер" if is_intern else tpl.get("title", data.get("title", "Специалист"))
    sz_info = data.get("sz_info", "По СЗ")
    curator = data.get("curator", "—")
    period_str = data.get("period_str", "Бессрочно (штат)")
    raw_exp = data.get("account_expires_dt")
    exp_dt = datetime.datetime.fromisoformat(raw_exp) if raw_exp else None

    await state.clear()
    await call.answer("⏳ Создаю учетную запись в AD...")
    await _finish_create_user(
        target_msg=call.message,
        admin_user=call.from_user,
        full_name=full_name,
        department=tpl["department"],
        title=title,
        is_intern=is_intern,
        sz_info=sz_info,
        curator=curator,
        period_str=period_str,
        account_expires_dt=exp_dt,
        groups=tpl["groups"],
        edit=True,
    )


@ad_admin_router.message(CreateUserState.waiting_for_department)
async def process_create_user_department(message: Message, state: FSMContext):
    raw_dept = (message.text or "").strip()
    data = await state.get_data()
    full_name = data.get("full_name", "")
    is_intern = bool(data.get("is_intern", False))
    default_title = "Стажер" if is_intern else data.get("title", "Специалист")

    if "|" in raw_dept:
        parts = [p.strip() for p in raw_dept.split("|", 1)]
        department = parts[0]
        title = parts[1] or default_title
    else:
        department = raw_dept
        title = default_title

    sz_info = data.get("sz_info", "По СЗ")
    curator = data.get("curator", "—")
    period_str = data.get("period_str", "Бессрочно (штат)")
    raw_exp = data.get("account_expires_dt")
    exp_dt = datetime.datetime.fromisoformat(raw_exp) if raw_exp else None

    await state.clear()
    await _finish_create_user(
        target_msg=message,
        admin_user=message.from_user,
        full_name=full_name,
        department=department,
        title=title,
        is_intern=is_intern,
        sz_info=sz_info,
        curator=curator,
        period_str=period_str,
        account_expires_dt=exp_dt,
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
    username = (message.text or "").strip()
    if not username:
        await send_rich(message, render_bubble_card(
            title="⚠️ Пустой ввод",
            badge="AD Recovery",
            body_lines=["Введите текстовый логин сотрудника."],
            buttons=[button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link"))],
        ))
        return
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

async def _render_ad_locked(call: CallbackQuery):
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
        return

    body = [f"Найдено заблокированных: <b>{len(users)}</b>"]
    table = []
    buttons = []
    for u in users[:8]:
        table.append((u["username"], f"{html_text(u.get('name'))} ({html_text(u.get('department'))})"))
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


@ad_admin_router.callback_query(F.data == "ad:locked")
async def cb_ad_locked(call: CallbackQuery):
    await _render_ad_locked(call)
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
    await _render_ad_locked(call)

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
    username = (message.text or "").strip()
    if not username:
        await send_rich(message, render_bubble_card(
            title="⚠️ Пустой ввод",
            badge="Offboarding",
            body_lines=["Введите текстовый логин сотрудника."],
            buttons=[button_row(callback_button("❌ Отмена", "menu:ad", "link"))],
        ))
        return
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
        buttons = [
            button_row(
                callback_button("🙈 Скрыть из GAL (Exchange)", f"exchange:gal_hide:{username}", "secondary"),
                callback_button("🗑 Удалить почту Exchange", f"exchange:del_ask:{username}", "danger"),
            ),
            button_row(
                callback_button("🗄 Диски сотрудника (GPO)", f"drv:user:{username}", "primary"),
            ),
            button_row(callback_button("⬅️ Назад в AD", "menu:ad", "link")),
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


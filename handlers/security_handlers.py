import re
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.fsm.context import FSMContext

_RE_SAM_ACCOUNT = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

from services.ad_service import ad_service
from services.security_service import emergency_kill_switch
from services.db_service import log_audit_action, get_active_jit_grants
from services.jit_service import jit_service
from services.rich_message_service import (
    render_bubble_card,
    button_row,
    callback_button,
    html_text,
    send_rich,
    edit_rich
)
from handlers.states import (
    KillSwitchState,
    JITPrivilegeState
)

security_router = Router()

@security_router.callback_query(F.data.in_(["menu:killswitch", "killswitch:prompt"]))
async def cb_killswitch_start(call: CallbackQuery, state: FSMContext):
    await state.set_state(KillSwitchState.waiting_for_username)
    body = [
        "🚨 <b>Чрезвычайная ситуация: Emergency Kill Switch</b>",
        "Мгновенная изоляция и нейтрализация подозрительной учетной записи:",
        "1. Немедленная блокировка в Active Directory (ACCOUNTDISABLE)",
        "2. Сброс сессий и отзыв прав доступа",
        "3. Перемещение в изолятор OU=Disabled Users",
        "",
        "✍️ <i>Введите логин сотрудника (sAMAccountName) для изоляции:</i>"
    ]
    buttons = [button_row(callback_button("❌ Отмена", "menu:home", "link"))]
    card = render_bubble_card(
        title="🛡 Emergency Kill Switch",
        badge="Zero Trust",
        body_lines=body,
        buttons=buttons,
        footer_note="Для отмены нажмите 'Отмена' в любой момент"
    )
    await edit_rich(call.message, card)
    await call.answer()

@security_router.message(KillSwitchState.waiting_for_username, F.text)
async def process_killswitch_username(message: Message, state: FSMContext):
    username = (message.text or "").strip()
    if not _RE_SAM_ACCOUNT.fullmatch(username):
        await message.answer("❌ Некорректный логин. Используйте только латиницу, цифры и символы . _ - (до 64 симв.).")
        return
    await state.update_data(killswitch_target=username)
    await state.set_state(KillSwitchState.waiting_for_confirmation)

    body = [
        f"⚠️ <b>ВНИМАНИЕ! ДВУХЭТАПНОЕ ПОДТВЕРЖДЕНИЕ ИЗОЛЯЦИИ</b>",
        f"Целевой логин: <code>{html_text(username)}</code>",
        "",
        "Будет запущена аварийная процедура полной блокировки и изоляции аккаунта.",
        "Вы подтверждаете немедленное выполнение Kill Switch?"
    ]
    buttons = [
        button_row(
            callback_button("🔥 ПОДТВЕРДИТЬ ИЗОЛЯЦИЮ", f"ks:confirm:{username}", "danger")
        ),
        button_row(
            callback_button("❌ Отмена операции", "menu:home", "link")
        )
    ]
    card = render_bubble_card(
        title="🛡 Двухэтапное подтверждение Kill Switch",
        badge="Action Required",
        body_lines=body,
        buttons=buttons
    )
    await send_rich(message, card)

@security_router.callback_query(F.data.startswith("ks:confirm:"))
async def cb_killswitch_execute(call: CallbackQuery, state: FSMContext):
    username = call.data.split(":")[2]
    await state.clear()
    await call.answer("🚨 Активирован Kill Switch...", show_alert=True)

    res = await emergency_kill_switch(username, call.from_user.id)
    success = res.get("success", False)

    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="EMERGENCY_KILL_SWITCH",
        target=username,
        status="ISOLATED" if success else "FAILED",
        details=f"KillSwitch result: {res}"
    )

    if success:
        vpn_removed = ", ".join(res.get("vpn_groups_removed") or []) or "нет VPN-групп"
        body = [
            f"🛡 <b>ПОЛЬЗОВАТЕЛЬ УСПЕШНО ИЗОЛИРОВАН!</b>",
            f"• Логин: <code>{html_text(username)}</code>",
            f"• Учетная запись: <b>Отключена (ACCOUNTDISABLE)</b>",
            f"• Пароль перезаписан (32 симв.): <b>{'Да' if res.get('password_reset') else 'Нет'}</b>",
            f"• Отозваны VPN-группы: <code>{html_text(vpn_removed)}</code>",
            f"• Флаг статуса: <b>[TERMINATED]</b> (снапшот сохранен)",
            f"• Перемещение в Disabled OU: <b>{'Да' if res.get('moved') else 'Не настроено / не требуется'}</b>",
            "",
            "Уведомление занесено в глобальный журнал инцидентов ИБ."
        ]
    else:
        body = [
            f"❌ <b>ОШИБКА ИЗОЛЯЦИИ АККАУНТА:</b>",
            f"• Логин: <code>{html_text(username)}</code>",
            f"• Причина: {html_text(res.get('error', 'Ошибка обращения к AD'))}"
        ]

    buttons = [
        button_row(
            callback_button("🛡 Kill Switch другого", "menu:killswitch", "danger"),
            callback_button("⬅️ Главное меню", "menu:home", "link")
        )
    ]
    card = render_bubble_card(
        title="🛡 Отчет Emergency Kill Switch",
        badge="Incident Response",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

# ==========================================
# 7. JIT Временные права (Just-In-Time)
# ==========================================
JIT_GROUPS = ["Domain Admins", "VPN_Users"]
JIT_DURATIONS = {
    "30m": ("30 минут", 1800),
    "1h": ("1 час", 3600),
    "2h": ("2 часа", 7200),
    "4h": ("4 часа", 14400),
}

@security_router.callback_query(F.data.in_(["menu:jit", "jit:menu"]))
async def cb_jit_menu(call: CallbackQuery, state: FSMContext):
    await state.clear()
    body = [
        "⏳ <b>JIT (Just-In-Time) Временные привилегии</b>",
        "Предоставление временного членства в привилегированных группах безопасности AD с автоматическим отзывом.",
        "",
        "<b>Шаг 1:</b> Выберите группу для временного назначения:"
    ]
    buttons = []
    for g in JIT_GROUPS:
        buttons.append(button_row(
            callback_button(f"🔑 {g}", f"jit:grp:{g}", "primary")
        ))
    buttons.append(button_row(callback_button("📋 Активные гранты", "jit:active", "primary")))
    buttons.append(button_row(callback_button("⬅️ Главное меню", "menu:home", "link")))

    card = render_bubble_card(
        title="⏳ JIT Временные права",
        badge="Zero Trust RBAC",
        body_lines=body,
        buttons=buttons,
        footer_note="Автоматический таймер отзовет доступ после истечения срока"
    )
    await edit_rich(call.message, card)
    await call.answer()

@security_router.callback_query(F.data == "jit:active")
async def cb_jit_active(call: CallbackQuery):
    await call.answer("📋 Загружаю активные JIT-гранты...", show_alert=False)
    grants = await get_active_jit_grants()
    buttons = []
    if not grants:
        body = ["✅ Активных JIT-грантов в данный момент нет."]
    else:
        body = [f"📋 <b>Активные JIT-гранты ({len(grants)}):</b>", ""]
        for g in grants:
            g_dict = dict(g)
            gid = g_dict["id"]
            uname = g_dict["username"]
            grp = g_dict["group_name"]
            exp = g_dict.get("expires_at", "N/A")
            body.append(f"• #{gid} <code>{html_text(uname)}</code> → <b>{html_text(grp)}</b> (до {html_text(str(exp))})")
            buttons.append(button_row(
                callback_button(f"🚫 Отозвать #{gid} ({uname})", f"jit:revoke:{gid}", "danger")
            ))
    buttons.append(button_row(callback_button("⬅️ Назад в JIT", "menu:jit", "link")))
    card = render_bubble_card(
        title="📋 Активные JIT-гранты",
        badge="Zero Trust RBAC",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

@security_router.callback_query(F.data.startswith("jit:revoke:"))
async def cb_jit_revoke(call: CallbackQuery):
    grant_id = int(call.data.split(":")[2])
    await call.answer(f"🚫 Отзываю грант #{grant_id}...", show_alert=False)
    res = await jit_service.revoke_grant_now(
        grant_id,
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
    )
    if res.get("success"):
        body = [
            f"✅ <b>JIT-грант #{grant_id} досрочно отозван!</b>",
            f"• Пользователь: <code>{html_text(res.get('username', ''))}</code>",
            f"• Группа: <b>{html_text(res.get('group_name', ''))}</b>",
        ]
    else:
        body = [f"❌ <b>Ошибка отзыва:</b> {html_text(res.get('error', 'Неизвестная ошибка'))}"]
    buttons = [
        button_row(
            callback_button("📋 Активные гранты", "jit:active", "primary"),
            callback_button("⬅️ Назад в JIT", "menu:jit", "link"),
        )
    ]
    card = render_bubble_card(
        title="🚫 Досрочный отзыв JIT",
        badge="Zero Trust RBAC",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

@security_router.callback_query(F.data.startswith("jit:grp:"))
async def cb_jit_select_group(call: CallbackQuery, state: FSMContext):
    group = call.data.split(":")[2]
    if group not in JIT_GROUPS:
        await call.answer("⛔️ Недопустимая JIT-группа.", show_alert=True)
        return
    await state.update_data(jit_group=group)
    await state.set_state(JITPrivilegeState.waiting_for_username)

    body = [
        f"⏳ Выбрана группа: <b>{html_text(group)}</b>",
        "",
        "<b>Шаг 2:</b> Введите логин пользователя в Active Directory (sAMAccountName):"
    ]
    buttons = [button_row(callback_button("⬅️ Назад к выбору группы", "menu:jit", "link"))]
    card = render_bubble_card(
        title="⏳ JIT: Ввод логина",
        badge="Шаг 2/3",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)
    await call.answer()

@security_router.message(JITPrivilegeState.waiting_for_username, F.text)
async def process_jit_username(message: Message, state: FSMContext):
    username = (message.text or "").strip()
    if not _RE_SAM_ACCOUNT.fullmatch(username):
        await message.answer("❌ Некорректный логин. Используйте только латиницу, цифры и символы . _ - (до 64 симв.).")
        return
    data = await state.get_data()
    group = data.get("jit_group", "Domain Admins")
    await state.update_data(jit_username=username)

    body = [
        f"⏳ Пользователь: <code>{html_text(username)}</code>",
        f"🔑 Целевая группа: <b>{html_text(group)}</b>",
        "",
        "<b>Шаг 3:</b> Выберите срок действия временных привилегий:"
    ]
    buttons = [
        button_row(
            callback_button("⏱ 30 минут", f"jit:dur:{group}:{username}:30m", "primary"),
            callback_button("⏱ 1 час", f"jit:dur:{group}:{username}:1h", "primary"),
        ),
        button_row(
            callback_button("⏱ 2 часа", f"jit:dur:{group}:{username}:2h", "primary"),
            callback_button("⏱ 4 часа", f"jit:dur:{group}:{username}:4h", "primary"),
        ),
        button_row(
            callback_button("❌ Отмена", "menu:home", "link")
        )
    ]
    card = render_bubble_card(
        title="⏳ JIT: Выбор срока действия",
        badge="Шаг 3/3",
        body_lines=body,
        buttons=buttons
    )
    await send_rich(message, card)

@security_router.callback_query(F.data.startswith("jit:dur:"))
async def cb_jit_grant(call: CallbackQuery, state: FSMContext):
    parts = call.data.split(":")
    if len(parts) < 5:
        await call.answer("❌ Некорректные параметры JIT.", show_alert=True)
        return
    group = parts[2]
    username = parts[3]
    dur_code = parts[4]
    if group not in JIT_GROUPS:
        await call.answer("⛔️ Недопустимая JIT-группа.", show_alert=True)
        return
    if not _RE_SAM_ACCOUNT.fullmatch(username):
        await call.answer("❌ Некорректный логин пользователя.", show_alert=True)
        return
    await state.clear()

    dur_label, dur_sec = JIT_DURATIONS.get(dur_code, ("1 час", 3600))
    duration_min = max(1, dur_sec // 60)
    await call.answer(f"⏳ Назначаю права на {dur_label}...", show_alert=False)

    res = await jit_service.grant_temporary_access(
        username,
        group,
        duration_min,
        call.from_user.id,
        admin_username=call.from_user.username,
    )
    ok = res.get("success", False) if isinstance(res, dict) else bool(res)

    if ok:
        body = [
            f"✅ <b>ВРЕМЕННЫЕ ПРАВА УСПЕШНО НАЗНАЧЕНЫ!</b>",
            f"• Пользователь: <code>{html_text(username)}</code>",
            f"• Группа: <b>{html_text(group)}</b>",
            f"• Длительность: <b>{dur_label}</b>",
            f"• Авто-отзыв: <b>Включен (контроль через JIT-воркер)</b>",
            "",
            "По истечении срока права будут автоматически отозваны с записью в аудит."
        ]
    else:
        err = res.get("error", "Проверьте правильность логина и наличие прав в AD.") if isinstance(res, dict) else "Ошибка AD"
        body = [
            f"❌ <b>ОШИБКА НАЗНАЧЕНИЯ ПРАВ:</b>",
            f"Не удалось добавить <code>{html_text(username)}</code> в группу <b>{html_text(group)}</b>.",
            html_text(str(err))
        ]

    buttons = [
        button_row(
            callback_button("⏳ Выдать еще JIT-права", "menu:jit", "primary"),
            callback_button("⬅️ Главное меню", "menu:home", "link")
        )
    ]
    card = render_bubble_card(
        title="⏳ Результат выдачи JIT-прав",
        badge="JIT Granted" if ok else "Failed",
        body_lines=body,
        buttons=buttons
    )
    await edit_rich(call.message, card)

# ==========================================
# 8. Bash Терминал (/exec)
# ==========================================

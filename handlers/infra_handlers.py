import asyncio
import socket
import ssl
from datetime import datetime
from aiogram import Router, F
from aiogram.types import Message, CallbackQuery
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext

from config import settings
from services.infra_service import (
    get_system_metrics,
    check_ping,
    check_tcp_port_rtt,
    get_all_services_status,
    restart_service,
    get_service_logs,
    MANAGED_SERVICES,
    SERVICE_LABELS,
)
from services.exchange_service import (
    get_exchange_overview,
    get_exchange_mailflow_errors,
    get_exchange_forwarding_audit,
    enable_user_mailbox,
    disable_user_mailbox,
    get_mailbox_details,
    set_mailbox_hidden_gal,
    grant_mailbox_full_access,
    set_mailbox_forwarding,
)
from handlers.states import ExchangeActionState
from services.playbooks_service import get_playbooks_list, execute_playbook, PLAYBOOKS
from services.terminal_service import run_quick_command
from services.db_service import log_audit_action
from services.briefing_worker import build_briefing_card
from services.backup_service import create_and_send_backup
from services import docker_service
from services.rich_message_service import (
    render_bubble_card,
    render_progress_bar,
    button_row,
    callback_button,
    html_text,
    send_rich,
    edit_rich,
)
from handlers.states import NetCheckState

infra_router = Router()


@infra_router.callback_query(F.data == "menu:infra")
async def cb_infra_menu(call: CallbackQuery):
    metrics = await get_system_metrics()
    ram = metrics["ram"]
    disk = metrics["disk"]

    body = [
        f"⏱ <b>Uptime хоста:</b> <code>{metrics['uptime']}</code>",
        f"📈 <b>Load Average:</b> <code>{metrics['load_avg']}</code>",
        f"🧠 <b>RAM:</b> {ram['bar']} ({ram['used_gb']} GB / {ram['total_gb']} GB)",
        f"💾 <b>Диск (/):</b> {disk['bar']} ({disk['used_gb']} GB / {disk['total_gb']} GB)",
    ]

    all_statuses = await get_all_services_status(MANAGED_SERVICES)

    table = []
    for s in all_statuses:
        status_icon = "🟢 active" if s["active"] else f"🔴 {s['status']}"
        table.append((s["label"], status_icon))

    buttons = [
        button_row(
            callback_button("🔄 Перезапуск Kolins Bot", "srv:restart:kolins-bot", "danger"),
            callback_button("🔄 WebApp", "srv:restart:kolins-webapp", "danger"),
        ),
        button_row(
            callback_button("🔄 Перезапуск Tunnel", "srv:restart:kolins-tunnel", "danger"),
            callback_button("🔄 Tauria Bot", "srv:restart:tauria-bot", "danger"),
        ),
        button_row(
            callback_button("📄 Логи сервисов", "srv:logs:menu", "primary"),
            callback_button("🔄 Обновить метрики", "menu:infra", "primary"),
        ),
        button_row(
            callback_button("🌅 Дайджест сейчас", "infra:briefing", "primary"),
            callback_button("💾 Сделать бэкап", "infra:backup", "success"),
        ),
        button_row(
            callback_button("📧 Exchange Server", "infra:exchange", "primary"),
            callback_button("🐳 Docker / RustDesk", "infra:docker", "primary"),
        ),
        button_row(
            callback_button("⬅️ Главное меню", "menu:home", "link"),
        ),
    ]

    card = render_bubble_card(
        title="🖥 Сервер Инфраструктуры",
        badge="Ubuntu 24.04",
        body_lines=body,
        table_rows=table,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


# ==========================================
# Exchange Server Monitoring (192.168.254.23)
# ==========================================

@infra_router.callback_query(F.data == "infra:exchange")
async def cb_infra_exchange(call: CallbackQuery):
    await call.answer("📧 Опрос сервера Exchange по WinRM...", show_alert=False)
    exch_host = settings.EXCHANGE_SERVER or "192.168.254.23"

    loading_card = render_bubble_card(
        title="📧 Microsoft Exchange Server",
        badge=exch_host,
        body_lines=[
            f"⏳ Подключение по WinRM к <code>{html_text(exch_host)}</code>...",
            "<i>Проверка служб транспорта, очередей писем, баз данных, дисков и сертификатов.</i>",
        ],
    )
    await edit_rich(call.message, loading_card)

    overview = await get_exchange_overview()
    if not overview.get("ok"):
        err = overview.get("error", "Неизвестная ошибка WinRM")
        card = render_bubble_card(
            title="📧 Exchange Server — Недоступен",
            badge=exch_host,
            body_lines=[
                f"❌ <b>Не удалось выполнить PowerShell-опрос Exchange ({html_text(exch_host)}):</b>",
                f"<code>{html_text(err)}</code>",
            ],
            buttons=[
                button_row(
                    callback_button("🔄 Повторить", "infra:exchange", "primary"),
                    callback_button("⬅️ Инфраструктура", "menu:infra", "link"),
                )
            ],
        )
        await edit_rich(call.message, card)
        return

    services = overview.get("services", [])
    queues = overview.get("queues", [])
    databases = overview.get("databases", [])
    disks = overview.get("disks", [])
    certs = overview.get("certificates", [])

    running_svc = sum(1 for s in services if s.get("running"))
    total_svc = len(services)
    total_queued_msgs = sum(int(q.get("message_count", 0)) for q in queues)
    mounted_dbs = sum(1 for d in databases if d.get("mounted"))
    total_dbs = len(databases)

    body = [
        f"🖥 <b>Хост:</b> <code>{html_text(exch_host)}</code>",
        f"⚙️ <b>Ключевые службы:</b> <b>{running_svc}/{total_svc}</b> запущены",
        f"📬 <b>Писем в очередях (Get-Queue):</b> <b>{total_queued_msgs}</b> (очередей: {len(queues)})",
        f"🗄 <b>Базы почтовых ящиков:</b> <b>{mounted_dbs}/{total_dbs}</b> смонтированы",
    ]

    table = []
    for s in services:
        icon = "🟢" if s.get("running") else "🔴"
        table.append((f"Служба {s.get('name')}", f"{icon} {html_text(s.get('status', '—'))}"))

    for db in databases[:5]:
        db_icon = "🟢 Mounted" if db.get("mounted") else "🔴 Dismounted"
        size_str = f" · {html_text(db.get('size'))}" if db.get("size") else ""
        bkp_str = f"<br><small>Backup: {html_text(db.get('last_full_backup', '—'))}</small>"
        table.append((f"БД {db.get('name')}", f"{db_icon}{size_str}{bkp_str}"))

    for d in disks:
        dev = d.get("device", "Disk")
        free_gb = d.get("free_gb", 0)
        size_gb = d.get("size_gb", 0)
        free_pct = float(d.get("free_pct", 0))
        used_pct = max(0.0, 100.0 - free_pct)
        disk_alert = "🚨 " if free_pct < 10 else ("⚠️ " if free_pct < 15 else "")
        bar = render_progress_bar(used_pct, length=8)
        table.append((f"Диск {dev}", f"{disk_alert}{bar}<br>Свободно: <b>{free_gb} GB</b> из {size_gb} GB ({free_pct}%)"))

    details_lines = []
    if queues:
        details_lines.append("<b>📬 Очереди транспорта (Get-Queue):</b>")
        for q in queues[:10]:
            q_err = f" — <i>{html_text(q['last_error'][:80])}</i>" if q.get("last_error") else ""
            details_lines.append(
                f"• <code>{html_text(q.get('identity'))}</code> [{html_text(q.get('status'))}]: "
                f"<b>{q.get('message_count', 0)}</b> писем → {html_text(q.get('next_hop', '—'))}{q_err}"
            )
    if certs:
        details_lines.append("<br><b>🔐 Сертификаты Exchange:</b>")
        for c in certs[:6]:
            days = c.get("days_left", 999)
            c_icon = "🔴" if days < 0 else ("🟡" if days < 30 else "🟢")
            subj = str(c.get("subject") or "—")
            if len(subj) > 48:
                subj = subj[:48] + "..."
            details_lines.append(
                f"• {c_icon} <code>{html_text(subj)}</code> [{html_text(c.get('services', ''))}] — до {html_text(c.get('not_after'))} ({days} дн.)"
            )

    buttons = [
        button_row(
            callback_button("📨 Ошибки MailFlow (2ч)", "exchange:mailflow", "primary"),
            callback_button("🛡 Аудит пересылок", "exchange:security", "primary"),
        ),
        button_row(
            callback_button("🔄 Обновить статус", "infra:exchange", "secondary"),
            callback_button("⬅️ Инфраструктура", "menu:infra", "link"),
        ),
    ]

    card = render_bubble_card(
        title="📧 Microsoft Exchange Server",
        badge="Online" if running_svc == total_svc else "Degraded",
        body_lines=body,
        table_rows=table,
        details_title="📋 Детали очередей и сертификатов",
        details_content="<br>".join(details_lines) if details_lines else "Очереди пусты, сертификаты в норме",
        buttons=buttons,
    )
    await edit_rich(call.message, card)


@infra_router.callback_query(F.data == "exchange:mailflow")
async def cb_exchange_mailflow(call: CallbackQuery):
    await call.answer("📨 Проверка журнала MessageTrackingLog...", show_alert=False)
    exch_host = settings.EXCHANGE_SERVER or "192.168.254.23"

    await edit_rich(
        call.message,
        render_bubble_card(
            title="📨 Анализ MailFlow (2 часа)",
            badge=exch_host,
            body_lines=["⏳ Поиск событий FAIL, DEFER, BADMAIL, POISONMESSAGE в <code>Get-MessageTrackingLog</code>..."],
        ),
    )

    res = await get_exchange_mailflow_errors(hours=2)
    if not res.get("ok"):
        card = render_bubble_card(
            title="❌ Ошибка проверки MailFlow",
            badge=exch_host,
            body_lines=[f"<code>{html_text(res.get('error', 'Ошибка WinRM'))}</code>"],
            buttons=[button_row(callback_button("⬅️ Назад к Exchange", "infra:exchange", "link"))],
        )
        await edit_rich(call.message, card)
        return

    events = res.get("events", [])
    total = res.get("total_found", len(events))
    if not events:
        body = [
            "✅ <b>За последние 2 часа ошибок доставки (FAIL / DEFER / BADMAIL / POISONMESSAGE) не обнаружено!</b>",
            "Почтовый поток работает штатно.",
        ]
    else:
        body = [f"⚠️ <b>Обнаружено проблемных событий за 2 часа: {total}</b> (показаны последние {len(events[:12])}):", ""]
        for ev in events[:12]:
            ev_id = ev.get("event_id", "ERR")
            icon = "🔴" if ev_id in ("FAIL", "BADMAIL", "POISONMESSAGE") else "🟡"
            subj = ev.get("subject") or "(без темы)"
            if len(subj) > 45:
                subj = subj[:45] + "..."
            body.append(
                f"{icon} <b>[{html_text(ev_id)}]</b> <code>{html_text(ev.get('timestamp', ''))}</code>\n"
                f"  От: <code>{html_text(ev.get('sender', '—'))}</code> → <code>{html_text(ev.get('recipients', '—')[:50])}</code>\n"
                f"  Тема: <i>{html_text(subj)}</i>"
            )

    buttons = [
        button_row(
            callback_button("🔄 Обновить", "exchange:mailflow", "primary"),
            callback_button("⬅️ Назад к Exchange", "infra:exchange", "link"),
        )
    ]
    card = render_bubble_card(
        title="📨 Диагностика MailFlow (2ч)",
        badge=f"Событий: {total}",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)


@infra_router.callback_query(F.data == "exchange:security")
async def cb_exchange_security(call: CallbackQuery):
    await call.answer("🛡 Запуск аудита пересылок Exchange...", show_alert=False)
    exch_host = settings.EXCHANGE_SERVER or "192.168.254.23"

    await edit_rich(
        call.message,
        render_bubble_card(
            title="🛡 Аудит безопасности Exchange",
            badge=exch_host,
            body_lines=["⏳ Проверка ящиков с пересылкой (ForwardingSmtpAddress / ForwardingAddress) и транспортных правил..."],
        ),
    )

    res = await get_exchange_forwarding_audit()
    if not res.get("ok"):
        card = render_bubble_card(
            title="❌ Ошибка аудита Exchange",
            badge=exch_host,
            body_lines=[f"<code>{html_text(res.get('error', 'Ошибка WinRM'))}</code>"],
            buttons=[button_row(callback_button("⬅️ Назад к Exchange", "infra:exchange", "link"))],
        )
        await edit_rich(call.message, card)
        return

    mb_fwds = res.get("mailbox_forwards", [])
    tr_rules = res.get("transport_rules", [])
    jr_rules = res.get("journal_rules", [])

    body = [
        f"📬 <b>Ящики с пересылкой (Mailbox Forwarding):</b> <b>{len(mb_fwds)}</b>",
        f"🔀 <b>Транспортные правила с BCC/Redirect:</b> <b>{len(tr_rules)}</b>",
        f"📓 <b>Правила журналирования (Journal Rules):</b> <b>{len(jr_rules)}</b>",
        "",
    ]

    if mb_fwds:
        body.append("<b>🔍 Ящики с активной пересылкой:</b>")
        for m in mb_fwds[:12]:
            target = m.get("forwarding_smtp") or m.get("forwarding_address") or "—"
            body.append(
                f"• <code>{html_text(m.get('primary_smtp') or m.get('display_name'))}</code> → <b>{html_text(target)}</b>"
            )
    else:
        body.append("✅ На уровне почтовых ящиков переадресаций не обнаружено.")

    if tr_rules:
        body.append("\n<b>🔀 Транспортные правила с копированием/перенаправлением:</b>")
        for r in tr_rules[:10]:
            body.append(
                f"• <b>{html_text(r.get('name'))}</b> [{html_text(r.get('state'))}]: <code>{html_text(r.get('targets'))}</code>"
            )

    if jr_rules:
        body.append("\n<b>📓 Правила журналирования:</b>")
        for j in jr_rules[:6]:
            st = "🟢 Enabled" if j.get("enabled") else "🔴 Disabled"
            body.append(f"• <b>{html_text(j.get('name'))}</b> ({st}) → <code>{html_text(j.get('email'))}</code>")

    buttons = [
        button_row(
            callback_button("🔄 Обновить аудит", "exchange:security", "primary"),
            callback_button("⬅️ Назад к Exchange", "infra:exchange", "link"),
        )
    ]
    card = render_bubble_card(
        title="🛡 Аудит пересылок Exchange (GTS)",
        badge="Security Audit",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)


# ==========================================
# Утренний дайджест и Резервное копирование
# ==========================================

@infra_router.callback_query(F.data == "infra:briefing")
async def cb_infra_briefing(call: CallbackQuery):
    await call.answer("🌅 Формирую утренний дайджест...", show_alert=False)
    buttons = [
        button_row(
            callback_button("🔄 Обновить дайджест", "infra:briefing", "primary"),
            callback_button("⬅️ Назад в Инфраструктуру", "menu:infra", "link"),
        )
    ]
    briefing_card = await build_briefing_card(buttons=buttons)
    await edit_rich(call.message, briefing_card)


@infra_router.callback_query(F.data == "infra:backup")
async def cb_infra_backup(call: CallbackQuery):
    await call.answer("💾 Создаю и отправляю бэкап...", show_alert=False)
    target_chat = getattr(settings, "LOG_CHAT_ID", None) or call.from_user.id
    res = await create_and_send_backup(call.bot, target_chat)
    ok = res.get("success", False) if isinstance(res, dict) else bool(res)
    if ok:
        body = [f"✅ Бэкап успешно создан и отправлен в чат <code>{target_chat}</code>."]
    else:
        err = res.get("error", "Неизвестная ошибка") if isinstance(res, dict) else str(res)
        body = [f"❌ <b>Ошибка создания бэкапа:</b> {html_text(str(err))}"]
    buttons = [button_row(callback_button("⬅️ Назад в Инфраструктуру", "menu:infra", "link"))]
    card = render_bubble_card(
        title="💾 Резервное копирование",
        badge="Backup",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)


@infra_router.callback_query(F.data.startswith("srv:restart:"))
async def cb_restart_service(call: CallbackQuery):
    service = call.data.split(":")[2]
    res = await restart_service(service)
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action=f"RESTART_{service.upper()}",
        target=service,
        status="SUCCESS" if res else "FAILED",
    )
    if res:
        await call.answer(f"✅ Служба {service} успешно перезапущена!", show_alert=True)
    else:
        await call.answer(f"❌ Ошибка перезапуска {service}", show_alert=True)
    await cb_infra_menu(call)


# Меню выбора логов сервиса
@infra_router.callback_query(F.data == "srv:logs:menu")
async def cb_logs_menu(call: CallbackQuery):
    body = ["Выберите системный сервис для просмотра последних логов journalctl:"]
    buttons = [
        button_row(
            callback_button("📄 Kolins Bot", "srv:viewlog:kolins-bot", "primary"),
            callback_button("📄 Kolins WebApp", "srv:viewlog:kolins-webapp", "primary"),
        ),
        button_row(
            callback_button("📄 Kolins Tunnel", "srv:viewlog:kolins-tunnel", "primary"),
            callback_button("📄 Tauria Bot", "srv:viewlog:tauria-bot", "primary"),
        ),
        button_row(callback_button("⬅️ Назад в Инфраструктуру", "menu:infra", "link")),
    ]
    card = render_bubble_card(
        title="📄 Журнал логов Systemd",
        badge="journalctl",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


@infra_router.callback_query(F.data.startswith("srv:viewlog:"))
async def cb_view_service_logs(call: CallbackQuery):
    service = call.data.split(":")[2]
    log_data = await get_service_logs(service, lines=25)
    logs_raw = log_data.get("logs", "")
    lines = logs_raw.splitlines()
    recent_lines = lines[-15:] if lines else ["Логи отсутствуют."]
    formatted_logs = "\n".join(recent_lines)
    if len(formatted_logs) > 3500:
        formatted_logs = formatted_logs[-3500:]

    body = [
        f"<b>Сервис:</b> <code>{html_text(service)}</code>",
        f"<b>Всего прочитано строк:</b> {log_data.get('lines_count', 0)}",
        "",
        f"<pre>{html_text(formatted_logs)}</pre>",
    ]
    buttons = [
        button_row(
            callback_button("🔄 Обновить логи", f"srv:viewlog:{service}", "primary"),
            callback_button("🔄 Перезапустить", f"srv:restart:{service}", "danger"),
        ),
        button_row(callback_button("⬅️ К списку сервисов", "srv:logs:menu", "link")),
    ]
    card = render_bubble_card(
        title=f"📄 Логи: {service}",
        badge="Journalctl",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


# ==========================================
# 3. Сеть и Порты (с замером RTT ms)
# ==========================================
@infra_router.callback_query(F.data == "menu:net")
async def cb_net_menu(call: CallbackQuery):
    exch_host = settings.EXCHANGE_SERVER or "192.168.254.23"
    targets = [
        ("Active Directory (LDAP)", settings.AD_SERVER or "192.168.201.15", 389),
        ("AD Global Catalog", settings.AD_SERVER or "192.168.201.15", 3268),
        ("Exchange HTTPS (OWA/EWS)", exch_host, 443),
        ("Exchange SMTP", exch_host, 25),
        ("Ubuntu SSH Server", "192.168.202.117", 51522),
    ]

    table = []
    for name, host, port in targets:
        port_info = await check_tcp_port_rtt(host, port)
        if port_info["open"]:
            status = f"🟢 Доступен ({port_info['rtt_ms']} ms)"
        else:
            status = f"🔴 Закрыт ({port_info['error']})"
        table.append((f"{name} ({port})", status))

    body = [
        "Экспресс-мониторинг ключевых сетевых узлов и портов с точным замером RTT (времени отклика)."
    ]

    buttons = [
        button_row(
            callback_button("🔍 Проверить свой хост/порт", "net:custom", "primary"),
            callback_button("🔄 Обновить", "menu:net", "link"),
        ),
        button_row(callback_button("⬅️ Главное меню", "menu:home", "link")),
    ]

    card = render_bubble_card(
        title="🌐 Сеть & Порты",
        badge="Network Health & RTT",
        body_lines=body,
        table_rows=table,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


@infra_router.callback_query(F.data == "net:custom")
async def cb_net_custom_prompt(call: CallbackQuery, state: FSMContext):
    await state.set_state(NetCheckState.waiting_for_target)
    body = [
        "🔍 <b>Проверка хоста, порта и SSL-сертификата:</b>",
        "Отправьте адрес в формате <code>host:port</code> (например, <code>192.168.202.10:389</code> или <code>example.com:443</code>) или просто <code>domain</code> (например, <code>google.com</code>).",
    ]
    buttons = [button_row(callback_button("⬅️ Отмена", "menu:net", "link"))]
    card = render_bubble_card(
        title="🌐 Проверка сети & SSL",
        badge="Custom Target",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


def _check_ssl_expiry(host: str, port: int = 443) -> str:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                if not not_after:
                    return "⚠️ Не удалось определить срок"
                exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp_dt - datetime.utcnow()).days
                if days_left < 0:
                    return f"🔴 Истёк ({days_left} дн.)"
                elif days_left < 14:
                    return f"🟡 {days_left} дн. (до {exp_dt.strftime('%Y-%m-%d')})"
                return f"🟢 {days_left} дн. (до {exp_dt.strftime('%Y-%m-%d')})"
    except Exception as e:
        return f"❌ Ошибка SSL: {e}"


@infra_router.message(NetCheckState.waiting_for_target)
async def process_net_custom_target(message: Message, state: FSMContext):
    target = (message.text or "").strip()
    await state.clear()

    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            await send_rich(message, render_bubble_card(
                title="❌ Ошибка формата",
                badge="Network",
                body_lines=["Некорректный порт. Используйте <code>host:port</code> или <code>domain</code>."],
                buttons=[button_row(callback_button("⬅️ Назад", "menu:net", "link"))],
            ))
            return
        check_ssl = (port == 443)
    else:
        host = target
        port = 443
        check_ssl = True

    ping_res = await check_ping(host)
    ping_ok = bool(ping_res.get("alive")) if isinstance(ping_res, dict) else bool(ping_res)

    tcp_res = await check_tcp_port_rtt(host, port)
    if isinstance(tcp_res, dict):
        tcp_ok = bool(tcp_res.get("open"))
        rtt = tcp_res.get("rtt_ms", 0)
    else:
        tcp_ok, rtt = bool(tcp_res), 0

    table = [
        ("Цель", f"{html_text(host)}:{port}"),
        ("ICMP Ping", "🟢 Доступен" if ping_ok else "🔴 Недоступен"),
        (f"TCP :{port}", f"🟢 Открыт ({rtt} мс)" if tcp_ok else "🔴 Закрыт / Таймаут"),
    ]
    if check_ssl:
        ssl_status = await asyncio.to_thread(_check_ssl_expiry, host, port)
        table.append(("SSL-сертификат", ssl_status))

    buttons = [
        button_row(
            callback_button("🔍 Проверить другой", "net:custom", "primary"),
            callback_button("⬅️ В меню сети", "menu:net", "link"),
        )
    ]
    card = render_bubble_card(
        title="🌐 Результат проверки",
        badge=host,
        table_rows=table,
        buttons=buttons,
    )
    await send_rich(message, card)


@infra_router.callback_query(F.data.startswith("exchange:menu:"))
async def cb_exchange_user_menu(call: CallbackQuery):
    username = call.data.split(":", 2)[2].strip()
    await call.answer(f"📧 Загружаю данные ящика {username}...", show_alert=False)

    res = await get_mailbox_details(username)
    if not res.get("ok"):
        card = render_bubble_card(
            title="❌ Ошибка Exchange",
            badge="Exchange",
            body_lines=[f"Не удалось получить данные для <code>{html_text(username)}</code>:\n<code>{html_text(str(res.get('error', 'Ошибка')))}</code>"],
            buttons=[
                button_row(callback_button("👤 В карточку сотрудника", f"user:show:{username}", "primary")),
                button_row(callback_button("⬅️ Главное меню", "menu:home", "link")),
            ],
        )
        await edit_rich(call.message, card)
        return

    if not res.get("exists"):
        card = render_bubble_card(
            title="📧 Почта Exchange",
            badge="Не создан",
            body_lines=[
                f"<b>Сотрудник:</b> <code>{html_text(username)}</code>",
                "Почтовый ящик Exchange отсутствует.",
            ],
            buttons=[
                button_row(callback_button("➕ Создать почту", f"exchange:mbx_user:{username}", "success")),
                button_row(callback_button("👤 В карточку сотрудника", f"user:show:{username}", "primary")),
            ],
        )
        await edit_rich(call.message, card)
        return

    hidden_gal = bool(res.get("hidden_from_gal", False))
    gal_status = "🙈 Скрыт" if hidden_gal else "👁 Виден"
    fwd = res.get("forwarding") or "—"
    body = [
        f"<b>Сотрудник:</b> <code>{html_text(username)}</code>",
        f"<b>Email:</b> <code>{html_text(res.get('primary_smtp', '—'))}</code>",
        f"<b>Размер:</b> <code>{html_text(res.get('total_size', '—'))}</code>",
        f"<b>Писем:</b> <code>{res.get('item_count', 0)}</code>",
        f"<b>База:</b> <code>{html_text(res.get('database', '—'))}</code>",
        f"<b>Статус в GAL:</b> {gal_status}",
        f"<b>Пересылка:</b> <code>{html_text(fwd)}</code>",
    ]

    gal_btn = (
        callback_button("👁 Показать в GAL", f"exchange:gal_show:{username}", "secondary")
        if hidden_gal
        else callback_button("🙈 Скрыть из GAL", f"exchange:gal_hide:{username}", "secondary")
    )
    fwd_row = [callback_button("↪️ Пересылка писем", f"exchange:fwd:{username}", "primary")]
    if res.get("forwarding"):
        fwd_row.append(callback_button("❌ Отключить пересылку", f"exchange:fwd_off:{username}", "danger"))

    buttons = [
        button_row(gal_btn, callback_button("🤝 Выдать FullAccess", f"exchange:delegate:{username}", "primary")),
        button_row(*fwd_row),
        button_row(callback_button("🗑 Удалить почту", f"exchange:del_ask:{username}", "danger")),
        button_row(callback_button("👤 В карточку сотрудника", f"user:show:{username}", "link")),
    ]
    card = render_bubble_card(
        title="📧 Почта Exchange",
        badge="Active Mailbox",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)


@infra_router.callback_query(F.data.startswith("exchange:gal_show:") | F.data.startswith("exchange:gal_hide:"))
async def cb_exchange_gal_toggle(call: CallbackQuery):
    action_key, _, username = call.data.partition(":")[2].partition(":")
    hidden = action_key == "gal_hide"
    await call.answer("⏳ Обновляю видимость в GAL...", show_alert=False)

    res = await set_mailbox_hidden_gal(username, hidden=hidden)
    ok = bool(res.get("ok"))
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="EXCHANGE_HIDE_GAL" if hidden else "EXCHANGE_SHOW_GAL",
        target=username,
        status="SUCCESS" if ok else "FAILED",
    )
    if not ok:
        card = render_bubble_card(
            title="❌ Ошибка GAL",
            badge="Exchange",
            body_lines=[f"Не удалось обновить GAL для <code>{html_text(username)}</code>:\n<code>{html_text(str(res.get('error', 'Ошибка')))}</code>"],
            buttons=[button_row(callback_button("⬅️ К ящику", f"exchange:menu:{username}", "primary"))],
        )
        await edit_rich(call.message, card)
        return

    await cb_exchange_user_menu(call)


@infra_router.callback_query(F.data.startswith("exchange:delegate:"))
async def cb_exchange_delegate_prompt(call: CallbackQuery, state: FSMContext):
    username = call.data.split(":", 2)[2].strip()
    await state.update_data(exchange_target_username=username)
    await state.set_state(ExchangeActionState.waiting_for_delegate_user)
    card = render_bubble_card(
        title="🤝 Выдача FullAccess",
        badge="Exchange",
        body_lines=[
            f"Ящик: <code>{html_text(username)}</code>",
            "Введите <b>логин (sAMAccountName)</b> делегата, которому нужно выдать права FullAccess (с AutoMapping):",
        ],
        buttons=[button_row(callback_button("❌ Отмена", f"exchange:menu:{username}", "link"))],
    )
    await edit_rich(call.message, card)
    await call.answer()


@infra_router.message(ExchangeActionState.waiting_for_delegate_user)
async def process_exchange_delegate_user(message: Message, state: FSMContext):
    data = await state.get_data()
    username = data.get("exchange_target_username", "")
    delegate_user = (message.text or "").strip()
    await state.clear()

    res = await grant_mailbox_full_access(username, delegate_user)
    ok = bool(res.get("ok"))
    await log_audit_action(
        admin_id=message.from_user.id,
        admin_username=message.from_user.username,
        action="EXCHANGE_GRANT_FULLACCESS",
        target=f"{username} -> {delegate_user}",
        status="SUCCESS" if ok else "FAILED",
    )
    if ok:
        title = "✅ Права FullAccess выданы"
        body = [f"Пользователю <code>{html_text(delegate_user)}</code> выданы права FullAccess на ящик <code>{html_text(username)}</code>."]
    else:
        title = "❌ Ошибка выдачи прав"
        body = [f"<code>{html_text(str(res.get('error', 'Ошибка')))}</code>"]

    card = render_bubble_card(
        title=title,
        badge="Exchange",
        body_lines=body,
        buttons=[button_row(callback_button("📧 К ящику", f"exchange:menu:{username}", "primary"))],
    )
    await send_rich(message, card)


@infra_router.callback_query(F.data.startswith("exchange:fwd:"))
async def cb_exchange_forward_prompt(call: CallbackQuery, state: FSMContext):
    username = call.data.split(":", 2)[2].strip()
    await state.update_data(exchange_target_username=username)
    await state.set_state(ExchangeActionState.waiting_for_forward_email)
    card = render_bubble_card(
        title="↪️ Пересылка писем",
        badge="Exchange",
        body_lines=[
            f"Ящик: <code>{html_text(username)}</code>",
            "Введите <b>Email-адрес</b>, на который нужно пересылать входящие письма (копия останется в ящике):",
        ],
        buttons=[
            button_row(callback_button("❌ Отключить пересылку", f"exchange:fwd_off:{username}", "danger")),
            button_row(callback_button("⬅️ Отмена", f"exchange:menu:{username}", "link")),
        ],
    )
    await edit_rich(call.message, card)
    await call.answer()


@infra_router.message(ExchangeActionState.waiting_for_forward_email)
async def process_exchange_forward_email(message: Message, state: FSMContext):
    data = await state.get_data()
    username = data.get("exchange_target_username", "")
    target_email = (message.text or "").strip()
    await state.clear()

    res = await set_mailbox_forwarding(username, target_email)
    ok = bool(res.get("ok"))
    await log_audit_action(
        admin_id=message.from_user.id,
        admin_username=message.from_user.username,
        action="EXCHANGE_SET_FORWARDING",
        target=f"{username} -> {target_email}",
        status="SUCCESS" if ok else "FAILED",
    )
    if ok:
        title = "✅ Пересылка настроена"
        body = [f"Письма для <code>{html_text(username)}</code> теперь пересылаются на <code>{html_text(target_email)}</code>."]
    else:
        title = "❌ Ошибка настройки пересылки"
        body = [f"<code>{html_text(str(res.get('error', 'Ошибка')))}</code>"]

    card = render_bubble_card(
        title=title,
        badge="Exchange",
        body_lines=body,
        buttons=[button_row(callback_button("📧 К ящику", f"exchange:menu:{username}", "primary"))],
    )
    await send_rich(message, card)


@infra_router.callback_query(F.data.startswith("exchange:fwd_off:"))
async def cb_exchange_forward_off(call: CallbackQuery, state: FSMContext):
    await state.clear()
    username = call.data.split(":", 2)[2].strip()
    await call.answer("⏳ Отключаю пересылку...", show_alert=False)

    res = await set_mailbox_forwarding(username, None)
    ok = bool(res.get("ok"))
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="EXCHANGE_DISABLE_FORWARDING",
        target=username,
        status="SUCCESS" if ok else "FAILED",
    )
    if not ok:
        card = render_bubble_card(
            title="❌ Ошибка отключения пересылки",
            badge="Exchange",
            body_lines=[f"<code>{html_text(str(res.get('error', 'Ошибка')))}</code>"],
            buttons=[button_row(callback_button("⬅️ К ящику", f"exchange:menu:{username}", "primary"))],
        )
        await edit_rich(call.message, card)
        return

    await cb_exchange_user_menu(call)


@infra_router.callback_query(F.data.startswith("exchange:mbx_user:"))
async def cb_exchange_create_user_mailbox(call: CallbackQuery):
    username = call.data.split(":", 2)[2].strip()
    await call.answer(f"📧 Создаю почтовый ящик для {username}...", show_alert=False)

    res = await enable_user_mailbox(identity=username)
    ok = bool(res.get("ok"))
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="EXCHANGE_ENABLE_MAILBOX",
        target=username,
        status="SUCCESS" if ok else "FAILED",
    )

    if ok:
        already = res.get("already_exists", False)
        title = "📧 Почтовый ящик уже существует" if already else "✅ Почтовый ящик создан"
        body = [
            f"<b>Сотрудник:</b> <code>{html_text(username)}</code>",
            f"<b>Email:</b> <code>{html_text(res.get('primary_smtp', '—'))}</code>",
            f"<b>База Exchange:</b> <code>{html_text(res.get('database', '—'))}</code>",
            f"<b>Alias:</b> <code>{html_text(res.get('alias', username))}</code>",
        ]
    else:
        title = "❌ Ошибка создания почты"
        body = [f"Не удалось создать ящик для <code>{html_text(username)}</code>:\n<code>{html_text(str(res.get('error', 'Ошибка')))}</code>"]

    card = render_bubble_card(
        title=title,
        badge="Exchange",
        body_lines=body,
        buttons=[
            button_row(callback_button("👤 В карточку сотрудника", f"user:show:{username}", "primary")),
            button_row(callback_button("⬅️ Главное меню", "menu:home", "link")),
        ],
    )
    await edit_rich(call.message, card)


@infra_router.callback_query(F.data.startswith("exchange:del_ask:"))
async def cb_exchange_delete_ask(call: CallbackQuery):
    username = call.data.split(":", 2)[2].strip()
    card = render_bubble_card(
        title="⚠️ Удаление почтового ящика",
        badge="Подтверждение",
        body_lines=[
            f"Вы уверены, что хотите удалить (отключить) почтовый ящик Exchange для <code>{html_text(username)}</code>?",
            "<i>Учетная запись в Active Directory при этом сохранится.</i>",
        ],
        buttons=[
            button_row(
                callback_button("🗑 Да, удалить почту", f"exchange:del_confirm:{username}", "danger"),
                callback_button("❌ Отмена", f"user:show:{username}", "link"),
            )
        ],
    )
    await edit_rich(call.message, card)
    await call.answer()


@infra_router.callback_query(F.data.startswith("exchange:del_confirm:"))
async def cb_exchange_delete_confirm(call: CallbackQuery):
    username = call.data.split(":", 2)[2].strip()
    await call.answer(f"🗑 Удаляю почтовый ящик {username}...", show_alert=False)

    res = await disable_user_mailbox(identity=username)
    ok = bool(res.get("ok"))
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="EXCHANGE_DISABLE_MAILBOX",
        target=username,
        status="SUCCESS" if ok else "FAILED",
    )

    if ok:
        title = "🗑 Почтовый ящик удален"
        body = [
            f"<b>Сотрудник:</b> <code>{html_text(username)}</code>",
            f"<b>Отключенный Email:</b> <code>{html_text(res.get('primary_smtp', '—'))}</code>",
        ]
    else:
        title = "❌ Ошибка удаления почты"
        body = [f"Не удалось удалить ящик для <code>{html_text(username)}</code>:\n<code>{html_text(str(res.get('error', 'Ошибка')))}</code>"]

    card = render_bubble_card(
        title=title,
        badge="Exchange",
        body_lines=body,
        buttons=[
            button_row(callback_button("👤 В карточку сотрудника", f"user:show:{username}", "primary")),
            button_row(callback_button("⬅️ Главное меню", "menu:home", "link")),
        ],
    )
    await edit_rich(call.message, card)


# ==========================================
# 4. Плейбуки и сценарии
# ==========================================

@infra_router.callback_query(F.data.in_(["menu:playbooks", "playbooks:menu"]))
async def cb_playbooks_menu(call: CallbackQuery):
    playbooks = get_playbooks_list()
    body = [
        "<b>Библиотека быстрых сценариев и плейбуков админа:</b>",
        "Выберите готовый сценарий для запуска на сервере управления/инфраструктуре.",
    ]
    buttons = []
    for pb in playbooks:
        sudo_tag = " [sudo]" if pb["sudo"] else ""
        buttons.append(button_row(
            callback_button(f"{pb['icon']} {pb['title']}{sudo_tag}", f"playbook:run:{pb['id']}", "primary")
        ))
    buttons.append(button_row(callback_button("⬅️ Главное меню", "menu:home", "link")))

    card = render_bubble_card(
        title="⚡️ Админ-плейбуки & Сценарии",
        badge="Playbooks",
        body_lines=body,
        buttons=buttons,
        footer_note="Команды выполняются безопасно с замером времени",
    )
    await edit_rich(call.message, card)
    await call.answer()


@infra_router.callback_query(F.data.startswith("playbook:run:"))
async def cb_playbook_run(call: CallbackQuery):
    pb_id = call.data.split(":")[2]
    await call.answer("⏳ Выполняю сценарий...", show_alert=False)

    res = await execute_playbook(pb_id)
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="EXEC_PLAYBOOK",
        target=pb_id,
        status="SUCCESS" if res["success"] else "FAILED",
        details=f"Duration: {res['execution_time_ms']}ms, ExitCode: {res['exit_code']}",
    )

    status_icon = "🟢" if res["success"] else "🔴"
    status_text = "Успешно" if res["success"] else f"Ошибка (код {res['exit_code']})"

    body = [
        f"{res['icon']} <b>Сценарий:</b> {html_text(res['title'])}",
        f"<b>Статус:</b> {status_icon} {status_text}",
        f"⏱ <b>Время выполнения:</b> <code>{res['execution_time_ms']} ms</code>",
        f"💻 <b>Команда:</b> <code>{html_text(res['command'])}</code>",
    ]

    raw_output = res["output"]
    if len(raw_output) > 2500:
        raw_output = raw_output[:2500] + "\n... [вывод обрезан]"

    formatted_output = f"<pre><code>{html_text(raw_output)}</code></pre>"

    buttons = [
        button_row(
            callback_button("🔄 Запустить повторно", f"playbook:run:{pb_id}", "primary"),
            callback_button("⚡️ Все сценарии", "menu:playbooks", "link"),
        ),
        button_row(
            callback_button("⬅️ Главное меню", "menu:home", "link")
        ),
    ]

    card = render_bubble_card(
        title=f"Результат сценария: {res['title']}",
        badge=f"{res['execution_time_ms']} ms",
        body_lines=body,
        details_title="📋 Полный терминальный вывод",
        details_content=formatted_output,
        buttons=buttons,
    )
    await edit_rich(call.message, card)


# ==========================================
# 5. Bash Терминал (/exec) и Docker
# ==========================================

@infra_router.message(Command("exec"))
async def cmd_exec_terminal(message: Message):
    """
    Выполнение команды Bash на сервере через /exec <команда>
    """
    full_text = message.text or ""
    parts = full_text.split(maxsplit=1)
    if len(parts) < 2 or not parts[1].strip():
        help_card = render_bubble_card(
            title="💻 Bash Терминал (/exec)",
            badge="SuperAdmin",
            body_lines=[
                "Быстрый безопасный терминал для выполнения команд на сервере управления Ubuntu.",
                "",
                "<b>Использование:</b>",
                "<code>/exec &lt;команда&gt;</code>",
                "",
                "<b>Примеры:</b>",
                "• <code>/exec uptime</code>",
                "• <code>/exec free -h</code>",
                "• <code>/exec docker ps</code>",
                "• <code>/exec systemctl status kolins-bot</code>",
                "",
                "<i>Команды выполняются с таймаутом 10 сек. Опасные команды (rm -rf /, форк-бомбы) блокируются ядром безопасности.</i>",
            ],
        )
        await send_rich(message, help_card)
        return

    command = parts[1].strip()
    status_msg = await send_rich(
        message,
        render_bubble_card(
            title="💻 Bash Terminal",
            badge="Выполняется...",
            body_lines=[f"⏳ Запуск команды: <code>{html_text(command)}</code>"],
        ),
    )

    result = await run_quick_command(command, timeout_sec=10)

    await log_audit_action(
        admin_id=message.from_user.id,
        admin_username=message.from_user.username,
        action="EXEC_BASH",
        target=command[:100],
        status="SUCCESS" if result["success"] else "FAILED",
        details=f"Duration: {result['duration_ms']}ms, ExitCode: {result['exit_code']}",
    )

    exit_code = result["exit_code"]
    status_badge = f"Exit: {exit_code} · {result['duration_ms']} ms"
    is_ok = result["success"]

    body = [
        f"💻 <b>Команда:</b> <code>{html_text(command)}</code>",
        f"<b>Статус:</b> {'🟢 Успешно' if is_ok else '🔴 Завершилось с ошибкой'}",
        f"⏱ <b>Время:</b> <code>{result['duration_ms']} ms</code>",
    ]

    if result.get("error") and not is_ok:
        body.append(f"⚠️ <b>Детали ошибки:</b> {html_text(result['error'])}")

    raw_output = result["output"]
    if len(raw_output) > 3000:
        raw_output = raw_output[:3000] + "\n... [вывод обрезан лимитом 3000 симв]"

    code_block = f"<pre><code>{html_text(raw_output)}</code></pre>"

    card = render_bubble_card(
        title="💻 Результат выполнения Bash",
        badge=status_badge,
        body_lines=body,
        details_title="📋 Терминальный вывод (stdout / stderr)",
        details_content=code_block,
    )
    await edit_rich(status_msg, card)


@infra_router.callback_query(F.data == "infra:docker")
async def cb_infra_docker(call: CallbackQuery):
    containers = await docker_service.list_containers()
    if not containers:
        body = ["🐳 Контейнеры Docker не найдены или Docker недоступен."]
        table = []
        buttons = []
    else:
        body = [f"Всего контейнеров: <b>{len(containers)}</b>"]
        table = []
        buttons = []
        for c in containers:
            name = c.get("name", "unknown")
            state = c.get("state", "unknown")
            status = c.get("status", "")
            icon = "🟢" if state == "running" else "🔴"
            table.append((f"{icon} {name}", status or state))
            buttons.append(
                button_row(
                    callback_button(f"🔄 {name}", f"docker:restart:{name}", "danger"),
                    callback_button(f"📄 Логи {name}", f"docker:logs:{name}", "primary"),
                )
            )

    buttons.append(button_row(callback_button("🔄 Обновить", "infra:docker", "primary")))
    buttons.append(button_row(callback_button("⬅️ Назад в Инфраструктуру", "menu:infra", "link")))

    card = render_bubble_card(
        title="🐳 Docker / RustDesk",
        badge="Containers",
        body_lines=body,
        table_rows=table,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()


@infra_router.callback_query(F.data.startswith("docker:restart:"))
async def cb_docker_restart(call: CallbackQuery):
    name = call.data.split("docker:restart:", 1)[1]
    await call.answer(f"🔄 Перезапускаю {name}...")
    ok = await docker_service.restart_container(name)
    await log_audit_action(
        admin_id=call.from_user.id,
        admin_username=call.from_user.username,
        action="DOCKER_RESTART",
        target=name,
        status="SUCCESS" if ok else "FAILED",
    )
    body = [
        f"✅ Контейнер <code>{html_text(name)}</code> перезапущен."
        if ok
        else f"❌ Не удалось перезапустить контейнер <code>{html_text(name)}</code>."
    ]
    buttons = [
        button_row(callback_button("⬅️ К контейнерам", "infra:docker", "link")),
    ]
    card = render_bubble_card(
        title="🐳 Перезапуск контейнера",
        badge=name,
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)


@infra_router.callback_query(F.data.startswith("docker:logs:"))
async def cb_docker_logs(call: CallbackQuery):
    name = call.data.split("docker:logs:", 1)[1]
    logs = await docker_service.get_container_logs(name, lines=30)
    logs_text = logs.strip() if logs else "Логи пусты."
    if len(logs_text) > 3000:
        logs_text = logs_text[-3000:]
    body = [f"<pre>{html_text(logs_text)}</pre>"]
    buttons = [
        button_row(
            callback_button("🔄 Обновить логи", f"docker:logs:{name}", "primary"),
            callback_button("⬅️ К контейнерам", "infra:docker", "link"),
        )
    ]
    card = render_bubble_card(
        title=f"📄 Логи {name}",
        badge="last 30 lines",
        body_lines=body,
        buttons=buttons,
    )
    await edit_rich(call.message, card)
    await call.answer()

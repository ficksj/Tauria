import asyncio
import inspect
from datetime import datetime, timedelta

from config import settings
from services import db_service, infra_service
from services.ad_service import ad_service
from services.logger_service import log
from services.rich_message_service import (
    button_row,
    callback_button,
    render_bubble_card,
    send_rich_to_chat,
)


async def build_briefing_card(buttons: list[str] | None = None) -> str:
    """
    Собирает утреннюю сводку (метрики Ubuntu, статусы служб, активные JIT-гранты,
    истекающие пароли AD, статус Exchange 443/25) и оформляет её в Bubble-карточку.
    """
    exch_host = settings.EXCHANGE_SERVER or "192.168.254.23"

    metrics, services, jit_grants, exch_443, exch_25 = await asyncio.gather(
        infra_service.get_system_metrics(),
        infra_service.get_all_services_status(),
        db_service.get_active_jit_grants(),
        infra_service.check_tcp_port_rtt(exch_host, 443, timeout_sec=2.0),
        infra_service.check_tcp_port_rtt(exch_host, 25, timeout_sec=2.0),
    )

    expiring_count_str = "н/д"
    try:
        res = ad_service.get_expiring_password_users(days=7)
        if inspect.isawaitable(res):
            res = await res
        if isinstance(res, dict):
            users_list = res.get("users", [])
            expiring_count_str = str(len(users_list))
        elif isinstance(res, int):
            expiring_count_str = str(res)
        elif res is not None:
            expiring_count_str = str(len(res))
        else:
            expiring_count_str = "0"
    except Exception as e:
        log.warning(f"Failed to fetch expiring password users: {e}")

    ram = metrics.get("ram", {})
    disk = metrics.get("disk", {})
    mem_percent = ram.get("percent", 0)
    mem_used = ram.get("used_gb", 0)
    mem_total = ram.get("total_gb", 0)
    disk_percent = disk.get("percent", 0)
    disk_used = disk.get("used_gb", 0)
    disk_total = disk.get("total_gb", 0)
    uptime = metrics.get("uptime", "—")
    load = metrics.get("load_avg", "—")

    active_services = sum(1 for s in services if s.get("active"))
    total_services = len(services)
    services_lines = [
        f"{'🟢' if s.get('active') else '🔴'} <code>{s.get('service') or s.get('label') or 'unknown'}</code>: {s.get('status', 'unknown')}"
        for s in services
    ]

    https_ok = bool(exch_443.get("open"))
    smtp_ok = bool(exch_25.get("open"))
    exch_summary = (
        f"443: {'🟢' if https_ok else '🔴'} ({exch_443.get('rtt_ms', 0)}ms) | "
        f"25: {'🟢' if smtp_ok else '🔴'} ({exch_25.get('rtt_ms', 0)}ms)"
    )

    now_str = datetime.now().strftime("%d.%m.%Y %H:%M")

    body_lines = [
        f"🖥️ <b>RAM:</b> {mem_percent}% ({mem_used}/{mem_total} GB)",
        f"💾 <b>Disk:</b> {disk_percent}% ({disk_used}/{disk_total} GB)",
        f"⏱️ <b>Uptime:</b> {uptime} | <b>Load:</b> {load}",
        f"📧 <b>Exchange ({exch_host}):</b> {exch_summary}",
    ]

    table_rows = [
        ("Службы", f"{active_services}/{total_services} активны"),
        ("Exchange (443 / 25)", f"{'🟢' if https_ok else '🔴'} HTTPS / {'🟢' if smtp_ok else '🔴'} SMTP"),
        ("Активные JIT-гранты", str(len(jit_grants))),
        ("Истекающие пароли (7 дн.)", expiring_count_str),
    ]

    card_buttons = buttons if buttons is not None else [
        button_row(
            callback_button("📧 Exchange Server", "infra:exchange", "primary"),
            callback_button("🖥 Инфраструктура", "menu:infra", "link"),
        )
    ]

    return render_bubble_card(
        title="☀️ Утренний брифинг Tauria",
        badge=now_str,
        body_lines=body_lines,
        table_rows=table_rows,
        details_title="Статусы служб",
        details_content="<br>".join(services_lines) if services_lines else "Нет данных",
        footer_note="Ежедневная автоматическая сводка инфраструктуры",
        buttons=card_buttons,
    )


async def start_briefing_worker(bot):
    """
    Фоновый цикл, который каждый день в 09:00 по локальному времени
    отправляет утренний брифинг всем settings.super_admins.
    """
    log.info("Briefing worker started (daily at 09:00 local time).")
    while True:
        try:
            now = datetime.now()
            target = now.replace(hour=9, minute=0, second=0, microsecond=0)
            if now >= target:
                target += timedelta(days=1)

            wait_seconds = (target - now).total_seconds()
            await asyncio.sleep(wait_seconds)

            card_html = await build_briefing_card()
            for admin_id in settings.super_admins:
                try:
                    await send_rich_to_chat(bot, admin_id, card_html)
                except Exception as e:
                    log.error(f"Failed to send briefing to {admin_id}: {e}")
        except asyncio.CancelledError:
            log.info("Briefing worker cancelled.")
            break
        except Exception as e:
            log.error(f"Briefing worker error: {e}")
            await asyncio.sleep(60)

import asyncio
import os
import shutil
from typing import Dict

from config import settings
from services.docker_service import list_containers
from services.logger_service import get_logger

DOCKER_WATCH_CONTAINERS = ("rustdesk-api", "rustdesk-hbbs", "rustdesk-hbbr")

logger = get_logger("HealthWatcher")


async def _check_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _check_systemd_service(service_name: str) -> bool:
    if os.name == "nt":
        return True
    try:
        proc = await asyncio.create_subprocess_exec(
            "systemctl",
            "is-active",
            "--quiet",
            service_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=5.0)
        return proc.returncode == 0
    except Exception:
        return False


def _check_root_disk_ok(min_free_ratio: float = 0.10) -> tuple[bool, float]:
    try:
        usage = shutil.disk_usage("/")
        free_ratio = usage.free / usage.total if usage.total > 0 else 1.0
        return free_ratio >= min_free_ratio, round(free_ratio * 100, 1)
    except Exception:
        return True, 100.0


async def _notify_all(bot, text: str) -> None:
    recipients: set[int] = set(settings.super_admins)
    if settings.LOG_CHAT_ID:
        recipients.add(int(settings.LOG_CHAT_ID))

    for chat_id in recipients:
        try:
            await bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML")
        except Exception as e:
            logger.warning(f"Failed to send health alert to {chat_id}: {e}")


async def start_health_watcher(bot, interval_sec: int = 60) -> None:
    """
    Фоновый воркер мониторинга критичной инфраструктуры:
    - 192.168.201.15:389 (LDAP)
    - kolins-bot (systemd)
    - kolins-webapp (systemd)
    - Свободное место на / (>= 10%)
    Отправляет уведомление только при изменении состояния.
    """
    logger.info(f"HealthWatcher started (interval={interval_sec}s)")
    prev_states: Dict[str, bool] = {}

    while True:
        try:
            ldap_ok = await _check_tcp(settings.AD_SERVER or "192.168.201.15", 389)
            kolins_bot_ok = await _check_systemd_service("kolins-bot")
            kolins_web_ok = await _check_systemd_service("kolins-webapp")
            disk_ok, free_pct = await asyncio.to_thread(_check_root_disk_ok, 0.10)

            containers = await list_containers() if os.name != "nt" else []
            container_states = {
                c["name"]: c["state"].lower() == "running"
                for c in containers
            }

            current_states = {
                "ldap": ldap_ok,
                "kolins-bot": kolins_bot_ok,
                "kolins-webapp": kolins_web_ok,
                "disk_root": disk_ok,
            }

            labels = {
                "ldap": f"LDAP ({settings.AD_SERVER or '192.168.201.15'}:389)",
                "kolins-bot": "Служба kolins-bot",
                "kolins-webapp": "Служба kolins-webapp",
                "disk_root": f"Диск / (свободно {free_pct}%)",
            }

            if containers:
                for cname in DOCKER_WATCH_CONTAINERS:
                    key = f"docker:{cname}"
                    current_states[key] = container_states.get(cname, False)
                    labels[key] = f"Docker {cname}"

            if not prev_states:
                prev_states = current_states.copy()
            else:
                for key, is_ok in current_states.items():
                    was_ok = prev_states.get(key, True)
                    if is_ok != was_ok:
                        if not is_ok:
                            msg = (
                                f"🚨 <b>АВАРИЯ ИНФРАСТРУКТУРЫ</b>\n"
                                f"Компонент: <code>{labels[key]}</code>\n"
                                f"Статус: <b>НЕДОСТУПЕН / КРИТИЧНО</b>"
                            )
                        else:
                            msg = (
                                f"✅ <b>ВОССТАНОВЛЕНИЕ</b>\n"
                                f"Компонент: <code>{labels[key]}</code>\n"
                                f"Статус: <b>В НОРМЕ</b>"
                            )
                        await _notify_all(bot, msg)
                        prev_states[key] = is_ok

        except asyncio.CancelledError:
            logger.info("HealthWatcher stopped")
            raise
        except Exception as e:
            logger.error(f"HealthWatcher loop error: {e}")

        await asyncio.sleep(interval_sec)

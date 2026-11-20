import asyncio
import os
import re
import shutil
import subprocess
import time
from typing import Dict, Any, List, Optional
from services.logger_service import log
from services.rich_message_service import render_progress_bar

_RE_DNS_NAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$")
_RE_DNS_ZONE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_RE_DNS_CNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")

# Список контролируемых системных служб
MANAGED_SERVICES = [
    "kolins-bot",
    "kolins-webapp",
    "kolins-tunnel",
    "tauria-bot",
]

SERVICE_LABELS = {
    "kolins-bot": "Kolins Support Bot",
    "kolins-webapp": "Kolins WebApp",
    "kolins-tunnel": "Kolins Tunnel (Nurl)",
    "tauria-bot": "Tauria SuperAdmin Bot",
}

async def check_ping(host: str, count: int = 2, timeout_sec: int = 2) -> Dict[str, Any]:
    """Асинхронный ICMP ping (работает и на Linux, и на Windows)"""
    clean_host = (host or "").strip()
    if not clean_host or clean_host.startswith(("-", "/")):
        return {"alive": False, "host": host, "output": "Некорректное имя хоста"}
    is_windows = os.name == 'nt'
    cmd = ["ping", "-n" if is_windows else "-c", str(count), "-w" if is_windows else "-W", str(timeout_sec * 1000 if is_windows else timeout_sec), clean_host]
    
    def _run():
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            return res.returncode == 0, res.stdout
        except subprocess.TimeoutExpired:
            return False, "Ping timeout (10s)"

    loop = asyncio.get_running_loop()
    alive, output = await loop.run_in_executor(None, _run)
    return {"alive": alive, "host": clean_host, "output": output}

async def check_tcp_port(host: str, port: int, timeout_sec: float = 2.5) -> bool:
    """Асинхронная проверка доступности TCP порта (True/False)"""
    res = await check_tcp_port_rtt(host, port, timeout_sec)
    return res["open"]

async def check_tcp_port_rtt(host: str, port: int, timeout_sec: float = 2.5) -> Dict[str, Any]:
    """
    Расширенная асинхронная проверка доступности TCP порта с замером времени отклика (RTT ms).
    Возвращает: {"host": host, "port": port, "open": bool, "rtt_ms": float, "error": str | None}
    """
    start_time = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_sec
        )
        rtt_ms = round((time.perf_counter() - start_time) * 1000, 2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "host": host,
            "port": port,
            "open": True,
            "rtt_ms": rtt_ms,
            "error": None
        }
    except asyncio.TimeoutError:
        rtt_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "host": host,
            "port": port,
            "open": False,
            "rtt_ms": rtt_ms,
            "error": "Timeout"
        }
    except Exception as e:
        rtt_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "host": host,
            "port": port,
            "open": False,
            "rtt_ms": rtt_ms,
            "error": str(e)
        }

async def get_system_metrics() -> Dict[str, Any]:
    """Получение метрик локального сервера (CPU, RAM, Disk, Uptime)"""
    def _metrics():
        # RAM
        mem_total, mem_used, mem_free = 0, 0, 0
        mem_percent = 0.0
        try:
            if os.path.exists("/proc/meminfo"):
                meminfo = {}
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            meminfo[parts[0].strip()] = int(parts[1].split()[0]) # in kB
                total_kb = meminfo.get("MemTotal", 1)
                avail_kb = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
                used_kb = total_kb - avail_kb
                mem_total = round(total_kb / 1024 / 1024, 2)
                mem_used = round(used_kb / 1024 / 1024, 2)
                mem_percent = round((used_kb / total_kb) * 100, 1)
        except Exception as e:
            log.warning(f"Failed to read /proc/meminfo: {e}")

        # Disks
        try:
            disk_path = "/" if os.name != 'nt' else "C:\\"
            disk_usage = shutil.disk_usage(disk_path)
            disk_total_gb = round(disk_usage.total / (1024**3), 1)
            disk_used_gb = round(disk_usage.used / (1024**3), 1)
            disk_free_gb = round(disk_usage.free / (1024**3), 1)
            disk_percent = round((disk_usage.used / disk_usage.total) * 100, 1)
        except Exception as e:
            log.warning(f"Failed to check disk usage: {e}")
            disk_total_gb, disk_used_gb, disk_free_gb, disk_percent = 0, 0, 0, 0.0

        # Uptime & Load
        uptime_str = "—"
        load_str = "—"
        try:
            if os.path.exists("/proc/uptime"):
                with open("/proc/uptime", "r") as f:
                    uptime_seconds = float(f.readline().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                mins = int((uptime_seconds % 3600) // 60)
                uptime_str = f"{days}d {hours}h {mins}m"
            if hasattr(os, "getloadavg"):
                load_avg = os.getloadavg()
                load_str = f"{load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}"
        except Exception:
            pass

        return {
            "ram": {
                "used_gb": mem_used,
                "total_gb": mem_total,
                "percent": mem_percent,
                "bar": render_progress_bar(mem_percent)
            },
            "disk": {
                "used_gb": disk_used_gb,
                "total_gb": disk_total_gb,
                "free_gb": disk_free_gb,
                "percent": disk_percent,
                "bar": render_progress_bar(disk_percent)
            },
            "uptime": uptime_str,
            "load_avg": load_str
        }

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _metrics)

async def get_service_status(service_name: str) -> Dict[str, Any]:
    """Проверка статуса systemd сервиса на сервере"""
    cmd = ["systemctl", "is-active", service_name]
    def _check():
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            status = res.stdout.strip() or res.stderr.strip() or "unknown"
            return {
                "service": service_name,
                "label": SERVICE_LABELS.get(service_name, service_name),
                "active": status == "active",
                "status": status
            }
        except Exception as e:
            return {
                "service": service_name,
                "label": SERVICE_LABELS.get(service_name, service_name),
                "active": False,
                "status": f"error: {e}"
            }
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _check)

async def get_all_services_status(service_list: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Пакетное получение статуса для списка сервисов (kolins-bot, kolins-webapp, kolins-tunnel, tauria-bot)"""
    services = service_list or MANAGED_SERVICES
    tasks = [get_service_status(srv) for srv in services]
    return await asyncio.gather(*tasks)

async def restart_service(service_name: str) -> bool:
    """Перезапуск systemd сервиса (требует sudo)"""
    if service_name not in MANAGED_SERVICES:
        log.warning(f"Rejected restart_service for unmanaged service: {service_name!r}")
        return False
    cmd = ["sudo", "systemctl", "restart", "--", service_name]
    def _restart():
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            return res.returncode == 0
        except Exception as e:
            log.error(f"Error restarting service {service_name}: {e}")
            return False
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _restart)

async def get_service_logs(service_name: str, lines: int = 50) -> Dict[str, Any]:
    """
    Получение последних логов systemd сервиса через journalctl -u <service> -n <lines> --no-pager
    """
    if service_name not in MANAGED_SERVICES:
        log.warning(f"Rejected get_service_logs for unmanaged service: {service_name!r}")
        return {
            "service": service_name,
            "success": False,
            "lines_count": 0,
            "logs": f"Служба '{service_name}' не входит в список управляемых служб."
        }
    safe_lines = max(1, min(int(lines), 500))
    cmd = ["journalctl", "-u", service_name, "-n", str(safe_lines), "--no-pager"]
    def _get_logs():
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            output = res.stdout if res.returncode == 0 else (res.stderr or res.stdout)
            return {
                "service": service_name,
                "success": res.returncode == 0,
                "lines_count": len(output.splitlines()),
                "logs": output
            }
        except Exception as e:
            log.error(f"Error reading journalctl for {service_name}: {e}")
            return {
                "service": service_name,
                "success": False,
                "lines_count": 0,
                "logs": f"Ошибка чтения логов: {e}"
            }
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _get_logs)


async def add_dns_record(
    name: str,
    value: str,
    record_type: str = "A",
    zone: str | None = None,
) -> Dict[str, Any]:
    """Создает A или CNAME запись в DNS-зоне Active Directory через WinRM (pypsrp)."""
    import ipaddress
    from config import settings

    clean_name = (name or "").strip().rstrip(".")
    clean_val = (value or "").strip()
    rtype = (record_type or "A").strip().upper()
    target_zone = (zone or settings.AD_DOMAIN or "kdb.kz").strip().rstrip(".")

    if not clean_name or len(clean_name) > 253 or not _RE_DNS_NAME.fullmatch(clean_name):
        return {"ok": False, "error": "Некорректное имя DNS-записи."}
    if not target_zone or len(target_zone) > 253 or not _RE_DNS_ZONE.fullmatch(target_zone):
        return {"ok": False, "error": f"Некорректная DNS-зона: {target_zone}"}

    if rtype == "A":
        try:
            ipaddress.IPv4Address(clean_val)
        except Exception:
            return {"ok": False, "error": f"Некорректный IPv4-адрес: {clean_val}"}
        ps_cmd = (
            f"$ErrorActionPreference='Stop'; "
            f"try {{ Add-DnsServerResourceRecordA -Name '{clean_name}' -ZoneName '{target_zone}' -IPv4Address '{clean_val}' -AllowUpdateAny -CreatePtr -ErrorAction Stop }} "
            f"catch {{ Add-DnsServerResourceRecordA -Name '{clean_name}' -ZoneName '{target_zone}' -IPv4Address '{clean_val}' -AllowUpdateAny -ErrorAction Stop }}; "
            f"Write-Output '__DNS_OK__'"
        )
    elif rtype == "CNAME":
        if not clean_val or len(clean_val) > 253 or not _RE_DNS_CNAME.fullmatch(clean_val):
            return {"ok": False, "error": f"Некорректное значение CNAME-записи: {clean_val}"}
        ps_cmd = (
            f"$ErrorActionPreference='Stop'; "
            f"Add-DnsServerResourceRecordCName -Name '{clean_name}' -ZoneName '{target_zone}' -HostNameAlias '{clean_val}' -ErrorAction Stop; "
            f"Write-Output '__DNS_OK__'"
        )
    else:
        return {"ok": False, "error": f"Неподдерживаемый тип записи: {rtype} (поддерживаются A и CNAME)."}

    def _run_dns():
        try:
            from pypsrp.client import Client as WinRMClient
        except ImportError:
            return {"ok": False, "error": "Пакет pypsrp не установлен на сервере."}

        host = (settings.AD_SERVER or "192.168.201.15").strip()
        user = (settings.AD_USER or "").strip()
        password = settings.AD_PASSWORD or ""
        if not user or not password:
            return {"ok": False, "error": "AD_USER / AD_PASSWORD не заданы в .env"}

        try:
            client = WinRMClient(
                host,
                username=user,
                password=password,
                ssl=False,
                auth="negotiate",
                encryption="auto",
                connection_timeout=6,
                read_timeout=20,
            )
            stdout, streams, had_errors = client.execute_ps(ps_cmd)
            if "__DNS_OK__" not in (stdout or ""):
                err_msgs = [str(e) for e in (streams.error or [])] if streams else []
                err_text = "; ".join(err_msgs)[:300] or "Ошибка PowerShell DNS"
                return {"ok": False, "error": err_text}
            return {
                "ok": True,
                "fqdn": f"{clean_name}.{target_zone}",
                "type": rtype,
                "value": clean_val,
                "zone": target_zone,
            }
        except Exception as e:
            log.error(f"DNS add error on {host}: {e}")
            return {"ok": False, "error": str(e)}

    return await asyncio.to_thread(_run_dns)

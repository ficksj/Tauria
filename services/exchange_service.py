import asyncio
import json
import platform
import subprocess
from typing import Any, Dict

try:
    from pypsrp.client import Client as WinRMClient
    from pypsrp.exceptions import AuthenticationError, WinRMError
except ImportError:
    WinRMClient = None

    class AuthenticationError(Exception):
        pass

    class WinRMError(Exception):
        pass

from config import settings
from services.logger_service import get_logger

logger = get_logger("ExchangeService")


def _run_exchange_ps_sync(ps_script: str, timeout: int = 25) -> Dict[str, Any]:
    """
    Выполняет PowerShell-скрипт на сервере Exchange (settings.EXCHANGE_SERVER)
    через pypsrp WinRMClient с учетной записью settings.AD_USER / settings.AD_PASSWORD.
    """
    host = (settings.EXCHANGE_SERVER or "192.168.254.23").strip()
    user = settings.exchange_user or settings.AD_USER or settings.pc_admin_user
    password = settings.exchange_password or settings.AD_PASSWORD or settings.pc_admin_password

    if WinRMClient is None:
        return {"ok": False, "error": "Пакет pypsrp не установлен", "stdout": ""}

    if not user or not password:
        return {"ok": False, "error": "Учетные данные EXCHANGE_USER / AD_USER не заданы в .env", "stdout": ""}

    try:
        client = WinRMClient(
            host,
            username=user,
            password=password,
            ssl=False,
            auth="negotiate",
            encryption="auto",
            connection_timeout=6,
            read_timeout=timeout,
        )
        stdout, streams, had_errors = client.execute_ps(ps_script)
        out_clean = (stdout or "").strip()
        if had_errors and not out_clean:
            err_msgs = []
            if streams and hasattr(streams, "error") and streams.error:
                err_msgs = [str(e) for e in streams.error]
            err_text = "; ".join(err_msgs)[:300] or "PowerShell execution error"
            return {"ok": False, "error": err_text, "stdout": ""}
        return {"ok": True, "error": None, "stdout": out_clean}
    except AuthenticationError as e:
        logger.warning(f"Exchange WinRM authentication error on {host}: {e}")
        return {"ok": False, "error": f"Ошибка авторизации WinRM ({user}): {e}", "stdout": ""}
    except (WinRMError, TimeoutError, ConnectionError, OSError) as e:
        logger.warning(f"Exchange WinRM connection error on {host}: {e}")
        return {"ok": False, "error": f"Сервер Exchange ({host}) недоступен по WinRM: {e}", "stdout": ""}
    except Exception as e:
        logger.error(f"Unexpected Exchange WinRM error on {host}: {e}")
        return {"ok": False, "error": str(e), "stdout": ""}


def _ensure_list(val: Any) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, dict):
        return [val]
    return []


async def get_exchange_overview() -> Dict[str, Any]:
    """
    Проверяет состояние сервера Microsoft Exchange:
    1) Ключевые службы (MSExchangeTransport, MSExchangeIS, MSExchangeFrontEndTransport, MSExchangeHM, W3SVC)
    2) Очереди писем (Get-Queue через Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn)
    3) Статус баз данных (Get-MailboxDatabase -Status)
    4) Логические диски (Get-CimInstance Win32_LogicalDisk)
    5) Сертификаты Exchange (Get-ExchangeCertificate)
    """
    ps_script = r"""
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
    } catch {}

    $svcNames = @('MSExchangeTransport', 'MSExchangeIS', 'MSExchangeFrontEndTransport', 'MSExchangeHM', 'W3SVC')
    $services = @()
    foreach ($name in $svcNames) {
        $s = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($s) {
            $services += @{
                name = [string]$s.Name
                display_name = [string]$s.DisplayName
                status = [string]$s.Status
                running = ($s.Status -eq 'Running')
            }
        } else {
            $services += @{
                name = $name
                display_name = $name
                status = 'NotFound'
                running = $false
            }
        }
    }

    $queues = @()
    try {
        $qRaw = @(Get-Queue -ErrorAction Stop)
        foreach ($q in $qRaw) {
            $queues += @{
                identity = [string]$q.Identity
                delivery_type = [string]$q.DeliveryType
                status = [string]$q.Status
                message_count = [int]$q.MessageCount
                next_hop = [string]$q.NextHopDomain
                last_error = [string]$q.LastError
            }
        }
    } catch {}

    $databases = @()
    try {
        $dbRaw = @(Get-MailboxDatabase -Status -ErrorAction Stop)
        foreach ($db in $dbRaw) {
            $lastFull = if ($db.LastFullBackup) { Get-Date $db.LastFullBackup -Format 'dd.MM.yyyy HH:mm' } else { '—' }
            $databases += @{
                name = [string]$db.Name
                server = [string]$db.Server
                mounted = [bool]$db.Mounted
                size = [string]$db.DatabaseSize
                last_full_backup = $lastFull
            }
        }
    } catch {}

    $disks = @()
    try {
        $dRaw = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)
        foreach ($d in $dRaw) {
            if ($d.Size -gt 0) {
                $sizeGb = [math]::Round($d.Size / 1GB, 1)
                $freeGb = [math]::Round($d.FreeSpace / 1GB, 1)
                $freePct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
                $disks += @{
                    device = [string]$d.DeviceID
                    size_gb = $sizeGb
                    free_gb = $freeGb
                    free_pct = $freePct
                }
            }
        }
    } catch {}

    $certs = @()
    try {
        $cRaw = @(Get-ExchangeCertificate -ErrorAction Stop)
        foreach ($c in $cRaw) {
            $notAfterStr = if ($c.NotAfter) { Get-Date $c.NotAfter -Format 'dd.MM.yyyy' } else { '—' }
            $daysLeft = if ($c.NotAfter) { [int](($c.NotAfter - (Get-Date)).TotalDays) } else { 999 }
            $certs += @{
                subject = [string]$c.Subject
                thumbprint = [string]$c.Thumbprint
                status = [string]$c.Status
                services = [string]$c.Services
                not_after = $notAfterStr
                days_left = $daysLeft
            }
        }
    } catch {}

    @{
        services = $services
        queues = $queues
        databases = $databases
        disks = $disks
        certificates = $certs
    } | ConvertTo-Json -Compress -Depth 4
    """

    res = await asyncio.to_thread(_run_exchange_ps_sync, ps_script, 25)
    if not res.get("ok"):
        return {
            "ok": False,
            "host": settings.EXCHANGE_SERVER,
            "error": res.get("error") or "Не удалось получить данные с Exchange",
        }

    stdout = res.get("stdout", "")
    try:
        data = json.loads(stdout)
        return {
            "ok": True,
            "host": settings.EXCHANGE_SERVER,
            "services": _ensure_list(data.get("services")),
            "queues": _ensure_list(data.get("queues")),
            "databases": _ensure_list(data.get("databases")),
            "disks": _ensure_list(data.get("disks")),
            "certificates": _ensure_list(data.get("certificates")),
        }
    except Exception as e:
        logger.error(f"Failed to parse Exchange overview JSON: {e} | raw={stdout[:300]}")
        return {
            "ok": False,
            "host": settings.EXCHANGE_SERVER,
            "error": f"Ошибка разбора ответа Exchange: {e}",
        }


async def get_exchange_mailflow_errors(hours: int = 2) -> Dict[str, Any]:
    """
    Ищет ошибки прохождения почты в Get-MessageTrackingLog за последние N часов
    с серверной фильтрацией по -EventId FAIL,DEFER,BADMAIL,POISONMESSAGE.
    """
    safe_hours = max(1, min(int(hours), 72))
    ps_script = f"""
    $ErrorActionPreference = 'SilentlyContinue'
    try {{
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
    }} catch {{}}

    $since = (Get-Date).AddHours(-{safe_hours})
    $targetEvents = @('FAIL', 'DEFER', 'BADMAIL', 'POISONMESSAGE')
    $allEvents = @()

    foreach ($evId in $targetEvents) {{
        try {{
            $items = @(Get-MessageTrackingLog -Start $since -EventId $evId -ResultSize 50 -ErrorAction SilentlyContinue)
            if ($items) {{
                $allEvents += $items
            }}
        }} catch {{}}
    }}

    $sorted = @($allEvents | Sort-Object Timestamp -Descending | Select-Object -First 40)
    $result = @()
    foreach ($e in $sorted) {{
        $ts = if ($e.Timestamp) {{ Get-Date $e.Timestamp -Format 'dd.MM HH:mm:ss' }} else {{ '—' }}
        $rcpts = if ($e.Recipients) {{ ($e.Recipients -join ', ') }} else {{ '—' }}
        $result += @{{
            timestamp = $ts
            event_id = [string]$e.EventId
            source = [string]$e.Source
            sender = [string]$e.Sender
            recipients = [string]$rcpts
            subject = [string]$e.MessageSubject
            status = [string]$e.RecipientStatus
        }}
    }}

    @{{
        hours = {safe_hours}
        total_found = $allEvents.Count
        events = $result
    }} | ConvertTo-Json -Compress -Depth 4
    """

    res = await asyncio.to_thread(_run_exchange_ps_sync, ps_script, 25)
    if not res.get("ok"):
        return {
            "ok": False,
            "host": settings.EXCHANGE_SERVER,
            "hours": safe_hours,
            "error": res.get("error") or "Не удалось запросить MessageTrackingLog",
            "events": [],
        }

    stdout = res.get("stdout", "")
    try:
        data = json.loads(stdout)
        return {
            "ok": True,
            "host": settings.EXCHANGE_SERVER,
            "hours": data.get("hours", safe_hours),
            "total_found": int(data.get("total_found", 0)),
            "events": _ensure_list(data.get("events")),
        }
    except Exception as e:
        logger.error(f"Failed to parse Exchange mailflow JSON: {e}")
        return {
            "ok": False,
            "host": settings.EXCHANGE_SERVER,
            "hours": safe_hours,
            "error": f"Ошибка разбора MessageTrackingLog: {e}",
            "events": [],
        }


async def get_exchange_forwarding_audit() -> Dict[str, Any]:
    """
    Аудит безопасности почтовых пересылок Exchange (GTS / KZ-CERT):
    1) Ящики с настроенным ForwardingSmtpAddress / ForwardingAddress
    2) Транспортные правила (Get-TransportRule) с пересылкой / скрытой копией (BlindCopyTo / RedirectMessageTo / AddToRecipients)
    3) Правила журналирования (Get-JournalRule)
    """
    ps_script = r"""
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
    } catch {}

    $mbForwards = @()
    try {
        $mbs = @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop |
            Where-Object { $_.ForwardingAddress -ne $null -or $_.ForwardingSmtpAddress -ne $null })
        foreach ($m in $mbs) {
            $mbForwards += @{
                display_name = [string]$m.DisplayName
                primary_smtp = [string]$m.PrimarySmtpAddress
                forwarding_address = [string]$m.ForwardingAddress
                forwarding_smtp = [string]$m.ForwardingSmtpAddress
                keep_copy = [bool]$m.DeliverToMailboxAndForward
            }
        }
    } catch {}

    $transportRules = @()
    try {
        $trRaw = @(Get-TransportRule -ErrorAction Stop | Where-Object {
            $_.BlindCopyTo -ne $null -or $_.RedirectMessageTo -ne $null -or $_.AddToRecipients -ne $null -or $_.CopyTo -ne $null
        })
        foreach ($r in $trRaw) {
            $targets = @()
            if ($r.BlindCopyTo) { $targets += "BCC: " + ($r.BlindCopyTo -join ';') }
            if ($r.RedirectMessageTo) { $targets += "Redirect: " + ($r.RedirectMessageTo -join ';') }
            if ($r.AddToRecipients) { $targets += "AddRcpt: " + ($r.AddToRecipients -join ';') }
            if ($r.CopyTo) { $targets += "CC: " + ($r.CopyTo -join ';') }
            $transportRules += @{
                name = [string]$r.Name
                state = [string]$r.State
                targets = ($targets -join ' | ')
            }
        }
    } catch {}

    $journalRules = @()
    try {
        $jrRaw = @(Get-JournalRule -ErrorAction Stop)
        foreach ($j in $jrRaw) {
            $journalRules += @{
                name = [string]$j.Name
                email = [string]$j.JournalEmailAddress
                scope = [string]$j.Scope
                enabled = [bool]$j.Enabled
            }
        }
    } catch {}

    @{
        mailbox_forwards = $mbForwards
        transport_rules = $transportRules
        journal_rules = $journalRules
    } | ConvertTo-Json -Compress -Depth 4
    """

    res = await asyncio.to_thread(_run_exchange_ps_sync, ps_script, 30)
    if not res.get("ok"):
        return {
            "ok": False,
            "host": settings.EXCHANGE_SERVER,
            "error": res.get("error") or "Не удалось выполнить аудит пересылок Exchange",
        }

    stdout = res.get("stdout", "")
    try:
        data = json.loads(stdout)
        return {
            "ok": True,
            "host": settings.EXCHANGE_SERVER,
            "mailbox_forwards": _ensure_list(data.get("mailbox_forwards")),
            "transport_rules": _ensure_list(data.get("transport_rules")),
            "journal_rules": _ensure_list(data.get("journal_rules")),
        }
    except Exception as e:
        logger.error(f"Failed to parse Exchange forwarding audit JSON: {e}")
        return {
            "ok": False,
            "host": settings.EXCHANGE_SERVER,
            "error": f"Ошибка разбора аудита пересылок: {e}",
        }


async def _run_exchange_task_ps(inner_ps: str, timeout: int = 35) -> Dict[str, Any]:
    """Запускает PowerShell-блок на сервере Exchange через одноразовый ScheduledTask (обход NTLM double-hop)."""
    ex_user = (settings.exchange_user or settings.AD_USER or "").strip()
    ex_pass = (settings.exchange_password or settings.AD_PASSWORD or "").replace("'", "''")
    ps_script = f"""
    $ErrorActionPreference = 'Stop'
    $uid = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $psPath = "$env:TEMP\\ex_task_$uid.ps1"
    $outPath = "$env:TEMP\\ex_task_$uid.json"
    $taskName = "TauriaExTask_$uid"

    $innerScript = @"
$ErrorActionPreference = 'Stop'
try {{
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
{inner_ps}
}} catch {{
    @{{
        ok = `$false
        error = `$_.Exception.Message
    }} | ConvertTo-Json -Compress | Set-Content -Path '$outPath' -Encoding UTF8
}}
"@

    Set-Content -Path $psPath -Value $innerScript -Encoding UTF8
    try {{
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$psPath`""
        Register-ScheduledTask -TaskName $taskName -Action $action -User '{ex_user}' -Password '{ex_pass}' -RunLevel Highest -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        for ($i = 0; $i -lt 30; $i++) {{
            Start-Sleep -Milliseconds 500
            if (Test-Path $outPath) {{ break }}
        }}
        if (Test-Path $outPath) {{
            Get-Content -Path $outPath -Raw -Encoding UTF8
        }} else {{
            '{{"ok":false,"error":"Таймаут ожидания результата задачи Exchange"}}'
        }}
    }} finally {{
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Path $psPath, $outPath -Force -ErrorAction SilentlyContinue
    }}
    """
    res = await asyncio.to_thread(_run_exchange_ps_sync, ps_script, timeout)
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error") or "Ошибка выполнения задачи Exchange"}
    try:
        data = json.loads(res.get("stdout", "{}"))
        if not data.get("ok", True):
            return {"ok": False, "error": str(data.get("error") or "Ошибка Exchange")}
        return data
    except Exception as e:
        logger.error(f"Failed to parse Exchange task JSON: {e}")
        return {"ok": False, "error": f"Ошибка разбора ответа Exchange: {e}"}


async def enable_user_mailbox(
    identity: str,
    alias: str | None = None,
    database: str | None = None,
) -> Dict[str, Any]:
    """Создает почтовый ящик Exchange (Enable-Mailbox) для существующей УЗ Active Directory."""
    clean_id = (identity or "").strip()
    if not clean_id or any(c in clean_id for c in ("'", '"', ";", "`", "$")):
        return {"ok": False, "error": "Некорректный логин пользователя"}

    clean_alias = (alias or clean_id).strip()
    if any(c in clean_alias for c in ("'", '"', ";", "`", "$", " ")):
        clean_alias = clean_id

    db_clause = f" -Database '{database.strip()}'" if database and database.strip() else ""
    inner_ps = f"""
    `$existing = Get-Mailbox -Identity '{clean_id}' -ErrorAction SilentlyContinue
    if (`$existing) {{
        @{{
            ok = `$true
            already_exists = `$true
            primary_smtp = [string]`$existing.PrimarySmtpAddress
            database = [string]`$existing.Database
            alias = [string]`$existing.Alias
        }} | ConvertTo-Json -Compress | Set-Content -Path '$outPath' -Encoding UTF8
        exit 0
    }}
    `$mbx = Enable-Mailbox -Identity '{clean_id}' -Alias '{clean_alias}'{db_clause} -ErrorAction Stop
    @{{
        ok = `$true
        already_exists = `$false
        primary_smtp = [string]`$mbx.PrimarySmtpAddress
        database = [string]`$mbx.Database
        alias = [string]`$mbx.Alias
    }} | ConvertTo-Json -Compress | Set-Content -Path '$outPath' -Encoding UTF8
    """
    data = await _run_exchange_task_ps(inner_ps, timeout=35)
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось создать почтовый ящик Exchange"}
    return {
        "ok": True,
        "already_exists": bool(data.get("already_exists", False)),
        "primary_smtp": str(data.get("primary_smtp") or f"{clean_alias}@kdb.kz"),
        "database": str(data.get("database") or "—"),
        "alias": str(data.get("alias") or clean_alias),
    }


async def disable_user_mailbox(identity: str) -> Dict[str, Any]:
    """Отключает/удаляет почтовый ящик Exchange (Disable-Mailbox), сохраняя УЗ Active Directory."""
    clean_id = (identity or "").strip()
    if not clean_id or any(c in clean_id for c in ("'", '"', ";", "`", "$")):
        return {"ok": False, "error": "Некорректный логин пользователя"}

    inner_ps = f"""
    `$existing = Get-Mailbox -Identity '{clean_id}' -ErrorAction SilentlyContinue
    if (-not `$existing) {{
        @{{
            ok = `$false
            error = "У пользователя '{clean_id}' нет активного почтового ящика Exchange"
        }} | ConvertTo-Json -Compress | Set-Content -Path '$outPath' -Encoding UTF8
        exit 0
    }}
    `$smtp = [string]`$existing.PrimarySmtpAddress
    Disable-Mailbox -Identity '{clean_id}' -Confirm:`$false -ErrorAction Stop
    @{{
        ok = `$true
        primary_smtp = `$smtp
    }} | ConvertTo-Json -Compress | Set-Content -Path '$outPath' -Encoding UTF8
    """
    data = await _run_exchange_task_ps(inner_ps, timeout=35)
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось удалить почтовый ящик Exchange"}
    return {
        "ok": True,
        "primary_smtp": str(data.get("primary_smtp") or "—"),
    }

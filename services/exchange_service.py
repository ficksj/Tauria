import asyncio
import base64
import json
import re
from typing import Any, Dict

_RE_IDENTITY = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
_RE_DATABASE = re.compile(r"^[A-Za-z0-9._ -]{1,64}$")

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

    stdout = res.get("stdout", "").lstrip("\ufeff")
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

    stdout = res.get("stdout", "").lstrip("\ufeff")
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

    stdout = res.get("stdout", "").lstrip("\ufeff")
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


async def _run_exchange_task_ps(
    inner_ps: str,
    params: Dict[str, Any] | None = None,
    timeout: int = 55,
) -> Dict[str, Any]:
    """Запускает PowerShell-блок на сервере Exchange через одноразовый ScheduledTask (обход NTLM double-hop)."""
    params_b64 = base64.b64encode(
        json.dumps(params or {}, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")

    # Внутренний скрипт передается в single-quoted here-string @'...'@ без интерполяции пользовательских данных.
    ps_script = (
        "$ErrorActionPreference = 'Stop'\n"
        "$uid = [guid]::NewGuid().ToString('N').Substring(0, 8)\n"
        '$workDir = "C:\\Windows\\Temp"\n'
        '$psPath = "$workDir\\ex_task_$uid.ps1"\n'
        '$outPath = "$workDir\\ex_task_$uid.json"\n'
        '$taskName = "TauriaExTask_$uid"\n'
        f"$paramsB64 = '{params_b64}'\n"
        "$innerScript = @'\n"
        "param([string]$OutPath, [string]$ParamsB64)\n"
        "$ErrorActionPreference = 'Stop'\n"
        "function Write-TaskOut($obj) {\n"
        '    $tmpPath = "$OutPath.tmp"\n'
        "    $obj | ConvertTo-Json -Compress | Set-Content -Path $tmpPath -Encoding UTF8\n"
        "    Move-Item -Path $tmpPath -Destination $OutPath -Force\n"
        "}\n"
        "try {\n"
        "    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue\n"
        "    $p = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ParamsB64)) | ConvertFrom-Json\n"
        f"{inner_ps}\n"
        "} catch {\n"
        "    Write-TaskOut @{ ok = $false; error = $_.Exception.Message }\n"
        "}\n"
        "'@\n"
        "Set-Content -Path $psPath -Value $innerScript -Encoding UTF8\n"
        "try {\n"
        '    $argStr = "-NoProfile -ExecutionPolicy Bypass -File `"$psPath`" `"$outPath`" `"$paramsB64`""\n'
        "    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argStr\n"
        "    Register-ScheduledTask -TaskName $taskName -Action $action -User 'NT AUTHORITY\\SYSTEM' -RunLevel Highest -Force | Out-Null\n"
        "    Start-ScheduledTask -TaskName $taskName\n"
        "    for ($i = 0; $i -lt 90; $i++) {\n"
        "        Start-Sleep -Milliseconds 500\n"
        "        if (Test-Path $outPath) { break }\n"
        "    }\n"
        "    if (Test-Path $outPath) {\n"
        "        Get-Content -Path $outPath -Raw -Encoding UTF8\n"
        "    } else {\n"
        "        $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue\n"
        "        $t = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue\n"
        "        $code = if ($info) { $info.LastTaskResult } else { -1 }\n"
        '        $st = if ($t) { [string]$t.State } else { "Unknown" }\n'
        '        @{ ok = $false; error = "Таймаут Exchange задачи (State=$st, LastResult=$code)" } | ConvertTo-Json -Compress\n'
        "    }\n"
        "} finally {\n"
        "    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue\n"
        '    Remove-Item -Path $psPath, $outPath, "$outPath.tmp" -Force -ErrorAction SilentlyContinue\n'
        "}\n"
    )
    res = await asyncio.to_thread(_run_exchange_ps_sync, ps_script, timeout)
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error") or "Ошибка выполнения задачи Exchange"}
    try:
        raw_out = (res.get("stdout", "{}") or "{}").lstrip("\ufeff")
        data = json.loads(raw_out)
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
    if not _RE_IDENTITY.fullmatch(clean_id):
        return {"ok": False, "error": "Некорректный логин пользователя"}

    clean_alias = (alias or clean_id).strip()
    if not _RE_IDENTITY.fullmatch(clean_alias):
        clean_alias = clean_id

    clean_db = (database or "").strip()
    if clean_db and not _RE_DATABASE.fullmatch(clean_db):
        return {"ok": False, "error": "Некорректное имя базы данных Exchange"}

    inner_ps = r"""
    $existing = Get-Mailbox -Identity $p.identity -ErrorAction SilentlyContinue
    if ($existing) {
        Write-TaskOut @{
            ok = $true
            already_exists = $true
            primary_smtp = [string]$existing.PrimarySmtpAddress
            database = [string]$existing.Database
            alias = [string]$existing.Alias
        }
        exit 0
    }
    if ($p.database) {
        $mbx = Enable-Mailbox -Identity $p.identity -Alias $p.alias -Database $p.database -ErrorAction Stop
    } else {
        $mbx = Enable-Mailbox -Identity $p.identity -Alias $p.alias -ErrorAction Stop
    }
    Write-TaskOut @{
        ok = $true
        already_exists = $false
        primary_smtp = [string]$mbx.PrimarySmtpAddress
        database = [string]$mbx.Database
        alias = [string]$mbx.Alias
    }
    """
    data = await _run_exchange_task_ps(
        inner_ps,
        params={"identity": clean_id, "alias": clean_alias, "database": clean_db},
        timeout=55,
    )
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось создать почтовый ящик Exchange"}
    default_domain = (settings.AD_DOMAIN or "kdb.kz").strip()
    return {
        "ok": True,
        "already_exists": bool(data.get("already_exists", False)),
        "primary_smtp": str(data.get("primary_smtp") or f"{clean_alias}@{default_domain}"),
        "database": str(data.get("database") or "—"),
        "alias": str(data.get("alias") or clean_alias),
    }


async def disable_user_mailbox(identity: str) -> Dict[str, Any]:
    """Отключает/удаляет почтовый ящик Exchange (Disable-Mailbox), сохраняя УЗ Active Directory."""
    clean_id = (identity or "").strip()
    if not _RE_IDENTITY.fullmatch(clean_id):
        return {"ok": False, "error": "Некорректный логин пользователя"}

    inner_ps = r"""
    $existing = Get-Mailbox -Identity $p.identity -ErrorAction SilentlyContinue
    if (-not $existing) {
        Write-TaskOut @{
            ok = $false
            error = "У пользователя '$($p.identity)' нет активного почтового ящика Exchange"
        }
        exit 0
    }
    $smtp = [string]$existing.PrimarySmtpAddress
    Disable-Mailbox -Identity $p.identity -Confirm:$false -ErrorAction Stop
    Write-TaskOut @{
        ok = $true
        primary_smtp = $smtp
    }
    """
    data = await _run_exchange_task_ps(inner_ps, params={"identity": clean_id}, timeout=55)
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось удалить почтовый ящик Exchange"}
    return {
        "ok": True,
        "primary_smtp": str(data.get("primary_smtp") or "—"),
    }


async def get_mailbox_details(identity: str) -> Dict[str, Any]:
    """Возвращает детальную информацию о почтовом ящике Exchange и его статистику."""
    clean_id = (identity or "").strip()
    if not _RE_IDENTITY.fullmatch(clean_id):
        return {"ok": False, "error": "Некорректный логин пользователя"}

    inner_ps = r"""
    $mbx = Get-Mailbox -Identity $p.identity -ErrorAction SilentlyContinue
    if (-not $mbx) {
        Write-TaskOut @{
            ok = $true
            exists = $false
        }
        exit 0
    }
    $stats = Get-MailboxStatistics -Identity $p.identity -ErrorAction SilentlyContinue
    $totalSize = if ($stats -and $stats.TotalItemSize) { [string]$stats.TotalItemSize } else { "—" }
    $itemCount = if ($stats -and $null -ne $stats.ItemCount) { [int]$stats.ItemCount } else { 0 }
    $fwd = if ($mbx.ForwardingSmtpAddress) { [string]$mbx.ForwardingSmtpAddress } else { "" }
    Write-TaskOut @{
        ok = $true
        exists = $true
        primary_smtp = [string]$mbx.PrimarySmtpAddress
        database = [string]$mbx.Database
        alias = [string]$mbx.Alias
        hidden_from_gal = [bool]$mbx.HiddenFromAddressListsEnabled
        forwarding = $fwd
        total_size = $totalSize
        item_count = $itemCount
    }
    """
    data = await _run_exchange_task_ps(inner_ps, params={"identity": clean_id}, timeout=55)
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось получить данные почтового ящика"}
    if not data.get("exists"):
        return {"ok": True, "exists": False}
    return {
        "ok": True,
        "exists": True,
        "primary_smtp": str(data.get("primary_smtp") or "—"),
        "database": str(data.get("database") or "—"),
        "alias": str(data.get("alias") or clean_id),
        "hidden_from_gal": bool(data.get("hidden_from_gal", False)),
        "forwarding": str(data.get("forwarding") or "").strip(),
        "total_size": str(data.get("total_size") or "—"),
        "item_count": int(data.get("item_count") or 0),
    }


async def set_mailbox_hidden_gal(identity: str, hidden: bool) -> Dict[str, Any]:
    """Скрывает или показывает почтовый ящик в глобальной адресной книге (GAL)."""
    clean_id = (identity or "").strip()
    if not _RE_IDENTITY.fullmatch(clean_id):
        return {"ok": False, "error": "Некорректный логин пользователя"}

    inner_ps = r"""
    Set-Mailbox -Identity $p.identity -HiddenFromAddressListsEnabled ([bool]$p.hidden) -ErrorAction Stop
    Write-TaskOut @{
        ok = $true
        hidden_from_gal = [bool]$p.hidden
    }
    """
    data = await _run_exchange_task_ps(
        inner_ps,
        params={"identity": clean_id, "hidden": bool(hidden)},
        timeout=55,
    )
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось обновить видимость в GAL"}
    return {"ok": True, "hidden_from_gal": hidden}


async def grant_mailbox_full_access(mailbox_id: str, delegate_user: str) -> Dict[str, Any]:
    """Выдает права FullAccess (с AutoMapping) указанному делегату на почтовый ящик."""
    clean_id = (mailbox_id or "").strip()
    clean_delegate = (delegate_user or "").strip()
    if not _RE_IDENTITY.fullmatch(clean_id):
        return {"ok": False, "error": "Некорректный логин ящика"}
    if not _RE_IDENTITY.fullmatch(clean_delegate):
        return {"ok": False, "error": "Некорректный логин делегата"}

    inner_ps = r"""
    Add-MailboxPermission -Identity $p.mailbox_id -User $p.delegate_user -AccessRights FullAccess -InheritanceType All -AutoMapping $true -ErrorAction Stop | Out-Null
    Write-TaskOut @{
        ok = $true
        mailbox_id = $p.mailbox_id
        delegate_user = $p.delegate_user
    }
    """
    data = await _run_exchange_task_ps(
        inner_ps,
        params={"mailbox_id": clean_id, "delegate_user": clean_delegate},
        timeout=55,
    )
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось выдать права FullAccess"}
    return {"ok": True, "mailbox_id": clean_id, "delegate_user": clean_delegate}


async def set_mailbox_forwarding(identity: str, target_email: str | None) -> Dict[str, Any]:
    """Настраивает или отключает пересылку писем (ForwardingSmtpAddress) для почтового ящика."""
    clean_id = (identity or "").strip()
    if not _RE_IDENTITY.fullmatch(clean_id):
        return {"ok": False, "error": "Некорректный логин пользователя"}

    clean_target = (target_email or "").strip()
    if clean_target and not _RE_EMAIL.fullmatch(clean_target):
        return {"ok": False, "error": "Некорректный email для пересылки"}

    inner_ps = r"""
    if ($p.target_email) {
        Set-Mailbox -Identity $p.identity -ForwardingSmtpAddress $p.target_email -DeliverToMailboxAndForward $true -ErrorAction Stop
    } else {
        Set-Mailbox -Identity $p.identity -ForwardingSmtpAddress $null -ForwardingAddress $null -DeliverToMailboxAndForward $false -ErrorAction Stop
    }
    Write-TaskOut @{
        ok = $true
        forwarding = $p.target_email
    }
    """
    data = await _run_exchange_task_ps(
        inner_ps,
        params={"identity": clean_id, "target_email": clean_target},
        timeout=55,
    )
    if not data.get("ok"):
        return {"ok": False, "error": data.get("error") or "Не удалось обновить пересылку писем"}
    return {"ok": True, "forwarding": clean_target}

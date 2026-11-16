import asyncio
import os
import subprocess
import time
from typing import Dict, Any, List
from config import settings
from services.winrm_service import run_ps as winrm_run_ps

PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "disk_usage": {
        "title": "Свободное место на дисках (/)",
        "icon": "💾",
        "description": "Проверка свободного места корневого раздела диска",
        "command_linux": "df -h /",
        "command_win": "Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free, @{Name='FreeGB';Expression={[math]::Round($_.Free/1GB, 2)}} | Format-Table -AutoSize",
        "sudo": False
    },
    "top_ram": {
        "title": "Топ-10 процессов по RAM",
        "icon": "🧠",
        "description": "Список 10 самых прожорливых процессов по оперативной памяти",
        "command_linux": "ps aux --sort=-%mem | head -n 11",
        "command_win": "Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Id, ProcessName, @{Name='RAM (MB)';Expression={[math]::Round($_.WorkingSet/1MB, 2)}} | Format-Table -AutoSize",
        "sudo": False
    },
    "listening_ports": {
        "title": "Сетевые подключения (Listening ports)",
        "icon": "🔌",
        "description": "Активные слушающие порты TCP/UDP",
        "command_linux": "ss -tulpn | grep LISTEN",
        "command_win": "Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | Format-Table -AutoSize",
        "sudo": False
    },
    "ntp_status": {
        "title": "Синхронизация времени / NTP",
        "icon": "⏱",
        "description": "Статус синхронизации системного времени и часового пояса",
        "command_linux": "timedatectl status",
        "command_win": "w32tm /query /status",
        "sudo": False
    },
    "ad_dns_replication": {
        "title": "Проверка репликации AD / DNS",
        "icon": "🌐",
        "description": "Проверка разрешения имени контроллера домена kdb.kz на 192.168.201.15",
        "command_linux": "nslookup kdb.kz 192.168.201.15",
        "command_win": "nslookup kdb.kz 192.168.201.15",
        "sudo": False
    },
    "drop_caches": {
        "title": "Очистка кэша памяти Linux",
        "icon": "🧹",
        "description": "Сброс pagecache, dentries и inodes в ядре Linux",
        "command_linux": "sync && echo 3 > /proc/sys/vm/drop_caches",
        "command_win": "Clear-History",
        "sudo": True
    },
    "winrm_repadmin": {
        "title": "Репликация AD (repadmin /replsummary)",
        "icon": "🔄",
        "description": "Сводка репликации Active Directory на контроллере домена",
        "command_linux": "repadmin /replsummary",
        "command_win": "repadmin /replsummary",
        "sudo": False,
        "winrm": True
    },
    "winrm_dc_services": {
        "title": "Службы DC (NTDS, DNS, DFSR, W32Time)",
        "icon": "🛡",
        "description": "Статус ключевых служб контроллера домена",
        "command_linux": "Get-Service NTDS, DNS, DFSR, W32Time | Select-Object Name, Status, StartType | Format-Table -AutoSize",
        "command_win": "Get-Service NTDS, DNS, DFSR, W32Time | Select-Object Name, Status, StartType | Format-Table -AutoSize",
        "sudo": False,
        "winrm": True
    },
    "winrm_smb_files": {
        "title": "Открытые SMB-файлы на DC",
        "icon": "📂",
        "description": "Список открытых сетевых файлов на контроллере домена",
        "command_linux": "Get-SmbOpenFile | Select-Object -First 30 FileId, ClientComputerName, ClientUserName, Path | Format-Table -AutoSize",
        "command_win": "Get-SmbOpenFile | Select-Object -First 30 FileId, ClientComputerName, ClientUserName, Path | Format-Table -AutoSize",
        "sudo": False,
        "winrm": True
    }
}

def get_playbooks_list() -> List[Dict[str, Any]]:
    """Возвращает список доступных сценариев."""
    result = []
    for pid, data in PLAYBOOKS.items():
        result.append({
            "id": pid,
            "title": data["title"],
            "icon": data["icon"],
            "description": data["description"],
            "sudo": data.get("sudo", False)
        })
    return result

async def execute_playbook(playbook_id: str) -> Dict[str, Any]:
    """
    Безопасное выполнение плейбука с замером времени и возвратом вывода.
    """
    if playbook_id not in PLAYBOOKS:
        return {
            "success": False,
            "error": f"Сценарий '{playbook_id}' не найден",
            "execution_time_ms": 0,
            "output": "",
            "playbook_id": playbook_id,
            "title": "Неизвестный сценарий"
        }

    info = PLAYBOOKS[playbook_id]

    if info.get("winrm"):
        start_time = time.perf_counter()
        res = await winrm_run_ps(settings.AD_SERVER, info["command_win"], timeout=15)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        success = res.get("success", False)
        output = res.get("stdout", "")
        if res.get("stderr"):
            output = f"{output}\n[STDERR]:\n{res['stderr']}".strip()
        if not output and success:
            output = "Команда выполнена успешно (вывод пуст)"
        return {
            "success": success,
            "playbook_id": playbook_id,
            "title": info["title"],
            "icon": info["icon"],
            "command": f"WinRM ({settings.AD_SERVER}): {info['command_win']}",
            "output": output,
            "exit_code": 0 if success else 1,
            "execution_time_ms": duration_ms
        }

    is_windows = os.name == 'nt'
    raw_cmd = info["command_win"] if is_windows else info["command_linux"]

    if not is_windows and info.get("sudo"):
        # Для команд требующих sudo
        if ">" in raw_cmd or "&&" in raw_cmd:
            cmd = f"sudo bash -c '{raw_cmd}'"
        else:
            cmd = f"sudo {raw_cmd}"
    else:
        cmd = raw_cmd

    start_time = time.perf_counter()
    loop = asyncio.get_running_loop()

    def _run():
        try:
            if is_windows:
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15,
                    encoding="utf-8",
                    errors="replace"
                )
            else:
                res = subprocess.run(
                    cmd,
                    shell=True,
                    executable="/bin/bash",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15,
                    encoding="utf-8",
                    errors="replace"
                )
            return {
                "exit_code": res.returncode,
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip()
            }
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Превышен таймаут выполнения (15 секунд)"
            }
        except Exception as e:
            return {
                "exit_code": -2,
                "stdout": "",
                "stderr": str(e)
            }

    exec_result = await loop.run_in_executor(None, _run)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    success = exec_result["exit_code"] == 0
    output = exec_result["stdout"]
    if exec_result["stderr"]:
        output = f"{output}\n[STDERR]:\n{exec_result['stderr']}".strip()

    if not output and success:
        output = "Команда выполнена успешно (вывод пуст)"

    return {
        "success": success,
        "playbook_id": playbook_id,
        "title": info["title"],
        "icon": info["icon"],
        "command": cmd,
        "output": output,
        "exit_code": exec_result["exit_code"],
        "execution_time_ms": duration_ms
    }

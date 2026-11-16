import asyncio
import os
import re
import subprocess
import time
from typing import Dict, Any

# Список паттернов опасных и деструктивных команд
FORBIDDEN_PATTERNS = [
    r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/(?:\s|$|\*)", # rm -rf / or rm -rf /*
    r"rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+--no-preserve-root",
    r"mkfs", # Форматирование дисков
    r"dd\s+if=.*of=/dev/(sd|nvme|vd)", # Запись напрямую в диск
    r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;", # Форк-бомба :(){ :|:& };:
    r"chmod\s+-R\s+777\s+/", # Убийство прав в корне
    r"chown\s+-R\s+.*\s+/", # Смена владельца корня
    r">\s*/dev/sd[a-z]", # Перезапись диска
    r">\s*/dev/nvme",
    r"\breboot\b", # Неожиданный ребут
    r"\bshutdown\b",
    r"\binit\s+[06]\b",
    r"\bhalt\b",
    r"\bpoweroff\b",
]

def is_dangerous_command(command: str) -> tuple[bool, str]:
    """
    Проверяет команду на наличие деструктивных действий.
    """
    cmd_clean = command.strip()
    
    # Защита от fork-бомбы в разных вариациях
    if ":(){ :|:& };:" in cmd_clean.replace(" ", ""):
        return True, "Обнаружена сигнатура Fork-бомбы!"

    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, cmd_clean, re.IGNORECASE):
            return True, f"Команда заблокирована политикой безопасности (паттерн: {pattern})"

    return False, ""

async def run_quick_command(command: str, timeout_sec: int = 10) -> Dict[str, Any]:
    """
    Выполнение команды Bash на сервере (с таймаутом и блокировкой опасных инструкций).
    """
    clean_cmd = command.strip()
    if not clean_cmd:
        return {
            "success": False,
            "error": "Пустая команда",
            "output": "",
            "exit_code": -1,
            "duration_ms": 0
        }

    # Проверка на безопасность
    dangerous, reason = is_dangerous_command(clean_cmd)
    if dangerous:
        return {
            "success": False,
            "error": f"⛔️ БЕЗОПАСНОСТЬ: {reason}",
            "output": "",
            "exit_code": 126,
            "duration_ms": 0
        }

    is_windows = os.name == 'nt'
    start_time = time.perf_counter()
    loop = asyncio.get_running_loop()

    def _exec():
        try:
            if is_windows:
                # В Windows используем powershell для локального тестирования
                res = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command", clean_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout_sec,
                    encoding="utf-8",
                    errors="replace"
                )
            else:
                # В Linux выполняем через bash
                res = subprocess.run(
                    clean_cmd,
                    shell=True,
                    executable="/bin/bash",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout_sec,
                    encoding="utf-8",
                    errors="replace"
                )
            return {
                "exit_code": res.returncode,
                "stdout": res.stdout,
                "stderr": res.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Превышен лимит времени выполнения ({timeout_sec} сек)"
            }
        except Exception as e:
            return {
                "exit_code": -2,
                "stdout": "",
                "stderr": str(e)
            }

    result = await loop.run_in_executor(None, _exec)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    stdout = result["stdout"].rstrip()
    stderr = result["stderr"].rstrip()

    combined_output = stdout
    if stderr:
        if combined_output:
            combined_output += f"\n\n[STDERR]:\n{stderr}"
        else:
            combined_output = stderr

    if not combined_output:
        combined_output = "Вывод отсутствует (код 0)"

    return {
        "success": result["exit_code"] == 0,
        "command": clean_cmd,
        "output": combined_output,
        "exit_code": result["exit_code"],
        "duration_ms": duration_ms,
        "error": stderr if result["exit_code"] != 0 else None
    }

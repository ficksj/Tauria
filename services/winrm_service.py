import asyncio
import winrm
from config import settings
from services.logger_service import get_logger

logger = get_logger("WinRM")


def _decode_bytes(data: bytes | str | None) -> str:
    if not data:
        return ""
    if isinstance(data, str):
        return data.strip()
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return data.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace").strip()


def run_ps_sync(host: str, script: str, timeout: int = 15) -> dict:
    """Синхронное выполнение PowerShell-скрипта на удаленном хосте через WinRM."""
    user = settings.AD_USER
    password = settings.AD_PASSWORD
    try:
        session = winrm.Session(
            f"http://{host}:5985/wsman",
            auth=(user, password),
            transport="ntlm",
            read_timeout_sec=timeout + 5,
            operation_timeout_sec=timeout,
        )
        res = session.run_ps(script)
        stdout = _decode_bytes(res.std_out)
        stderr = _decode_bytes(res.std_err)
        return {
            "success": res.status_code == 0,
            "stdout": stdout,
            "stderr": stderr,
        }
    except Exception as e:
        logger.debug(f"WinRM error on {host}: {e}")
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
        }


async def run_ps(host: str, script: str, timeout: int = 15) -> dict:
    """Асинхронная обертка для выполнения PowerShell через WinRM в executor."""
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, run_ps_sync, host, script, timeout),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"WinRM timeout ({timeout}s) on {host}",
        }
    except Exception as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
        }

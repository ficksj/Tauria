import asyncio
from typing import Dict, List

from services.logger_service import get_logger

logger = get_logger("DockerService")


async def list_containers() -> List[Dict[str, str]]:
    """Возвращает список Docker-контейнеров из `docker ps -a`."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "ps",
            "-a",
            "--format",
            "{{.Names}}|{{.State}}|{{.Status}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace").strip()
            logger.warning(f"docker ps failed (rc={proc.returncode}): {err}")
            return []

        containers: List[Dict[str, str]] = []
        for raw_line in stdout.decode("utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split("|", 2)
            if len(parts) != 3:
                continue
            name, state, status = parts
            containers.append({
                "name": name.strip(),
                "state": state.strip(),
                "status": status.strip(),
            })
        return containers
    except FileNotFoundError:
        logger.warning("docker binary not found")
        return []
    except Exception as e:
        logger.error(f"list_containers error: {e}")
        return []


async def restart_container(name: str) -> bool:
    """Перезапускает Docker-контейнер по имени."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "restart",
            name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace").strip()
            logger.warning(f"docker restart {name} failed (rc={proc.returncode}): {err}")
            return False
        return True
    except Exception as e:
        logger.error(f"restart_container({name}) error: {e}")
        return False


async def get_container_logs(name: str, lines: int = 30) -> str:
    """Возвращает последние N строк логов Docker-контейнера."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "logs",
            "--tail",
            str(lines),
            name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        out_text = stdout.decode("utf-8", errors="replace")
        err_text = stderr.decode("utf-8", errors="replace")
        combined = (out_text + ("\n" if out_text and err_text else "") + err_text).strip()
        if proc.returncode != 0 and not combined:
            return f"docker logs failed with exit code {proc.returncode}"
        return combined
    except Exception as e:
        logger.error(f"get_container_logs({name}) error: {e}")
        return f"Ошибка получения логов: {e}"

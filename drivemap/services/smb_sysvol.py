"""SYSVOL policy file access abstraction and SMBv3 implementation via smbprotocol."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol


class SysvolBackend(Protocol):
    """Protocol abstracting GPO SYSVOL read/write operations for testability."""

    async def read_drives_xml(self, gpo_guid: str) -> Optional[bytes]:
        ...

    async def read_gpt_ini(self, gpo_guid: str) -> Optional[str]:
        ...

    async def write_gpo_files_atomic(
        self,
        gpo_guid: str,
        drives_xml: bytes,
        gpt_ini_text: str,
        backup_root: Path,
        tx_id: str,
    ) -> Path:
        ...

    async def restore_from_backup(self, gpo_guid: str, backup_dir: Path) -> None:
        ...


class SmbSysvolClient:
    """Direct SMBv3 SYSVOL client targeting DC SYSVOL share without kernel mount.cifs."""

    def __init__(self, host: str, share: str, domain_dir: str, username: str, password: str) -> None:
        self.host = host
        self.share = share
        self.domain_dir = domain_dir
        self.username = username
        self.password = password

    def _policy_root(self, gpo_guid: str) -> str:
        clean_guid = gpo_guid.strip().strip("{}").upper()
        if not re.fullmatch(r"[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", clean_guid):
            raise ValueError(f"Некорректный GPO GUID: {gpo_guid!r}")
        return f"\\\\{self.host}\\{self.share}\\{self.domain_dir}\\Policies\\{{{clean_guid}}}"

    def _drives_dir(self, gpo_guid: str) -> str:
        return f"{self._policy_root(gpo_guid)}\\User\\Preferences\\Drives"

    def _drives_xml_path(self, gpo_guid: str) -> str:
        return f"{self._drives_dir(gpo_guid)}\\Drives.xml"

    def _gpt_ini_path(self, gpo_guid: str) -> str:
        return f"{self._policy_root(gpo_guid)}\\GPT.INI"

    def _ensure_session(self) -> None:
        import smbclient

        smbclient.register_session(
            self.host,
            username=self.username,
            password=self.password,
        )

    def _read_bytes_sync(self, unc_path: str) -> Optional[bytes]:
        import smbclient

        self._ensure_session()
        try:
            with smbclient.open_file(unc_path, mode="rb", username=self.username, password=self.password) as f:
                return f.read()
        except FileNotFoundError:
            return None
        except OSError as exc:
            # smbprotocol raises SMBOSError with winerror=2/3 when file or parent folder is absent.
            if getattr(exc, "winerror", None) in (2, 3) or "STATUS_OBJECT_NAME_NOT_FOUND" in str(exc) or "STATUS_OBJECT_PATH_NOT_FOUND" in str(exc):
                return None
            raise

    def _write_atomic_sync(self, unc_path: str, data: bytes, ensure_dir: Optional[str] = None) -> None:
        import smbclient

        self._ensure_session()
        if ensure_dir:
            smbclient.makedirs(ensure_dir, exist_ok=True, username=self.username, password=self.password)
        tmp_path = f"{unc_path}.tmp"
        with smbclient.open_file(tmp_path, mode="wb", username=self.username, password=self.password) as f:
            f.write(data)
        smbclient.replace(tmp_path, unc_path, username=self.username, password=self.password)

    async def read_drives_xml(self, gpo_guid: str) -> Optional[bytes]:
        return await asyncio.to_thread(self._read_bytes_sync, self._drives_xml_path(gpo_guid))

    async def read_gpt_ini(self, gpo_guid: str) -> Optional[str]:
        raw = await asyncio.to_thread(self._read_bytes_sync, self._gpt_ini_path(gpo_guid))
        if raw is None:
            return None
        return raw.decode("utf-8-sig", errors="replace")

    async def write_gpo_files_atomic(
        self,
        gpo_guid: str,
        drives_xml: bytes,
        gpt_ini_text: str,
        backup_root: Path,
        tx_id: str,
    ) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        tx_backup = backup_root / f"{stamp}_{tx_id}"
        tx_backup.mkdir(parents=True, exist_ok=True)

        old_xml = await self.read_drives_xml(gpo_guid)
        old_gpt = await self.read_gpt_ini(gpo_guid)
        if old_xml is not None:
            (tx_backup / "Drives.xml").write_bytes(old_xml)
        if old_gpt is not None:
            (tx_backup / "GPT.INI").write_text(old_gpt, encoding="utf-8")

        drives_dir = self._drives_dir(gpo_guid)
        await asyncio.to_thread(
            self._write_atomic_sync,
            self._drives_xml_path(gpo_guid),
            drives_xml,
            drives_dir,
        )
        await asyncio.to_thread(
            self._write_atomic_sync,
            self._gpt_ini_path(gpo_guid),
            gpt_ini_text.encode("utf-8"),
            None,
        )
        return tx_backup

    async def restore_from_backup(self, gpo_guid: str, backup_dir: Path) -> None:
        xml_bak = backup_dir / "Drives.xml"
        gpt_bak = backup_dir / "GPT.INI"
        if xml_bak.exists():
            await asyncio.to_thread(
                self._write_atomic_sync,
                self._drives_xml_path(gpo_guid),
                xml_bak.read_bytes(),
                self._drives_dir(gpo_guid),
            )
        if gpt_bak.exists():
            await asyncio.to_thread(
                self._write_atomic_sync,
                self._gpt_ini_path(gpo_guid),
                gpt_bak.read_bytes(),
                None,
            )


def parse_gpt_ini_version(gpt_text: Optional[str]) -> Optional[int]:
    """Extract Version=<int> from GPT.INI text."""
    if not gpt_text:
        return None
    for line in gpt_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("version="):
            val = stripped.split("=", 1)[1].strip()
            if val.isdigit():
                return int(val)
    return None


def update_gpt_ini_version(gpt_text: Optional[str], new_version: int, display_name: str) -> str:
    """Update Version=<new_version> in GPT.INI preserving CRLF line endings."""
    if not gpt_text:
        return f"[General]\r\nVersion={new_version}\r\ndisplayName={display_name}\r\n"

    lines = gpt_text.splitlines()
    out: list[str] = []
    replaced = False
    for line in lines:
        if line.strip().lower().startswith("version="):
            out.append(f"Version={new_version}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        out.append(f"Version={new_version}")
    return "\r\n".join(out) + "\r\n"

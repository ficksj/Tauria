"""SMBv2/3 NTFS Security Descriptor reader/mutator built directly on smbprotocol."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol

from smbprotocol.security_descriptor import (
    AccessAllowedAce,
    AccessDeniedAce,
    AccessMask,
    AceFlags,
    AceType,
    AclPacket,
    SDControl,
    SIDPacket,
    SMB2CreateSDBuffer,
)

from drivemap.models import ACCESS_FULL, ACCESS_NONE, ACCESS_RO, ACCESS_RW
from drivemap.services.share_discovery import format_smb_username

logger = logging.getLogger(__name__)

# Standard Windows FileSystemRights bitmasks
RIGHT_READ_EXECUTE = 0x001200A9  # ReadData | ReadEA | Execute | ReadAttributes | ReadControl | Synchronize
RIGHT_MODIFY = 0x001301BF        # ReadAndExecute + WriteData | AppendData | WriteEA | WriteAttributes | Delete
RIGHT_FULL_CONTROL = 0x001F01FF

_FILE_READ_DATA = 0x00000001
_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_FILE_EXECUTE = 0x00000020

_ACE_DIR_ROOT = AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE
_ACE_DIR_INHERITED = _ACE_DIR_ROOT | AceFlags.INHERITED_ACE
_ACE_FILE_INHERITED = AceFlags.INHERITED_ACE

# [MS-DTYP] SECURITY_INFORMATION constants (avoids upstream smbprotocol typo OWNER_SECURTIY_INFORMATION)
_SECINFO_OWNER_GROUP_DACL = 0x00000001 | 0x00000002 | 0x00000004
_SECINFO_DACL = 0x00000004

WELL_KNOWN_SID_NAMES: dict[str, str] = {
    "S-1-1-0": "Everyone",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-5-11": "NT AUTHORITY\\Authenticated Users",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
}


@dataclass(frozen=True)
class DecodedAce:
    """Normalized NTFS DACL entry parsed from a Windows Security Descriptor."""

    sid: str
    ace_type: int
    ace_flags: int
    mask: int
    level: str  # RO | RW | FULL | CUSTOM
    is_deny: bool
    is_inherited: bool


@dataclass(frozen=True)
class DecodedSd:
    """Decoded Windows Security Descriptor owner, control flags, and DACL ACEs."""

    owner_sid: str
    control: int
    aces: tuple[DecodedAce, ...]


class AclBackend(Protocol):
    """Protocol abstracting SMB share NTFS ACL inspection and mutations."""

    async def read_root_sd(self, unc_path: str) -> bytes:
        ...

    async def apply_access(
        self,
        unc_path: str,
        target_sid: str,
        level: str,
        backup_root: Path,
        tx_id: str,
        max_propagate: int = 2500,
    ) -> tuple[Path, int, int, bool]:
        ...

    async def restore_snapshot(self, backup_dir: Path) -> None:
        ...


def split_unc_share(unc_path: str) -> tuple[str, str, str]:
    """Split \\\\server\\share\\sub\\dir into (server, \\\\server\\share, sub\\dir)."""
    trimmed = unc_path.strip().rstrip("\\")
    parts = trimmed.lstrip("\\").split("\\", 2)
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Expected UNC path \\\\server\\share, got {unc_path!r}")
    server, share = parts[0], parts[1]
    rel = parts[2] if len(parts) > 2 else ""
    return server, f"\\\\{server}\\{share}", rel


def classify_access_mask(mask: int) -> str:
    """Map raw Windows FileSystemRights bitmask to RO, RW, FULL, or CUSTOM."""
    if (mask & AccessMask.GENERIC_ALL) or (mask & RIGHT_FULL_CONTROL) == RIGHT_FULL_CONTROL:
        return ACCESS_FULL
    if (
        (mask & AccessMask.WRITE_DACL)
        and (mask & AccessMask.WRITE_OWNER)
        and (mask & AccessMask.DELETE)
        and (mask & _FILE_WRITE_DATA)
    ):
        return ACCESS_FULL
    if (mask & AccessMask.GENERIC_WRITE) or (mask & _FILE_WRITE_DATA) or (mask & _FILE_APPEND_DATA):
        return ACCESS_RW
    if (mask & AccessMask.GENERIC_READ) or (mask & _FILE_READ_DATA) or (mask & _FILE_EXECUTE):
        return ACCESS_RO
    return "CUSTOM"


def _ace_sort_key(ace_obj) -> tuple[int, int]:
    """Return Windows MS-DTYP canonical DACL sort key (explicit deny/allow -> inherited deny/allow)."""
    if isinstance(ace_obj, bytes):
        ace_type = ace_obj[0]
        ace_flags = ace_obj[1]
    else:
        ace_type = int(ace_obj["ace_type"].get_value())
        ace_flags = int(ace_obj["ace_flags"].get_value())
    is_inherited = 1 if (ace_flags & AceFlags.INHERITED_ACE) else 0
    is_deny = ace_type in (
        AceType.ACCESS_DENIED_ACE_TYPE,
        AceType.ACCESS_DENIED_OBJECT_ACE_TYPE,
        AceType.ACCESS_DENIED_CALLBACK_ACE_TYPE,
    )
    return (is_inherited, 0 if is_deny else 1)


def decode_sd_bytes(sd_bytes: bytes) -> DecodedSd:
    """Decode raw self-relative Windows Security Descriptor bytes."""
    sd = SMB2CreateSDBuffer()
    sd.unpack(sd_bytes)
    owner = sd.get_owner()
    owner_sid = str(owner) if owner else ""
    control = int(sd["control"].get_value())

    dacl = sd.get_dacl()
    decoded: list[DecodedAce] = []
    if dacl is not None:
        for ace in dacl["aces"].get_value():
            if isinstance(ace, bytes):
                continue
            atype = int(ace["ace_type"].get_value())
            aflags = int(ace["ace_flags"].get_value())
            mask = int(ace["mask"].get_value())
            sid_str = str(ace["sid"])
            is_deny = atype in (
                AceType.ACCESS_DENIED_ACE_TYPE,
                AceType.ACCESS_DENIED_OBJECT_ACE_TYPE,
                AceType.ACCESS_DENIED_CALLBACK_ACE_TYPE,
            )
            decoded.append(
                DecodedAce(
                    sid=sid_str,
                    ace_type=atype,
                    ace_flags=aflags,
                    mask=mask,
                    level=classify_access_mask(mask),
                    is_deny=is_deny,
                    is_inherited=bool(aflags & AceFlags.INHERITED_ACE),
                )
            )
    return DecodedSd(owner_sid=owner_sid, control=control, aces=tuple(decoded))


def build_dacl_only_sd_bytes(aces: list, control_flags: int = 0) -> bytes:
    """Serialize canonical DACL-only Security Descriptor bytes ready for SMB2 SET_INFO."""
    ordered = sorted(aces, key=_ace_sort_key)
    acl = AclPacket()
    acl["aces"] = ordered

    sd = SMB2CreateSDBuffer()
    sd.set_dacl(acl)
    preserved = control_flags & (SDControl.DACL_PROTECTED | SDControl.DACL_AUTO_INHERITED)
    sd["control"].set_value(SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT | preserved)
    return sd.pack()


def mutate_dacl_bytes(
    sd_bytes: bytes,
    target_sid: str,
    target_level: str,
    *,
    inherited_mode: bool = False,
    is_directory: bool = True,
) -> tuple[bytes, bool]:
    """Return (new_dacl_sd_bytes, changed) applying RO/RW/NONE for target_sid in canonical ACL order."""
    sd = SMB2CreateSDBuffer()
    sd.unpack(sd_bytes)
    control = int(sd["control"].get_value())
    dacl = sd.get_dacl()
    existing = list(dacl["aces"].get_value()) if dacl is not None else []

    target_sid_up = target_sid.strip().upper()
    kept: list = []
    removed_any = False

    for ace in existing:
        if isinstance(ace, bytes):
            kept.append(ace)
            continue
        atype = int(ace["ace_type"].get_value())
        aflags = int(ace["ace_flags"].get_value())
        is_inh = bool(aflags & AceFlags.INHERITED_ACE)
        sid_str = str(ace["sid"]).upper()
        if sid_str == target_sid_up and atype == AceType.ACCESS_ALLOWED_ACE_TYPE and is_inh == inherited_mode:
            removed_any = True
            continue
        kept.append(ace)

    desired_level = target_level.upper()
    if desired_level == ACCESS_NONE:
        if not removed_any:
            return build_dacl_only_sd_bytes(kept, control), False
        return build_dacl_only_sd_bytes(kept, control), True

    if desired_level == ACCESS_RO:
        mask = RIGHT_READ_EXECUTE
    elif desired_level == ACCESS_RW:
        mask = RIGHT_MODIFY
    elif desired_level == ACCESS_FULL:
        mask = RIGHT_FULL_CONTROL
    else:
        raise ValueError(f"Unsupported NTFS access level: {target_level!r}")

    if inherited_mode:
        flags = _ACE_DIR_INHERITED if is_directory else _ACE_FILE_INHERITED
    else:
        flags = _ACE_DIR_ROOT if is_directory else 0

    sid_pkt = SIDPacket()
    sid_pkt.from_string(target_sid)

    new_ace = AccessAllowedAce()
    new_ace["ace_flags"].set_value(flags)
    new_ace["mask"].set_value(mask)
    new_ace["sid"] = sid_pkt

    # Check whether an identical single ACE was already present to avoid redundant writes.
    already_exact = False
    if removed_any:
        matching_old = [
            a
            for a in existing
            if not isinstance(a, bytes)
            and int(a["ace_type"].get_value()) == AceType.ACCESS_ALLOWED_ACE_TYPE
            and str(a["sid"]).upper() == target_sid_up
            and bool(int(a["ace_flags"].get_value()) & AceFlags.INHERITED_ACE) == inherited_mode
        ]
        if (
            len(matching_old) == 1
            and int(matching_old[0]["mask"].get_value()) == mask
            and int(matching_old[0]["ace_flags"].get_value()) == flags
        ):
            already_exact = True

    kept.append(new_ace)
    return build_dacl_only_sd_bytes(kept, control), not already_exact


def extract_dacl_only_bytes(full_sd_bytes: bytes) -> bytes:
    """Convert any captured full SD bytes into a DACL-only SD buffer for snapshot restore."""
    sd = SMB2CreateSDBuffer()
    sd.unpack(full_sd_bytes)
    control = int(sd["control"].get_value())
    dacl = sd.get_dacl()
    aces = list(dacl["aces"].get_value()) if dacl is not None else []
    return build_dacl_only_sd_bytes(aces, control)


class SmbAclClient:
    """SMBv2/3 client for reading and updating Windows NTFS Security Descriptors directly."""

    def __init__(self, username: str, password: str, domain: str = "") -> None:
        self.username = format_smb_username(username, domain)
        self.password = password

    def _connect_tree(self, share_root_unc: str):
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect

        server, share_root, _ = split_unc_share(share_root_unc)
        conn = Connection(uuid.uuid4(), server, 445)
        conn.connect(timeout=6)
        try:
            sess = Session(conn, self.username, self.password)
            sess.connect()
            tree = TreeConnect(sess, share_root)
            tree.connect()
            return conn, sess, tree
        except Exception:
            conn.disconnect(close=False)
            raise

    @staticmethod
    def _query_sd_on_tree(conn, sess, tree, rel_path: str, is_directory: bool) -> bytes:
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            FileAttributes,
            FilePipePrinterAccessMask,
            ImpersonationLevel,
            InfoType,
            Open,
            ShareAccess,
            SMB2QueryInfoRequest,
            SMB2QueryInfoResponse,
        )

        attrs = FileAttributes.FILE_ATTRIBUTE_DIRECTORY if is_directory else FileAttributes.FILE_ATTRIBUTE_NORMAL
        opts = (
            (CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_OPEN_REPARSE_POINT)
            if is_directory
            else CreateOptions.FILE_OPEN_REPARSE_POINT
        )
        handle = Open(tree, rel_path)
        handle.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.READ_CONTROL,
            attrs,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            opts,
        )
        try:
            buf_size = 65536
            qi = SMB2QueryInfoRequest()
            qi["info_type"] = InfoType.SMB2_0_INFO_SECURITY
            qi["output_buffer_length"] = buf_size
            qi["additional_information"] = _SECINFO_OWNER_GROUP_DACL
            qi["file_id"] = handle.file_id
            req = conn.send(qi, sess.session_id, tree.tree_connect_id)
            raw = conn.receive(req)
            resp = SMB2QueryInfoResponse()
            resp.unpack(raw["data"].get_value())
            return bytes(resp["buffer"].get_value())
        finally:
            handle.close()

    @staticmethod
    def _set_dacl_on_tree(conn, sess, tree, rel_path: str, is_directory: bool, dacl_sd_bytes: bytes) -> None:
        from smbprotocol.open import (
            CreateDisposition,
            CreateOptions,
            FileAttributes,
            FilePipePrinterAccessMask,
            ImpersonationLevel,
            InfoAdditionalInformation,
            InfoType,
            Open,
            ShareAccess,
            SMB2SetInfoRequest,
            SMB2SetInfoResponse,
        )

        attrs = FileAttributes.FILE_ATTRIBUTE_DIRECTORY if is_directory else FileAttributes.FILE_ATTRIBUTE_NORMAL
        opts = (
            (CreateOptions.FILE_DIRECTORY_FILE | CreateOptions.FILE_OPEN_REPARSE_POINT)
            if is_directory
            else CreateOptions.FILE_OPEN_REPARSE_POINT
        )
        handle = Open(tree, rel_path)
        handle.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.WRITE_DAC,
            attrs,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE | ShareAccess.FILE_SHARE_DELETE,
            CreateDisposition.FILE_OPEN,
            opts,
        )
        try:
            si = SMB2SetInfoRequest()
            si["info_type"] = InfoType.SMB2_0_INFO_SECURITY
            si["additional_information"] = InfoAdditionalInformation.DACL_SECURITY_INFORMATION
            si["file_id"] = handle.file_id
            si["buffer"] = dacl_sd_bytes
            req = conn.send(si, sess.session_id, tree.tree_connect_id)
            raw = conn.receive(req)
            resp = SMB2SetInfoResponse()
            resp.unpack(raw["data"].get_value())
        finally:
            handle.close()

    def _read_root_sd_sync(self, unc_path: str) -> bytes:
        _, share_root, rel_path = split_unc_share(unc_path)
        conn, sess, tree = self._connect_tree(share_root)
        try:
            return self._query_sd_on_tree(conn, sess, tree, rel_path, is_directory=True)
        finally:
            try:
                tree.disconnect()
            finally:
                conn.disconnect(close=False)

    def _apply_access_sync(
        self,
        unc_path: str,
        target_sid: str,
        level: str,
        backup_root: Path,
        tx_id: str,
        max_propagate: int,
    ) -> tuple[Path, int, int, bool]:
        import smbclient
        from smbprotocol.open import FileAttributes

        _, share_root, base_rel = split_unc_share(unc_path)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        tx_backup = backup_root / f"acl_{stamp}_{tx_id}"
        tx_backup.mkdir(parents=True, exist_ok=True)
        snapshots: list[dict] = []

        conn, sess, tree = self._connect_tree(share_root)
        propagated = 0
        skipped = 0
        truncated = False
        try:
            root_sd_raw = self._query_sd_on_tree(conn, sess, tree, base_rel, is_directory=True)
            new_root_dacl, changed = mutate_dacl_bytes(
                root_sd_raw,
                target_sid,
                level,
                inherited_mode=False,
                is_directory=True,
            )
            if changed:
                snapshots.append(
                    {
                        "rel_path": base_rel,
                        "is_dir": True,
                        "dacl_b64": base64.b64encode(extract_dacl_only_bytes(root_sd_raw)).decode("ascii"),
                    }
                )
                self._set_dacl_on_tree(conn, sess, tree, base_rel, True, new_root_dacl)

            # Propagate inherited ACE down non-protected children just like Windows SetNamedSecurityInfo.
            if max_propagate > 0:
                smbclient.register_session(split_unc_share(share_root)[0], username=self.username, password=self.password)
                queue: deque[str] = deque([base_rel])
                visited = 0
                while queue and not truncated:
                    cur_rel = queue.popleft()
                    cur_unc = f"{share_root}\\{cur_rel}" if cur_rel else share_root
                    try:
                        with smbclient.scandir(cur_unc, username=self.username, password=self.password) as it:
                            entries = list(it)
                    except Exception as exc:
                        logger.debug("Skipping ACL scan on %s: %s", cur_unc, exc)
                        skipped += 1
                        continue

                    for entry in entries:
                        if visited >= max_propagate:
                            truncated = True
                            break
                        visited += 1
                        fattrs = entry.smb_info.file_attributes
                        if fattrs & FileAttributes.FILE_ATTRIBUTE_REPARSE_POINT:
                            skipped += 1
                            continue
                        is_dir = bool(fattrs & FileAttributes.FILE_ATTRIBUTE_DIRECTORY)
                        child_rel = f"{cur_rel}\\{entry.name}" if cur_rel else entry.name
                        try:
                            child_sd_raw = self._query_sd_on_tree(conn, sess, tree, child_rel, is_directory=is_dir)
                            child_sd = SMB2CreateSDBuffer()
                            child_sd.unpack(child_sd_raw)
                            if int(child_sd["control"].get_value()) & SDControl.DACL_PROTECTED:
                                # Protected branch blocks inheritance from parent; stop descending cleanly.
                                skipped += 1
                                continue
                            new_child_dacl, child_changed = mutate_dacl_bytes(
                                child_sd_raw,
                                target_sid,
                                level,
                                inherited_mode=True,
                                is_directory=is_dir,
                            )
                            if child_changed:
                                snapshots.append(
                                    {
                                        "rel_path": child_rel,
                                        "is_dir": is_dir,
                                        "dacl_b64": base64.b64encode(extract_dacl_only_bytes(child_sd_raw)).decode("ascii"),
                                    }
                                )
                                self._set_dacl_on_tree(conn, sess, tree, child_rel, is_dir, new_child_dacl)
                                propagated += 1
                            if is_dir:
                                queue.append(child_rel)
                        except Exception as exc:
                            logger.debug("Skipping child ACL propagation on %s: %s", child_rel, exc)
                            skipped += 1
        finally:
            try:
                tree.disconnect()
            finally:
                conn.disconnect(close=False)

        (tx_backup / "acl_backup.json").write_text(
            json.dumps({"kind": "NTFS_ACL", "unc_path": unc_path, "snapshots": snapshots}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return tx_backup, propagated, skipped, truncated

    def _restore_snapshot_sync(self, backup_dir: Path) -> None:
        manifest_path = backup_dir / "acl_backup.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Отсутствует файл снимка ACL: {manifest_path}")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        unc_path = payload["unc_path"]
        snapshots = payload.get("snapshots", [])
        _, share_root, _ = split_unc_share(unc_path)

        conn, sess, tree = self._connect_tree(share_root)
        try:
            for item in reversed(snapshots):
                dacl_bytes = base64.b64decode(item["dacl_b64"])
                self._set_dacl_on_tree(conn, sess, tree, item["rel_path"], bool(item["is_dir"]), dacl_bytes)
        finally:
            try:
                tree.disconnect()
            finally:
                conn.disconnect(close=False)

    async def read_root_sd(self, unc_path: str) -> bytes:
        return await asyncio.to_thread(self._read_root_sd_sync, unc_path)

    async def apply_access(
        self,
        unc_path: str,
        target_sid: str,
        level: str,
        backup_root: Path,
        tx_id: str,
        max_propagate: int = 2500,
    ) -> tuple[Path, int, int, bool]:
        return await asyncio.to_thread(
            self._apply_access_sync, unc_path, target_sid, level, backup_root, tx_id, max_propagate
        )

    async def restore_snapshot(self, backup_dir: Path) -> None:
        await asyncio.to_thread(self._restore_snapshot_sync, backup_dir)

"""Network share discovery merging GPO DriveMap metadata and live SMB SRVSVC enumeration."""

from __future__ import annotations

import asyncio
import logging
import struct
import time
import uuid
from typing import Callable, Optional

from drivemap.config import PolicyConfig
from drivemap.models import ShareInfo
from drivemap.services.ad_ldap import AdBackend
from drivemap.services.drivemap_engine import parse_drives_xml
from drivemap.services.smb_sysvol import SysvolBackend

logger = logging.getLogger(__name__)

_SRVS_UUID_LE = uuid.UUID("4b324fc8-1670-01d3-1278-5a47bf6ee188").bytes_le
_NDR_UUID_LE = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860").bytes_le
_DCE_DREP_LE = b"\x10\x00\x00\x00"
_PTYPE_REQUEST = 0
_PTYPE_RESPONSE = 2
_PTYPE_FAULT = 3
_PTYPE_BIND = 11
_PTYPE_BIND_ACK = 12
_PTYPE_BIND_NAK = 13
_PFC_LAST_FRAG = 0x02


def _ndr_pack_wchar_ptr(text: str, referent_id: int) -> bytes:
    """Encode an NDR32 unique conformant-varying UTF-16LE string padded to 4 bytes."""
    chars = len(text) + 1
    raw = (text + "\x00").encode("utf-16-le")
    buf = struct.pack("<IIII", referent_id, chars, 0, chars) + raw
    pad = (-len(buf)) % 4
    return buf + (b"\x00" * pad)


def _ndr_unpack_wchar(buf: bytes, offset: int) -> tuple[str, int]:
    """Decode a 4-byte-aligned NDR32 conformant-varying UTF-16LE string."""
    offset = (offset + 3) & ~3
    _max_c, _str_off, actual_c = struct.unpack_from("<III", buf, offset)
    offset += 12
    raw = buf[offset : offset + actual_c * 2]
    offset = (offset + actual_c * 2 + 3) & ~3
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00").strip(), offset


def _build_srvsvc_bind_pdu(call_id: int = 1) -> bytes:
    """Build a DCE/RPC v5 BIND PDU for the MS-SRVS interface (v3.0)."""
    body = (
        struct.pack("<HHIB3xHBB", 4280, 4280, 0, 1, 0, 1, 0)
        + _SRVS_UUID_LE
        + struct.pack("<HH", 3, 0)
        + _NDR_UUID_LE
        + struct.pack("<HH", 2, 0)
    )
    header = struct.pack("<BBBB4sHHI", 5, 0, _PTYPE_BIND, 0x03, _DCE_DREP_LE, 16 + len(body), 0, call_id)
    return header + body


def _verify_bind_ack(pdu: bytes) -> None:
    """Validate DCE/RPC BIND_ACK acceptance."""
    if len(pdu) < 26:
        raise RuntimeError(f"Truncated DCE/RPC BIND response ({len(pdu)} bytes)")
    ptype = pdu[2]
    if ptype == _PTYPE_BIND_NAK:
        raise RuntimeError("DCE/RPC BIND_NAK rejected by SRVSVC pipe")
    if ptype != _PTYPE_BIND_ACK:
        raise RuntimeError(f"Unexpected DCE/RPC ptype {ptype} waiting for BIND_ACK")
    sec_addr_len = struct.unpack_from("<H", pdu, 24)[0]
    pos = (26 + sec_addr_len + 3) & ~3
    n_results = pdu[pos]
    pos += 4
    if n_results < 1:
        raise RuntimeError("DCE/RPC BIND_ACK returned 0 presentation results")
    result, reason = struct.unpack_from("<HH", pdu, pos)
    if result != 0:
        raise RuntimeError(f"SRVSVC presentation context rejected (result={result}, reason={reason})")


def _build_netr_share_enum_request(server: str, call_id: int = 2) -> bytes:
    """Build a DCE/RPC v5 REQUEST PDU for MS-SRVS NetrShareEnum (opnum 15, level 1)."""
    stub = (
        _ndr_pack_wchar_ptr(f"\\\\{server}", 0x00020000)
        + struct.pack("<IIIIIII", 1, 1, 0x00020004, 0, 0, 0xFFFFFFFF, 0x00020008)
        + struct.pack("<I", 0)
    )
    req_ext = struct.pack("<IHH", len(stub), 0, 15)
    header = struct.pack(
        "<BBBB4sHHI",
        5,
        0,
        _PTYPE_REQUEST,
        0x03,
        _DCE_DREP_LE,
        16 + len(req_ext) + len(stub),
        0,
        call_id,
    )
    return header + req_ext + stub


def _read_exact_dce_pdu(pipe, pending: bytearray) -> tuple[int, int, int, bytes]:
    """Read one complete DCE/RPC fragment from an SMB pipe, preserving trailing buffered bytes."""
    while len(pending) < 16:
        chunk = pipe.read(4280)
        if not chunk:
            raise EOFError("Unexpected EOF reading DCE/RPC header from SRVSVC")
        pending.extend(chunk)
    frag_len, auth_len = struct.unpack_from("<HH", pending, 8)
    if frag_len < 16:
        raise RuntimeError(f"Invalid DCE/RPC frag_len={frag_len}")
    while len(pending) < frag_len:
        chunk = pipe.read(max(4280, frag_len - len(pending)))
        if not chunk:
            raise EOFError("Unexpected EOF reading DCE/RPC fragment body from SRVSVC")
        pending.extend(chunk)
    pdu = bytes(pending[:frag_len])
    del pending[:frag_len]
    return pdu[2], pdu[3], auth_len, pdu


def _read_dce_response_stub(pipe, pending: bytearray) -> bytes:
    """Read and reassemble one complete DCE/RPC RESPONSE stub from an SMB pipe."""
    stub_parts: list[bytes] = []
    while True:
        ptype, pfc_flags, auth_len, pdu = _read_exact_dce_pdu(pipe, pending)
        if ptype == _PTYPE_FAULT:
            status = struct.unpack_from("<I", pdu, 24)[0] if len(pdu) >= 28 else 0
            raise RuntimeError(f"SRVSVC DCE/RPC FAULT (status=0x{status:08X})")
        if ptype != _PTYPE_RESPONSE:
            raise RuntimeError(f"Unexpected DCE/RPC ptype {ptype} in NetrShareEnum response")
        end = len(pdu) - auth_len if auth_len else len(pdu)
        stub_parts.append(pdu[24:end])
        if pfc_flags & _PFC_LAST_FRAG:
            break
    return b"".join(stub_parts)


def _parse_netr_share_enum_stub(stub: bytes) -> list[tuple[str, int]]:
    """Decode MS-SRVS NetrShareEnum level 1 NDR32 response stub."""
    pos = 0
    level, _switch_val, container_ref = struct.unpack_from("<III", stub, pos)
    pos += 12
    if level != 1:
        raise RuntimeError(f"Unexpected NetrShareEnum level {level}")
    if container_ref == 0:
        return []

    entries_read, buf_ref = struct.unpack_from("<II", stub, pos)
    pos += 8
    raw_items: list[tuple[int, int, int]] = []
    if entries_read > 0 and buf_ref != 0:
        _max_count = struct.unpack_from("<I", stub, pos)[0]
        pos += 4
        for _ in range(entries_read):
            netname_ref, stype, remark_ref = struct.unpack_from("<III", stub, pos)
            pos += 12
            raw_items.append((netname_ref, stype & 0xFFFFFFFF, remark_ref))

    result: list[tuple[str, int]] = []
    for netname_ref, stype, remark_ref in raw_items:
        name = ""
        if netname_ref != 0:
            name, pos = _ndr_unpack_wchar(stub, pos)
        if remark_ref != 0:
            _, pos = _ndr_unpack_wchar(stub, pos)
        if name:
            result.append((name, stype))

    if len(stub) - pos >= 12:
        _total_entries, resume_ref = struct.unpack_from("<II", stub, pos)
        pos += 8
        if resume_ref != 0 and len(stub) - pos >= 4:
            pos += 4
        if len(stub) - pos >= 4:
            winerror = struct.unpack_from("<I", stub, pos)[0]
            if winerror not in (0, 234):
                raise RuntimeError(f"NetrShareEnum failed with Win32 status {winerror}")

    return result


def format_smb_username(username: str, domain: str) -> str:
    """Format username as UPN (<user>@<domain>) when neither NETBIOS\\ nor @ is present."""
    if "\\" in username or "@" in username or not domain:
        return username
    return f"{username}@{domain}"


def enumerate_smb_shares_sync(server: str, username: str, password: str, domain: str = "") -> list[tuple[str, int]]:
    """Query regular disk shares on a file server over SMBv2/3 \\IPC$\\srvsvc using smbprotocol."""
    import smbclient

    smb_user = format_smb_username(username, domain)
    pipe_path = f"\\\\{server}\\IPC$\\srvsvc"
    smbclient.register_session(server, username=smb_user, password=password, connection_timeout=5)
    with smbclient.open_file(
        pipe_path,
        mode="r+b",
        buffering=0,
        file_type="pipe",
        username=smb_user,
        password=password,
        connection_timeout=5,
    ) as pipe:
        pending = bytearray()
        pipe.write(_build_srvsvc_bind_pdu(call_id=1))
        _ptype, _flags, _auth, ack_pdu = _read_exact_dce_pdu(pipe, pending)
        _verify_bind_ack(ack_pdu)

        pipe.write(_build_netr_share_enum_request(server, call_id=2))
        stub = _read_dce_response_stub(pipe, pending)
        return _parse_netr_share_enum_stub(stub)


class ShareDiscoveryService:
    """Maintains a cached catalog of business shares from GPOs and live SMB file servers."""

    def __init__(
        self,
        ad: AdBackend,
        sysvol: SysvolBackend,
        policy: PolicyConfig,
        file_servers: list[str],
        smb_username: str,
        smb_password: str,
        domain: str,
        cache_ttl_sec: int = 600,
        smb_scanner: Optional[Callable[[str, str, str, str], list[tuple[str, int]]]] = None,
    ) -> None:
        self.ad = ad
        self.sysvol = sysvol
        self.policy = policy
        self.file_servers = file_servers
        self.smb_username = smb_username
        self.smb_password = smb_password
        self.domain = domain
        self.cache_ttl_sec = cache_ttl_sec
        self._smb_scanner = smb_scanner or enumerate_smb_shares_sync
        self._cache: list[ShareInfo] = []
        self._cache_ts: float = 0.0
        self._lock = asyncio.Lock()

    async def get_shares(self, force_refresh: bool = False) -> list[ShareInfo]:
        now = time.monotonic()
        if not force_refresh and self._cache and (now - self._cache_ts) < self.cache_ttl_sec:
            return list(self._cache)

        async with self._lock:
            now = time.monotonic()
            if not force_refresh and self._cache and (now - self._cache_ts) < self.cache_ttl_sec:
                return list(self._cache)

            shares = await self._rebuild_catalog()
            self._cache = shares
            self._cache_ts = time.monotonic()
            return list(shares)

    async def search_shares(self, query: str, limit: int = 30) -> list[ShareInfo]:
        shares = await self.get_shares()
        q = query.strip().lower()
        if not q:
            return shares[:limit]
        scored: list[tuple[int, ShareInfo]] = []
        for s in shares:
            if q == s.share_name.lower() or q == s.label.lower():
                scored.append((0, s))
            elif s.share_name.lower().startswith(q) or s.label.lower().startswith(q):
                scored.append((1, s))
            elif q in s.unc_path.lower() or q in s.label.lower():
                scored.append((2, s))
        scored.sort(key=lambda item: (item[0], item[1].label.lower(), item[1].unc_path.lower()))
        return [item[1] for item in scored[:limit]]

    async def _rebuild_catalog(self) -> list[ShareInfo]:
        # 1. Harvest existing DriveMap GPO rules (canonical casing, labels, default letters).
        gpo_shares: dict[str, dict] = {}
        try:
            gpos = await self.ad.list_drivemap_gpos()
        except Exception as exc:
            logger.warning("Failed listing DriveMap GPOs during share discovery: %s", exc)
            gpos = []

        for gpo in gpos:
            try:
                raw_xml = await self.sysvol.read_drives_xml(gpo.guid)
            except Exception as exc:
                logger.warning("Failed reading Drives.xml for %s: %s", gpo.display_name, exc)
                continue
            if not raw_xml:
                continue
            for rule in parse_drives_xml(raw_xml, gpo.display_name, gpo.guid):
                if rule.action == "D" or not rule.path.startswith("\\\\"):
                    continue
                key = rule.path.lower()
                parts = rule.path.lstrip("\\").split("\\", 2)
                srv = parts[0] if parts else ""
                sname = parts[1] if len(parts) > 1 else ""
                if self.policy.is_share_blacklisted(sname):
                    continue
                bucket = gpo_shares.setdefault(
                    key,
                    {
                        "server": srv,
                        "share_name": sname,
                        "unc_path": rule.path,
                        "labels": [],
                        "letters": [],
                        "gpos": set(),
                    },
                )
                if rule.label:
                    bucket["labels"].append(rule.label)
                if rule.letter and rule.letter not in self.policy.protected_letters:
                    bucket["letters"].append(rule.letter)
                bucket["gpos"].add(gpo.display_name)

        # 2. Scan live SMB file servers via SRVSVC NetrShareEnum (type == 0 -> regular non-special disk shares).
        smb_shares: dict[str, tuple[str, str]] = {}
        for server in self.file_servers:
            try:
                discovered = await asyncio.to_thread(
                    self._smb_scanner,
                    server,
                    self.smb_username,
                    self.smb_password,
                    self.domain,
                )
            except Exception as exc:
                logger.warning("SMB share enumeration failed for %s: %s", server, exc)
                continue

            for share_name, stype in discovered:
                # 0 == STYPE_DISKTREE without STYPE_SPECIAL (0x80000000) or IPC/PRINTQ.
                if stype != 0 or self.policy.is_share_blacklisted(share_name):
                    continue
                unc = f"\\\\{server}\\{share_name}"
                smb_shares[unc.lower()] = (server, share_name)

        merged: list[ShareInfo] = []
        seen_keys: set[str] = set()

        for key, meta in gpo_shares.items():
            seen_keys.add(key)
            override = self.policy.custom_label_overrides.get(key)
            label = (override[0] if override and override[0] else "") or (
                meta["labels"][0] if meta["labels"] else meta["share_name"].rstrip("$")
            )
            pref_letter = (override[1] if override and override[1] else "") or (
                meta["letters"][0] if meta["letters"] else ""
            )
            source = "BOTH" if key in smb_shares else "GPO"
            merged.append(
                ShareInfo(
                    server=meta["server"],
                    share_name=meta["share_name"],
                    unc_path=meta["unc_path"],
                    label=label,
                    suggested_letter=pref_letter,
                    source=source,
                    dept_gpos=tuple(sorted(meta["gpos"])),
                )
            )

        for key, (server, share_name) in smb_shares.items():
            if key in seen_keys:
                continue
            unc = f"\\\\{server}\\{share_name}"
            override = self.policy.custom_label_overrides.get(key)
            label = (override[0] if override and override[0] else "") or share_name.rstrip("$")
            pref_letter = override[1] if override and override[1] else ""
            merged.append(
                ShareInfo(
                    server=server,
                    share_name=share_name,
                    unc_path=unc,
                    label=label,
                    suggested_letter=pref_letter,
                    source="SMB",
                )
            )

        # Prioritize GPO-known / BOTH shares first, then alphabetical.
        merged.sort(key=lambda s: (0 if s.source in ("BOTH", "GPO") else 1, s.label.lower(), s.unc_path.lower()))
        return merged

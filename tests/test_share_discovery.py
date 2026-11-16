"""Unit tests for share catalog merging, blacklisting, and search ranking."""

from __future__ import annotations

import struct
import pytest

from drivemap.config import PolicyConfig
from drivemap.services.share_discovery import (
    ShareDiscoveryService,
    _build_netr_share_enum_request,
    _build_srvsvc_bind_pdu,
    _ndr_pack_wchar_ptr,
    _parse_netr_share_enum_stub,
    _read_dce_response_stub,
    _verify_bind_ack,
)
from tests.test_drivemap_engine import FakeAdBackend, FakeSysvolBackend


@pytest.mark.asyncio
async def test_share_discovery_merges_gpo_and_smb_filters_blacklist() -> None:
    ad = FakeAdBackend()
    sysvol = FakeSysvolBackend()
    policy = PolicyConfig(
        share_blacklist_regexes=(
            __import__("re").compile(r"^ADMIN\$$", __import__("re").IGNORECASE),
            __import__("re").compile(r"^TEMP\d+$", __import__("re").IGNORECASE),
            __import__("re").compile(r"^SoftWare$", __import__("re").IGNORECASE),
        )
    )

    def fake_smb_scan(server: str, username: str, password: str, domain: str):
        if server == "FS01":
            return [
                ("ADMIN$", 0x80000000),
                ("C$", 0x80000000),
                ("TEMP1", 0),
                ("SoftWare", 0),
                ("Public", 0),
                ("Audit$", 0),
            ]
        return []

    svc = ShareDiscoveryService(
        ad=ad,
        sysvol=sysvol,
        policy=policy,
        file_servers=["FS01"],
        smb_username="svc",
        smb_password="pw",
        domain="corp.example.com",
        smb_scanner=fake_smb_scan,
    )

    shares = await svc.get_shares()
    names = {s.share_name for s in shares}
    assert "ADMIN$" not in names
    assert "C$" not in names
    assert "TEMP1" not in names
    assert "SoftWare" not in names
    assert "Public" in names
    assert "Audit$" in names

    public_entry = next(s for s in shares if s.share_name == "Public")
    assert public_entry.source == "BOTH"
    assert public_entry.suggested_letter == "P"

    search_hits = await svc.search_shares("audit")
    assert len(search_hits) == 1
    assert search_hits[0].unc_path == r"\\FS01\Audit$"


def test_srvsvc_bind_and_request_wire_format() -> None:
    bind_pdu = _build_srvsvc_bind_pdu(call_id=1)
    assert len(bind_pdu) == 72
    assert bind_pdu[2] == 11  # BIND
    assert struct.unpack_from("<H", bind_pdu, 8)[0] == 72

    sec_addr = b"\\pipe\\srvsvc\x00"  # 13 bytes -> 26+13=39 -> aligned to 40
    ack_hdr = struct.pack("<BBBB4sHHI", 5, 0, 12, 0x03, b"\x10\x00\x00\x00", 68, 0, 1)
    ack_body = struct.pack("<HHI", 4280, 4280, 1234) + struct.pack("<H", len(sec_addr)) + sec_addr + b"\x00"
    ack_res = struct.pack("<B3xHH", 1, 0, 0) + (b"\x00" * 20)
    _verify_bind_ack(ack_hdr + ack_body + ack_res)

    req_pdu = _build_netr_share_enum_request("FS01", call_id=2)
    assert req_pdu[2] == 0  # REQUEST
    assert struct.unpack_from("<H", req_pdu, 22)[0] == 15  # NetrShareEnum opnum 15


def test_srvsvc_parse_stub_and_multifragment_reassembly() -> None:
    stub = bytearray()
    stub += struct.pack("<III", 1, 1, 0x00020000)  # Level=1, Switch=1, Container ref
    stub += struct.pack("<II", 2, 0x00020004)     # EntriesRead=2, Buffer ref
    stub += struct.pack("<I", 2)                  # MaxCount=2
    stub += struct.pack("<III", 0x00020008, 0x00000000, 0x0002000C)  # Public + remark
    stub += struct.pack("<III", 0x00020010, 0x80000003, 0x00000000)  # IPC$ + NULL remark
    stub += _ndr_pack_wchar_ptr("Public", 0)[4:]
    stub += _ndr_pack_wchar_ptr("Shared files", 0)[4:]
    stub += _ndr_pack_wchar_ptr("IPC$", 0)[4:]
    stub += struct.pack("<III", 2, 0, 0)          # TotalEntries=2, ResumeHandle=NULL, Return=0 (NERR_Success)

    mid = len(stub) // 2
    frag1_stub, frag2_stub = bytes(stub[:mid]), bytes(stub[mid:])
    pdu1 = struct.pack("<BBBB4sHHI", 5, 0, 2, 0x01, b"\x10\x00\x00\x00", 24 + len(frag1_stub), 0, 2) + struct.pack("<IHBB", len(stub), 0, 0, 0) + frag1_stub
    pdu2 = struct.pack("<BBBB4sHHI", 5, 0, 2, 0x02, b"\x10\x00\x00\x00", 24 + len(frag2_stub), 0, 2) + struct.pack("<IHBB", len(frag2_stub), 0, 0, 0) + frag2_stub

    class _FakePipe:
        def __init__(self, chunks: list[bytes]) -> None:
            self._stream = b"".join(chunks)

        def read(self, n: int) -> bytes:
            out, self._stream = self._stream[:n], self._stream[n:]
            return out

    reassembled = _read_dce_response_stub(_FakePipe([pdu1 + pdu2]), bytearray())
    shares = _parse_netr_share_enum_stub(reassembled)
    assert shares == [("Public", 0x00000000), ("IPC$", 0x80000003)]

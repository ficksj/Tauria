"""Unit tests for DriveMap XML parsing, RSOP conflict guard, and transactional mutations."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

import pytest

from drivemap.config import PolicyConfig
from drivemap.models import ADGroup, ADUser, GpoInfo, ResolvedSid
from drivemap.services.audit_db import AuditRepository
from drivemap.services.drivemap_engine import (
    DriveMapConflictError,
    DriveMapEngine,
    DriveMapValidationError,
    apply_assign_to_drives_xml,
    apply_unassign_to_drives_xml,
    empty_drives_xml_bytes,
    parse_drives_xml,
    validate_unc_path,
)
from drivemap.services.smb_sysvol import parse_gpt_ini_version, update_gpt_ini_version


DOM_SAMPLE_XML = """<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="P:" status="P:" image="0" uid="{11111111-1111-1111-1111-111111111111}" userContext="1" bypassErrors="1">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\\\FS01\\Public" label="Public" persistent="1" useLetter="1" letter="P" />
  </Drive>
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="W:" status="W:" image="0" uid="{22222222-2222-2222-2222-222222222222}" userContext="1" bypassErrors="1">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\\\FS01\\HelpDesk" label="HelpDesk" persistent="1" useLetter="1" letter="W" />
  </Drive>
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="J:" status="J:" image="0" uid="{33333333-3333-3333-3333-333333333333}" userContext="1" bypassErrors="1">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\\\FS01\\Transfer$" label="Transfer" persistent="1" useLetter="1" letter="J" />
    <Filters>
      <FilterOrgUnit bool="OR" not="0" name="OU=Sales,OU=Departments,OU=Users,DC=corp,DC=example,DC=com" userContext="1" directMember="0" />
      <FilterUser bool="OR" not="0" name="CORP\\mgreen" sid="S-1-5-21-100-200-300-1002" userContext="1" />
    </Filters>
  </Drive>
</Drives>
""".encode("utf-8")

IT_OU_XML = """<?xml version="1.0" encoding="utf-8"?>
<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">
  <Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="Z:" status="Z:" image="0" uid="{44444444-4444-4444-4444-444444444444}" userContext="1" bypassErrors="1">
    <Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\\\FS01\\IT$" label="IT" persistent="1" useLetter="1" letter="Z" />
  </Drive>
</Drives>
""".encode("utf-8")


class FakeAdBackend:
    def __init__(self, fail_next_version_write: bool = False) -> None:
        self.gpos = {
            "DOM-CFG-MapNetworkDrives": GpoInfo(
                guid="{DOM-GUID-1111}",
                display_name="DOM-CFG-MapNetworkDrives",
                distinguished_name="CN={DOM-GUID-1111},CN=Policies,CN=System,DC=corp,DC=example,DC=com",
                version_number=655364,
            ),
            "OU-IT-CFG-DriveMaps-U": GpoInfo(
                guid="{IT-GUID-2222}",
                display_name="OU-IT-CFG-DriveMaps-U",
                distinguished_name="CN={IT-GUID-2222},CN=Policies,CN=System,DC=corp,DC=example,DC=com",
                version_number=65536,
            ),
            "USR-CFG-DriveMaps-PerUser-U": GpoInfo(
                guid="{USR-GUID-3333}",
                display_name="USR-CFG-DriveMaps-PerUser-U",
                distinguished_name="CN={USR-GUID-3333},CN=Policies,CN=System,DC=corp,DC=example,DC=com",
                version_number=65536,
            ),
        }
        self.fail_next_version_write = fail_next_version_write

    async def search_users(self, query: str, limit: int = 20) -> list[ADUser]:
        return []

    async def get_user_by_sam(self, sam_account_name: str) -> Optional[ADUser]:
        return None

    async def get_gpo_by_name(self, display_name: str) -> Optional[GpoInfo]:
        return self.gpos.get(display_name)

    async def list_drivemap_gpos(self, extra_names: tuple[str, ...] = ()) -> list[GpoInfo]:
        return list(self.gpos.values())

    async def get_applicable_gpo_guids_for_user(self, user: ADUser) -> list[str]:
        guids = ["{DOM-GUID-1111}", "{USR-GUID-3333}"]
        if "OU=IT," in user.distinguished_name:
            guids.append("{IT-GUID-2222}")
        return guids

    async def set_gpo_version(self, gpo_dn: str, new_version: int) -> None:
        if self.fail_next_version_write:
            self.fail_next_version_write = False
            raise RuntimeError("Simulated LDAPS write failure")
        for k, g in self.gpos.items():
            if g.distinguished_name == gpo_dn:
                self.gpos[k] = GpoInfo(
                    guid=g.guid,
                    display_name=g.display_name,
                    distinguished_name=g.distinguished_name,
                    version_number=new_version,
                )

    async def resolve_sids(self, sids: Sequence[str]) -> dict[str, ResolvedSid]:
        return {}

    async def get_group(self, identifier: str) -> Optional[ADGroup]:
        return None

    async def get_group_members(self, group_dn: str, limit: int = 200) -> list[ADUser]:
        return []

    async def add_user_to_group(self, group_dn: str, user_dn: str) -> bool:
        return False

    async def remove_user_from_group(self, group_dn: str, user_dn: str) -> bool:
        return False

    async def user_in_any_group_transitive(self, user_dn: str, group_dns: Sequence[str]) -> set[str]:
        return set()


class FakeSysvolBackend:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {
            "{DOM-GUID-1111}": DOM_SAMPLE_XML,
            "{IT-GUID-2222}": IT_OU_XML,
            "{USR-GUID-3333}": empty_drives_xml_bytes(),
        }
        self.gpts: dict[str, str] = {
            "{USR-GUID-3333}": "[General]\r\nVersion=65536\r\ndisplayName=USR-CFG-DriveMaps-PerUser-U\r\n"
        }

    async def read_drives_xml(self, gpo_guid: str) -> Optional[bytes]:
        return self.files.get(gpo_guid.upper())

    async def read_gpt_ini(self, gpo_guid: str) -> Optional[str]:
        return self.gpts.get(gpo_guid.upper())

    async def write_gpo_files_atomic(
        self,
        gpo_guid: str,
        drives_xml: bytes,
        gpt_ini_text: str,
        backup_root: Path,
        tx_id: str,
    ) -> Path:
        bdir = backup_root / tx_id
        bdir.mkdir(parents=True, exist_ok=True)
        (bdir / "Drives.xml").write_bytes(self.files[gpo_guid.upper()])
        (bdir / "GPT.INI").write_text(self.gpts[gpo_guid.upper()], encoding="utf-8")
        self.files[gpo_guid.upper()] = drives_xml
        self.gpts[gpo_guid.upper()] = gpt_ini_text
        return bdir

    async def restore_from_backup(self, gpo_guid: str, backup_dir: Path) -> None:
        self.files[gpo_guid.upper()] = (backup_dir / "Drives.xml").read_bytes()
        self.gpts[gpo_guid.upper()] = (backup_dir / "GPT.INI").read_text(encoding="utf-8")


@pytest.fixture
def it_user() -> ADUser:
    return ADUser(
        sam_account_name="jdoe",
        display_name="John Doe",
        distinguished_name="CN=John Doe,OU=IT,OU=Departments,OU=Users,DC=corp,DC=example,DC=com",
        sid="S-1-5-21-100-200-300-1001",
    )


@pytest.fixture
def mgreen_user() -> ADUser:
    return ADUser(
        sam_account_name="mgreen",
        display_name="Maria Green",
        distinguished_name="CN=Maria Green,OU=Finance,OU=Users,DC=corp,DC=example,DC=com",
        sid="S-1-5-21-100-200-300-1002",
    )


def test_unc_validation_rejects_bad_paths() -> None:
    assert validate_unc_path(r"\\FS01\BI$\\") == r"\\FS01\BI$"
    assert validate_unc_path(r"\\FS01\BI$\2026 Reports") == r"\\FS01\BI$\2026 Reports"
    with pytest.raises(DriveMapValidationError):
        validate_unc_path(r"C:\Temp")
    with pytest.raises(DriveMapValidationError):
        validate_unc_path(r"\\FS01\Share\..\Secret")
    with pytest.raises(DriveMapValidationError):
        validate_unc_path(r"\\FS01\bad;cmd")


def test_gpt_ini_version_helpers() -> None:
    txt = "[General]\r\nVersion=655364\r\ndisplayName=Test\r\n"
    assert parse_gpt_ini_version(txt) == 655364
    updated = update_gpt_ini_version(txt, 720900, "Test")
    assert parse_gpt_ini_version(updated) == 720900
    assert "\r\n" in updated


def test_xml_assign_dedup_and_unassign(it_user: ADUser, mgreen_user: ADUser) -> None:
    xml1 = apply_assign_to_drives_xml(empty_drives_xml_bytes(), it_user, "CORP", r"\\FS01\BI$", "G", "BI")
    xml2 = apply_assign_to_drives_xml(xml1, mgreen_user, "CORP", r"\\FS01\BI$", "G", "BI")
    rules = parse_drives_xml(xml2)
    assert len(rules) == 1
    assert len(rules[0].filters) == 2
    assert {f.sid for f in rules[0].filters} == {it_user.sid, mgreen_user.sid}

    # Unassign one user keeps the other intact.
    xml3, changed = apply_unassign_to_drives_xml(xml2, it_user, "CORP", "G", delete_persistent=False)
    assert changed is True
    rules_after_one = parse_drives_xml(xml3)
    assert len(rules_after_one) == 1
    assert [f.sid for f in rules_after_one[0].filters] == [mgreen_user.sid]

    # Unassign last user with delete_persistent creates action="D" tombstone cleanly.
    xml4, changed2 = apply_unassign_to_drives_xml(xml3, mgreen_user, "CORP", "G", delete_persistent=True)
    assert changed2 is True
    rules_after_del = parse_drives_xml(xml4)
    assert len(rules_after_del) == 1
    assert rules_after_del[0].action == "D"
    assert rules_after_del[0].letter == "G"


@pytest.mark.asyncio
async def test_conflict_guard_and_free_letter_suggestion(tmp_path: Path, it_user: ADUser, mgreen_user: ADUser) -> None:
    ad = FakeAdBackend()
    sysvol = FakeSysvolBackend()
    audit = AuditRepository(tmp_path / "audit.db", tmp_path / "audit.jsonl")
    await audit.init()

    engine = DriveMapEngine(
        ad=ad,
        sysvol=sysvol,
        audit=audit,
        policy=PolicyConfig(),
        target_gpo_name="USR-CFG-DriveMaps-PerUser-U",
        netbios_domain="CORP",
        backup_dir=tmp_path / "backups",
        dry_run=False,
    )

    matrix = {c.letter: c for c in await engine.get_letter_matrix(it_user)}
    assert matrix["A"].status == "PROTECTED"
    assert matrix["P"].status == "CONFLICT_GLOBAL"
    assert matrix["W"].status == "CONFLICT_GLOBAL"
    assert matrix["Z"].status == "CONFLICT_OU"
    assert matrix["G"].status == "FREE"
    assert matrix["J"].status == "FREE"  # Transfer$ OU filter doesn't apply to IT user

    # If share prefers Z: (conflict with IT department), engine recommends G:
    rec = engine.choose_recommended_letter(list(matrix.values()), preferred_letter="Z")
    assert rec == "G"

    # Attempting to assign Z: must raise DriveMapConflictError
    with pytest.raises(DriveMapConflictError):
        await engine.assign_drive(it_user, r"\\FS01\BI$", "Z", "BI", 100000001, "admin")

    # mgreen already has FilterUser J: from DOM-CFG-MapNetworkDrives
    mg_matrix = {c.letter: c for c in await engine.get_letter_matrix(mgreen_user)}
    assert mg_matrix["J"].status == "MAPPED_PER_USER"

    # Assigning free G: succeeds and bumps GPO version in both AD and GPT.INI
    res = await engine.assign_drive(it_user, r"\\FS01\BI$", "G", "BI", 100000001, "admin")
    assert res.gpo_version_before == 65536
    assert res.gpo_version_after == 131072
    assert ad.gpos["USR-CFG-DriveMaps-PerUser-U"].version_number == 131072
    assert parse_gpt_ini_version(sysvol.gpts["{USR-GUID-3333}"]) == 131072

    # Rollback restores empty Drives.xml while advancing version safely
    rec_row = await audit.get_by_tx_id(res.tx_id)
    assert rec_row is not None
    rb = await engine.rollback_transaction(rec_row, 100000001, "admin")
    assert rb.gpo_version_after == 196608
    assert parse_drives_xml(sysvol.files["{USR-GUID-3333}"]) == []


@pytest.mark.asyncio
async def test_ad_failure_rolls_back_sysvol(tmp_path: Path, it_user: ADUser) -> None:
    ad = FakeAdBackend(fail_next_version_write=True)
    sysvol = FakeSysvolBackend()
    audit = AuditRepository(tmp_path / "audit.db", tmp_path / "audit.jsonl")
    await audit.init()

    engine = DriveMapEngine(
        ad=ad,
        sysvol=sysvol,
        audit=audit,
        policy=PolicyConfig(),
        target_gpo_name="USR-CFG-DriveMaps-PerUser-U",
        netbios_domain="CORP",
        backup_dir=tmp_path / "backups",
        dry_run=False,
    )

    with pytest.raises(RuntimeError, match="Simulated LDAPS write failure"):
        await engine.assign_drive(it_user, r"\\FS01\BI$", "G", "BI", 100000001, "admin")

    # SYSVOL must be restored cleanly to empty state and GPT.INI version unchanged
    assert parse_drives_xml(sysvol.files["{USR-GUID-3333}"]) == []
    assert parse_gpt_ini_version(sysvol.gpts["{USR-GUID-3333}"]) == 65536

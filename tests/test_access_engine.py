"""Unit tests for hybrid ShareAccessEngine (AD AGDLP groups + direct SMB NTFS ACL + rollback)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Sequence

import pytest
from smbprotocol.security_descriptor import AccessDeniedAce, SDControl, SIDPacket

from drivemap.config import PolicyConfig
from drivemap.models import ACCESS_NONE, ACCESS_RO, ACCESS_RW, ADGroup, ADUser, ResolvedSid
from drivemap.services.access_engine import AccessOperationError, ShareAccessEngine
from drivemap.services.audit_db import AuditRepository
from drivemap.services.smb_acl import RIGHT_MODIFY, build_dacl_only_sd_bytes, decode_sd_bytes, mutate_dacl_bytes


class FakeAccessAdBackend:
    def __init__(self) -> None:
        self.user_a = ADUser(
            sam_account_name="iivanov",
            display_name="Ivanov Ivan",
            distinguished_name="CN=Ivanov Ivan,OU=IT,OU=Users,DC=corp,DC=example,DC=com",
            sid="S-1-5-21-100-200-300-1001",
            department="IT",
        )
        self.user_b = ADUser(
            sam_account_name="apetrova",
            display_name="Petrova Anna",
            distinguished_name="CN=Petrova Anna,OU=Sales,OU=Users,DC=corp,DC=example,DC=com",
            sid="S-1-5-21-100-200-300-1002",
            department="Sales",
        )
        self.users_by_sam = {
            "iivanov": self.user_a,
            "apetrova": self.user_b,
        }
        self.groups: dict[str, ADGroup] = {
            "CN=Share_Finance_RO,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com": ADGroup(
                sam_account_name="Share_Finance_RO",
                distinguished_name="CN=Share_Finance_RO,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com",
                sid="S-1-5-21-100-200-300-5001",
            ),
            "CN=Share_Finance_RW,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com": ADGroup(
                sam_account_name="Share_Finance_RW",
                distinguished_name="CN=Share_Finance_RW,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com",
                sid="S-1-5-21-100-200-300-5002",
            ),
            "CN=Share_Projects_RW,OU=Groups,OU=Users,DC=corp,DC=example,DC=com": ADGroup(
                sam_account_name="Share_Projects_RW",
                distinguished_name="CN=Share_Projects_RW,OU=Groups,OU=Users,DC=corp,DC=example,DC=com",
                sid="S-1-5-21-100-200-300-5003",
                member_dns=(self.user_b.distinguished_name,),
            ),
            "CN=Dept_Sales,OU=Groups,OU=Users,DC=corp,DC=example,DC=com": ADGroup(
                sam_account_name="Dept_Sales",
                distinguished_name="CN=Dept_Sales,OU=Groups,OU=Users,DC=corp,DC=example,DC=com",
                sid="S-1-5-21-100-200-300-6001",
                member_dns=(self.user_b.distinguished_name,),
            ),
        }
        self.nested_membership: dict[tuple[str, str], bool] = {}

    async def resolve_sids(self, sids: Sequence[str]) -> dict[str, ResolvedSid]:
        out: dict[str, ResolvedSid] = {}
        wanted = {s.upper() for s in sids}
        for u in self.users_by_sam.values():
            if u.sid.upper() in wanted:
                out[u.sid.upper()] = ResolvedSid(
                    sid=u.sid,
                    sam_account_name=u.sam_account_name,
                    display_name=u.display_name,
                    principal_type="USER",
                    distinguished_name=u.distinguished_name,
                )
        for g in self.groups.values():
            if g.sid.upper() in wanted:
                out[g.sid.upper()] = ResolvedSid(
                    sid=g.sid,
                    sam_account_name=g.sam_account_name,
                    display_name=g.sam_account_name,
                    principal_type="GROUP",
                    distinguished_name=g.distinguished_name,
                    member_dns=g.member_dns,
                )
        return out

    async def get_group(self, identifier: str) -> Optional[ADGroup]:
        if identifier in self.groups:
            return self.groups[identifier]
        for g in self.groups.values():
            if g.sam_account_name.lower() == identifier.lower():
                return g
        return None

    async def get_group_members(self, group_dn: str, limit: int = 200) -> list[ADUser]:
        grp = self.groups.get(group_dn)
        if not grp:
            return []
        by_dn = {u.distinguished_name: u for u in self.users_by_sam.values()}
        return [by_dn[dn] for dn in grp.member_dns if dn in by_dn][:limit]

    async def add_user_to_group(self, group_dn: str, user_dn: str) -> bool:
        grp = self.groups[group_dn]
        if user_dn in grp.member_dns:
            return False
        self.groups[group_dn] = ADGroup(
            sam_account_name=grp.sam_account_name,
            distinguished_name=grp.distinguished_name,
            sid=grp.sid,
            member_dns=grp.member_dns + (user_dn,),
        )
        return True

    async def remove_user_from_group(self, group_dn: str, user_dn: str) -> bool:
        grp = self.groups[group_dn]
        if user_dn not in grp.member_dns:
            return False
        self.groups[group_dn] = ADGroup(
            sam_account_name=grp.sam_account_name,
            distinguished_name=grp.distinguished_name,
            sid=grp.sid,
            member_dns=tuple(m for m in grp.member_dns if m != user_dn),
        )
        return True

    async def user_in_any_group_transitive(self, user_dn: str, group_dns: Sequence[str]) -> set[str]:
        hits: set[str] = set()
        for gdn in group_dns:
            grp = self.groups.get(gdn)
            if grp and (user_dn in grp.member_dns or self.nested_membership.get((user_dn, gdn), False)):
                hits.add(gdn.lower())
        return hits

    async def search_users(self, query: str, limit: int = 20) -> list[ADUser]:
        return list(self.users_by_sam.values())

    async def get_user_by_sam(self, sam_account_name: str) -> Optional[ADUser]:
        return self.users_by_sam.get(sam_account_name)

    async def get_gpo_by_name(self, display_name: str):
        return None

    async def list_drivemap_gpos(self, extra_names: tuple[str, ...] = ()):
        return []

    async def get_applicable_gpo_guids_for_user(self, user: ADUser) -> list[str]:
        return []

    async def set_gpo_version(self, gpo_dn: str, new_version: int) -> None:
        return None


class FakeAclBackend:
    def __init__(self, ad: FakeAccessAdBackend) -> None:
        base = build_dacl_only_sd_bytes([], SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT)
        fin_sd, _ = mutate_dacl_bytes(base, "S-1-5-21-100-200-300-5001", ACCESS_RO)
        fin_sd, _ = mutate_dacl_bytes(fin_sd, "S-1-5-21-100-200-300-5002", ACCESS_RW)
        fin_sd, _ = mutate_dacl_bytes(fin_sd, "S-1-5-18", "FULL")

        proj_sd, _ = mutate_dacl_bytes(base, "S-1-5-21-100-200-300-5003", ACCESS_RW)
        proj_sd, _ = mutate_dacl_bytes(proj_sd, "S-1-5-21-100-200-300-6001", ACCESS_RO)

        helpdesk_sd, _ = mutate_dacl_bytes(base, ad.user_a.sid, ACCESS_RO)

        self.shares: dict[str, bytes] = {
            r"\\FS01\Finance": fin_sd,
            r"\\FS01\Projects": proj_sd,
            r"\\FS01\HelpDesk": helpdesk_sd,
        }

    async def read_root_sd(self, unc_path: str) -> bytes:
        if unc_path not in self.shares:
            raise PermissionError("STATUS_ACCESS_DENIED")
        return self.shares[unc_path]

    async def apply_access(
        self,
        unc_path: str,
        target_sid: str,
        level: str,
        backup_dir: Path,
        tx_id: str,
        *,
        max_propagate: int = 2500,
    ) -> tuple[Path, int, int, bool]:
        bdir = backup_dir / f"acl_test_{tx_id}"
        bdir.mkdir(parents=True, exist_ok=True)
        prev_sd = self.shares[unc_path]
        (bdir / "acl_backup.json").write_text(
            json.dumps({"unc_path": unc_path, "root_sd_hex": prev_sd.hex()}),
            encoding="utf-8",
        )
        new_sd, changed = mutate_dacl_bytes(prev_sd, target_sid, level)
        self.shares[unc_path] = new_sd
        return bdir, (3 if changed else 0), 0, False

    async def restore_snapshot(self, backup_dir: Path) -> int:
        payload = json.loads((backup_dir / "acl_backup.json").read_text(encoding="utf-8"))
        self.shares[payload["unc_path"]] = bytes.fromhex(payload["root_sd_hex"])
        return 1


def _make_engine(tmp_path: Path, *, dry_run: bool = False):
    ad = FakeAccessAdBackend()
    acl = FakeAclBackend(ad)
    audit = AuditRepository(db_path=tmp_path / "audit.db", jsonl_path=tmp_path / "audit.jsonl")
    policy = PolicyConfig()
    engine = ShareAccessEngine(
        ad=ad,
        acl=acl,
        audit=audit,
        policy=policy,
        netbios_domain="CORP",
        share_access_ou="OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com",
        backup_dir=tmp_path / "backups",
        dry_run=dry_run,
    )
    return engine, ad, acl, audit


@pytest.mark.asyncio
async def test_inspect_and_effective_check(tmp_path: Path) -> None:
    engine, ad, acl, audit = _make_engine(tmp_path)
    await audit.init()

    fin = await engine.inspect_share_access(r"\\FS01\Finance")
    assert fin.readable is True
    assert fin.ro_group is not None and fin.ro_group.sam_account_name == "Share_Finance_RO"
    assert fin.rw_group is not None and fin.rw_group.sam_account_name == "Share_Finance_RW"

    st_a = await engine.check_user_access(r"\\FS01\Finance", ad.user_a, report=fin)
    assert st_a.effective_level == ACCESS_NONE

    st_b_proj = await engine.check_user_access(r"\\FS01\Projects", ad.user_b)
    assert st_b_proj.effective_level == ACCESS_RW
    assert st_b_proj.blocked_by_protected_group is True  # Dept_Sales RO + Share_Projects_RW

    unreadable = await engine.inspect_share_access(r"\\FS01\Locked")
    assert unreadable.readable is False
    st_locked = await engine.check_user_access(r"\\FS01\Locked", ad.user_a, report=unreadable)
    assert st_locked.acl_readable is False
    assert st_locked.effective_level == "UNKNOWN"


@pytest.mark.asyncio
async def test_hybrid_ad_group_grant_upgrade_and_rollback(tmp_path: Path) -> None:
    engine, ad, acl, audit = _make_engine(tmp_path)
    await audit.init()

    r1 = await engine.grant_access(ad.user_a, r"\\FS01\Finance", ACCESS_RO, 1, "admin")
    assert r1.mechanism == "AD_GROUP"
    assert r1.group_name == "Share_Finance_RO"
    assert r1.requires_relogon is True
    assert ad.user_a.distinguished_name in ad.groups[
        "CN=Share_Finance_RO,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns

    r2 = await engine.grant_access(ad.user_a, r"\\FS01\Finance", ACCESS_RW, 1, "admin")
    assert r2.group_name == "Share_Finance_RW"
    assert ad.user_a.distinguished_name not in ad.groups[
        "CN=Share_Finance_RO,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns
    assert ad.user_a.distinguished_name in ad.groups[
        "CN=Share_Finance_RW,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns

    rec2 = await audit.get_by_tx_id(r2.tx_id)
    assert rec2 is not None
    await engine.rollback_access_transaction(rec2, 1, "admin")
    assert ad.user_a.distinguished_name in ad.groups[
        "CN=Share_Finance_RO,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns
    assert ad.user_a.distinguished_name not in ad.groups[
        "CN=Share_Finance_RW,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns


@pytest.mark.asyncio
async def test_missing_ro_group_falls_back_to_direct_ntfs_and_revokes(tmp_path: Path) -> None:
    engine, ad, acl, audit = _make_engine(tmp_path)
    await audit.init()

    res = await engine.grant_access(ad.user_b, r"\\FS01\Projects", ACCESS_RO, 1, "admin")
    assert res.mechanism == "NTFS_DIRECT"
    assert ad.user_b.distinguished_name not in ad.groups[
        "CN=Share_Projects_RW,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns
    dec = decode_sd_bytes(acl.shares[r"\\FS01\Projects"])
    assert any(a.sid == ad.user_b.sid and a.level == ACCESS_RO for a in dec.aces)

    rec = await audit.get_by_tx_id(res.tx_id)
    assert rec is not None
    await engine.rollback_access_transaction(rec, 1, "admin")
    dec_after = decode_sd_bytes(acl.shares[r"\\FS01\Projects"])
    assert not any(a.sid == ad.user_b.sid for a in dec_after.aces)
    assert ad.user_b.distinguished_name in ad.groups[
        "CN=Share_Projects_RW,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns


@pytest.mark.asyncio
async def test_ntfs_direct_revoke_and_safety_guards(tmp_path: Path) -> None:
    engine, ad, acl, audit = _make_engine(tmp_path)
    await audit.init()

    await engine.grant_access(ad.user_a, r"\\FS01\HelpDesk", ACCESS_RW, 1, "admin")
    assert (await engine.check_user_access(r"\\FS01\HelpDesk", ad.user_a)).effective_level == ACCESS_RW

    await engine.revoke_access(ad.user_a, r"\\FS01\HelpDesk", 1, "admin")
    assert (await engine.check_user_access(r"\\FS01\HelpDesk", ad.user_a)).effective_level == ACCESS_NONE

    protected = ADUser("Administrator", "Administrator", "CN=Administrator,DC=corp,DC=example,DC=com", "S-1-5-21-100-200-300-500")
    with pytest.raises(AccessOperationError):
        await engine.grant_access(protected, r"\\FS01\HelpDesk", ACCESS_RW, 1, "admin")

    await ad.remove_user_from_group("CN=Share_Projects_RW,OU=Groups,OU=Users,DC=corp,DC=example,DC=com", ad.user_b.distinguished_name)
    with pytest.raises(AccessOperationError):
        await engine.revoke_access(ad.user_b, r"\\FS01\Projects", 1, "admin")


@pytest.mark.asyncio
async def test_dry_run_makes_no_mutations(tmp_path: Path) -> None:
    engine, ad, acl, audit = _make_engine(tmp_path, dry_run=True)
    await audit.init()

    before_sd = acl.shares[r"\\FS01\HelpDesk"]
    res = await engine.grant_access(ad.user_b, r"\\FS01\HelpDesk", ACCESS_RW, 1, "admin")
    assert res.dry_run is True
    assert acl.shares[r"\\FS01\HelpDesk"] == before_sd

    res_grp = await engine.grant_access(ad.user_a, r"\\FS01\Finance", ACCESS_RO, 1, "admin")
    assert res_grp.dry_run is True
    assert ad.user_a.distinguished_name not in ad.groups[
        "CN=Share_Finance_RO,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com"
    ].member_dns


@pytest.mark.asyncio
async def test_deny_ace_detected_in_effective_status(tmp_path: Path) -> None:
    engine, ad, acl, audit = _make_engine(tmp_path)
    await audit.init()

    deny = AccessDeniedAce()
    sid_pkt = SIDPacket()
    sid_pkt.from_string(ad.user_a.sid)
    deny["ace_flags"].set_value(0)
    deny["mask"].set_value(RIGHT_MODIFY)
    deny["sid"] = sid_pkt
    acl.shares[r"\\FS01\Finance"] = build_dacl_only_sd_bytes([deny], SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT)

    st = await engine.check_user_access(r"\\FS01\Finance", ad.user_a)
    assert st.effective_level == "DENY"

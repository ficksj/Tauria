"""Hybrid file share access orchestrator (AD security groups + direct SMB NTFS ACL fallback)."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from drivemap.config import PolicyConfig
from drivemap.models import (
    ACCESS_FULL,
    ACCESS_NONE,
    ACCESS_RO,
    ACCESS_RW,
    AccessMutationResult,
    ADGroup,
    ADUser,
    AuditRecord,
    ShareAccessReport,
    ShareAclEntry,
    UserShareAccessStatus,
)
from drivemap.services.ad_ldap import AdBackend
from drivemap.services.audit_db import AuditRepository
from drivemap.services.drivemap_engine import validate_sid, validate_unc_path
from drivemap.services.smb_acl import WELL_KNOWN_SID_NAMES, AclBackend, decode_sd_bytes

logger = logging.getLogger(__name__)

_LEVEL_RANK = {
    ACCESS_NONE: 0,
    "CUSTOM": 1,
    ACCESS_RO: 2,
    ACCESS_RW: 3,
    ACCESS_FULL: 4,
    "DENY": 99,
}


class AccessOperationError(RuntimeError):
    """Raised when a share access grant, revoke, or rollback fails policy or permission checks."""


def _ad_backup_write(backup_root: Path, tx_id: str, payload: dict) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    bdir = backup_root / f"ad_acl_{stamp}_{tx_id}"
    bdir.mkdir(parents=True, exist_ok=True)
    (bdir / "ad_access.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return bdir


class ShareAccessEngine:
    """Inspects live share ACLs and grants/revokes access via AD groups or direct NTFS ACLs."""

    def __init__(
        self,
        ad: AdBackend,
        acl: AclBackend,
        audit: AuditRepository,
        policy: PolicyConfig,
        netbios_domain: str,
        share_access_ou: str,
        backup_dir: Path,
        *,
        max_propagate: int = 2500,
        dry_run: bool = False,
    ) -> None:
        self.ad = ad
        self.acl = acl
        self.audit = audit
        self.policy = policy
        self.netbios_domain = netbios_domain
        self.share_access_ou = share_access_ou
        self.backup_dir = backup_dir
        self.max_propagate = max_propagate
        self.dry_run = dry_run
        self._lock = asyncio.Lock()

    async def inspect_share_access(self, unc_path: str) -> ShareAccessReport:
        """Read live NTFS DACL from a share and resolve AD principals and manageable access groups."""
        clean_unc = validate_unc_path(unc_path)
        try:
            sd_bytes = await self.acl.read_root_sd(clean_unc)
        except Exception as exc:
            logger.warning("Failed reading SD on %s: %s", clean_unc, exc)
            return ShareAccessReport(unc_path=clean_unc, readable=False, error=str(exc))

        decoded = decode_sd_bytes(sd_bytes)
        unknown_sids = [a.sid for a in decoded.aces if a.sid.upper() not in WELL_KNOWN_SID_NAMES]
        resolved_map = await self.ad.resolve_sids(unknown_sids) if unknown_sids else {}

        entries: list[ShareAclEntry] = []
        ro_group: Optional[ADGroup] = None
        rw_group: Optional[ADGroup] = None

        seen_keys: set[tuple[str, bool, int, bool]] = set()
        for ace in decoded.aces:
            key = (ace.sid.upper(), ace.is_deny, ace.mask, ace.is_inherited)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            sid_up = ace.sid.upper()
            info = resolved_map.get(sid_up)
            if info is not None:
                sam = info.sam_account_name
                display = info.display_name or sam
                ptype = info.principal_type
                dn = info.distinguished_name
                desc = info.description
                members = info.member_dns
                pname = f"{self.netbios_domain}\\{sam}"
            elif sid_up in WELL_KNOWN_SID_NAMES:
                pname = WELL_KNOWN_SID_NAMES[sid_up]
                sam = pname.split("\\", 1)[-1]
                display = pname
                ptype = "WELLKNOWN"
                dn = ""
                desc = ""
                members = ()
            else:
                pname = ace.sid
                sam = ace.sid
                display = ace.sid
                ptype = "UNKNOWN"
                dn = ""
                desc = ""
                members = ()

            is_prot = self.policy.is_protected_acl_principal(ace.sid, pname) or (
                ptype == "WELLKNOWN"
            )
            is_mg = (
                ptype == "GROUP"
                and not is_prot
                and not ace.is_deny
                and self.policy.is_manageable_access_group(sam, dn, self.share_access_ou)
            )

            entry = ShareAclEntry(
                sid=ace.sid,
                principal_name=pname,
                display_name=display,
                principal_type=ptype,
                level=ace.level,
                is_deny=ace.is_deny,
                is_inherited=ace.is_inherited,
                raw_mask=ace.mask,
                raw_flags=ace.ace_flags,
                is_manageable_group=is_mg,
                is_protected=is_prot,
                group_dn=dn if ptype == "GROUP" else "",
                group_member_count=len(members) if ptype == "GROUP" else 0,
            )
            entries.append(entry)

            if is_mg and dn:
                grp_obj = ADGroup(
                    sam_account_name=sam,
                    distinguished_name=dn,
                    sid=ace.sid,
                    description=desc,
                    member_dns=members,
                )
                if ace.level == ACCESS_RO and ro_group is None:
                    ro_group = grp_obj
                elif ace.level in (ACCESS_RW, ACCESS_FULL) and rw_group is None:
                    rw_group = grp_obj

        def _display_sort(e: ShareAclEntry) -> tuple[int, int, str]:
            if e.is_manageable_group:
                bucket = 0
            elif e.principal_type == "USER" and not e.is_protected:
                bucket = 1
            elif e.principal_type == "GROUP" and not e.is_protected:
                bucket = 2
            else:
                bucket = 3
            return (bucket, 0 if e.is_deny else 1, e.display_name.lower())

        entries.sort(key=_display_sort)
        return ShareAccessReport(
            unc_path=clean_unc,
            readable=True,
            owner_sid=decoded.owner_sid,
            entries=tuple(entries),
            ro_group=ro_group,
            rw_group=rw_group,
        )

    async def check_user_access(
        self,
        unc_path: str,
        user: ADUser,
        *,
        report: Optional[ShareAccessReport] = None,
    ) -> UserShareAccessStatus:
        """Evaluate user's effective NTFS/group access on unc_path."""
        clean_unc = validate_unc_path(unc_path)
        rep = report or await self.inspect_share_access(clean_unc)
        if not rep.readable:
            return UserShareAccessStatus(
                user=user,
                unc_path=clean_unc,
                effective_level="UNKNOWN",
                acl_readable=False,
            )

        direct_member_dns = {dn.lower() for dn in user.member_of_dns}
        candidate_group_dns = [
            e.group_dn
            for e in rep.entries
            if e.group_dn and e.group_dn.lower() not in direct_member_dns
        ]
        nested_hits = (
            await self.ad.user_in_any_group_transitive(user.distinguished_name, candidate_group_dns)
            if (candidate_group_dns and user.distinguished_name)
            else set()
        )
        all_user_groups = direct_member_dns | nested_hits

        best_rank = 0
        best_level = ACCESS_NONE
        has_deny = False
        direct_rank = 0
        direct_level = ACCESS_NONE
        can_revoke_direct = False
        sources: list[str] = []
        manageable_member_dns: list[str] = []
        has_protected_grant = False

        for entry in rep.entries:
            matched = False
            src_label = ""
            if entry.sid.upper() == user.sid.upper():
                matched = True
                src_label = f"Прямой NTFS: {entry.level}"
                if not entry.is_deny and not entry.is_inherited:
                    can_revoke_direct = True
                if not entry.is_deny and _LEVEL_RANK.get(entry.level, 0) > direct_rank:
                    direct_rank = _LEVEL_RANK.get(entry.level, 0)
                    direct_level = entry.level
            elif entry.sid.upper() in ("S-1-1-0", "S-1-5-11") or entry.sid.endswith("-513"):
                matched = True
                src_label = f"Общая группа {entry.principal_name} ({entry.level})"
                if not entry.is_deny:
                    has_protected_grant = True
            elif entry.group_dn and entry.group_dn.lower() in all_user_groups:
                matched = True
                src_label = f"Группа {entry.display_name} ({entry.level})"
                if entry.is_manageable_group:
                    if entry.group_dn.lower() in direct_member_dns or user.distinguished_name.lower() in {
                        m.lower() for m in ((rep.ro_group.member_dns if rep.ro_group and rep.ro_group.distinguished_name.lower() == entry.group_dn.lower() else ()) or (rep.rw_group.member_dns if rep.rw_group and rep.rw_group.distinguished_name.lower() == entry.group_dn.lower() else ()))
                    }:
                        manageable_member_dns.append(entry.group_dn)
                        can_revoke_direct = True
                elif not entry.is_deny:
                    has_protected_grant = True

            if matched:
                if entry.is_deny:
                    has_deny = True
                    sources.append(f"⛔ ЗАПРЕТ ({entry.principal_name})")
                else:
                    sources.append(src_label)
                    rank = _LEVEL_RANK.get(entry.level, 0)
                    if rank > best_rank:
                        best_rank = rank
                        best_level = entry.level

        effective = "DENY" if has_deny else best_level
        dedup_sources = tuple(dict.fromkeys(sources))
        dedup_mg = tuple(dict.fromkeys(manageable_member_dns))
        return UserShareAccessStatus(
            user=user,
            unc_path=clean_unc,
            effective_level=effective,
            sources=dedup_sources,
            direct_level=direct_level,
            can_revoke_direct=can_revoke_direct,
            member_of_manageable_groups=dedup_mg,
            blocked_by_protected_group=has_protected_grant,
            acl_readable=True,
        )

    async def grant_access(
        self,
        user: ADUser,
        unc_path: str,
        level: str,
        tg_user_id: int,
        tg_username: str,
        *,
        mode: str = "AUTO",
    ) -> AccessMutationResult:
        """Grant RO or RW access to user on unc_path using AD group (preferred) or direct NTFS ACL."""
        clean_unc = validate_unc_path(unc_path)
        clean_sid = validate_sid(user.sid)
        clean_level = level.strip().upper()
        if clean_level not in (ACCESS_RO, ACCESS_RW):
            raise AccessOperationError(f"Неподдерживаемый уровень доступа: {level!r}")
        if self.policy.is_protected_acl_principal(clean_sid, user.sam_account_name):
            raise AccessOperationError(f"Учётная запись '{user.sam_account_name}' защищена политикой безопасности.")

        async with self._lock:
            tx_id = uuid.uuid4().hex[:10]
            report = await self.inspect_share_access(clean_unc)
            if not report.readable:
                raise AccessOperationError(
                    f"Нет прав чтения/изменения ACL на {clean_unc}: {report.error}. "
                    "Запустите Initialize-ShareAccessDelegation.ps1 от имени администратора домена."
                )

            status = await self.check_user_access(clean_unc, user, report=report)
            target_group: Optional[ADGroup] = None
            if mode in ("AUTO", "AD_GROUP"):
                target_group = report.ro_group if clean_level == ACCESS_RO else report.rw_group
                if mode == "AD_GROUP" and target_group is None:
                    raise AccessOperationError(
                        f"В ACL {clean_unc} не найдена управляемая AD-группа уровня {clean_level}."
                    )

            ad_actions: list[dict[str, str]] = []
            notes: list[str] = []

            if target_group is not None and mode != "NTFS_DIRECT":
                opposite_group = report.rw_group if clean_level == ACCESS_RO else report.ro_group
                removed_opp = False
                if opposite_group and opposite_group.distinguished_name.lower() != target_group.distinguished_name.lower():
                    if opposite_group.distinguished_name in status.member_of_manageable_groups:
                        if not self.dry_run:
                            removed_opp = await self.ad.remove_user_from_group(
                                opposite_group.distinguished_name, user.distinguished_name
                            )
                        else:
                            removed_opp = True
                        if removed_opp:
                            ad_actions.append(
                                {
                                    "action": "REMOVE",
                                    "group_dn": opposite_group.distinguished_name,
                                    "group_sam": opposite_group.sam_account_name,
                                    "user_dn": user.distinguished_name,
                                }
                            )
                            notes.append(f"Убран из противоположной группы {opposite_group.sam_account_name}")

                if self.dry_run:
                    await self._record_audit(
                        tx_id, tg_user_id, tg_username, "ACCESS_GRANT_AD", user, clean_sid,
                        clean_unc, clean_level, target_group.sam_account_name, "", "DRY_RUN",
                        f"Dry-run AD group {target_group.sam_account_name}",
                    )
                    return AccessMutationResult(
                        tx_id=tx_id,
                        operation="ACCESS_GRANT_AD",
                        dry_run=True,
                        target_user=user.sam_account_name,
                        target_sid=clean_sid,
                        unc_path=clean_unc,
                        level=clean_level,
                        mechanism="AD_GROUP",
                        group_name=target_group.sam_account_name,
                        requires_relogon=True,
                        message=f"DRY-RUN: добавление в группу {target_group.sam_account_name} ({clean_level}).",
                    )

                added = await self.ad.add_user_to_group(target_group.distinguished_name, user.distinguished_name)
                if added:
                    ad_actions.append(
                        {
                            "action": "ADD",
                            "group_dn": target_group.distinguished_name,
                            "group_sam": target_group.sam_account_name,
                            "user_dn": user.distinguished_name,
                        }
                    )

                acl_bdir = ""
                if status.direct_level != ACCESS_NONE:
                    acl_path, _, _, _ = await self.acl.apply_access(
                        clean_unc, clean_sid, ACCESS_NONE, self.backup_dir, f"{tx_id}_clr", max_propagate=self.max_propagate
                    )
                    acl_bdir = str(acl_path)
                    notes.append(f"Удалён лишний прямой ACE ({status.direct_level})")

                bdir = _ad_backup_write(
                    self.backup_dir,
                    tx_id,
                    {"kind": "AD_ACCESS", "ad_actions": ad_actions, "acl_backup_dir": acl_bdir},
                )
                await self._record_audit(
                    tx_id, tg_user_id, tg_username, "ACCESS_GRANT_AD", user, clean_sid,
                    clean_unc, clean_level, target_group.sam_account_name, str(bdir), "SUCCESS",
                    "; ".join(notes) if notes else f"Added to {target_group.sam_account_name}",
                )
                msg = (
                    f"Добавлен в группу AD {target_group.sam_account_name} ({clean_level})."
                    if added
                    else f"Пользователь уже состоит в группе {target_group.sam_account_name} ({clean_level})."
                )
                if notes:
                    msg += " " + "; ".join(notes) + "."
                return AccessMutationResult(
                    tx_id=tx_id,
                    operation="ACCESS_GRANT_AD",
                    dry_run=False,
                    target_user=user.sam_account_name,
                    target_sid=clean_sid,
                    unc_path=clean_unc,
                    level=clean_level,
                    mechanism="AD_GROUP",
                    group_name=target_group.sam_account_name,
                    requires_relogon=True,
                    backup_path=str(bdir),
                    message=msg,
                )

            # Fallback / direct NTFS ACE path over SMBv2/3
            if clean_level == ACCESS_RO and report.rw_group and report.rw_group.distinguished_name in status.member_of_manageable_groups:
                if not self.dry_run:
                    if await self.ad.remove_user_from_group(report.rw_group.distinguished_name, user.distinguished_name):
                        ad_actions.append(
                            {
                                "action": "REMOVE",
                                "group_dn": report.rw_group.distinguished_name,
                                "group_sam": report.rw_group.sam_account_name,
                                "user_dn": user.distinguished_name,
                            }
                        )
                        notes.append(f"Исключён из группы {report.rw_group.sam_account_name}")

            if clean_level == ACCESS_RO and status.blocked_by_protected_group and status.effective_level in (ACCESS_RW, ACCESS_FULL):
                notes.append("Внимание: у сотрудника уже есть RW/Full через группу отдела/домена — прямой RO-ACE не понизит их")

            if self.dry_run:
                await self._record_audit(
                    tx_id, tg_user_id, tg_username, "ACCESS_GRANT_NTFS", user, clean_sid,
                    clean_unc, clean_level, "NTFS", "", "DRY_RUN", "; ".join(notes) or "Dry-run NTFS ACL",
                )
                return AccessMutationResult(
                    tx_id=tx_id,
                    operation="ACCESS_GRANT_NTFS",
                    dry_run=True,
                    target_user=user.sam_account_name,
                    target_sid=clean_sid,
                    unc_path=clean_unc,
                    level=clean_level,
                    mechanism="NTFS_DIRECT",
                    message=f"DRY-RUN: прямой NTFS ACL ({clean_level}) на {clean_unc}.",
                )

            acl_dir, prop, skip, trunc = await self.acl.apply_access(
                clean_unc, clean_sid, clean_level, self.backup_dir, tx_id, max_propagate=self.max_propagate
            )
            if ad_actions:
                (acl_dir / "ad_actions.json").write_text(json.dumps(ad_actions, ensure_ascii=False, indent=2), encoding="utf-8")

            await self._record_audit(
                tx_id, tg_user_id, tg_username, "ACCESS_GRANT_NTFS", user, clean_sid,
                clean_unc, clean_level, "NTFS", str(acl_dir), "SUCCESS",
                f"propagated={prop}, skipped={skip}, truncated={trunc}" + (f"; {'; '.join(notes)}" if notes else ""),
            )
            note_tail = (" " + "; ".join(notes)) if notes else ""
            return AccessMutationResult(
                tx_id=tx_id,
                operation="ACCESS_GRANT_NTFS",
                dry_run=False,
                target_user=user.sam_account_name,
                target_sid=clean_sid,
                unc_path=clean_unc,
                level=clean_level,
                mechanism="NTFS_DIRECT",
                propagated_objects=prop,
                skipped_objects=skip,
                truncated_propagation=trunc,
                requires_relogon=False,
                backup_path=str(acl_dir),
                message=f"Прямые NTFS-права ({clean_level}) применены на {clean_unc} (обновлено подпапок/файлов: {prop}).{note_tail}",
            )

    async def revoke_access(
        self,
        user: ADUser,
        unc_path: str,
        tg_user_id: int,
        tg_username: str,
    ) -> AccessMutationResult:
        """Revoke direct NTFS ACE and manageable share AD group memberships for user on unc_path."""
        clean_unc = validate_unc_path(unc_path)
        clean_sid = validate_sid(user.sid)
        if self.policy.is_protected_acl_principal(clean_sid, user.sam_account_name):
            raise AccessOperationError(f"Учётная запись '{user.sam_account_name}' защищена от изменения ACL.")

        async with self._lock:
            tx_id = uuid.uuid4().hex[:10]
            report = await self.inspect_share_access(clean_unc)
            if not report.readable:
                raise AccessOperationError(f"Нет доступа к чтению ACL на {clean_unc}: {report.error}")

            status = await self.check_user_access(clean_unc, user, report=report)
            if not status.member_of_manageable_groups and status.direct_level == ACCESS_NONE:
                if status.sources:
                    raise AccessOperationError(
                        "Доступ пользователя выдан через группу отдела/домена ("
                        + ", ".join(status.sources)
                        + "), не управляемую ботом автоматически."
                    )
                raise AccessOperationError("У пользователя нет управляемых прав на этот ресурс.")

            if self.dry_run:
                await self._record_audit(
                    tx_id, tg_user_id, tg_username, "ACCESS_REVOKE", user, clean_sid,
                    clean_unc, ACCESS_NONE, "HYBRID", "", "DRY_RUN", "Dry-run access revoke",
                )
                return AccessMutationResult(
                    tx_id=tx_id,
                    operation="ACCESS_REVOKE",
                    dry_run=True,
                    target_user=user.sam_account_name,
                    target_sid=clean_sid,
                    unc_path=clean_unc,
                    level=ACCESS_NONE,
                    mechanism="HYBRID",
                    message=f"DRY-RUN: отзыв управляемых прав на {clean_unc}.",
                )

            ad_actions: list[dict[str, str]] = []
            removed_groups: list[str] = []
            for gdn in status.member_of_manageable_groups:
                grp_sam = gdn.split(",", 1)[0].removeprefix("CN=")
                if await self.ad.remove_user_from_group(gdn, user.distinguished_name):
                    ad_actions.append({"action": "REMOVE", "group_dn": gdn, "group_sam": grp_sam, "user_dn": user.distinguished_name})
                    removed_groups.append(grp_sam)

            prop = skip = 0
            trunc = False
            acl_backup_dir = ""
            if status.direct_level != ACCESS_NONE:
                acl_path, prop, skip, trunc = await self.acl.apply_access(
                    clean_unc, clean_sid, ACCESS_NONE, self.backup_dir, tx_id, max_propagate=self.max_propagate
                )
                acl_backup_dir = str(acl_path)

            if acl_backup_dir:
                bdir = Path(acl_backup_dir)
                if ad_actions:
                    (bdir / "ad_actions.json").write_text(json.dumps(ad_actions, ensure_ascii=False, indent=2), encoding="utf-8")
                op_name = "ACCESS_REVOKE_NTFS" if not removed_groups else "ACCESS_REVOKE"
                mech = "NTFS_DIRECT" if not removed_groups else "HYBRID"
                label = "NTFS" if not removed_groups else ",".join(removed_groups) + "+NTFS"
            else:
                bdir = _ad_backup_write(self.backup_dir, tx_id, {"kind": "AD_ACCESS", "ad_actions": ad_actions, "acl_backup_dir": ""})
                op_name = "ACCESS_REVOKE_AD"
                mech = "AD_GROUP"
                label = ",".join(removed_groups)

            detail_note = ""
            if status.blocked_by_protected_group:
                detail_note = " Остаётся доступ через группу отдела/домена."

            await self._record_audit(
                tx_id, tg_user_id, tg_username, op_name, user, clean_sid,
                clean_unc, ACCESS_NONE, label, str(bdir), "SUCCESS",
                f"removed_groups={removed_groups}, direct={status.direct_level}",
            )
            return AccessMutationResult(
                tx_id=tx_id,
                operation=op_name,
                dry_run=False,
                target_user=user.sam_account_name,
                target_sid=clean_sid,
                unc_path=clean_unc,
                level=ACCESS_NONE,
                mechanism=mech,
                group_name=", ".join(removed_groups),
                propagated_objects=prop,
                skipped_objects=skip,
                truncated_propagation=trunc,
                requires_relogon=bool(removed_groups),
                backup_path=str(bdir),
                message=f"Управляемые права на {clean_unc} отозваны.{detail_note}",
            )

    async def revoke_from_group(
        self,
        group: ADGroup,
        unc_path: str,
        user: ADUser,
        tg_user_id: int,
        tg_username: str,
    ) -> AccessMutationResult:
        """Remove user from a single manageable share AD group directly."""
        clean_unc = validate_unc_path(unc_path)
        clean_sid = validate_sid(user.sid)
        if not self.policy.is_manageable_access_group(group.sam_account_name, group.distinguished_name, self.share_access_ou):
            raise AccessOperationError(f"Группа '{group.sam_account_name}' не управляется ботом.")

        async with self._lock:
            tx_id = uuid.uuid4().hex[:10]
            if self.dry_run:
                await self._record_audit(
                    tx_id, tg_user_id, tg_username, "ACCESS_REVOKE_AD", user, clean_sid,
                    clean_unc, ACCESS_NONE, group.sam_account_name, "", "DRY_RUN", "Dry-run group removal",
                )
                return AccessMutationResult(
                    tx_id=tx_id,
                    operation="ACCESS_REVOKE_AD",
                    dry_run=True,
                    target_user=user.sam_account_name,
                    target_sid=clean_sid,
                    unc_path=clean_unc,
                    level=ACCESS_NONE,
                    mechanism="AD_GROUP",
                    group_name=group.sam_account_name,
                    requires_relogon=True,
                    message=f"DRY-RUN: исключение из {group.sam_account_name}.",
                )

            removed = await self.ad.remove_user_from_group(group.distinguished_name, user.distinguished_name)
            ad_actions = (
                [{"action": "REMOVE", "group_dn": group.distinguished_name, "group_sam": group.sam_account_name, "user_dn": user.distinguished_name}]
                if removed
                else []
            )
            bdir = _ad_backup_write(self.backup_dir, tx_id, {"kind": "AD_ACCESS", "ad_actions": ad_actions, "acl_backup_dir": ""})
            await self._record_audit(
                tx_id, tg_user_id, tg_username, "ACCESS_REVOKE_AD", user, clean_sid,
                clean_unc, ACCESS_NONE, group.sam_account_name, str(bdir), "SUCCESS", "",
            )
            return AccessMutationResult(
                tx_id=tx_id,
                operation="ACCESS_REVOKE_AD",
                dry_run=False,
                target_user=user.sam_account_name,
                target_sid=clean_sid,
                unc_path=clean_unc,
                level=ACCESS_NONE,
                mechanism="AD_GROUP",
                group_name=group.sam_account_name,
                requires_relogon=True,
                backup_path=str(bdir),
                message=f"Сотрудник исключён из группы {group.sam_account_name}.",
            )

    async def rollback_access_transaction(
        self,
        record: AuditRecord,
        tg_user_id: int,
        tg_username: str,
    ) -> AccessMutationResult:
        """Restore ACL / AD group state from a recorded access transaction backup directory."""
        if not record.backup_path:
            raise AccessOperationError("Для этой транзакции нет сохранённого бэкапа.")
        bdir = Path(record.backup_path)
        if not bdir.exists():
            raise AccessOperationError(f"Каталог бэкапа не найден: {bdir}")

        async with self._lock:
            tx_id = uuid.uuid4().hex[:10]
            if self.dry_run:
                return AccessMutationResult(
                    tx_id=tx_id,
                    operation="ACCESS_ROLLBACK",
                    dry_run=True,
                    target_user=record.target_sam,
                    target_sid=record.target_sid,
                    unc_path=record.unc_path,
                    level=record.letter,
                    mechanism="HYBRID",
                    message=f"DRY-RUN: откат транзакции {record.tx_id}.",
                )

            acl_manifest = bdir / "acl_backup.json"
            ad_access_file = bdir / "ad_access.json"
            ad_actions_sidecar = bdir / "ad_actions.json"

            extra_acl_dir = ""
            ad_actions: list[dict[str, str]] = []
            if ad_access_file.exists():
                payload = json.loads(ad_access_file.read_text(encoding="utf-8"))
                ad_actions = payload.get("ad_actions", [])
                extra_acl_dir = payload.get("acl_backup_dir", "")
            elif ad_actions_sidecar.exists():
                ad_actions = json.loads(ad_actions_sidecar.read_text(encoding="utf-8"))

            if acl_manifest.exists():
                await self.acl.restore_snapshot(bdir)
            if extra_acl_dir and Path(extra_acl_dir).exists():
                await self.acl.restore_snapshot(Path(extra_acl_dir))

            for act in reversed(ad_actions):
                if act["action"] == "ADD":
                    await self.ad.remove_user_from_group(act["group_dn"], act["user_dn"])
                elif act["action"] == "REMOVE":
                    await self.ad.add_user_to_group(act["group_dn"], act["user_dn"])

            await self.audit.record(
                AuditRecord(
                    tx_id=tx_id,
                    created_at="",
                    tg_user_id=tg_user_id,
                    tg_username=tg_username,
                    operation="ACCESS_ROLLBACK",
                    target_sam=record.target_sam,
                    target_sid=record.target_sid,
                    unc_path=record.unc_path,
                    letter=record.letter,
                    label=record.label,
                    gpo_version_before=0,
                    gpo_version_after=0,
                    backup_path="",
                    status="SUCCESS",
                    details=f"Rollback of {record.tx_id}",
                )
            )
            return AccessMutationResult(
                tx_id=tx_id,
                operation="ACCESS_ROLLBACK",
                dry_run=False,
                target_user=record.target_sam,
                target_sid=record.target_sid,
                unc_path=record.unc_path,
                level=record.letter,
                mechanism="HYBRID",
                requires_relogon=bool(ad_actions),
                message=f"Откат доступа транзакции {record.tx_id} выполнен.",
            )

    async def _record_audit(
        self,
        tx_id: str,
        tg_user_id: int,
        tg_username: str,
        operation: str,
        user: ADUser,
        clean_sid: str,
        unc_path: str,
        level: str,
        label: str,
        backup_path: str,
        status: str,
        details: str,
    ) -> None:
        await self.audit.record(
            AuditRecord(
                tx_id=tx_id,
                created_at="",
                tg_user_id=tg_user_id,
                tg_username=tg_username,
                operation=operation,
                target_sam=user.sam_account_name,
                target_sid=clean_sid,
                unc_path=unc_path,
                letter=level,
                label=label,
                gpo_version_before=0,
                gpo_version_after=0,
                backup_path=backup_path,
                status=status,
                details=details,
            )
        )

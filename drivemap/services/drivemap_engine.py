"""GPP Drives.xml parser, RSOP conflict guard, and transactional DriveMap mutator."""

from __future__ import annotations

import asyncio
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from drivemap.config import PolicyConfig
from drivemap.models import (
    ADUser,
    AuditRecord,
    DriveRule,
    EffectiveMapping,
    FilterCondition,
    GpoInfo,
    LetterChoice,
    MutationResult,
)
from drivemap.services.ad_ldap import AdBackend
from drivemap.services.audit_db import AuditRepository
from drivemap.services.smb_sysvol import SysvolBackend, parse_gpt_ini_version, update_gpt_ini_version

DRIVES_CLSID = "{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}"
DRIVE_CLSID = "{935D1B74-9CB8-4e3c-9914-7DD559B7A417}"

UNC_RE = re.compile(r"^\\\\[A-Za-z0-9._-]+\\[^\\/:*?\"<>|;`\x00-\x1f]+(?:\\[^\\/:*?\"<>|;`\x00-\x1f]+)*$")
SID_RE = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$")
LETTER_RE = re.compile(r"^[A-Z]$")


class DriveMapValidationError(ValueError):
    """Raised when UNC path, drive letter, or SID fails strict input validation."""


class DriveMapConflictError(RuntimeError):
    """Raised when requested drive letter conflicts with global/OU policy without resolution."""


def empty_drives_xml_bytes() -> bytes:
    """Return a valid minimal GPP Drives.xml document."""
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        f'<Drives clsid="{DRIVES_CLSID}" />\n'
    ).encode("utf-8")


def validate_unc_path(path: str) -> str:
    """Validate and normalize UNC share path (prevents path traversal or shell chars)."""
    cleaned = path.strip().rstrip("\\")
    if not UNC_RE.match(cleaned):
        raise DriveMapValidationError(f"Некорректный UNC-путь: {path!r}")
    if ".." in cleaned.split("\\"):
        raise DriveMapValidationError("Сегмент '..' в UNC-пути запрещен")
    try:
        from drivemap.config import settings as dm_settings
        allowed_hosts = [h.strip().lower() for h in (getattr(dm_settings, "file_server_list", None) or []) if h.strip()]
        if allowed_hosts:
            host = cleaned.lstrip("\\").split("\\", 1)[0].lower()
            if host not in allowed_hosts:
                raise DriveMapValidationError(
                    f"Хост '{host}' не входит в список разрешённых файловых серверов."
                )
    except DriveMapValidationError:
        raise
    except Exception:
        pass
    return cleaned


def validate_letter(letter: str, policy: PolicyConfig) -> str:
    """Validate drive letter A-Z and reject OS/system protected letters."""
    up = letter.strip().rstrip(":").upper()
    if not LETTER_RE.match(up):
        raise DriveMapValidationError(f"Некорректная буква диска: {letter!r}")
    if up in policy.protected_letters:
        raise DriveMapValidationError(f"Буква {up}: защищена политикой (системный диск)")
    return up


def validate_sid(sid: str) -> str:
    cleaned = sid.strip()
    if not SID_RE.match(cleaned):
        raise DriveMapValidationError(f"Некорректный SID пользователя: {sid!r}")
    return cleaned


def derive_default_label(unc_path: str, explicit_label: str = "") -> str:
    """Compute human-friendly Windows Explorer volume label."""
    if explicit_label.strip():
        return explicit_label.strip()[:48]
    tail = unc_path.rstrip("\\").rsplit("\\", 1)[-1].rstrip("$")
    return (tail or "NetworkDrive")[:48]


def _extract_group_cn(group_dn: str) -> str:
    first = group_dn.split(",", 1)[0]
    if first.upper().startswith("CN="):
        return first[3:].strip().lower()
    return group_dn.strip().lower()


def _parse_filters(filters_elem: Optional[ET.Element]) -> tuple[FilterCondition, ...]:
    if filters_elem is None:
        return ()
    parsed: list[FilterCondition] = []
    for child in filters_elem:
        tag = child.tag
        parsed.append(
            FilterCondition(
                kind=tag,
                bool_op=child.attrib.get("bool", "AND").upper(),
                negated=child.attrib.get("not", "0") == "1",
                name=child.attrib.get("name", ""),
                sid=child.attrib.get("sid", ""),
                user_context=child.attrib.get("userContext", "1") == "1",
                direct_member=child.attrib.get("directMember", "0") == "1",
            )
        )
    return tuple(parsed)


def parse_drives_xml(xml_bytes: bytes, gpo_name: str = "", gpo_guid: str = "") -> list[DriveRule]:
    """Parse GPP Drives.xml bytes into typed DriveRule objects."""
    if not xml_bytes or not xml_bytes.strip():
        return []
    root = ET.fromstring(xml_bytes)
    rules: list[DriveRule] = []
    for drv in root.findall("Drive"):
        props = drv.find("Properties")
        if props is None:
            continue
        letter = props.attrib.get("letter", "").strip().upper()
        if not letter:
            name_attr = drv.attrib.get("name", "").strip().rstrip(":").upper()
            letter = name_attr
        if not letter:
            continue
        rules.append(
            DriveRule(
                uid=drv.attrib.get("uid", ""),
                letter=letter,
                path=props.attrib.get("path", ""),
                label=props.attrib.get("label", ""),
                action=props.attrib.get("action", "U").upper(),
                persistent=props.attrib.get("persistent", "1") == "1",
                use_letter=props.attrib.get("useLetter", "1") == "1",
                user_context=drv.attrib.get("userContext", "1") == "1",
                bypass_errors=drv.attrib.get("bypassErrors", "1") == "1",
                changed=drv.attrib.get("changed", ""),
                source_gpo_name=gpo_name,
                source_gpo_guid=gpo_guid,
                filters=_parse_filters(drv.find("Filters")),
            )
        )
    return rules


def _eval_single_filter(f: FilterCondition, user: ADUser) -> Optional[str]:
    """Evaluate a single GPP Item-Level Targeting filter; return matched kind if True."""
    user_dn_l = user.distinguished_name.lower()
    if f.kind == "FilterUser":
        matched = (bool(f.sid) and f.sid.upper() == user.sid.upper()) or (
            f.name.lower().endswith("\\" + user.sam_account_name.lower())
        )
        outcome = (not matched) if f.negated else matched
        return "PER_USER" if outcome else None

    if f.kind == "FilterOrgUnit":
        ou_dn_l = f.name.strip().lower()
        user_parent = user_dn_l.split(",", 1)[1] if "," in user_dn_l else ""
        if f.direct_member:
            matched = user_parent == ou_dn_l
        else:
            matched = user_dn_l.endswith("," + ou_dn_l) or user_parent == ou_dn_l
        outcome = (not matched) if f.negated else matched
        return "ORG_UNIT_FILTER" if outcome else None

    if f.kind == "FilterGroup":
        target_name = f.name.strip().lower()
        target_short = target_name.split("\\", 1)[-1]
        user_group_cns = {_extract_group_cn(dn) for dn in user.member_of_dns}
        matched = target_short in user_group_cns or target_name in {dn.lower() for dn in user.member_of_dns}
        outcome = (not matched) if f.negated else matched
        return "GROUP_FILTER" if outcome else None

    return None


def rule_applies_to_user(rule: DriveRule, user: ADUser, gpo_is_ou_level: bool) -> Optional[str]:
    """Evaluate whether a DriveRule applies to user and return its scope classification."""
    if not rule.filters:
        return "OU_GPO" if gpo_is_ou_level else "GLOBAL"

    acc_result: Optional[bool] = None
    matched_kinds: list[str] = []
    for idx, flt in enumerate(rule.filters):
        kind_hit = _eval_single_filter(flt, user)
        val = kind_hit is not None
        if kind_hit:
            matched_kinds.append(kind_hit)
        if idx == 0:
            acc_result = val
        elif flt.bool_op == "OR":
            acc_result = bool(acc_result) or val
        else:
            acc_result = bool(acc_result) and val

    if not acc_result:
        return None
    if rule.action == "D" and "PER_USER" in matched_kinds:
        return "PER_USER_DELETE"
    if "PER_USER" in matched_kinds:
        return "PER_USER"
    if "ORG_UNIT_FILTER" in matched_kinds:
        return "ORG_UNIT_FILTER"
    if "GROUP_FILTER" in matched_kinds:
        return "GROUP_FILTER"
    return "OU_GPO" if gpo_is_ou_level else "GLOBAL"


def _now_gpp_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _new_gpp_uid() -> str:
    return "{" + str(uuid.uuid4()).upper() + "}"


def _serialize_xml(root: ET.Element) -> bytes:
    ET.indent(root, space="  ")
    body = ET.tostring(root, encoding="unicode")
    return f'<?xml version="1.0" encoding="utf-8"?>\n{body}\n'.encode("utf-8")


def _load_or_init_xml_root(xml_bytes: Optional[bytes]) -> ET.Element:
    if not xml_bytes or not xml_bytes.strip():
        return ET.Element("Drives", {"clsid": DRIVES_CLSID})
    root = ET.fromstring(xml_bytes)
    if root.tag != "Drives":
        raise DriveMapValidationError(f"Ожидался корневой тег <Drives>, получен <{root.tag}>")
    return root


def _build_drive_element(
    letter: str,
    unc_path: str,
    label: str,
    action: str,
    qualified_user: str,
    user_sid: str,
) -> ET.Element:
    drv = ET.Element(
        "Drive",
        {
            "clsid": DRIVE_CLSID,
            "name": f"{letter}:",
            "status": f"{letter}:",
            "image": "0" if action != "D" else "3",
            "changed": _now_gpp_timestamp(),
            "uid": _new_gpp_uid(),
            "userContext": "1",
            "bypassErrors": "1",
        },
    )
    ET.SubElement(
        drv,
        "Properties",
        {
            "action": action,
            "thisDrive": "NOCHANGE",
            "allDrives": "NOCHANGE",
            "userName": "",
            "path": unc_path,
            "label": label,
            "persistent": "1",
            "useLetter": "1",
            "letter": letter,
        },
    )
    filters = ET.SubElement(drv, "Filters")
    ET.SubElement(
        filters,
        "FilterUser",
        {
            "bool": "OR",
            "not": "0",
            "name": qualified_user,
            "sid": user_sid,
            "userContext": "1",
        },
    )
    return drv


def _remove_user_from_drive_element(drv: ET.Element, user_sid: str) -> bool:
    """Remove matching FilterUser from a <Drive>; return True if XML changed."""
    filters = drv.find("Filters")
    if filters is None:
        return False
    removed = False
    for flt in list(filters):
        if flt.tag == "FilterUser" and flt.attrib.get("sid", "").upper() == user_sid.upper():
            filters.remove(flt)
            removed = True
    if removed:
        drv.set("changed", _now_gpp_timestamp())
        # Normalize first remaining filter to bool="OR" to avoid dangling AND/OR edge cases.
        remaining = list(filters)
        if remaining and remaining[0].attrib.get("bool") not in ("AND", "OR"):
            remaining[0].set("bool", "OR")
    return removed


def apply_assign_to_drives_xml(
    xml_bytes: Optional[bytes],
    user: ADUser,
    netbios_domain: str,
    unc_path: str,
    letter: str,
    label: str,
) -> bytes:
    """Return updated Drives.xml assigning (unc_path, letter) to user with deduplicated <Drive> blocks."""
    root = _load_or_init_xml_root(xml_bytes)
    qualified_user = user.qualified_name(netbios_domain)
    norm_unc = unc_path.lower()

    matching_drive: Optional[ET.Element] = None
    for drv in list(root.findall("Drive")):
        props = drv.find("Properties")
        if props is None:
            continue
        drv_letter = props.attrib.get("letter", "").strip().upper()
        drv_action = props.attrib.get("action", "U").strip().upper()
        drv_path = props.attrib.get("path", "").strip().lower()

        if drv_letter != letter:
            continue

        # Remove user from any conflicting previous per-user rule or Delete tombstone on the same letter.
        if drv_action == "D" or drv_path != norm_unc:
            _remove_user_from_drive_element(drv, user.sid)
            filters = drv.find("Filters")
            if filters is not None and len(list(filters)) == 0:
                root.remove(drv)
            continue

        if drv_action in ("U", "C") and drv_path == norm_unc and matching_drive is None:
            matching_drive = drv

    if matching_drive is not None:
        filters = matching_drive.find("Filters")
        if filters is None:
            filters = ET.SubElement(matching_drive, "Filters")
        already = any(
            flt.tag == "FilterUser" and flt.attrib.get("sid", "").upper() == user.sid.upper()
            for flt in filters
        )
        if not already:
            ET.SubElement(
                filters,
                "FilterUser",
                {
                    "bool": "OR",
                    "not": "0",
                    "name": qualified_user,
                    "sid": user.sid,
                    "userContext": "1",
                },
            )
        matching_drive.set("changed", _now_gpp_timestamp())
        props = matching_drive.find("Properties")
        if props is not None and label:
            props.set("label", label)
    else:
        root.append(
            _build_drive_element(
                letter=letter,
                unc_path=unc_path,
                label=label,
                action="U",
                qualified_user=qualified_user,
                user_sid=user.sid,
            )
        )

    return _serialize_xml(root)


def apply_unassign_to_drives_xml(
    xml_bytes: Optional[bytes],
    user: ADUser,
    netbios_domain: str,
    letter: str,
    delete_persistent: bool = False,
    last_known_path: str = "",
) -> tuple[bytes, bool]:
    """Remove user's mapping for letter (optionally inserting an action='D' tombstone)."""
    root = _load_or_init_xml_root(xml_bytes)
    changed = False
    captured_path = last_known_path

    for drv in list(root.findall("Drive")):
        props = drv.find("Properties")
        if props is None:
            continue
        if props.attrib.get("letter", "").strip().upper() != letter:
            continue
        if not captured_path and props.attrib.get("path"):
            captured_path = props.attrib.get("path", "")
        if _remove_user_from_drive_element(drv, user.sid):
            changed = True
        filters = drv.find("Filters")
        if filters is not None and len(list(filters)) == 0:
            root.remove(drv)
            changed = True

    if delete_persistent:
        root.append(
            _build_drive_element(
                letter=letter,
                unc_path=captured_path,
                label="",
                action="D",
                qualified_user=user.qualified_name(netbios_domain),
                user_sid=user.sid,
            )
        )
        changed = True

    return _serialize_xml(root), changed


class DriveMapEngine:
    """High-level safe orchestrator for RSOP conflict checking and DriveMap GPO updates."""

    def __init__(
        self,
        ad: AdBackend,
        sysvol: SysvolBackend,
        audit: AuditRepository,
        policy: PolicyConfig,
        target_gpo_name: str,
        netbios_domain: str,
        backup_dir: Path,
        dry_run: bool = False,
    ) -> None:
        self.ad = ad
        self.sysvol = sysvol
        self.audit = audit
        self.policy = policy
        self.target_gpo_name = target_gpo_name
        self.netbios_domain = netbios_domain
        self.backup_dir = backup_dir
        self.dry_run = dry_run
        self._write_lock = asyncio.Lock()

    async def get_effective_mappings(self, user: ADUser) -> list[EffectiveMapping]:
        """Compute effective DriveMap assignments across all applicable GPOs for user."""
        applicable_guids = await self.ad.get_applicable_gpo_guids_for_user(user)
        all_gpos = await self.ad.list_drivemap_gpos(extra_names=(self.target_gpo_name,))
        gpo_by_guid: dict[str, GpoInfo] = {g.guid.upper(): g for g in all_gpos}

        ordered_gpos = [gpo_by_guid[g.upper()] for g in applicable_guids if g.upper() in gpo_by_guid]
        # Ensure target per-user GPO is always inspected even if link replication lags.
        target_gpo = next((g for g in all_gpos if g.display_name.lower() == self.target_gpo_name.lower()), None)
        if target_gpo and all(g.guid != target_gpo.guid for g in ordered_gpos):
            ordered_gpos.append(target_gpo)

        effective_by_letter: dict[str, EffectiveMapping] = {}
        for gpo in ordered_gpos:
            raw_xml = await self.sysvol.read_drives_xml(gpo.guid)
            if not raw_xml:
                continue
            is_ou_gpo = gpo.display_name.upper().startswith("OU-")
            is_target = gpo.display_name.lower() == self.target_gpo_name.lower()
            for rule in parse_drives_xml(raw_xml, gpo.display_name, gpo.guid):
                scope = rule_applies_to_user(rule, user, gpo_is_ou_level=is_ou_gpo)
                if scope is None:
                    continue
                if scope == "PER_USER_DELETE":
                    # Reflect active delete rule visibly for target GPO, clearing prior mapping.
                    if is_target:
                        effective_by_letter[rule.letter] = EffectiveMapping(
                            letter=rule.letter,
                            path=rule.path,
                            label=rule.label,
                            action=rule.action,
                            source_gpo=gpo.display_name,
                            scope_type=scope,
                            removable_by_bot=True,
                            uid=rule.uid,
                        )
                    else:
                        effective_by_letter.pop(rule.letter, None)
                    continue

                effective_by_letter[rule.letter] = EffectiveMapping(
                    letter=rule.letter,
                    path=rule.path,
                    label=rule.label,
                    action=rule.action,
                    source_gpo=gpo.display_name,
                    scope_type=scope,
                    removable_by_bot=is_target and scope == "PER_USER",
                    uid=rule.uid,
                )

        return sorted(effective_by_letter.values(), key=lambda m: m.letter)

    async def get_letter_matrix(self, user: ADUser) -> list[LetterChoice]:
        """Return A-Z availability matrix incorporating protected letters and existing GPOs."""
        effective = {m.letter: m for m in await self.get_effective_mappings(user)}
        matrix: list[LetterChoice] = []
        for code in range(ord("A"), ord("Z") + 1):
            letter = chr(code)
            if letter in self.policy.protected_letters:
                matrix.append(LetterChoice(letter=letter, status="PROTECTED"))
                continue
            hit = effective.get(letter)
            if not hit or hit.scope_type == "PER_USER_DELETE":
                matrix.append(LetterChoice(letter=letter, status="FREE"))
                continue
            if hit.scope_type == "GLOBAL":
                status = "CONFLICT_GLOBAL"
            elif hit.scope_type in ("OU_GPO", "ORG_UNIT_FILTER", "GROUP_FILTER"):
                status = "CONFLICT_OU"
            else:
                status = "MAPPED_PER_USER"
            matrix.append(
                LetterChoice(
                    letter=letter,
                    status=status,
                    occupied_by_path=hit.path,
                    occupied_by_gpo=hit.source_gpo,
                )
            )
        return matrix

    def choose_recommended_letter(self, matrix: list[LetterChoice], preferred_letter: str = "") -> Optional[str]:
        """Select share's preferred letter if free, else highest-priority free letter from pool."""
        by_letter = {c.letter: c for c in matrix}
        if preferred_letter:
            p = preferred_letter.strip().rstrip(":").upper()
            if p in by_letter and by_letter[p].is_available:
                return p
        for candidate in self.policy.preferred_free_pool:
            choice = by_letter.get(candidate)
            if choice and choice.is_available:
                return candidate
        return next((c.letter for c in matrix if c.is_available), None)

    async def assign_drive(
        self,
        user: ADUser,
        unc_path: str,
        letter: str,
        label: str,
        tg_user_id: int,
        tg_username: str,
        allow_overwrite_per_user: bool = False,
    ) -> MutationResult:
        """Assign unc_path to user on letter inside target per-user GPO with full conflict checks."""
        clean_unc = validate_unc_path(unc_path)
        clean_letter = validate_letter(letter, self.policy)
        clean_sid = validate_sid(user.sid)
        clean_label = derive_default_label(clean_unc, label)

        async with self._write_lock:
            matrix = {c.letter: c for c in await self.get_letter_matrix(user)}
            current = matrix[clean_letter]
            if current.status in ("CONFLICT_GLOBAL", "CONFLICT_OU"):
                raise DriveMapConflictError(
                    f"Буква {clean_letter}: занята правилом '{current.occupied_by_gpo}' "
                    f"({current.occupied_by_path}). Выберите свободную букву."
                )
            if (
                current.status == "MAPPED_PER_USER"
                and current.occupied_by_path.lower() != clean_unc.lower()
                and not allow_overwrite_per_user
            ):
                raise DriveMapConflictError(
                    f"На букве {clean_letter}: уже подключена персональная шара {current.occupied_by_path} "
                    f"в {current.occupied_by_gpo}."
                )

            return await self._commit_target_update(
                operation="MAP",
                user=user,
                clean_sid=clean_sid,
                unc_path=clean_unc,
                letter=clean_letter,
                label=clean_label,
                tg_user_id=tg_user_id,
                tg_username=tg_username,
                mutator=lambda raw_xml: apply_assign_to_drives_xml(
                    raw_xml, user, self.netbios_domain, clean_unc, clean_letter, clean_label
                ),
            )

    async def unassign_drive(
        self,
        user: ADUser,
        letter: str,
        tg_user_id: int,
        tg_username: str,
        delete_persistent: bool = False,
    ) -> MutationResult:
        """Remove a user's mapping from target per-user GPO (optionally creating action='D')."""
        clean_letter = validate_letter(letter, self.policy)
        clean_sid = validate_sid(user.sid)
        effective = await self.get_effective_mappings(user)
        match = next((m for m in effective if m.letter == clean_letter and m.removable_by_bot), None)
        known_path = match.path if match else ""
        known_label = match.label if match else ""

        op = "DELETE_PERSISTENT" if delete_persistent else "UNMAP"
        async with self._write_lock:
            return await self._commit_target_update(
                operation=op,
                user=user,
                clean_sid=clean_sid,
                unc_path=known_path,
                letter=clean_letter,
                label=known_label,
                tg_user_id=tg_user_id,
                tg_username=tg_username,
                mutator=lambda raw_xml: apply_unassign_to_drives_xml(
                    raw_xml,
                    user,
                    self.netbios_domain,
                    clean_letter,
                    delete_persistent=delete_persistent,
                    last_known_path=known_path,
                )[0],
            )

    async def rollback_transaction(
        self,
        record: AuditRecord,
        tg_user_id: int,
        tg_username: str,
    ) -> MutationResult:
        """Restore Drives.xml from a recorded transaction backup directory."""
        tx_id = uuid.uuid4().hex[:10]
        bdir = Path(record.backup_path).resolve()
        try:
            bdir.relative_to(self.backup_dir.resolve())
        except ValueError:
            raise ValueError(f"Недопустимый путь бэкапа вне backup_dir: {record.backup_path}")
        if not bdir.exists() or not (bdir / "Drives.xml").exists():
            raise FileNotFoundError(f"Каталог бэкапа не найден: {bdir}")

        async with self._write_lock:
            target_gpo = await self.ad.get_gpo_by_name(self.target_gpo_name)
            if not target_gpo:
                raise RuntimeError(f"Целевая GPO '{self.target_gpo_name}' не найдена в AD")

            gpt_text = await self.sysvol.read_gpt_ini(target_gpo.guid)
            gpt_ver = parse_gpt_ini_version(gpt_text) or 0
            base_ver = max(target_gpo.version_number, gpt_ver)
            new_ver = (((base_ver >> 16) + 1) << 16) | (base_ver & 0xFFFF)

            if self.dry_run:
                res = MutationResult(
                    tx_id=tx_id,
                    operation="ROLLBACK",
                    dry_run=True,
                    target_user=record.target_sam,
                    target_sid=record.target_sid,
                    unc_path=record.unc_path,
                    letter=record.letter,
                    label=record.label,
                    gpo_version_before=base_ver,
                    gpo_version_after=new_ver,
                    backup_dir=str(bdir),
                    message="DRY_RUN: откат симулирован без изменения AD/SYSVOL",
                )
                await self.audit.record(
                    AuditRecord(
                        tx_id=tx_id,
                        created_at="",
                        tg_user_id=tg_user_id,
                        tg_username=tg_username,
                        operation="ROLLBACK",
                        target_sam=record.target_sam,
                        target_sid=record.target_sid,
                        unc_path=record.unc_path,
                        letter=record.letter,
                        label=record.label,
                        gpo_version_before=base_ver,
                        gpo_version_after=new_ver,
                        backup_path=str(bdir),
                        status="DRY_RUN",
                        details=f"rollback_of={record.tx_id}",
                    )
                )
                return res

            restored_xml = (bdir / "Drives.xml").read_bytes()
            new_gpt = update_gpt_ini_version(gpt_text, new_ver, target_gpo.display_name)
            pre_rollback_backup = await self.sysvol.write_gpo_files_atomic(
                target_gpo.guid,
                restored_xml,
                new_gpt,
                self.backup_dir,
                tx_id,
            )
            try:
                await self.ad.set_gpo_version(target_gpo.distinguished_name, new_ver)
            except Exception:
                await self.sysvol.restore_from_backup(target_gpo.guid, pre_rollback_backup)
                raise

            await self.audit.record(
                AuditRecord(
                    tx_id=tx_id,
                    created_at="",
                    tg_user_id=tg_user_id,
                    tg_username=tg_username,
                    operation="ROLLBACK",
                    target_sam=record.target_sam,
                    target_sid=record.target_sid,
                    unc_path=record.unc_path,
                    letter=record.letter,
                    label=record.label,
                    gpo_version_before=base_ver,
                    gpo_version_after=new_ver,
                    backup_path=str(pre_rollback_backup),
                    status="SUCCESS",
                    details=f"rollback_of={record.tx_id}",
                )
            )
            return MutationResult(
                tx_id=tx_id,
                operation="ROLLBACK",
                dry_run=False,
                target_user=record.target_sam,
                target_sid=record.target_sid,
                unc_path=record.unc_path,
                letter=record.letter,
                label=record.label,
                gpo_version_before=base_ver,
                gpo_version_after=new_ver,
                backup_dir=str(pre_rollback_backup),
                message="Откат выполнен, версии AD и SYSVOL синхронизированы.",
            )

    async def find_users_by_share(self, unc_path: str) -> list[tuple[str, str, str, str]]:
        """List per-user rules matching unc_path: [(gpo_name, letter, user_name, sid)]."""
        clean = unc_path.strip().rstrip("\\").lower()
        gpos = await self.ad.list_drivemap_gpos(extra_names=(self.target_gpo_name,))
        hits: list[tuple[str, str, str, str]] = []
        for gpo in gpos:
            raw_xml = await self.sysvol.read_drives_xml(gpo.guid)
            if not raw_xml:
                continue
            for rule in parse_drives_xml(raw_xml, gpo.display_name, gpo.guid):
                if rule.action == "D" or rule.path.rstrip("\\").lower() != clean:
                    continue
                for flt in rule.filters:
                    if flt.kind == "FilterUser" and not flt.negated:
                        hits.append((gpo.display_name, rule.letter, flt.name, flt.sid))
        return hits

    async def _commit_target_update(
        self,
        operation: str,
        user: ADUser,
        clean_sid: str,
        unc_path: str,
        letter: str,
        label: str,
        tg_user_id: int,
        tg_username: str,
        mutator,
    ) -> MutationResult:
        tx_id = uuid.uuid4().hex[:10]
        target_gpo = await self.ad.get_gpo_by_name(self.target_gpo_name)
        if not target_gpo:
            raise RuntimeError(
                f"Целевая GPO '{self.target_gpo_name}' не найдена в AD. "
                "Сначала выполните Initialize-PerUserDriveMapGPO.ps1."
            )

        raw_xml = await self.sysvol.read_drives_xml(target_gpo.guid)
        gpt_text = await self.sysvol.read_gpt_ini(target_gpo.guid)
        gpt_ver = parse_gpt_ini_version(gpt_text) or 0
        base_ver = max(target_gpo.version_number, gpt_ver)
        new_ver = (((base_ver >> 16) + 1) << 16) | (base_ver & 0xFFFF)

        new_xml_bytes = mutator(raw_xml)
        # Verify resulting XML parses cleanly before touching SYSVOL.
        parse_drives_xml(new_xml_bytes, target_gpo.display_name, target_gpo.guid)
        new_gpt_text = update_gpt_ini_version(gpt_text, new_ver, target_gpo.display_name)

        if self.dry_run:
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
                    letter=letter,
                    label=label,
                    gpo_version_before=base_ver,
                    gpo_version_after=new_ver,
                    backup_path="",
                    status="DRY_RUN",
                    details="Dry-run simulation",
                )
            )
            return MutationResult(
                tx_id=tx_id,
                operation=operation,
                dry_run=True,
                target_user=user.sam_account_name,
                target_sid=clean_sid,
                unc_path=unc_path,
                letter=letter,
                label=label,
                gpo_version_before=base_ver,
                gpo_version_after=new_ver,
                message="DRY_RUN: XML проверен, изменения в AD/SYSVOL не вносились.",
            )

        tx_backup = await self.sysvol.write_gpo_files_atomic(
            target_gpo.guid,
            new_xml_bytes,
            new_gpt_text,
            self.backup_dir,
            tx_id,
        )
        try:
            await self.ad.set_gpo_version(target_gpo.distinguished_name, new_ver)
        except Exception as exc:
            await self.sysvol.restore_from_backup(target_gpo.guid, tx_backup)
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
                    letter=letter,
                    label=label,
                    gpo_version_before=base_ver,
                    gpo_version_after=base_ver,
                    backup_path=str(tx_backup),
                    status="ERROR",
                    details=str(exc),
                )
            )
            raise

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
                letter=letter,
                label=label,
                gpo_version_before=base_ver,
                gpo_version_after=new_ver,
                backup_path=str(tx_backup),
                status="SUCCESS",
            )
        )
        return MutationResult(
            tx_id=tx_id,
            operation=operation,
            dry_run=False,
            target_user=user.sam_account_name,
            target_sid=clean_sid,
            unc_path=unc_path,
            letter=letter,
            label=label,
            gpo_version_before=base_ver,
            gpo_version_after=new_ver,
            backup_dir=str(tx_backup),
            message=f"Успешно применено в {self.target_gpo_name}.",
        )

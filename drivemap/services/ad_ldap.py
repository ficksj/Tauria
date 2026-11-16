"""Active Directory LDAP/LDAPS client for user search, GPO link resolution, and version updates."""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
import struct
from typing import Optional, Protocol, Sequence

from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, NTLM, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import to_dn

from drivemap.config import PolicyConfig
from drivemap.models import ADGroup, ADUser, GpoInfo, ResolvedSid

logger = logging.getLogger(__name__)

DRIVE_MAP_CSE_GUID = "{5794DAFD-BE60-433F-88A2-1A31939AC01F}"
GPLINK_RE = re.compile(r"\[LDAP://cn=(\{[0-9a-fA-F-]+\}),cn=policies,[^\];]+;(\d+)\]", re.IGNORECASE)
_USER_ATTRS = ["sAMAccountName", "displayName", "cn", "distinguishedName", "objectSid", "department", "title", "memberOf"]
_GROUP_ATTRS = ["sAMAccountName", "displayName", "cn", "distinguishedName", "objectSid", "description", "member", "objectClass"]


def bytes_to_sid_str(raw: bytes | str) -> str:
    """Convert raw Windows binary SID (or passthrough string SID) to S-1-5-21-... notation."""
    if isinstance(raw, str):
        return raw
    if not raw or len(raw) < 8:
        raise ValueError(f"Invalid binary SID payload: {raw!r}")
    revision = raw[0]
    sub_auth_count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = struct.unpack(f"<{sub_auth_count}I", raw[8 : 8 + 4 * sub_auth_count])
    return f"S-{revision}-{authority}-" + "-".join(str(s) for s in subs)


def sid_str_to_bytes(sid: str) -> bytes:
    """Encode a Windows SID string (S-1-...) into little-endian binary objectSid format."""
    parts = sid.strip().split("-")
    if len(parts) < 3 or parts[0].upper() != "S":
        raise ValueError(f"Invalid SID string: {sid!r}")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    return struct.pack(f"<BB6s{len(subs)}I", revision, len(subs), authority.to_bytes(6, "big"), *subs)


def _bytes_to_ldap_hex(raw: bytes) -> str:
    return "".join(f"\\{b:02x}" for b in raw)


def parse_gplink_attribute(gplink_value: str) -> list[tuple[str, int]]:
    """Parse AD gPLink string into ordered list of (guid_upper_with_braces, flags).

    AD stores links right-to-left in application precedence, so reversing gives evaluation order.
    """
    if not gplink_value:
        return []
    matches = [(m.group(1).upper(), int(m.group(2))) for m in GPLINK_RE.finditer(gplink_value)]
    matches.reverse()
    return matches


def extract_ancestor_dns(user_dn: str, domain_dn: str) -> list[str]:
    """Build OU/domain ancestry DNs ordered from domain root down to nearest parent OU."""
    rdns = to_dn(user_dn)
    ancestors: list[str] = []
    domain_upper = domain_dn.upper()
    for idx in range(1, len(rdns)):
        sub_dn = ",".join(rdns[idx:])
        sub_upper = sub_dn.upper()
        if sub_upper.startswith("OU=") or sub_upper == domain_upper:
            ancestors.append(sub_dn)
        if sub_upper == domain_upper:
            break
    ancestors.reverse()
    return ancestors


class AdBackend(Protocol):
    """Protocol abstracting AD queries and GPO version mutations."""

    async def search_users(self, query: str, limit: int = 20) -> list[ADUser]:
        ...

    async def get_user_by_sam(self, sam_account_name: str) -> Optional[ADUser]:
        ...

    async def get_gpo_by_name(self, display_name: str) -> Optional[GpoInfo]:
        ...

    async def list_drivemap_gpos(self, extra_names: tuple[str, ...] = ()) -> list[GpoInfo]:
        ...

    async def get_applicable_gpo_guids_for_user(self, user: ADUser) -> list[str]:
        ...

    async def set_gpo_version(self, gpo_dn: str, new_version: int) -> None:
        ...

    async def resolve_sids(self, sids: Sequence[str]) -> dict[str, ResolvedSid]:
        ...

    async def get_group(self, identifier: str) -> Optional[ADGroup]:
        ...

    async def get_group_members(self, group_dn: str, limit: int = 200) -> list[ADUser]:
        ...

    async def add_user_to_group(self, group_dn: str, user_dn: str) -> bool:
        ...

    async def remove_user_from_group(self, group_dn: str, user_dn: str) -> bool:
        ...

    async def user_in_any_group_transitive(self, user_dn: str, group_dns: Sequence[str]) -> set[str]:
        ...


class LdapsAdClient:
    """Active Directory client supporting LDAPS (port 636, CERT_NONE) with automatic fallback to LDAP 389 (NTLM / StartTLS)."""

    def __init__(
        self,
        dc_host: str,
        ldaps_port: int,
        domain: str,
        search_base: str,
        username: str,
        password: str,
        ca_bundle: str,
        policy: PolicyConfig,
        *,
        use_ssl: bool = False,
    ) -> None:
        self.dc_host = dc_host.replace("ldap://", "").replace("ldaps://", "").strip()
        self.ldaps_port = ldaps_port
        self.domain = domain
        self.search_base = search_base
        self.username = username
        self.password = password
        self.ca_bundle = ca_bundle
        self.policy = policy
        self.use_ssl = use_ssl

    @property
    def domain_dn(self) -> str:
        return ",".join(f"DC={part}" for part in self.domain.split(".") if part)

    def _ntlm_user(self) -> str:
        netbios = self.domain.split(".")[0].upper() if self.domain else "KDB"
        u = self.username.strip()
        if "@" in u:
            return f"{netbios}\\{u.split('@', 1)[0]}"
        if "\\" not in u:
            return f"{netbios}\\{u}"
        return u

    def _upn_user(self) -> str:
        u = self.username.strip()
        if "\\" in u:
            u = u.split("\\", 1)[-1]
        if "@" not in u and self.domain:
            return f"{u}@{self.domain}"
        return u

    def _try_bind_on_server(self, port: int, ssl_flag: bool) -> Optional[Connection]:
        tls = Tls(validate=ssl.CERT_NONE)
        server = Server(self.dc_host, port=port, use_ssl=ssl_flag, tls=tls, connect_timeout=6)

        # 1. Try NTLM bind first (standard in Tauria for 192.168.201.15)
        try:
            conn = Connection(
                server,
                user=self._ntlm_user(),
                password=self.password,
                authentication=NTLM,
                auto_bind=False,
                receive_timeout=10,
            )
            if conn.bind():
                return conn
            try:
                conn.unbind()
            except Exception:
                pass
        except Exception as exc:
            logger.debug("NTLM bind on %s:%s (ssl=%s) failed: %s", self.dc_host, port, ssl_flag, exc)

        # 2. Try SIMPLE bind (with StartTLS if plain port 389)
        try:
            conn = Connection(
                server,
                user=self._upn_user(),
                password=self.password,
                authentication=SIMPLE,
                auto_bind=False,
                receive_timeout=10,
            )
            conn.open()
            if not ssl_flag:
                try:
                    conn.start_tls()
                except Exception as tls_exc:
                    logger.debug("StartTLS on %s:%s not active: %s", self.dc_host, port, tls_exc)
            if conn.bind():
                return conn
            try:
                conn.unbind()
            except Exception:
                pass
        except Exception as exc:
            logger.debug("SIMPLE bind on %s:%s (ssl=%s) failed: %s", self.dc_host, port, ssl_flag, exc)

        return None

    def _connect(self) -> Connection:
        # Order of attempts: if use_ssl is True, try 636 LDAPS first then fallback to 389 LDAP;
        # if use_ssl is False (Tauria default for 192.168.201.15), try 389 first then fallback to 636.
        attempts = (
            [(self.ldaps_port or 636, True), (389, False)]
            if self.use_ssl
            else [(389, False), (self.ldaps_port or 636, True)]
        )
        for port, ssl_flag in attempts:
            conn = self._try_bind_on_server(port, ssl_flag)
            if conn is not None:
                return conn
        raise RuntimeError(f"Не удалось подключиться к контроллеру домена {self.dc_host} (порты 389/636).")

    def _entry_to_user(self, entry) -> ADUser:
        sam = str(entry.sAMAccountName.value)
        dn = str(entry.distinguishedName.value)
        display = str(entry.displayName.value or entry.cn.value or sam)
        dept = str(entry.department.value or "")
        title = str(entry.title.value or "")
        raw_sid = entry.objectSid.raw_values[0] if entry.objectSid.raw_values else entry.objectSid.value
        sid = bytes_to_sid_str(raw_sid)
        member_of = tuple(str(x) for x in (entry.memberOf.values or []))
        return ADUser(
            sam_account_name=sam,
            display_name=display,
            distinguished_name=dn,
            sid=sid,
            department=dept,
            title=title,
            enabled=True,
            member_of_dns=member_of,
        )

    def _search_users_sync(self, query: str, limit: int) -> list[ADUser]:
        escaped = escape_filter_chars(query.strip())
        if not escaped:
            return []
        ldap_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            f"(|(sAMAccountName=*{escaped}*)(displayName=*{escaped}*)(cn=*{escaped}*)(department=*{escaped}*)))"
        )
        attrs = _USER_ATTRS
        users: list[ADUser] = []
        with self._connect() as conn:
            conn.search(
                search_base=self.search_base,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attrs,
                size_limit=limit * 2,
            )
            for entry in conn.entries:
                dn = str(entry.distinguishedName.value)
                if self.policy.is_user_excluded(dn):
                    continue
                users.append(self._entry_to_user(entry))
                if len(users) >= limit:
                    break
        users.sort(key=lambda u: (u.display_name.lower(), u.sam_account_name.lower()))
        return users

    def _get_user_by_sam_sync(self, sam: str) -> Optional[ADUser]:
        escaped = escape_filter_chars(sam.strip())
        ldap_filter = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={escaped}))"
        with self._connect() as conn:
            conn.search(
                search_base=self.domain_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=_USER_ATTRS,
                size_limit=2,
            )
            if not conn.entries:
                return None
            return self._entry_to_user(conn.entries[0])

    def _entry_to_gpo(self, entry) -> GpoInfo:
        return GpoInfo(
            guid=str(entry.cn.value).upper(),
            display_name=str(entry.displayName.value or ""),
            distinguished_name=str(entry.distinguishedName.value),
            version_number=int(entry.versionNumber.value or 0),
            flags=int(entry.flags.value or 0),
            user_extensions=str(entry.gPCUserExtensionNames.value or ""),
        )

    def _get_gpo_by_name_sync(self, display_name: str) -> Optional[GpoInfo]:
        escaped = escape_filter_chars(display_name)
        policies_base = f"CN=Policies,CN=System,{self.domain_dn}"
        ldap_filter = f"(&(objectClass=groupPolicyContainer)(displayName={escaped}))"
        attrs = ["cn", "displayName", "distinguishedName", "versionNumber", "flags", "gPCUserExtensionNames"]
        with self._connect() as conn:
            conn.search(search_base=policies_base, search_filter=ldap_filter, search_scope=SUBTREE, attributes=attrs, size_limit=2)
            if not conn.entries:
                return None
            return self._entry_to_gpo(conn.entries[0])

    def _list_drivemap_gpos_sync(self, extra_names: tuple[str, ...]) -> list[GpoInfo]:
        policies_base = f"CN=Policies,CN=System,{self.domain_dn}"
        extra_clauses = "".join(f"(displayName={escape_filter_chars(n)})" for n in extra_names if n)
        ldap_filter = (
            "(&(objectClass=groupPolicyContainer)"
            f"(|(gPCUserExtensionNames=*{DRIVE_MAP_CSE_GUID}*)(displayName=*DriveMap*)(displayName=*MapNetworkDrives*){extra_clauses}))"
        )
        attrs = ["cn", "displayName", "distinguishedName", "versionNumber", "flags", "gPCUserExtensionNames"]
        with self._connect() as conn:
            conn.search(search_base=policies_base, search_filter=ldap_filter, search_scope=SUBTREE, attributes=attrs)
            return sorted((self._entry_to_gpo(e) for e in conn.entries), key=lambda g: g.display_name.lower())

    def _get_applicable_gpo_guids_sync(self, user: ADUser) -> list[str]:
        """Compute LSDOU-ordered enabled GPO GUIDs linked along the user's OU ancestry."""
        ancestors = extract_ancestor_dns(user.distinguished_name, self.domain_dn)

        blocked = False
        ordered_guids: list[str] = []
        enforced_guids: list[str] = []
        with self._connect() as conn:
            # Query child->parent to respect Block Inheritance (gPOptions & 1), then rebuild LSDOU.
            containers: list[tuple[str, int]] = []
            for som_dn in reversed(ancestors):
                conn.search(search_base=som_dn, search_filter="(objectClass=*)", search_scope="BASE", attributes=["gPLink", "gPOptions"])
                if not conn.entries:
                    continue
                e = conn.entries[0]
                gplink = str(e.gPLink.value or "")
                gpoptions = int(e.gPOptions.value or 0)
                containers.append((gplink, 1 if blocked else 0))
                if gpoptions & 1:
                    blocked = True

            for gplink, is_blocked_above in reversed(containers):
                for guid, link_flags in parse_gplink_attribute(gplink):
                    disabled = bool(link_flags & 1)
                    enforced = bool(link_flags & 2)
                    if disabled:
                        continue
                    if is_blocked_above and not enforced:
                        continue
                    if enforced:
                        enforced_guids.append(guid)
                    else:
                        ordered_guids.append(guid)

        ordered_guids.extend(enforced_guids)
        # Preserve precedence order without duplicates.
        deduped: list[str] = []
        seen: set[str] = set()
        for g in ordered_guids:
            if g not in seen:
                seen.add(g)
                deduped.append(g)
        return deduped

    def _set_gpo_version_sync(self, gpo_dn: str, new_version: int) -> None:
        with self._connect() as conn:
            ok = conn.modify(gpo_dn, {"versionNumber": [(MODIFY_REPLACE, [str(new_version)])]})
            if not ok or conn.result.get("result", -1) != 0:
                raise RuntimeError(f"Failed to update versionNumber on {gpo_dn}: {conn.result}")

    def _entry_to_resolved_sid(self, entry) -> ResolvedSid:
        raw_sid = entry.objectSid.raw_values[0] if entry.objectSid.raw_values else entry.objectSid.value
        sid = bytes_to_sid_str(raw_sid)
        classes = {str(c).lower() for c in (entry.objectClass.values or [])}
        if "group" in classes:
            ptype = "GROUP"
        elif "computer" in classes:
            ptype = "COMPUTER"
        elif "user" in classes or "person" in classes:
            ptype = "USER"
        else:
            ptype = "UNKNOWN"
        sam = str(entry.sAMAccountName.value or entry.cn.value or sid)
        display = str(entry.displayName.value or entry.cn.value or sam)
        dn = str(entry.distinguishedName.value or "")
        desc = str(entry.description.value or "") if hasattr(entry, "description") else ""
        members = tuple(str(x) for x in (entry.member.values or [])) if hasattr(entry, "member") else ()
        return ResolvedSid(
            sid=sid,
            sam_account_name=sam,
            display_name=display,
            principal_type=ptype,
            distinguished_name=dn,
            description=desc,
            member_dns=members,
        )

    def _resolve_sids_sync(self, sids: Sequence[str]) -> dict[str, ResolvedSid]:
        resolved: dict[str, ResolvedSid] = {}
        encodable: list[tuple[str, str]] = []
        for sid in dict.fromkeys(s.strip() for s in sids if s):
            try:
                encodable.append((sid, _bytes_to_ldap_hex(sid_str_to_bytes(sid))))
            except ValueError:
                continue
        if not encodable:
            return resolved

        with self._connect() as conn:
            for start in range(0, len(encodable), 25):
                batch = encodable[start : start + 25]
                clauses = "".join(f"(objectSid={hex_val})" for _sid, hex_val in batch)
                ldap_filter = f"(|{clauses})" if len(batch) > 1 else clauses
                conn.search(
                    search_base=self.domain_dn,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=_GROUP_ATTRS,
                )
                for entry in conn.entries:
                    item = self._entry_to_resolved_sid(entry)
                    resolved[item.sid.upper()] = item
        return resolved

    def _get_group_sync(self, identifier: str) -> Optional[ADGroup]:
        clean = identifier.strip()
        if not clean:
            return None
        with self._connect() as conn:
            if "=" in clean and "," in clean:
                conn.search(
                    search_base=clean,
                    search_filter="(objectCategory=group)",
                    search_scope="BASE",
                    attributes=_GROUP_ATTRS,
                )
            else:
                escaped = escape_filter_chars(clean)
                conn.search(
                    search_base=self.domain_dn,
                    search_filter=f"(&(objectCategory=group)(sAMAccountName={escaped}))",
                    search_scope=SUBTREE,
                    attributes=_GROUP_ATTRS,
                    size_limit=2,
                )
            if not conn.entries:
                return None
            info = self._entry_to_resolved_sid(conn.entries[0])
            return ADGroup(
                sam_account_name=info.sam_account_name,
                distinguished_name=info.distinguished_name,
                sid=info.sid,
                description=info.description,
                member_dns=info.member_dns,
            )

    def _get_group_members_sync(self, group_dn: str, limit: int) -> list[ADUser]:
        escaped = escape_filter_chars(group_dn)
        ldap_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            f"(memberOf={escaped}))"
        )
        users: list[ADUser] = []
        with self._connect() as conn:
            conn.search(
                search_base=self.domain_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=_USER_ATTRS,
                size_limit=limit,
            )
            for entry in conn.entries:
                users.append(self._entry_to_user(entry))
        users.sort(key=lambda u: (u.display_name.lower(), u.sam_account_name.lower()))
        return users

    def _add_user_to_group_sync(self, group_dn: str, user_dn: str) -> bool:
        with self._connect() as conn:
            ok = conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
            rc = conn.result.get("result", -1)
            if ok and rc == 0:
                return True
            if rc in (20, 68):  # attributeOrValueExists / entryAlreadyExists
                return False
            raise RuntimeError(f"Failed adding {user_dn} to {group_dn}: {conn.result}")

    def _remove_user_from_group_sync(self, group_dn: str, user_dn: str) -> bool:
        with self._connect() as conn:
            ok = conn.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
            rc = conn.result.get("result", -1)
            if ok and rc == 0:
                return True
            if rc in (16, 53):  # noSuchAttribute / absent
                return False
            raise RuntimeError(f"Failed removing {user_dn} from {group_dn}: {conn.result}")

    def _user_in_any_group_transitive_sync(self, user_dn: str, group_dns: Sequence[str]) -> set[str]:
        matched: set[str] = set()
        if not group_dns:
            return matched
        with self._connect() as conn:
            for gdn in dict.fromkeys(group_dns):
                escaped_gdn = escape_filter_chars(gdn)
                conn.search(
                    search_base=user_dn,
                    search_filter=f"(memberOf:1.2.840.113556.1.4.1941:={escaped_gdn})",
                    search_scope="BASE",
                    attributes=["distinguishedName"],
                )
                if conn.entries:
                    matched.add(gdn.lower())
        return matched

    async def search_users(self, query: str, limit: int = 20) -> list[ADUser]:
        return await asyncio.to_thread(self._search_users_sync, query, limit)

    async def get_user_by_sam(self, sam_account_name: str) -> Optional[ADUser]:
        return await asyncio.to_thread(self._get_user_by_sam_sync, sam_account_name)

    async def get_gpo_by_name(self, display_name: str) -> Optional[GpoInfo]:
        return await asyncio.to_thread(self._get_gpo_by_name_sync, display_name)

    async def list_drivemap_gpos(self, extra_names: tuple[str, ...] = ()) -> list[GpoInfo]:
        return await asyncio.to_thread(self._list_drivemap_gpos_sync, extra_names)

    async def get_applicable_gpo_guids_for_user(self, user: ADUser) -> list[str]:
        return await asyncio.to_thread(self._get_applicable_gpo_guids_sync, user)

    async def set_gpo_version(self, gpo_dn: str, new_version: int) -> None:
        await asyncio.to_thread(self._set_gpo_version_sync, gpo_dn, new_version)

    async def resolve_sids(self, sids: Sequence[str]) -> dict[str, ResolvedSid]:
        return await asyncio.to_thread(self._resolve_sids_sync, sids)

    async def get_group(self, identifier: str) -> Optional[ADGroup]:
        return await asyncio.to_thread(self._get_group_sync, identifier)

    async def get_group_members(self, group_dn: str, limit: int = 200) -> list[ADUser]:
        return await asyncio.to_thread(self._get_group_members_sync, group_dn, limit)

    async def add_user_to_group(self, group_dn: str, user_dn: str) -> bool:
        return await asyncio.to_thread(self._add_user_to_group_sync, group_dn, user_dn)

    async def remove_user_from_group(self, group_dn: str, user_dn: str) -> bool:
        return await asyncio.to_thread(self._remove_user_from_group_sync, group_dn, user_dn)

    async def user_in_any_group_transitive(self, user_dn: str, group_dns: Sequence[str]) -> set[str]:
        return await asyncio.to_thread(self._user_in_any_group_transitive_sync, user_dn, group_dns)

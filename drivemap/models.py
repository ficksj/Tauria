"""Domain models for Active Directory, GPP Drives.xml, and DriveMap operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ADUser:
    """Represents an active Active Directory user account."""

    sam_account_name: str
    display_name: str
    distinguished_name: str
    sid: str
    department: str = ""
    title: str = ""
    enabled: bool = True
    member_of_dns: tuple[str, ...] = ()

    @property
    def domain_qualified_name(self) -> str:
        """Return default <NETBIOS>\\sam format expected by GPP FilterUser."""
        return self._qualified("KDB")

    def qualified_name(self, netbios_domain: str) -> str:
        """Return <NETBIOS>\\<sAMAccountName>."""
        return f"{netbios_domain}\\{self.sam_account_name}"

    def _qualified(self, netbios: str) -> str:
        return f"{netbios}\\{self.sam_account_name}"

    @property
    def division_label(self) -> str:
        """Extract the nearest OU label from DN for compact UI display."""
        parts = [p.strip() for p in self.distinguished_name.split(",") if p.strip().upper().startswith("OU=")]
        return parts[0][3:] if parts else "-"


@dataclass(frozen=True)
class FilterCondition:
    """Represents a single GPP Item-Level Targeting filter node."""

    kind: str  # FilterUser | FilterOrgUnit | FilterGroup
    bool_op: str  # AND | OR
    negated: bool
    name: str
    sid: str = ""
    user_context: bool = True
    direct_member: bool = False


@dataclass(frozen=True)
class DriveRule:
    """Represents a parsed <Drive> rule from a GPP Drives.xml file."""

    uid: str
    letter: str  # Single uppercase A-Z
    path: str
    label: str
    action: str  # U | C | R | D
    persistent: bool = True
    use_letter: bool = True
    user_context: bool = True
    bypass_errors: bool = True
    changed: str = ""
    source_gpo_name: str = ""
    source_gpo_guid: str = ""
    filters: tuple[FilterCondition, ...] = ()


@dataclass(frozen=True)
class GpoInfo:
    """AD Group Policy Object metadata relevant to DriveMap evaluation."""

    guid: str
    display_name: str
    distinguished_name: str
    version_number: int
    flags: int = 0
    user_extensions: str = ""

    @property
    def user_version(self) -> int:
        return (self.version_number >> 16) & 0xFFFF

    @property
    def computer_version(self) -> int:
        return self.version_number & 0xFFFF


@dataclass(frozen=True)
class EffectiveMapping:
    """A drive letter mapping that applies to a specific user."""

    letter: str
    path: str
    label: str
    action: str
    source_gpo: str
    scope_type: str  # GLOBAL | OU_GPO | ORG_UNIT_FILTER | GROUP_FILTER | PER_USER | PER_USER_DELETE
    removable_by_bot: bool = False
    uid: str = ""


@dataclass(frozen=True)
class ShareInfo:
    """Network share discovered from GPO catalog or SMB SRVSVC enumeration."""

    server: str
    share_name: str
    unc_path: str
    label: str
    suggested_letter: str = ""
    source: str = "SMB"  # GPO | SMB | BOTH
    dept_gpos: tuple[str, ...] = ()


@dataclass(frozen=True)
class LetterChoice:
    """Availability status of a drive letter A-Z for a given target user."""

    letter: str
    status: str  # FREE | PROTECTED | CONFLICT_GLOBAL | CONFLICT_OU | MAPPED_PER_USER
    occupied_by_path: str = ""
    occupied_by_gpo: str = ""

    @property
    def is_available(self) -> bool:
        return self.status == "FREE"


@dataclass(frozen=True)
class MutationResult:
    """Outcome of a DriveMap add/remove/rollback transaction."""

    tx_id: str
    operation: str  # MAP | UNMAP | DELETE_PERSISTENT | ROLLBACK
    dry_run: bool
    target_user: str
    target_sid: str
    unc_path: str
    letter: str
    label: str
    gpo_version_before: int
    gpo_version_after: int
    backup_dir: str = ""
    message: str = ""


@dataclass
class AuditRecord:
    """Database record of an executed DriveMap transaction."""

    tx_id: str
    created_at: str
    tg_user_id: int
    tg_username: str
    operation: str
    target_sam: str
    target_sid: str
    unc_path: str
    letter: str
    label: str
    gpo_version_before: int
    gpo_version_after: int
    backup_path: str
    status: str
    details: str = ""


ACCESS_NONE = "NONE"
ACCESS_RO = "RO"
ACCESS_RW = "RW"
ACCESS_FULL = "FULL"


@dataclass(frozen=True)
class ADGroup:
    """Represents an Active Directory security group relevant to share access."""

    sam_account_name: str
    distinguished_name: str
    sid: str
    description: str = ""
    member_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class ResolvedSid:
    """Active Directory object metadata resolved by binary objectSid lookup."""

    sid: str
    sam_account_name: str
    display_name: str
    principal_type: str  # USER | GROUP | COMPUTER | WELLKNOWN | UNKNOWN
    distinguished_name: str = ""
    description: str = ""
    member_dns: tuple[str, ...] = ()


@dataclass(frozen=True)
class ShareAclEntry:
    """Single decoded NTFS ACL principal entry on a network share root."""

    sid: str
    principal_name: str
    display_name: str
    principal_type: str  # USER | GROUP | COMPUTER | WELLKNOWN | UNKNOWN
    level: str  # RO | RW | FULL | CUSTOM
    is_deny: bool = False
    is_inherited: bool = False
    raw_mask: int = 0
    raw_flags: int = 0
    is_manageable_group: bool = False
    is_protected: bool = False
    group_dn: str = ""
    group_member_count: int = 0


@dataclass(frozen=True)
class ShareAccessReport:
    """Full live inspection result for NTFS ACLs and linked AD access groups of a share."""

    unc_path: str
    readable: bool
    error: str = ""
    owner_sid: str = ""
    entries: tuple[ShareAclEntry, ...] = ()
    ro_group: Optional[ADGroup] = None
    rw_group: Optional[ADGroup] = None


@dataclass(frozen=True)
class UserShareAccessStatus:
    """Computed effective access summary for a specific AD user on a share."""

    user: ADUser
    unc_path: str
    effective_level: str  # NONE | RO | RW | FULL | DENY | UNKNOWN
    sources: tuple[str, ...] = ()
    direct_level: str = ACCESS_NONE
    can_revoke_direct: bool = False
    member_of_manageable_groups: tuple[str, ...] = ()
    blocked_by_protected_group: bool = False
    acl_readable: bool = True


@dataclass(frozen=True)
class AccessMutationResult:
    """Outcome of granting, revoking, or rolling back access to a share."""

    tx_id: str
    operation: str  # ACCESS_GRANT_AD | ACCESS_REVOKE_AD | ACCESS_GRANT_NTFS | ACCESS_REVOKE_NTFS | ACCESS_ROLLBACK
    dry_run: bool
    target_user: str
    target_sid: str
    unc_path: str
    level: str  # RO | RW | NONE
    mechanism: str  # AD_GROUP | NTFS_DIRECT | HYBRID
    group_name: str = ""
    propagated_objects: int = 0
    skipped_objects: int = 0
    truncated_propagation: bool = False
    requires_relogon: bool = False
    backup_path: str = ""
    message: str = ""

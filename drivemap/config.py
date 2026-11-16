"""Application settings and YAML share policy loader for Tauria DriveMap & Share ACL Engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _load_tauria_defaults() -> dict[str, Any]:
    """Read base configuration from Tauria's config.settings when available."""
    try:
        from config import settings as t_settings

        return {
            "bot_token": getattr(t_settings, "BOT_TOKEN", "") or "0000000000:TAURIA_DEFAULT_PLACEHOLDER",
            "allowed_tg_user_ids": getattr(t_settings, "SUPER_ADMIN_IDS", "") or "0",
            "ad_domain": getattr(t_settings, "AD_DOMAIN", "") or "kdb.kz",
            "ad_dc_host": getattr(t_settings, "AD_SERVER", "") or "192.168.201.15",
            "sysvol_host": getattr(t_settings, "AD_SERVER", "") or "192.168.201.15",
            "sysvol_domain_dir": getattr(t_settings, "AD_DOMAIN", "") or "kdb.kz",
            "ad_user": getattr(t_settings, "AD_USER", "") or "",
            "ad_password": getattr(t_settings, "AD_PASSWORD", "") or "",
            "ad_search_base": getattr(t_settings, "AD_SEARCH_BASE", "") or "DC=kdb,DC=kz",
            "ad_use_ssl": bool(getattr(t_settings, "AD_USE_SSL", False)),
        }
    except Exception:
        return {}


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables / Tauria .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    bot_token: str = Field(default="")
    allowed_tg_user_ids: str = Field(default="")

    ad_domain: str = "kdb.kz"
    ad_netbios: str = "KDB"
    ad_dc_host: str = "192.168.201.15"
    ad_ldaps_port: int = 636
    ad_use_ssl: bool = False
    ad_search_base: str = "DC=kdb,DC=kz"
    ad_ca_bundle: str = "/etc/ssl/certs/ca-certificates.crt"
    ad_user: str = ""
    ad_password: str = ""

    sysvol_host: str = "192.168.201.15"
    sysvol_share: str = "SYSVOL"
    sysvol_domain_dir: str = "kdb.kz"

    target_gpo_name: str = "USR-CFG-DriveMaps-PerUser-U"
    readonly_global_gpo_name: str = "DOM-CFG-MapNetworkDrives"
    file_servers: str = "storage.kdb.kz"
    share_access_ou: str = "OU=ShareAccess,DC=kdb,DC=kz"
    groups_search_base: str = "DC=kdb,DC=kz"
    smb_acl_propagate_max_objects: int = 2500

    dry_run: bool = False
    tls_relax_x509_strict: bool = True

    policy_config_path: Path = Path("config/shares_policy.yaml")
    db_path: Path = Path("data/drivemap_audit.db")
    jsonl_log_path: Path = Path("logs/drivemap_audit.jsonl")
    backup_dir: Path = Path("backups/drivemap")
    share_cache_ttl_sec: int = 600

    @model_validator(mode="before")
    @classmethod
    def _populate_from_tauria(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        t_defs = _load_tauria_defaults()
        out = dict(values)

        # Map Tauria uppercase env keys if present in raw input
        if not out.get("bot_token") and out.get("BOT_TOKEN"):
            out["bot_token"] = out["BOT_TOKEN"]
        if not out.get("allowed_tg_user_ids") and out.get("SUPER_ADMIN_IDS"):
            out["allowed_tg_user_ids"] = out["SUPER_ADMIN_IDS"]
        if not out.get("ad_dc_host") and out.get("AD_SERVER"):
            out["ad_dc_host"] = out["AD_SERVER"]
        if not out.get("sysvol_host") and out.get("AD_SERVER"):
            out["sysvol_host"] = out["AD_SERVER"]
        if not out.get("ad_domain") and out.get("AD_DOMAIN"):
            out["ad_domain"] = out["AD_DOMAIN"]
        if not out.get("sysvol_domain_dir") and out.get("AD_DOMAIN"):
            out["sysvol_domain_dir"] = out["AD_DOMAIN"]
        if not out.get("ad_user") and out.get("AD_USER"):
            out["ad_user"] = out["AD_USER"]
        if not out.get("ad_password") and out.get("AD_PASSWORD"):
            out["ad_password"] = out["AD_PASSWORD"]
        if not out.get("ad_search_base") and out.get("AD_SEARCH_BASE"):
            out["ad_search_base"] = out["AD_SEARCH_BASE"]
        if "ad_use_ssl" not in out and "AD_USE_SSL" in out:
            out["ad_use_ssl"] = out["AD_USE_SSL"]

        for k, v in t_defs.items():
            if not out.get(k) and v not in ("", None):
                out[k] = v

        if not out.get("bot_token"):
            out["bot_token"] = "0000000000:TAURIA_DEFAULT_PLACEHOLDER"
        if not out.get("allowed_tg_user_ids"):
            out["allowed_tg_user_ids"] = "0"
        return out

    @field_validator("allowed_tg_user_ids")
    @classmethod
    def _validate_ids(cls, v: str) -> str:
        ids = [x.strip() for x in str(v).split(",") if x.strip()]
        if not ids or not all(x.isdigit() for x in ids):
            raise ValueError("ALLOWED_TG_USER_IDS must be a comma-separated list of integer user IDs")
        return v

    @property
    def admin_ids(self) -> set[int]:
        return {int(x.strip()) for x in self.allowed_tg_user_ids.split(",") if x.strip() and x.strip().isdigit() and int(x.strip()) > 0}

    @property
    def file_server_list(self) -> list[str]:
        return [s.strip() for s in self.file_servers.split(",") if s.strip()]

    @property
    def primary_file_server(self) -> str:
        return self.file_server_list[0] if self.file_server_list else "storage.kdb.kz"


DEFAULT_PROTECTED_ACL_PRINCIPALS = frozenset(
    {
        "s-1-5-32-544",  # BUILTIN\Administrators
        "s-1-5-32-545",  # BUILTIN\Users
        "s-1-5-18",      # NT AUTHORITY\SYSTEM
        "s-1-3-0",       # CREATOR OWNER
        "s-1-5-11",      # NT AUTHORITY\Authenticated Users
        "s-1-1-0",       # Everyone
        "administrator",
        "администратор",
        "domain admins",
        "enterprise admins",
        "domain users",
        "administrators",
        "администраторы",
        "пользователи",
        "svc_drivemap_bot",
    }
)


@dataclass(frozen=True)
class PolicyConfig:
    """Parsed YAML rules governing protected letters, free pool, blacklists, and ACL groups."""

    protected_letters: frozenset[str] = frozenset({"A", "B", "C", "D"})
    preferred_free_pool: tuple[str, ...] = (
        "G", "E", "F", "H", "I", "J", "K", "L", "M", "N",
        "Q", "V", "O", "S", "U", "X", "R", "T", "P", "W", "Y", "Z",
    )
    share_blacklist_regexes: tuple[re.Pattern[str], ...] = ()
    custom_label_overrides: dict[str, tuple[str, str]] = field(default_factory=dict)
    excluded_user_ou_substrings: tuple[str, ...] = ("OU=Fired,", "OU=Service Accounts,", "OU=Guest,")
    manageable_group_regexes: tuple[re.Pattern[str], ...] = (
        re.compile(r"^Share_.+_(RO|RW)$", re.IGNORECASE),
        re.compile(r"^FS[-_].+_(RO|RW)$", re.IGNORECASE),
    )
    explicit_manageable_groups: frozenset[str] = frozenset()
    protected_acl_principals: frozenset[str] = DEFAULT_PROTECTED_ACL_PRINCIPALS

    def is_share_blacklisted(self, share_name: str) -> bool:
        return any(rx.search(share_name) for rx in self.share_blacklist_regexes)

    def is_user_excluded(self, dn: str) -> bool:
        dn_lower = dn.lower()
        return any(sub.lower() in dn_lower for sub in self.excluded_user_ou_substrings)

    def is_protected_acl_principal(self, sid: str, principal_name: str = "") -> bool:
        sid_l = sid.strip().lower()
        if sid_l in self.protected_acl_principals:
            return True
        if sid_l.endswith(("-500", "-512", "-513", "-519")):
            return True
        if principal_name:
            short = principal_name.strip().split("\\", 1)[-1].lower()
            if short in self.protected_acl_principals or principal_name.strip().lower() in self.protected_acl_principals:
                return True
        return False

    def is_manageable_access_group(self, sam: str, dn: str = "", share_access_ou: str = "") -> bool:
        clean_sam = sam.strip()
        if not clean_sam or self.is_protected_acl_principal("", clean_sam):
            return False
        if share_access_ou and dn and ("," + share_access_ou.lower()) in ("," + dn.lower()):
            return True
        if clean_sam.lower() in self.explicit_manageable_groups:
            return True
        return any(rx.search(clean_sam) for rx in self.manageable_group_regexes)


def load_policy_config(path: Path) -> PolicyConfig:
    """Load YAML share & letter policy configuration safely."""
    target = path if path.exists() else path.with_name("shares_policy.example.yaml")
    if not target.exists():
        return PolicyConfig()
    raw = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    protected = frozenset(str(x).strip().upper() for x in raw.get("protected_letters", ["A", "B", "C", "D"]))
    pool = tuple(str(x).strip().upper() for x in raw.get("preferred_free_pool", [])) or PolicyConfig().preferred_free_pool
    rx_list = tuple(re.compile(p, re.IGNORECASE) for p in raw.get("share_blacklist_patterns", []))
    overrides: dict[str, tuple[str, str]] = {}
    for unc, meta in (raw.get("custom_label_overrides") or {}).items():
        if isinstance(meta, dict):
            overrides[unc.lower()] = (
                str(meta.get("label", "")).strip(),
                str(meta.get("preferred_letter", "")).strip().upper(),
            )
    excluded_ous = tuple(str(x) for x in raw.get("excluded_user_ou_substrings", ["OU=Fired,", "OU=Service Accounts,", "OU=Guest,"]))
    default_mg_patterns = [r"^Share_.+_(RO|RW)$", r"^FS[-_].+_(RO|RW)$"]
    mg_regexes = tuple(re.compile(p, re.IGNORECASE) for p in raw.get("manageable_group_patterns", default_mg_patterns))
    explicit_groups = frozenset(str(x).strip().lower() for x in raw.get("explicit_manageable_groups", []) if str(x).strip())
    prot_principals = DEFAULT_PROTECTED_ACL_PRINCIPALS | frozenset(
        str(x).strip().lower() for x in raw.get("protected_acl_principals", []) if str(x).strip()
    )
    return PolicyConfig(
        protected_letters=protected,
        preferred_free_pool=pool,
        share_blacklist_regexes=rx_list,
        custom_label_overrides=overrides,
        excluded_user_ou_substrings=excluded_ous,
        manageable_group_regexes=mg_regexes,
        explicit_manageable_groups=explicit_groups,
        protected_acl_principals=prot_principals,
    )

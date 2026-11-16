import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Telegram
    BOT_TOKEN: str = Field(default="", description="Telegram Bot API Token")
    SUPER_ADMIN_IDS: str = Field(default="", description="Comma-separated Telegram IDs of SuperAdmins")
    LOG_CHAT_ID: int | None = Field(default=None, description="Telegram Chat ID for audit/alerts")

    # Shared SQLite Database (Tauria & Testarossa)
    SHARED_DB_PATH: str = Field(default="", description="Shared SQLite DB path for Tauria & Testarossa")

    # Active Directory
    AD_SERVER: str = Field(default="192.168.201.15", description="AD Domain Controller IP or FQDN")
    AD_DOMAIN: str = Field(default="kdb.kz", description="Active Directory domain")
    AD_USER: str = Field(default="", description="Service account login")
    AD_PASSWORD: str = Field(default="", description="Service account password")
    AD_SEARCH_BASE: str = Field(default="DC=kdb,DC=kz", description="LDAP search base")
    AD_USE_SSL: bool = Field(default=False, description="Use LDAPS")

    # Workstation Admin Credentials (WinRM / SMB C$)
    PC_ADMIN_USER: str = Field(default="", description="Workstation admin user for WinRM/SMB")
    PC_ADMIN_PASSWORD: str = Field(default="", description="Workstation admin password")

    # IBM Lotus Notes ID Storage & Subpath
    LOTUS_STORAGE_UNC: str = Field(default=r"\\storage\public\id", description="UNC path for Lotus ID storage")
    LOTUS_NOTES_SUBPATH: str = Field(default=r"AppData\Local\IBM\Notes\Data", description="Subpath for Lotus ID on PC")
    LOTUS_STORAGE_USER: str = Field(default="", description="SMB user for Lotus storage")
    LOTUS_STORAGE_PASSWORD: str = Field(default="", description="SMB password for Lotus storage")

    # Specific AD OUs
    AD_DISABLED_USERS_OU: str = Field(
        default="OU=Disabled Users,DC=kdb,DC=kz",
        description="OU where offboarded/disabled accounts are moved"
    )
    TARGET_PC_OUS: str = Field(
        default="OU=KDB Computers,DC=kdb,DC=kz;OU=KDB Nout,DC=kdb,DC=kz;CN=Servers,DC=kdb,DC=kz",
        description="Semicolon-separated OUs for PC scanning"
    )
    TARGET_PC_MOVE_OU: str = Field(
        default="OU=KDB notebooklenovo,OU=KDB Nout,DC=kdb,DC=kz",
        description="Target OU for laptop moves"
    )
    CERT_USER_OU: str = Field(
        default="OU=notebooklenovo,OU=Bank Divisions,OU=KDB Users,DC=kdb,DC=kz",
        description="Target OU for certificate issuance"
    )

    # Exchange Server
    EXCHANGE_SERVER: str = Field(default="192.168.254.23", description="Exchange Server IP/FQDN")

    # DriveMap & File Shares Integration (SYSVOL / GPO / SMB ACL)
    SYSVOL_HOST: str = Field(default="192.168.201.15", description="SYSVOL Domain Controller host")
    SYSVOL_SHARE: str = Field(default="SYSVOL", description="SYSVOL SMB share name")
    SYSVOL_DOMAIN_DIR: str = Field(default="kdb.kz", description="SYSVOL domain directory")
    TARGET_GPO_NAME: str = Field(default="USR-CFG-DriveMaps-PerUser-U", description="Per-user DriveMap GPO name")
    READONLY_GLOBAL_GPO_NAME: str = Field(default="DOM-CFG-MapNetworkDrives", description="Global read-only DriveMap GPO")
    FILE_SERVERS: str = Field(default="STORAGE", description="Comma-separated file servers for SMB share discovery")
    SHARE_ACCESS_OU: str = Field(
        default="OU=ShareAccess,OU=Groups,OU=KDB Users,DC=kdb,DC=kz",
        description="OU for share access security groups"
    )
    GROUPS_SEARCH_BASE: str = Field(
        default="DC=kdb,DC=kz",
        description="Base DN for searching share access groups"
    )
    POLICY_CONFIG_PATH: str = Field(
        default="config/shares_policy.yaml",
        description="Path to YAML share & letter policy configuration"
    )

    # Monitored Servers & Infrastructure
    DEFAULT_MONITOR_HOSTS: str = Field(
        default="192.168.201.15:389:AD DS,192.168.202.117:51522:App Server,192.168.201.1:80:Gateway",
        description="Comma-separated default targets host:port:name"
    )

    # Kolins (Testarossa) Integration
    KOLINS_PATH: str = Field(default="/opt/kolins", description="Path to Kolins Support Bot directory")

    @property
    def super_admins(self) -> List[int]:
        if not self.SUPER_ADMIN_IDS:
            return []
        res = []
        for raw_id in str(self.SUPER_ADMIN_IDS).split(","):
            raw_id = raw_id.strip()
            if raw_id.isdigit():
                res.append(int(raw_id))
        return res

    @property
    def pc_admin_user(self) -> str:
        return self.PC_ADMIN_USER or self.AD_USER

    @property
    def pc_admin_password(self) -> str:
        return self.PC_ADMIN_PASSWORD or self.AD_PASSWORD

    @property
    def lotus_storage_user(self) -> str:
        return self.LOTUS_STORAGE_USER or self.AD_USER

    @property
    def lotus_storage_password(self) -> str:
        return self.LOTUS_STORAGE_PASSWORD or self.AD_PASSWORD

    @property
    def target_pc_ous_list(self) -> List[str]:
        raw = (self.TARGET_PC_OUS or "").strip()
        if not raw:
            return [
                "OU=KDB Computers,DC=kdb,DC=kz",
                "OU=KDB Nout,DC=kdb,DC=kz",
                "CN=Servers,DC=kdb,DC=kz",
            ]
        return [ou.strip() for ou in raw.split(";") if ou.strip()]

    @property
    def file_server_list(self) -> List[str]:
        return [s.strip() for s in (self.FILE_SERVERS or "").split(",") if s.strip()]


settings = Settings()

# Module-level compatibility aliases for Kolins / DriveMap modules
BOT_TOKEN = settings.BOT_TOKEN
AD_SERVER = settings.AD_SERVER
AD_DOMAIN = settings.AD_DOMAIN
AD_USER = settings.AD_USER
AD_PASSWORD = settings.AD_PASSWORD
AD_SEARCH_BASE = settings.AD_SEARCH_BASE
PC_ADMIN_USER = settings.pc_admin_user
PC_ADMIN_PASSWORD = settings.pc_admin_password
LOTUS_STORAGE_UNC = settings.LOTUS_STORAGE_UNC
LOTUS_NOTES_SUBPATH = settings.LOTUS_NOTES_SUBPATH
LOTUS_STORAGE_USER = settings.lotus_storage_user
LOTUS_STORAGE_PASSWORD = settings.lotus_storage_password
TARGET_PC_OUS = settings.target_pc_ous_list
TARGET_PC_MOVE_OU = settings.TARGET_PC_MOVE_OU
CERT_USER_OU = settings.CERT_USER_OU
EXCHANGE_SERVER = settings.EXCHANGE_SERVER
PROTECTED_AD_GROUPS = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "administrators",
    "account operators",
    "backup operators",
}
LOG_CHAT_ID = settings.LOG_CHAT_ID
ADMIN_IDS = settings.super_admins

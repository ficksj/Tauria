"""DriveMap & Share ACL Engine integration package for Tauria SuperAdmin Bot."""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Dict, Optional

from aiogram import BaseMiddleware, Dispatcher, Router
from aiogram.types import TelegramObject

from drivemap.config import PolicyConfig, Settings, load_policy_config
from drivemap.handlers import build_root_router
from drivemap.services.access_engine import ShareAccessEngine
from drivemap.services.ad_ldap import LdapsAdClient
from drivemap.services.audit_db import AuditRepository
from drivemap.services.drivemap_engine import DriveMapEngine
from drivemap.services.share_discovery import ShareDiscoveryService
from drivemap.services.smb_acl import SmbAclClient
from drivemap.services.smb_sysvol import SmbSysvolClient

logger = logging.getLogger("drivemap")

__all__ = [
    "DriveMapContextMiddleware",
    "init_drivemap_module",
]


class DriveMapContextMiddleware(BaseMiddleware):
    """Injects DriveMap & Share ACL service dependencies into handler data dict."""

    def __init__(
        self,
        *,
        settings: Settings,
        policy: PolicyConfig,
        ad: LdapsAdClient,
        sysvol: SmbSysvolClient,
        shares_svc: ShareDiscoveryService,
        engine: DriveMapEngine,
        access_engine: ShareAccessEngine,
        audit: AuditRepository,
    ) -> None:
        self.deps = {
            "settings": settings,
            "policy": policy,
            "ad": ad,
            "sysvol": sysvol,
            "shares_svc": shares_svc,
            "engine": engine,
            "access_engine": access_engine,
            "audit": audit,
        }

    async def __call__(
        self,
        handler: Callable[[TelegramObject, Dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: Dict[str, Any],
    ) -> Any:
        data.update(self.deps)
        return await handler(event, data)


async def init_drivemap_module(dp: Optional[Dispatcher] = None) -> Router:
    """Initialize DriveMap & Share ACL services, register dependency middleware, and return the Router."""
    settings = Settings()
    policy = load_policy_config(settings.policy_config_path)

    audit = AuditRepository(db_path=settings.db_path, jsonl_path=settings.jsonl_log_path)
    await audit.init()

    ad_client = LdapsAdClient(
        dc_host=settings.ad_dc_host,
        ldaps_port=settings.ad_ldaps_port,
        domain=settings.ad_domain,
        search_base=settings.ad_search_base,
        username=settings.ad_user,
        password=settings.ad_password,
        ca_bundle=settings.ad_ca_bundle,
        policy=policy,
        use_ssl=settings.ad_use_ssl,
    )
    sysvol_client = SmbSysvolClient(
        host=settings.sysvol_host,
        share=settings.sysvol_share,
        domain_dir=settings.sysvol_domain_dir,
        username=settings.ad_user,
        password=settings.ad_password,
    )
    shares_svc = ShareDiscoveryService(
        ad=ad_client,
        sysvol=sysvol_client,
        policy=policy,
        file_servers=settings.file_server_list,
        smb_username=settings.ad_user,
        smb_password=settings.ad_password,
        domain=settings.ad_domain,
        cache_ttl_sec=settings.share_cache_ttl_sec,
    )
    engine = DriveMapEngine(
        ad=ad_client,
        sysvol=sysvol_client,
        audit=audit,
        policy=policy,
        target_gpo_name=settings.target_gpo_name,
        netbios_domain=settings.ad_netbios,
        backup_dir=settings.backup_dir,
        dry_run=settings.dry_run,
    )
    acl_client = SmbAclClient(
        username=settings.ad_user,
        password=settings.ad_password,
        domain=settings.ad_domain,
    )
    access_engine = ShareAccessEngine(
        ad=ad_client,
        acl=acl_client,
        audit=audit,
        policy=policy,
        netbios_domain=settings.ad_netbios,
        share_access_ou=settings.share_access_ou,
        backup_dir=settings.backup_dir,
        max_propagate=settings.smb_acl_propagate_max_objects,
        dry_run=settings.dry_run,
    )

    router = build_root_router()
    ctx_mw = DriveMapContextMiddleware(
        settings=settings,
        policy=policy,
        ad=ad_client,
        sysvol=sysvol_client,
        shares_svc=shares_svc,
        engine=engine,
        access_engine=access_engine,
        audit=audit,
    )
    router.message.middleware(ctx_mw)
    router.callback_query.middleware(ctx_mw)

    if dp is not None:
        dp["drivemap_settings"] = settings
        dp["drivemap_policy"] = policy
        dp["ad"] = ad_client
        dp["sysvol"] = sysvol_client
        dp["shares_svc"] = shares_svc
        dp["engine"] = engine
        dp["access_engine"] = access_engine
        dp["audit"] = audit

    logger.info(
        "DriveMap & Share ACL module initialized (dc=%s, domain=%s, gpo=%s, dry_run=%s)",
        settings.ad_dc_host,
        settings.ad_domain,
        settings.target_gpo_name,
        settings.dry_run,
    )
    return router

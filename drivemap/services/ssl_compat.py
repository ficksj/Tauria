"""TLS helpers for Python 3.13+ compatibility behind corporate TLS proxies and internal AD LDAPS."""

from __future__ import annotations

import ssl
from pathlib import Path
from typing import Optional

from aiogram.client.session.aiohttp import AiohttpSession
from ldap3 import Tls


def build_ssl_context(ca_bundle: Optional[str] = None, relax_x509_strict: bool = True) -> ssl.SSLContext:
    """Create a verifying SSLContext compatible with CAs lacking Authority Key Identifier."""
    cafile = ca_bundle if ca_bundle and Path(ca_bundle).exists() else None
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    if relax_x509_strict and hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def create_aiogram_session(ca_bundle: Optional[str], relax_x509_strict: bool) -> AiohttpSession:
    """Build an aiogram AiohttpSession with verified TLS compatible with local CA gateways."""
    session = AiohttpSession()
    session._connector_init["ssl"] = build_ssl_context(
        ca_bundle=ca_bundle,
        relax_x509_strict=relax_x509_strict,
    )
    return session


def create_ldaps_tls(ca_bundle: Optional[str], validate: int = ssl.CERT_NONE) -> Tls:
    """Create ldap3 Tls configuration for AD LDAPS / StartTLS.

    Defaults to CERT_NONE when connecting to internal DC IPs (e.g. 192.168.201.15)
    unless an explicit CA bundle file exists and strict validation is requested.
    """
    cafile = ca_bundle if ca_bundle and Path(ca_bundle).exists() else None
    return Tls(
        ca_certs_file=cafile,
        validate=validate,
        version=ssl.PROTOCOL_TLS_CLIENT,
    )

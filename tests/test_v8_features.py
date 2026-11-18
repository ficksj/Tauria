from __future__ import annotations

import json
import os
import zipfile
from unittest.mock import AsyncMock, patch

import pytest

from services import exchange_service
from services import infra_service
from services import audit_pack_service


@pytest.mark.asyncio
async def test_exchange_mailbox_operations(monkeypatch):
    # Mock _run_exchange_ps_sync to return valid JSON payloads
    def fake_run_ps(ps_script: str, timeout: int = 35):
        if "Get-MailboxStatistics" in ps_script:
            return {
                "ok": True,
                "stdout": json.dumps({
                    "ok": True,
                    "exists": True,
                    "primary_smtp": "ivanov@kdb.kz",
                    "database": "EXDB01",
                    "alias": "ivanov",
                    "hidden_from_gal": False,
                    "forwarding": "",
                    "total_size": "50 MB",
                    "item_count": 120,
                }),
            }
        if "Enable-Mailbox" in ps_script:
            return {
                "ok": True,
                "stdout": json.dumps({
                    "ok": True,
                    "already_exists": False,
                    "primary_smtp": "ivanov@kdb.kz",
                    "database": "EXDB01",
                    "alias": "ivanov",
                }),
            }
        if "Disable-Mailbox" in ps_script:
            return {
                "ok": True,
                "stdout": json.dumps({
                    "ok": True,
                    "primary_smtp": "ivanov@kdb.kz",
                }),
            }
        return {"ok": True, "stdout": json.dumps({"ok": True})}

    monkeypatch.setattr(exchange_service, "_run_exchange_ps_sync", fake_run_ps)

    details = await exchange_service.get_mailbox_details("ivanov")
    assert details["ok"] is True
    assert details["exists"] is True
    assert details["primary_smtp"] == "ivanov@kdb.kz"
    assert details["item_count"] == 120

    created = await exchange_service.enable_user_mailbox("ivanov")
    assert created["ok"] is True
    assert created["already_exists"] is False
    assert created["database"] == "EXDB01"

    deleted = await exchange_service.disable_user_mailbox("ivanov")
    assert deleted["ok"] is True
    assert deleted["primary_smtp"] == "ivanov@kdb.kz"

    gal = await exchange_service.set_mailbox_hidden_gal("ivanov", True)
    assert gal["ok"] is True

    # Injection guard
    bad = await exchange_service.enable_user_mailbox("ivanov; rm -rf")
    assert bad["ok"] is False


@pytest.mark.asyncio
async def test_add_dns_record_validation_and_mock(monkeypatch):
    # Invalid IPv4 should fail before WinRM
    bad_ip = await infra_service.add_dns_record("gitlab", "999.999.1.1", "A", zone="kdb.kz")
    assert bad_ip["ok"] is False
    assert "IPv4" in bad_ip["error"]

    # Invalid record type
    bad_type = await infra_service.add_dns_record("gitlab", "192.168.202.50", "MX", zone="kdb.kz")
    assert bad_type["ok"] is False

    # Injection guard
    bad_name = await infra_service.add_dns_record("gitlab;whoami", "192.168.202.50", "A", zone="kdb.kz")
    assert bad_name["ok"] is False


@pytest.mark.asyncio
async def test_generate_kpmg_audit_zip(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

    with (
        patch.object(
            audit_pack_service.ad_service,
            "inspect_privileged_groups",
            new=AsyncMock(return_value={"success": True, "groups": {"Domain Admins": ["dcadm01"]}}),
        ),
        patch.object(
            audit_pack_service.ad_service,
            "get_inactive_users",
            new=AsyncMock(return_value=[{"username": "old_user", "display_name": "Old User", "days_inactive": 95}]),
        ),
        patch.object(
            audit_pack_service.ad_service,
            "get_never_expire_password_users",
            new=AsyncMock(return_value=[{"username": "svc_test", "display_name": "Service Test", "department": "IT"}]),
        ),
        patch.object(
            audit_pack_service,
            "get_exchange_overview",
            new=AsyncMock(return_value={"ok": True, "queues": [], "databases": []}),
        ),
        patch.object(
            audit_pack_service,
            "get_exchange_forwarding_audit",
            new=AsyncMock(return_value={"ok": True, "mailbox_forwards": [], "transport_rules": [], "journal_rules": []}),
        ),
    ):
        zip_path = await audit_pack_service.generate_kpmg_audit_zip()
        assert os.path.exists(zip_path)
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = set(zf.namelist())
            assert "00_KPMG_GTS_Summary.html" in names
            assert "01_privileged_groups.csv" in names
            assert "02_inactive_users_60d.csv" in names
            assert "03_never_expire_passwords.csv" in names
            assert "04_exchange_gts_summary.json" in names

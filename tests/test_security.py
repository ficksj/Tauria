"""Unit tests for Auth middleware and Settings validation."""

from __future__ import annotations

import pytest

from drivemap.config import Settings
from drivemap.middlewares.auth_middleware import AdminAllowlistMiddleware


def test_settings_parses_admin_ids() -> None:
    s = Settings(
        _env_file=None,
        bot_token="123456:ABCDEF_fake_test_token",
        allowed_tg_user_ids="100000001, 999999",
        file_servers="FS01,FS02",
    )
    assert s.admin_ids == {100000001, 999999}
    assert s.file_server_list == ["FS01", "FS02"]
    assert s.primary_file_server == "FS01"


@pytest.mark.asyncio
async def test_auth_middleware_blocks_unlisted_and_group_chats() -> None:
    mw = AdminAllowlistMiddleware({100000001})
    called = False

    async def dummy_handler(event, data):
        nonlocal called
        called = True
        return "ok"

    from aiogram.types import Chat, Message, User

    m_non_admin = Message.model_construct(
        message_id=1,
        date=0,
        chat=Chat(id=1, type="private"),
        from_user=User(id=111111, is_bot=False, first_name="Bad"),
    )
    assert await mw(dummy_handler, m_non_admin, {}) is None
    assert called is False

    m_group = Message.model_construct(
        message_id=2,
        date=0,
        chat=Chat(id=-100, type="supergroup"),
        from_user=User(id=100000001, is_bot=False, first_name="Admin"),
    )
    assert await mw(dummy_handler, m_group, {}) is None
    assert called is False

    m_ok = Message.model_construct(
        message_id=3,
        date=0,
        chat=Chat(id=100000001, type="private"),
        from_user=User(id=100000001, is_bot=False, first_name="Admin"),
    )
    assert await mw(dummy_handler, m_ok, {}) == "ok"
    assert called is True


def test_extract_ancestor_dns_handles_escaped_cn_comma() -> None:
    from drivemap.services.ad_ldap import extract_ancestor_dns

    dn = r"CN=Smith\, John,OU=IT,OU=Users,DC=corp,DC=example,DC=com"
    assert extract_ancestor_dns(dn, "DC=corp,DC=example,DC=com") == [
        "DC=corp,DC=example,DC=com",
        "OU=Users,DC=corp,DC=example,DC=com",
        "OU=IT,OU=Users,DC=corp,DC=example,DC=com",
    ]

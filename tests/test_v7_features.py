from __future__ import annotations

from unittest.mock import AsyncMock
import pytest
from aiogram.types import Message, CallbackQuery, User

import services.db_service as db_service
from config import settings
from middlewares.admin_middleware import SuperAdminMiddleware


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_tauria_v7.db")
    monkeypatch.setattr(db_service, "DB_PATH", db_file)
    db_service._init_db_sync(db_file)
    return db_file


@pytest.mark.asyncio
async def test_bot_admins_crud(temp_db):
    # Изначально список пуст
    admins = await db_service.get_bot_admins()
    assert admins == []
    assert await db_service.get_bot_admin_role(1001) is None

    # Добавляем оператора
    await db_service.add_bot_admin(1001, "operator_ivan", "operator")
    role = await db_service.get_bot_admin_role(1001)
    assert role == "operator"

    # Добавляем суперадмина
    await db_service.add_bot_admin(1002, "super_petr", "superadmin")
    assert await db_service.get_bot_admin_role(1002) == "superadmin"

    admins = await db_service.get_bot_admins()
    assert len(admins) == 2
    by_id = {a["user_id"]: a for a in admins}
    assert by_id[1001]["username"] == "operator_ivan"
    assert by_id[1001]["role"] == "operator"
    assert by_id[1002]["username"] == "super_petr"
    assert by_id[1002]["role"] == "superadmin"

    # Обновление роли существующего админа через ON CONFLICT
    await db_service.add_bot_admin(1001, "ivan_upgraded", "superadmin")
    assert await db_service.get_bot_admin_role(1001) == "superadmin"

    # Удаление
    removed = await db_service.remove_bot_admin(1001)
    assert removed is True
    assert await db_service.get_bot_admin_role(1001) is None

    # Повторное удаление несуществующего возвращает False
    assert await db_service.remove_bot_admin(1001) is False


def _make_callback(user_id: int, username: str, data: str) -> CallbackQuery:
    cb = AsyncMock(spec=CallbackQuery)
    cb.from_user = User(id=user_id, is_bot=False, first_name="Test", username=username)
    cb.data = data
    cb.answer = AsyncMock()
    return cb


def _make_message(user_id: int, username: str, text: str) -> Message:
    msg = AsyncMock(spec=Message)
    msg.from_user = User(id=user_id, is_bot=False, first_name="Test", username=username)
    msg.text = text
    msg.answer = AsyncMock()
    return msg


@pytest.mark.asyncio
async def test_superadmin_middleware_roles(temp_db, monkeypatch):
    # Настраиваем корневого суперадмина 9999 в settings
    monkeypatch.setattr(settings, "SUPER_ADMIN_IDS", "9999")
    # Настраиваем оператора 2002 в SQLite
    await db_service.add_bot_admin(2002, "op_user", "operator")

    mw = SuperAdminMiddleware()
    handler = AsyncMock(return_value="handled")

    # 1. SuperAdmin проходит к killswitch:prompt и /exec
    cb_sa = _make_callback(9999, "root_admin", "killswitch:prompt")
    data_sa = {}
    res = await mw(handler, cb_sa, data_sa)
    assert res == "handled"
    assert data_sa["user_role"] == "superadmin"

    msg_sa = _make_message(9999, "root_admin", "/exec uptime")
    data_sa_msg = {}
    res_msg = await mw(handler, msg_sa, data_sa_msg)
    assert res_msg == "handled"
    assert data_sa_msg["user_role"] == "superadmin"

    # 2. Operator проходит к обычным операциям (например, home:user)
    handler.reset_mock()
    cb_op_ok = _make_callback(2002, "op_user", "home:user")
    data_op = {}
    res_op = await mw(handler, cb_op_ok, data_op)
    assert res_op == "handled"
    assert data_op["user_role"] == "operator"

    # 3. Operator блокируется на killswitch:prompt, ad:offboard, menu:rbac
    for restricted_cb in ("killswitch:prompt", "ad:offboard", "menu:rbac", "rbac:add:operator"):
        handler.reset_mock()
        cb_op_block = _make_callback(2002, "op_user", restricted_cb)
        res_block = await mw(handler, cb_op_block, {})
        assert res_block is None
        handler.assert_not_called()
        cb_op_block.answer.assert_awaited_once_with(
            "⛔️ Доступ запрещен: эта операция доступна только SuperAdmin.",
            show_alert=True,
        )

    # 4. Operator блокируется на /exec
    handler.reset_mock()
    msg_op_exec = _make_message(2002, "op_user", "/exec ls -la")
    res_exec = await mw(handler, msg_op_exec, {})
    assert res_exec is None
    handler.assert_not_called()
    msg_op_exec.answer.assert_awaited_once_with(
        "⛔️ Команда /exec доступна только для роли SuperAdmin."
    )

    # 5. Неизвестный пользователь блокируется полностью (и на message, и на callback)
    handler.reset_mock()
    cb_stranger = _make_callback(7777, "stranger", "home:user")
    assert await mw(handler, cb_stranger, {}) is None
    handler.assert_not_called()
    cb_stranger.answer.assert_awaited_once_with(
        "⛔️ Доступ запрещен: недостаточно прав.",
        show_alert=True,
    )

    msg_stranger = _make_message(7777, "stranger", "/start")
    assert await mw(handler, msg_stranger, {}) is None
    handler.assert_not_called()
    msg_stranger.answer.assert_awaited_once()


def test_parse_sz_text_and_report_formatting():
    import datetime
    from handlers.ad_admin_handlers import (
        parse_sz_text,
        format_helpdesk_onboarding_report,
        _generate_ad_username,
    )
    from services.ad_service import datetime_to_ad_filetime

    raw_sz = """
    Служебная записка: № 14-05/782 от 16.11.2026
    ФИО: Сериков Айбек Нурланович
    Подразделение: Департамент информационных технологий
    Должность: Стажер-разработчик
    Куратор: Белецкий К. (каб. 405)
    Период: 60 дней
    """
    parsed = parse_sz_text(raw_sz)
    assert parsed["full_name"] == "Сериков Айбек Нурланович"
    assert parsed["department"] == "Департамент информационных технологий"
    assert parsed["is_intern"] is True
    assert parsed["expires_days"] == 60
    assert "14-05/782" in parsed["sz_number"]
    assert "Белецкий" in parsed["curator"]

    uname = _generate_ad_username(parsed["full_name"])
    assert uname == "s.aybek"

    report = format_helpdesk_onboarding_report(
        full_name=parsed["full_name"],
        username=uname,
        password="TempPass!23",
        department=parsed["department"],
        title=parsed["title"],
        sz_info=parsed["sz_number"],
        curator=parsed["curator"],
        period_str="60 дней (стажер)",
        access_str="IT, VPN-Users",
    )
    assert "Выход сотрудника/стажера / УЗ готова" in report
    assert "• СЗ: № 14-05/782 от 16.11.2026" in report
    assert "• Логин: s.aybek" in report
    assert "(смена при первом входе)" in report

    ft = datetime_to_ad_filetime(datetime.datetime(2026, 12, 31, 12, 0))
    assert ft > 130_000_000_000_000_000

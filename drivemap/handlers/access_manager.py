"""Handlers for inspecting and managing network share NTFS/AGDLP permissions."""

from __future__ import annotations

import logging
from typing import Optional

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from drivemap.config import Settings
from drivemap.handlers.states import AccessStates
from drivemap.keyboards.inline import (
    access_direct_users_keyboard,
    access_members_keyboard,
    access_result_keyboard,
    access_share_keyboard,
    access_user_grant_keyboard,
    back_home_keyboard,
    clear_tracked_panel,
    safe_edit_markup,
    safe_edit_text,
    shares_keyboard,
    track_panel,
    users_keyboard,
)
from drivemap.models import (
    ACCESS_NONE,
    ACCESS_RO,
    ACCESS_RW,
    ADGroup,
    ADUser,
    ShareAccessReport,
    ShareAclEntry,
    ShareInfo,
)
from drivemap.services.access_engine import AccessOperationError, ShareAccessEngine
from drivemap.services.ad_ldap import AdBackend
from drivemap.services.drivemap_engine import DriveMapValidationError, validate_unc_path
from drivemap.services.share_discovery import ShareDiscoveryService
from drivemap.ui import (
    banner_bubble,
    filter_shares_by_category,
    h,
    progress_header,
    render_access_direct_users,
    render_access_group_members,
    render_access_result,
    render_access_share_view,
    render_access_user_grant,
    render_access_user_prompt,
    render_share_step,
)

logger = logging.getLogger(__name__)
router = Router()


async def _show_access_share_step(
    target_msg: Message,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
    *,
    edit: bool = True,
    force_refresh: bool = False,
    server_filter: str = "ALL",
    query: str = "",
    banner_html: str = "",
) -> None:
    primary = settings.primary_file_server
    all_shares = await shares_svc.get_shares(force_refresh=force_refresh)
    base_list = await shares_svc.search_shares(query, limit=60) if query else all_shares
    filtered = filter_shares_by_category(base_list, server_filter, primary_server=primary)

    await state.set_state(AccessStates.choosing_share)
    await state.update_data(
        acc_catalog=all_shares,
        acc_shares=filtered,
        acc_page=0,
        acc_filter=server_filter,
        acc_query=query,
    )
    text = render_share_step(
        filtered,
        total_catalog=len(all_shares),
        server_filter=server_filter,
        query=query,
        banner_html=banner_html,
        step_header=progress_header(1, 2, "🔐 Доступы к дискам", "Выбор сетевой шары"),
        primary_label=primary,
    )
    kb = shares_keyboard(
        filtered,
        page=0,
        prefix="ash",
        server_filter=server_filter,
        has_query=bool(query),
        primary_label=primary,
    )
    if edit:
        edited = await safe_edit_text(target_msg, text, reply_markup=kb)
        await track_panel(state, edited)
    else:
        if target_msg.bot:
            await clear_tracked_panel(target_msg.bot, state)
        sent = await target_msg.answer(text, reply_markup=kb)
        await track_panel(state, sent)


async def _show_share_acl_view(
    target_msg: Message,
    state: FSMContext,
    access_engine: ShareAccessEngine,
    unc_path: str,
    *,
    edit: bool = True,
    banner_html: str = "",
) -> None:
    report = await access_engine.inspect_share_access(unc_path)
    await state.set_state(AccessStates.viewing_share)
    await state.update_data(acc_unc=report.unc_path, acc_report=report)
    text = render_access_share_view(report, banner_html=banner_html)
    kb = access_share_keyboard(report)
    if edit:
        edited = await safe_edit_text(target_msg, text, reply_markup=kb)
        await track_panel(state, edited)
    else:
        if target_msg.bot:
            await clear_tracked_panel(target_msg.bot, state)
        sent = await target_msg.answer(text, reply_markup=kb)
        await track_panel(state, sent)


async def _show_user_access_view(
    target_msg: Message,
    state: FSMContext,
    settings: Settings,
    access_engine: ShareAccessEngine,
    user: ADUser,
    *,
    edit: bool = True,
    refresh_acl: bool = True,
    banner_html: str = "",
) -> None:
    data = await state.get_data()
    unc_path: str = data["acc_unc"]
    report: Optional[ShareAccessReport] = data.get("acc_report")
    if refresh_acl or report is None or report.unc_path != unc_path:
        report = await access_engine.inspect_share_access(unc_path)
    status = await access_engine.check_user_access(unc_path, user, report=report)

    await state.set_state(AccessStates.configuring_user)
    await state.update_data(acc_report=report, acc_user=user, acc_status=status)
    text = render_access_user_grant(
        settings.ad_netbios,
        unc_path,
        status,
        report,
        banner_html=banner_html,
    )
    kb = access_user_grant_keyboard(status, report)
    if edit:
        edited = await safe_edit_text(target_msg, text, reply_markup=kb)
        await track_panel(state, edited)
    else:
        if target_msg.bot:
            await clear_tracked_panel(target_msg.bot, state)
        sent = await target_msg.answer(text, reply_markup=kb)
        await track_panel(state, sent)


@router.callback_query(F.data.in_({"drv:access", "menu:access"}))
async def cb_access_menu(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    await callback.answer("Загружаю список шар...")
    if callback.message:
        await _show_access_share_step(callback.message, state, shares_svc, settings, edit=True)


@router.callback_query(AccessStates.choosing_share, F.data.startswith("ash:flt:"))
async def cb_access_share_filter(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    category = callback.data.split(":")[2]
    data = await state.get_data()
    await callback.answer()
    if callback.message:
        await _show_access_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=category,
            query=data.get("acc_query", ""),
        )


@router.callback_query(AccessStates.choosing_share, F.data.startswith("ash:page:"))
async def cb_access_share_page(callback: CallbackQuery, state: FSMContext, settings: Settings) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    shares: list[ShareInfo] = data.get("acc_shares", [])
    await state.update_data(acc_page=page)
    if callback.message:
        await safe_edit_markup(
            callback.message,
            reply_markup=shares_keyboard(
                shares,
                page=page,
                prefix="ash",
                server_filter=data.get("acc_filter", "ALL"),
                has_query=bool(data.get("acc_query")),
                primary_label=settings.primary_file_server,
            ),
        )
    await callback.answer()


@router.callback_query(AccessStates.choosing_share, F.data == "ash:reset")
async def cb_access_share_reset(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    data = await state.get_data()
    await callback.answer("Поиск сброшен")
    if callback.message:
        await _show_access_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=data.get("acc_filter", "ALL"),
            query="",
        )


@router.callback_query(AccessStates.choosing_share, F.data == "ash:refresh")
async def cb_access_share_refresh(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    data = await state.get_data()
    await callback.answer("Обновляю список шар...")
    if callback.message:
        await _show_access_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            force_refresh=True,
            server_filter=data.get("acc_filter", "ALL"),
            query=data.get("acc_query", ""),
            banner_html=banner_bubble("ok", "Список шар обновлён."),
        )


@router.callback_query(AccessStates.choosing_share, F.data.startswith("ash:sel:"))
async def cb_access_share_select(
    callback: CallbackQuery,
    state: FSMContext,
    access_engine: ShareAccessEngine,
) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    shares: list[ShareInfo] = data.get("acc_shares", [])
    if idx < 0 or idx >= len(shares):
        await callback.answer("Список устарел, выберите снова.", show_alert=True)
        return
    share = shares[idx]
    await callback.answer("Читаю NTFS ACL и группы AD...")
    if callback.message:
        await _show_share_acl_view(callback.message, state, access_engine, share.unc_path, edit=True)


@router.message(AccessStates.choosing_share, F.text)
async def msg_access_share_search(
    message: Message,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    access_engine: ShareAccessEngine,
    settings: Settings,
) -> None:
    q = (message.text or "").strip()
    if q.startswith("\\\\"):
        try:
            clean_unc = validate_unc_path(q)
        except DriveMapValidationError as exc:
            if message.bot:
                await clear_tracked_panel(message.bot, state)
            sent = await message.answer(
                banner_bubble("warn", f"{h(str(exc))}\nПопробуйте ещё раз или выберите ресурс из списка."),
                reply_markup=back_home_keyboard("ash:back", "⬅️ К списку шар"),
            )
            await track_panel(state, sent)
            return
        await _show_share_acl_view(message, state, access_engine, clean_unc, edit=False)
        return

    matches = await shares_svc.search_shares(q, limit=60)
    data = await state.get_data()
    all_shares: list[ShareInfo] = data.get("acc_catalog", [])
    primary = settings.primary_file_server
    if not matches:
        if message.bot:
            await clear_tracked_panel(message.bot, state)
        sent = await message.answer(
            render_share_step(
                [],
                total_catalog=len(all_shares),
                server_filter="ALL",
                query=q,
                primary_label=primary,
                banner_html=banner_bubble(
                    "warn",
                    f"По запросу <code>{h(q)}</code> шары не найдены. Введите другое слово или путь <code>\\\\{h(primary)}\\Folder</code>.",
                ),
                step_header=progress_header(1, 2, "🔐 Доступы к дискам", "Выбор сетевой шары"),
            ),
            reply_markup=shares_keyboard([], page=0, prefix="ash", server_filter="ALL", has_query=True, primary_label=primary),
        )
        await track_panel(state, sent)
        return

    await _show_access_share_step(
        message,
        state,
        shares_svc,
        settings,
        edit=False,
        server_filter="ALL",
        query=q,
    )


@router.callback_query(F.data == "ash:back")
async def cb_access_back_to_shares(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    data = await state.get_data()
    await callback.answer()
    if callback.message:
        await _show_access_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=data.get("acc_filter", "ALL"),
            query=data.get("acc_query", ""),
        )


@router.callback_query(AccessStates.viewing_share, F.data == "acl:refresh_one")
async def cb_acl_refresh_share(
    callback: CallbackQuery,
    state: FSMContext,
    access_engine: ShareAccessEngine,
) -> None:
    data = await state.get_data()
    unc_path = data.get("acc_unc", "")
    await callback.answer("Обновляю ACL шары...")
    if callback.message and unc_path:
        await _show_share_acl_view(
            callback.message,
            state,
            access_engine,
            unc_path,
            edit=True,
            banner_html=banner_bubble("ok", "Список NTFS ACL и групп AD перечитан."),
        )


@router.callback_query(F.data == "acl:back_share")
async def cb_acl_back_share(
    callback: CallbackQuery,
    state: FSMContext,
    access_engine: ShareAccessEngine,
) -> None:
    data = await state.get_data()
    unc_path = data.get("acc_unc", "")
    await callback.answer()
    if callback.message and unc_path:
        await _show_share_acl_view(callback.message, state, access_engine, unc_path, edit=True)


@router.callback_query(F.data == "acl:pick_user")
async def cb_acl_pick_user(callback: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    unc_path = data.get("acc_unc", "")
    await state.set_state(AccessStates.searching_user)
    await state.update_data(acc_user_results=None, acc_user_query="")
    await callback.answer()
    if callback.message:
        edited = await safe_edit_text(
            callback.message,
            render_access_user_prompt(unc_path),
            reply_markup=back_home_keyboard("acl:back_share", "⬅️ К шаре"),
        )
        await track_panel(state, edited)


@router.message(AccessStates.searching_user, F.text)
async def msg_acl_search_user(
    message: Message,
    state: FSMContext,
    ad: AdBackend,
    settings: Settings,
    access_engine: ShareAccessEngine,
) -> None:
    q = (message.text or "").strip()
    data = await state.get_data()
    unc_path = data.get("acc_unc", "")
    if len(q) < 2:
        if message.bot:
            await clear_tracked_panel(message.bot, state)
        sent = await message.answer(
            render_access_user_prompt(
                unc_path,
                banner_html=banner_bubble("warn", "Введите минимум <b>2 символа</b> для поиска сотрудника."),
            ),
            reply_markup=back_home_keyboard("acl:back_share", "⬅️ К шаре"),
        )
        await track_panel(state, sent)
        return

    users = await ad.search_users(q, limit=25)
    await state.update_data(acc_user_results=users, acc_user_query=q)
    if len(users) == 1:
        await _show_user_access_view(message, state, settings, access_engine, users[0], edit=False)
        return

    if message.bot:
        await clear_tracked_panel(message.bot, state)
    sent = await message.answer(
        render_access_user_prompt(unc_path, query=q, users=users),
        reply_markup=users_keyboard(
            users,
            page=0,
            prefix="ausr",
            back_callback="acl:back_share",
            back_text="⬅️ К шаре",
        ),
    )
    await track_panel(state, sent)


@router.callback_query(AccessStates.searching_user, F.data.startswith("ausr:page:"))
async def cb_acl_user_page(callback: CallbackQuery, state: FSMContext) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    users: list[ADUser] = data.get("acc_user_results") or []
    if callback.message:
        await safe_edit_markup(
            callback.message,
            reply_markup=users_keyboard(
                users,
                page=page,
                prefix="ausr",
                back_callback="acl:back_share",
                back_text="⬅️ К шаре",
            ),
        )
    await callback.answer()


@router.callback_query(AccessStates.searching_user, F.data.startswith("ausr:sel:"))
async def cb_acl_user_select(
    callback: CallbackQuery,
    state: FSMContext,
    settings: Settings,
    access_engine: ShareAccessEngine,
) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    users: list[ADUser] = data.get("acc_user_results") or []
    if idx < 0 or idx >= len(users):
        await callback.answer("Список устарел, повторите поиск.", show_alert=True)
        return
    await callback.answer("Проверяю права сотрудника...")
    if callback.message:
        await _show_user_access_view(
            callback.message,
            state,
            settings,
            access_engine,
            users[idx],
            edit=True,
        )


@router.callback_query(AccessStates.configuring_user, F.data == "acl:recheck")
async def cb_acl_user_recheck(
    callback: CallbackQuery,
    state: FSMContext,
    settings: Settings,
    access_engine: ShareAccessEngine,
) -> None:
    data = await state.get_data()
    user: Optional[ADUser] = data.get("acc_user")
    if not user:
        await callback.answer("Сотрудник не выбран.", show_alert=True)
        return
    await callback.answer("Перечитываю ACL и группы...")
    if callback.message:
        await _show_user_access_view(
            callback.message,
            state,
            settings,
            access_engine,
            user,
            edit=True,
            refresh_acl=True,
            banner_html=banner_bubble("ok", "Эффективные права перепроверены по AD и NTFS."),
        )


@router.callback_query(AccessStates.configuring_user, F.data.startswith("acl:set:"))
async def cb_acl_apply_level(
    callback: CallbackQuery,
    state: FSMContext,
    settings: Settings,
    access_engine: ShareAccessEngine,
) -> None:
    level = callback.data.split(":")[2]
    data = await state.get_data()
    user: Optional[ADUser] = data.get("acc_user")
    unc_path: str = data.get("acc_unc", "")
    if not user or not unc_path:
        await callback.answer("Контекст устарел.", show_alert=True)
        return

    tg_user = callback.from_user
    await callback.answer("Применяю изменения прав...")
    try:
        if level == ACCESS_NONE:
            res = await access_engine.revoke_access(
                user=user,
                unc_path=unc_path,
                tg_user_id=tg_user.id,
                tg_username=tg_user.username or tg_user.full_name,
            )
        elif level in (ACCESS_RO, ACCESS_RW):
            res = await access_engine.grant_access(
                user=user,
                unc_path=unc_path,
                level=level,
                tg_user_id=tg_user.id,
                tg_username=tg_user.username or tg_user.full_name,
            )
        else:
            await callback.answer("Неизвестный уровень прав.", show_alert=True)
            return

        if callback.message:
            edited = await safe_edit_text(
                callback.message,
                render_access_result(res, display_name=user.display_name),
                reply_markup=access_result_keyboard(),
            )
            await track_panel(state, edited)
    except (AccessOperationError, DriveMapValidationError) as exc:
        if callback.message:
            await _show_user_access_view(
                callback.message,
                state,
                settings,
                access_engine,
                user,
                edit=True,
                banner_html=banner_bubble("warn", f"<b>Операция отклонена</b>\n<code>{h(str(exc))}</code>"),
            )
    except Exception as exc:
        logger.exception("Share access change failed")
        if callback.message:
            await _show_user_access_view(
                callback.message,
                state,
                settings,
                access_engine,
                user,
                edit=True,
                banner_html=banner_bubble("err", f"<b>Ошибка изменения прав</b>\n<code>{h(str(exc))}</code>"),
            )


async def _show_group_members_view(
    target_msg: Message,
    state: FSMContext,
    ad: AdBackend,
    unc_path: str,
    group: ADGroup,
    level: str,
    *,
    page: int = 0,
    banner_html: str = "",
) -> None:
    members = await ad.get_group_members(group.distinguished_name)
    await state.set_state(AccessStates.viewing_members)
    await state.update_data(
        acc_group=group,
        acc_group_level=level,
        acc_members=members,
        acc_members_page=page,
    )
    edited = await safe_edit_text(
        target_msg,
        render_access_group_members(unc_path, group, level, members, banner_html=banner_html),
        reply_markup=access_members_keyboard(members, page=page),
    )
    await track_panel(state, edited)


@router.callback_query(AccessStates.viewing_share, F.data.startswith("acl:grp:"))
async def cb_acl_open_group(callback: CallbackQuery, state: FSMContext, ad: AdBackend) -> None:
    lvl = callback.data.split(":")[2]
    data = await state.get_data()
    report: Optional[ShareAccessReport] = data.get("acc_report")
    unc_path: str = data.get("acc_unc", "")
    if not report or not unc_path:
        await callback.answer("Отчёт шары не найден.", show_alert=True)
        return
    group = report.ro_group if lvl == ACCESS_RO else report.rw_group
    if group is None:
        await callback.answer("Группа не найдена.", show_alert=True)
        return
    await callback.answer("Загружаю участников группы...")
    if callback.message:
        await _show_group_members_view(callback.message, state, ad, unc_path, group, lvl)


@router.callback_query(AccessStates.viewing_members, F.data.startswith("acl:grpg:"))
async def cb_acl_members_page(callback: CallbackQuery, state: FSMContext) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    members: list[ADUser] = data.get("acc_members") or []
    await state.update_data(acc_members_page=page)
    if callback.message:
        await safe_edit_markup(callback.message, reply_markup=access_members_keyboard(members, page=page))
    await callback.answer()


@router.callback_query(AccessStates.viewing_members, F.data.startswith("acl:grm:"))
async def cb_acl_remove_group_member(
    callback: CallbackQuery,
    state: FSMContext,
    ad: AdBackend,
    access_engine: ShareAccessEngine,
) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    members: list[ADUser] = data.get("acc_members") or []
    group: Optional[ADGroup] = data.get("acc_group")
    lvl: str = data.get("acc_group_level", ACCESS_RO)
    unc_path: str = data.get("acc_unc", "")
    if not group or not unc_path or idx < 0 or idx >= len(members):
        await callback.answer("Список устарел.", show_alert=True)
        return

    member = members[idx]
    tg_user = callback.from_user
    await callback.answer("Удаляю из группы AD...")
    try:
        res = await access_engine.revoke_from_group(
            group=group,
            unc_path=unc_path,
            user=member,
            tg_user_id=tg_user.id,
            tg_username=tg_user.username or tg_user.full_name,
        )
        kind = "dry" if res.dry_run else "ok"
        banner = banner_bubble(kind, f"{h(res.message)} (tx <code>{h(res.tx_id)}</code>)")
    except Exception as exc:
        logger.exception("Group member removal failed")
        banner = banner_bubble("err", f"Ошибка удаления: <code>{h(str(exc))}</code>")

    if callback.message:
        await _show_group_members_view(callback.message, state, ad, unc_path, group, lvl, banner_html=banner)


@router.callback_query(AccessStates.viewing_share, F.data == "acl:direct")
async def cb_acl_open_direct(callback: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    report: Optional[ShareAccessReport] = data.get("acc_report")
    unc_path: str = data.get("acc_unc", "")
    if not report:
        await callback.answer("Отчёт устарел.", show_alert=True)
        return
    direct_entries = [e for e in report.entries if e.principal_type == "USER" and not e.is_protected]
    await state.set_state(AccessStates.viewing_direct)
    await state.update_data(acc_direct_entries=direct_entries, acc_direct_page=0)
    await callback.answer()
    if callback.message:
        edited = await safe_edit_text(
            callback.message,
            render_access_direct_users(unc_path, direct_entries),
            reply_markup=access_direct_users_keyboard(direct_entries, page=0),
        )
        await track_panel(state, edited)


@router.callback_query(AccessStates.viewing_direct, F.data == "acl:inh")
async def cb_acl_direct_inherited_hint(callback: CallbackQuery) -> None:
    await callback.answer(
        "Эта запись унаследована от родительского каталога и не удаляется на уровне шары.",
        show_alert=True,
    )


@router.callback_query(AccessStates.viewing_direct, F.data.startswith("acl:drpg:"))
async def cb_acl_direct_page(callback: CallbackQuery, state: FSMContext) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    entries: list[ShareAclEntry] = data.get("acc_direct_entries") or []
    await state.update_data(acc_direct_page=page)
    if callback.message:
        await safe_edit_markup(callback.message, reply_markup=access_direct_users_keyboard(entries, page=page))
    await callback.answer()


@router.callback_query(AccessStates.viewing_direct, F.data.startswith("acl:drm:"))
async def cb_acl_remove_direct_ace(
    callback: CallbackQuery,
    state: FSMContext,
    ad: AdBackend,
    access_engine: ShareAccessEngine,
) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    entries: list[ShareAclEntry] = data.get("acc_direct_entries") or []
    unc_path: str = data.get("acc_unc", "")
    if not unc_path or idx < 0 or idx >= len(entries):
        await callback.answer("Список устарел.", show_alert=True)
        return

    entry = entries[idx]
    sam = entry.principal_name.split("\\", 1)[-1]
    ad_user = await ad.get_user_by_sam(sam)
    if ad_user is None:
        ad_user = ADUser(
            sam_account_name=sam,
            display_name=entry.display_name,
            distinguished_name="",
            sid=entry.sid,
        )

    tg_user = callback.from_user
    await callback.answer("Удаляю прямой NTFS ACE...")
    try:
        res = await access_engine.revoke_access(
            user=ad_user,
            unc_path=unc_path,
            tg_user_id=tg_user.id,
            tg_username=tg_user.username or tg_user.full_name,
        )
        kind = "dry" if res.dry_run else "ok"
        banner = banner_bubble(kind, f"{h(res.message)} (tx <code>{h(res.tx_id)}</code>)")
    except Exception as exc:
        logger.exception("Direct ACE revoke failed")
        banner = banner_bubble("err", f"Ошибка удаления ACE: <code>{h(str(exc))}</code>")

    if callback.message:
        report = await access_engine.inspect_share_access(unc_path)
        new_direct = [e for e in report.entries if e.principal_type == "USER" and not e.is_protected]
        await state.update_data(acc_report=report, acc_direct_entries=new_direct)
        edited = await safe_edit_text(
            callback.message,
            render_access_direct_users(unc_path, new_direct, banner_html=banner),
            reply_markup=access_direct_users_keyboard(new_direct, page=0),
        )
        await track_panel(state, edited)

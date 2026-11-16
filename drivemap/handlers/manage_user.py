"""Handlers for viewing user drives, disconnecting shares, reverse share lookup, and audit rollback."""

from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from drivemap.config import Settings
from drivemap.handlers.states import ManageUserStates, ShareLookupStates
from drivemap.keyboards.inline import (
    audit_keyboard,
    back_home_keyboard,
    clear_tracked_panel,
    confirm_unmap_keyboard,
    safe_edit_markup,
    safe_edit_text,
    shares_keyboard,
    track_panel,
    user_mappings_keyboard,
    users_keyboard,
)
from drivemap.models import ADUser, EffectiveMapping, ShareInfo
from drivemap.services.access_engine import ShareAccessEngine
from drivemap.services.ad_ldap import AdBackend
from drivemap.services.audit_db import AuditRepository
from drivemap.services.drivemap_engine import DriveMapEngine, validate_unc_path
from drivemap.services.share_discovery import ShareDiscoveryService
from drivemap.ui import (
    banner_bubble,
    filter_shares_by_category,
    h,
    progress_header,
    render_audit_screen,
    render_share_step,
    render_share_users_screen,
    render_unmap_confirm,
    render_user_drives_screen,
    render_user_search_screen,
)

logger = logging.getLogger(__name__)
router = Router()


@router.callback_query(F.data.in_({"drv:user_drives", "menu:user_drives"}))
async def cb_user_drives_start(callback: CallbackQuery, state: FSMContext) -> None:
    await state.set_state(ManageUserStates.searching_user)
    if callback.message:
        edited = await safe_edit_text(
            callback.message,
            render_user_search_screen(),
            reply_markup=back_home_keyboard(),
        )
        await track_panel(state, edited)
    await callback.answer()


@router.callback_query(F.data.startswith("drv:user:"))
async def cb_direct_user_drives(
    callback: CallbackQuery,
    state: FSMContext,
    ad: AdBackend,
    engine: DriveMapEngine,
) -> None:
    username = callback.data.removeprefix("drv:user:").strip()
    if not username:
        await callback.answer("Не указан логин пользователя.", show_alert=True)
        return

    await callback.answer("Загружаю сетевые диски сотрудника...")
    try:
        user = await ad.get_user_by_sam(username)
    except Exception as exc:
        logger.exception("Failed fetching AD user %s for direct drive view", username)
        if callback.message:
            edited = await safe_edit_text(
                callback.message,
                banner_bubble("err", f"Ошибка подключения к AD: <code>{h(str(exc))}</code>"),
                reply_markup=back_home_keyboard(f"user:show:{username}", "👤 К карточке сотрудника"),
            )
            await track_panel(state, edited)
        return

    if not user:
        if callback.message:
            edited = await safe_edit_text(
                callback.message,
                banner_bubble("warn", f"Сотрудник <code>{h(username)}</code> не найден в Active Directory."),
                reply_markup=back_home_keyboard(f"user:show:{username}", "👤 К карточке сотрудника"),
            )
            await track_panel(state, edited)
        return

    if callback.message:
        try:
            await _render_user_drives(callback.message, state, engine, user)
        except Exception as exc:
            logger.exception("Failed computing effective mappings for %s", username)
            edited = await safe_edit_text(
                callback.message,
                banner_bubble("err", f"Ошибка расчёта сетевых дисков: <code>{h(str(exc))}</code>"),
                reply_markup=back_home_keyboard(f"user:show:{username}", "👤 К карточке сотрудника"),
            )
            await track_panel(state, edited)


@router.message(ManageUserStates.searching_user, F.text)
async def msg_manage_user_search(message: Message, state: FSMContext, ad: AdBackend) -> None:
    q = (message.text or "").strip()
    if message.bot:
        await clear_tracked_panel(message.bot, state)

    if len(q) < 2:
        sent = await message.answer(
            render_user_search_screen(banner_html=banner_bubble("warn", "Введите минимум <b>2 символа</b> для поиска.")),
            reply_markup=back_home_keyboard(),
        )
        await track_panel(state, sent)
        return

    try:
        users = await ad.search_users(q, limit=24)
    except Exception as exc:
        logger.exception("AD user search failed")
        sent = await message.answer(
            banner_bubble("err", f"Ошибка поиска в AD: <code>{h(str(exc))}</code>"),
            reply_markup=back_home_keyboard(),
        )
        await track_panel(state, sent)
        return

    if not users:
        sent = await message.answer(
            render_user_search_screen(banner_html=banner_bubble("warn", f"Пользователи по запросу <code>{h(q)}</code> не найдены.")),
            reply_markup=back_home_keyboard(),
        )
        await track_panel(state, sent)
        return

    await state.update_data(manage_users=users, manage_query=q)
    sent = await message.answer(
        render_user_search_screen(query=q, users=users),
        reply_markup=users_keyboard(users, prefix="musr"),
    )
    await track_panel(state, sent)


async def _render_user_drives(
    target_msg: Message,
    state: FSMContext,
    engine: DriveMapEngine,
    user: ADUser,
    *,
    banner_html: str = "",
) -> None:
    mappings = await engine.get_effective_mappings(user)
    await state.set_state(ManageUserStates.viewing_user)
    await state.update_data(manage_user=user, manage_mappings=mappings)
    text = render_user_drives_screen(user, mappings, banner_html=banner_html)
    edited = await safe_edit_text(
        target_msg,
        text,
        reply_markup=user_mappings_keyboard(mappings, username=user.sam_account_name),
    )
    await track_panel(state, edited)


@router.callback_query(F.data == "map:view_user")
async def cb_open_last_user_drives(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    data = await state.get_data()
    user: ADUser | None = data.get("last_user")
    if not user:
        await callback.answer("Контекст пользователя устарел — найдите его заново.", show_alert=True)
        await state.set_state(ManageUserStates.searching_user)
        if callback.message:
            edited = await safe_edit_text(
                callback.message,
                render_user_search_screen(),
                reply_markup=back_home_keyboard(),
            )
            await track_panel(state, edited)
        return

    await callback.answer("Загружаю профиль пользователя...")
    if callback.message:
        await _render_user_drives(callback.message, state, engine, user)


@router.callback_query(ManageUserStates.searching_user, F.data.startswith("musr:page:"))
async def cb_manage_user_page(callback: CallbackQuery, state: FSMContext) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    users: list[ADUser] = data.get("manage_users", [])
    if callback.message:
        await safe_edit_markup(callback.message, reply_markup=users_keyboard(users, page=page, prefix="musr"))
    await callback.answer()


@router.callback_query(ManageUserStates.searching_user, F.data.startswith("musr:sel:"))
async def cb_manage_user_select(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    users: list[ADUser] = data.get("manage_users", [])
    if idx < 0 or idx >= len(users):
        await callback.answer("Список устарел.", show_alert=True)
        return
    await callback.answer("Загружаю диски пользователя...")
    if callback.message:
        await _render_user_drives(callback.message, state, engine, users[idx])


@router.callback_query(ManageUserStates.viewing_user, F.data == "umap:refresh")
async def cb_manage_user_refresh(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    data = await state.get_data()
    user: ADUser = data["manage_user"]
    await callback.answer("Обновляю RSOP дисков...")
    if callback.message:
        await _render_user_drives(
            callback.message,
            state,
            engine,
            user,
            banner_html=banner_bubble("info", "Список дисков обновлён по актуальному состоянию AD и SYSVOL."),
        )


@router.callback_query(ManageUserStates.viewing_user, F.data.startswith("umap:ask:"))
async def cb_unmap_ask(callback: CallbackQuery, state: FSMContext) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    mappings: list[EffectiveMapping] = data.get("manage_mappings", [])
    user: ADUser = data["manage_user"]
    if idx < 0 or idx >= len(mappings) or not mappings[idx].removable_by_bot:
        await callback.answer("Правило нельзя изменить через бота.", show_alert=True)
        return
    m = mappings[idx]
    await state.set_state(ManageUserStates.confirming_unmap)
    is_del = m.scope_type == "PER_USER_DELETE"
    if callback.message:
        edited = await safe_edit_text(
            callback.message,
            render_unmap_confirm(user, m, is_del),
            reply_markup=confirm_unmap_keyboard(idx, is_delete_marker=is_del),
        )
        await track_panel(state, edited)
    await callback.answer()


@router.callback_query(ManageUserStates.confirming_unmap, F.data == "umap:back")
async def cb_unmap_back(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    data = await state.get_data()
    user: ADUser = data["manage_user"]
    await callback.answer()
    if callback.message:
        await _render_user_drives(callback.message, state, engine, user)


@router.callback_query(ManageUserStates.confirming_unmap, F.data.startswith("umap:do_"))
async def cb_unmap_execute(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    parts = callback.data.split(":")
    mode = parts[1]  # do_soft | do_hard
    idx = int(parts[2])
    data = await state.get_data()
    mappings: list[EffectiveMapping] = data.get("manage_mappings", [])
    user: ADUser = data["manage_user"]
    if idx < 0 or idx >= len(mappings):
        await callback.answer("Неактуальный выбор.", show_alert=True)
        return
    m = mappings[idx]
    hard = mode == "do_hard"
    tg_user = callback.from_user

    await callback.answer("Обновляю политику...")
    try:
        res = await engine.unassign_drive(
            user=user,
            letter=m.letter,
            tg_user_id=tg_user.id,
            tg_username=tg_user.username or tg_user.full_name,
            delete_persistent=hard,
        )
        kind = "dry" if res.dry_run else "ok"
        dry_tag = "[DRY-RUN] " if res.dry_run else ""
        banner = banner_bubble(
            kind,
            f"{dry_tag}Операция <b>{h(res.operation)}</b> для диска <b>{res.letter}:</b> выполнена "
            f"(tx <code>{h(res.tx_id)}</code>, GPO v.{res.gpo_version_before}→{res.gpo_version_after}).",
        )
    except Exception as exc:
        logger.exception("Failed unmapping drive")
        banner = banner_bubble("err", f"Ошибка отключения: <code>{h(str(exc))}</code>")

    if callback.message:
        await _render_user_drives(callback.message, state, engine, user, banner_html=banner)


async def _show_lookup_share_step(
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

    await state.set_state(ShareLookupStates.searching_share)
    await state.update_data(
        lookup_catalog=all_shares,
        lookup_shares=filtered,
        lookup_filter=server_filter,
        lookup_query=query,
    )
    text = render_share_step(
        filtered,
        total_catalog=len(all_shares),
        server_filter=server_filter,
        query=query,
        banner_html=banner_html,
        step_header=progress_header(1, 1, "📁 Поиск по шаре", "Кто подключён персонально"),
        primary_label=primary,
    )
    kb = shares_keyboard(
        filtered,
        page=0,
        prefix="lsh",
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


@router.callback_query(F.data.in_({"drv:share_users", "menu:share_users"}))
async def cb_share_lookup_start(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    await callback.answer("Загружаю список шар...")
    if callback.message:
        await _show_lookup_share_step(callback.message, state, shares_svc, settings, edit=True)


@router.callback_query(ShareLookupStates.searching_share, F.data == "lsh:back")
async def cb_lookup_share_back(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    data = await state.get_data()
    await callback.answer()
    if callback.message:
        await _show_lookup_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=data.get("lookup_filter", "ALL"),
            query=data.get("lookup_query", ""),
        )


@router.callback_query(ShareLookupStates.searching_share, F.data == "lsh:reset")
async def cb_lookup_share_reset(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    data = await state.get_data()
    await callback.answer("Поиск сброшен")
    if callback.message:
        await _show_lookup_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=data.get("lookup_filter", "ALL"),
            query="",
        )


@router.callback_query(ShareLookupStates.searching_share, F.data.startswith("lsh:flt:"))
async def cb_lookup_share_filter(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    category = callback.data.split(":")[2]
    data = await state.get_data()
    await callback.answer()
    if callback.message:
        await _show_lookup_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=category,
            query=data.get("lookup_query", ""),
        )


@router.callback_query(ShareLookupStates.searching_share, F.data.startswith("lsh:page:"))
async def cb_lookup_share_page(callback: CallbackQuery, state: FSMContext, settings: Settings) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    shares: list[ShareInfo] = data.get("lookup_shares", [])
    if callback.message:
        await safe_edit_markup(
            callback.message,
            reply_markup=shares_keyboard(
                shares,
                page=page,
                prefix="lsh",
                server_filter=data.get("lookup_filter", "ALL"),
                has_query=bool(data.get("lookup_query")),
                primary_label=settings.primary_file_server,
            ),
        )
    await callback.answer()


@router.callback_query(ShareLookupStates.searching_share, F.data == "lsh:refresh")
async def cb_lookup_share_refresh(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    await callback.answer("Обновляю...")
    data = await state.get_data()
    if callback.message:
        await _show_lookup_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            force_refresh=True,
            server_filter=data.get("lookup_filter", "ALL"),
            banner_html=banner_bubble("ok", "Список шар обновлён."),
        )


async def _render_share_users(
    target_msg: Message,
    state: FSMContext,
    engine: DriveMapEngine,
    unc_path: str,
    edit: bool,
) -> None:
    hits = await engine.find_users_by_share(unc_path)
    text = render_share_users_screen(unc_path, hits)
    kb = back_home_keyboard("lsh:back", "⬅️ К шарам")
    if edit:
        edited = await safe_edit_text(target_msg, text, reply_markup=kb)
        await track_panel(state, edited)
    else:
        if target_msg.bot:
            await clear_tracked_panel(target_msg.bot, state)
        sent = await target_msg.answer(text, reply_markup=kb)
        await track_panel(state, sent)


@router.callback_query(ShareLookupStates.searching_share, F.data.startswith("lsh:sel:"))
async def cb_lookup_share_select(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    shares: list[ShareInfo] = data.get("lookup_shares", [])
    if idx < 0 or idx >= len(shares):
        await callback.answer("Список устарел.", show_alert=True)
        return
    await callback.answer("Ищу пользователей...")
    if callback.message:
        await _render_share_users(callback.message, state, engine, shares[idx].unc_path, edit=True)


@router.message(ShareLookupStates.searching_share, F.text)
async def msg_lookup_share_text(
    message: Message,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    engine: DriveMapEngine,
    settings: Settings,
) -> None:
    q = (message.text or "").strip()
    if q.startswith("\\\\"):
        try:
            unc = validate_unc_path(q)
        except Exception as exc:
            if message.bot:
                await clear_tracked_panel(message.bot, state)
            sent = await message.answer(
                banner_bubble("warn", h(str(exc))),
                reply_markup=back_home_keyboard("lsh:back", "⬅️ К шарам"),
            )
            await track_panel(state, sent)
            return
        await _render_share_users(message, state, engine, unc, edit=False)
        return

    matches = await shares_svc.search_shares(q, limit=60)
    primary = settings.primary_file_server
    if not matches:
        data = await state.get_data()
        if message.bot:
            await clear_tracked_panel(message.bot, state)
        sent = await message.answer(
            render_share_step(
                [],
                total_catalog=len(data.get("lookup_catalog", [])),
                server_filter="ALL",
                query=q,
                primary_label=primary,
                banner_html=banner_bubble("warn", f"Шары по запросу <code>{h(q)}</code> не найдены."),
                step_header=progress_header(1, 1, "📁 Поиск по шаре", "Кто подключён персонально"),
            ),
            reply_markup=shares_keyboard([], page=0, prefix="lsh", server_filter="ALL", has_query=True, primary_label=primary),
        )
        await track_panel(state, sent)
        return

    await _show_lookup_share_step(
        message,
        state,
        shares_svc,
        settings,
        edit=False,
        server_filter="ALL",
        query=q,
    )


async def _show_audit_screen(
    target_msg: Message,
    state: FSMContext,
    audit: AuditRepository,
    *,
    banner_html: str = "",
) -> None:
    records = await audit.list_recent(limit=8)
    edited = await safe_edit_text(
        target_msg,
        render_audit_screen(records, banner_html=banner_html),
        reply_markup=audit_keyboard(records),
    )
    await track_panel(state, edited)


@router.callback_query(F.data == "drv:audit")
async def cb_audit_log(callback: CallbackQuery, state: FSMContext, audit: AuditRepository) -> None:
    await state.clear()
    await callback.answer()
    if callback.message:
        await _show_audit_screen(callback.message, state, audit)


@router.callback_query(F.data.startswith("aud:rb:"))
async def cb_rollback(
    callback: CallbackQuery,
    state: FSMContext,
    audit: AuditRepository,
    engine: DriveMapEngine,
    access_engine: ShareAccessEngine,
) -> None:
    tx_id = callback.data.split(":")[2]
    rec = await audit.get_by_tx_id(tx_id)
    if not rec:
        await callback.answer("Транзакция не найдена.", show_alert=True)
        return
    tg_user = callback.from_user
    is_access = rec.operation.startswith("ACCESS_")
    await callback.answer("Выполняю откат прав..." if is_access else "Выполняю откат GPO...")
    try:
        if is_access:
            acc_res = await access_engine.rollback_access_transaction(
                record=rec,
                tg_user_id=tg_user.id,
                tg_username=tg_user.username or tg_user.full_name,
            )
            kind = "dry" if acc_res.dry_run else "ok"
            banner = banner_bubble(
                kind,
                f"Откат прав <code>{h(tx_id)}</code> выполнен (новая tx <code>{h(acc_res.tx_id)}</code>): "
                f"{h(acc_res.message)}",
            )
        else:
            res = await engine.rollback_transaction(
                record=rec,
                tg_user_id=tg_user.id,
                tg_username=tg_user.username or tg_user.full_name,
            )
            kind = "dry" if res.dry_run else "ok"
            banner = banner_bubble(
                kind,
                f"Откат транзакции <code>{h(tx_id)}</code> выполнен (новая tx <code>{h(res.tx_id)}</code>, "
                f"GPO v.{res.gpo_version_before}→{res.gpo_version_after}).",
            )
    except Exception as exc:
        logger.exception("Rollback failed")
        banner = banner_bubble("err", f"Ошибка отката <code>{h(tx_id)}</code>: <code>{h(str(exc))}</code>")

    if callback.message:
        await _show_audit_screen(callback.message, state, audit, banner_html=banner)

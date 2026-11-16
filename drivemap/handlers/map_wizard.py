"""Step-by-step wizard for assigning a DriveMap share to a specific AD user."""

from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message

from drivemap.config import Settings
from drivemap.handlers.states import MapWizardStates
from drivemap.keyboards.inline import (
    back_home_keyboard,
    clear_tracked_panel,
    confirm_map_keyboard,
    letters_keyboard,
    main_menu_keyboard,
    map_result_keyboard,
    safe_edit_markup,
    safe_edit_text,
    shares_keyboard,
    track_panel,
    users_keyboard,
)
from drivemap.models import ACCESS_NONE, ACCESS_RO, ACCESS_RW, ADUser, LetterChoice, ShareInfo
from drivemap.services.access_engine import ShareAccessEngine
from drivemap.services.ad_ldap import AdBackend
from drivemap.services.drivemap_engine import (
    DriveMapConflictError,
    DriveMapEngine,
    DriveMapValidationError,
    derive_default_label,
    validate_unc_path,
)
from drivemap.services.share_discovery import ShareDiscoveryService
from drivemap.ui import (
    banner_bubble,
    filter_shares_by_category,
    h,
    render_confirm_step,
    render_letter_step,
    render_map_result,
    render_overwrite_step,
    render_share_step,
    render_user_prompt,
)

logger = logging.getLogger(__name__)
router = Router()


async def _show_share_step(
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

    await state.set_state(MapWizardStates.choosing_share)
    await state.update_data(
        share_catalog=all_shares,
        share_results=filtered,
        share_page=0,
        share_filter=server_filter,
        share_query=query,
    )
    text = render_share_step(
        filtered,
        total_catalog=len(all_shares),
        server_filter=server_filter,
        query=query,
        banner_html=banner_html,
        primary_label=primary,
    )
    kb = shares_keyboard(
        filtered,
        page=0,
        prefix="sh",
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


@router.callback_query(F.data.in_({"drv:map", "menu:map"}))
async def cb_start_map(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    await callback.answer("Загружаю список шар...")
    if callback.message:
        try:
            await _show_share_step(callback.message, state, shares_svc, settings, edit=True)
        except Exception as exc:
            logger.exception("Failed opening map wizard")
            edited = await safe_edit_text(
                callback.message,
                banner_bubble("err", f"Не удалось получить список шар: <code>{h(str(exc))}</code>"),
                reply_markup=back_home_keyboard(),
            )
            await track_panel(state, edited)


@router.callback_query(MapWizardStates.choosing_share, F.data == "sh:refresh")
async def cb_share_refresh(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    await callback.answer("Обновляю список шар...")
    data = await state.get_data()
    if callback.message:
        await _show_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            force_refresh=True,
            server_filter=data.get("share_filter", "ALL"),
            banner_html=banner_bubble("ok", "Список шар синхронизирован с GPO и файловыми серверами."),
        )


@router.callback_query(MapWizardStates.choosing_share, F.data == "sh:reset")
async def cb_share_reset(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    await callback.answer("Поиск сброшен")
    data = await state.get_data()
    if callback.message:
        await _show_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=data.get("share_filter", "ALL"),
            query="",
        )


@router.callback_query(MapWizardStates.choosing_share, F.data.startswith("sh:flt:"))
async def cb_share_filter(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    category = callback.data.split(":")[2]
    data = await state.get_data()
    query = data.get("share_query", "")
    await callback.answer()
    if callback.message:
        await _show_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=category,
            query=query,
        )


@router.callback_query(MapWizardStates.choosing_share, F.data.startswith("sh:page:"))
async def cb_share_page(callback: CallbackQuery, state: FSMContext, settings: Settings) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    shares: list[ShareInfo] = data.get("share_results", [])
    await state.update_data(share_page=page)
    if callback.message:
        await safe_edit_markup(
            callback.message,
            reply_markup=shares_keyboard(
                shares,
                page=page,
                prefix="sh",
                server_filter=data.get("share_filter", "ALL"),
                has_query=bool(data.get("share_query")),
                primary_label=settings.primary_file_server,
            ),
        )
    await callback.answer()


@router.message(MapWizardStates.choosing_share, F.text)
async def msg_share_search(
    message: Message,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
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
                reply_markup=back_home_keyboard("sh:reset", "⬅️ К списку шар"),
            )
            await track_panel(state, sent)
            return
        parts = clean_unc.lstrip("\\").split("\\")
        share = ShareInfo(
            server=parts[0],
            share_name=parts[1],
            unc_path=clean_unc,
            label=derive_default_label(clean_unc),
            suggested_letter="",
            source="CUSTOM",
        )
        await _proceed_to_user_prompt(message, state, share, edit=False)
        return

    matches = await shares_svc.search_shares(q, limit=60)
    data = await state.get_data()
    all_shares: list[ShareInfo] = data.get("share_catalog", [])
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
                    f"По запросу <code>{h(q)}</code> шары не найдены. Введите другое слово или UNC-путь <code>\\\\{h(primary)}\\Folder</code>.",
                ),
            ),
            reply_markup=shares_keyboard([], page=0, prefix="sh", server_filter="ALL", has_query=True, primary_label=primary),
        )
        await track_panel(state, sent)
        return

    await _show_share_step(
        message,
        state,
        shares_svc,
        settings,
        edit=False,
        server_filter="ALL",
        query=q,
    )


async def _proceed_to_user_prompt(target_msg: Message, state: FSMContext, share: ShareInfo, edit: bool) -> None:
    await state.set_state(MapWizardStates.choosing_user)
    await state.update_data(selected_share=share, user_results=None, user_query="")
    text = render_user_prompt(share)
    kb = back_home_keyboard("usr:back_share", "⬅️ К шарам")
    if edit:
        edited = await safe_edit_text(target_msg, text, reply_markup=kb)
        await track_panel(state, edited)
    else:
        if target_msg.bot:
            await clear_tracked_panel(target_msg.bot, state)
        sent = await target_msg.answer(text, reply_markup=kb)
        await track_panel(state, sent)


@router.callback_query(MapWizardStates.choosing_share, F.data.startswith("sh:sel:"))
async def cb_share_select(callback: CallbackQuery, state: FSMContext) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    shares: list[ShareInfo] = data.get("share_results", [])
    if idx < 0 or idx >= len(shares):
        await callback.answer("Список устарел, выберите заново.", show_alert=True)
        return
    if callback.message:
        await _proceed_to_user_prompt(callback.message, state, shares[idx], edit=True)
    await callback.answer()


@router.callback_query(MapWizardStates.choosing_user, F.data == "usr:back_share")
async def cb_back_to_shares(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    data = await state.get_data()
    await callback.answer()
    if callback.message:
        await _show_share_step(
            callback.message,
            state,
            shares_svc,
            settings,
            edit=True,
            server_filter=data.get("share_filter", "ALL"),
            query=data.get("share_query", ""),
        )


@router.message(MapWizardStates.choosing_user, F.text)
async def msg_user_search(message: Message, state: FSMContext, ad: AdBackend) -> None:
    q = (message.text or "").strip()
    data = await state.get_data()
    share: ShareInfo = data["selected_share"]

    if message.bot:
        await clear_tracked_panel(message.bot, state)

    if len(q) < 2:
        sent = await message.answer(
            render_user_prompt(
                share,
                banner_html=banner_bubble("warn", "Введите минимум <b>2 символа</b> для поиска в Active Directory."),
            ),
            reply_markup=back_home_keyboard("usr:back_share", "⬅️ К шарам"),
        )
        await track_panel(state, sent)
        return

    try:
        users = await ad.search_users(q, limit=24)
    except Exception as exc:
        logger.exception("AD user search failed")
        sent = await message.answer(
            banner_bubble("err", f"Ошибка поиска в AD: <code>{h(str(exc))}</code>"),
            reply_markup=back_home_keyboard("usr:back_share", "⬅️ К шарам"),
        )
        await track_panel(state, sent)
        return

    if not users:
        sent = await message.answer(
            render_user_prompt(
                share,
                banner_html=banner_bubble("warn", f"Активные пользователи по запросу <code>{h(q)}</code> не найдены."),
            ),
            reply_markup=back_home_keyboard("usr:back_share", "⬅️ К шарам"),
        )
        await track_panel(state, sent)
        return

    await state.update_data(user_results=users, user_page=0, user_query=q)
    sent = await message.answer(
        render_user_prompt(share, query=q, users=users),
        reply_markup=users_keyboard(users, page=0, prefix="usr", back_callback="usr:back_share", back_text="⬅️ К шарам"),
    )
    await track_panel(state, sent)


@router.callback_query(MapWizardStates.choosing_user, F.data.startswith("usr:page:"))
async def cb_user_page(callback: CallbackQuery, state: FSMContext) -> None:
    page = int(callback.data.split(":")[2])
    data = await state.get_data()
    users: list[ADUser] = data.get("user_results", [])
    await state.update_data(user_page=page)
    if callback.message:
        await safe_edit_markup(
            callback.message,
            reply_markup=users_keyboard(users, page=page, prefix="usr", back_callback="usr:back_share", back_text="⬅️ К шарам"),
        )
    await callback.answer()


async def _show_letter_step(target_msg: Message, state: FSMContext, engine: DriveMapEngine) -> None:
    data = await state.get_data()
    share: ShareInfo = data["selected_share"]
    user: ADUser = data["selected_user"]

    effective = await engine.get_effective_mappings(user)
    matrix = await engine.get_letter_matrix(user)
    recommended = engine.choose_recommended_letter(matrix, share.suggested_letter)

    await state.set_state(MapWizardStates.choosing_letter)
    await state.update_data(
        letter_matrix=matrix,
        recommended_letter=recommended,
        effective_mappings=effective,
        allow_overwrite_per_user=False,
    )

    text = render_letter_step(share, user, effective, matrix, recommended)
    edited = await safe_edit_text(target_msg, text, reply_markup=letters_keyboard(matrix, recommended))
    await track_panel(state, edited)


@router.callback_query(MapWizardStates.choosing_user, F.data.startswith("usr:sel:"))
async def cb_user_select(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    idx = int(callback.data.split(":")[2])
    data = await state.get_data()
    users: list[ADUser] = data.get("user_results", [])
    if idx < 0 or idx >= len(users):
        await callback.answer("Список устарел.", show_alert=True)
        return
    await state.update_data(selected_user=users[idx])
    await callback.answer("Проверяю текущие диски и конфликты...")
    if callback.message:
        try:
            await _show_letter_step(callback.message, state, engine)
        except Exception as exc:
            logger.exception("Failed building RSOP letter matrix")
            edited = await safe_edit_text(
                callback.message,
                banner_bubble("err", f"Ошибка расчёта дисков пользователя: <code>{h(str(exc))}</code>"),
                reply_markup=back_home_keyboard("usr:back_share", "⬅️ К шарам"),
            )
            await track_panel(state, edited)


@router.callback_query(MapWizardStates.choosing_letter, F.data == "ltr:back_user")
async def cb_letter_back_user(callback: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    share: ShareInfo = data["selected_share"]
    users: list[ADUser] | None = data.get("user_results")
    query: str = data.get("user_query", "")
    await state.set_state(MapWizardStates.choosing_user)
    await callback.answer()
    if callback.message:
        if users:
            kb = users_keyboard(
                users,
                page=data.get("user_page", 0),
                prefix="usr",
                back_callback="usr:back_share",
                back_text="⬅️ К шарам",
            )
            text = render_user_prompt(share, query=query, users=users)
        else:
            kb = back_home_keyboard("usr:back_share", "⬅️ К шарам")
            text = render_user_prompt(share)
        edited = await safe_edit_text(callback.message, text, reply_markup=kb)
        await track_panel(state, edited)


async def _show_confirm_step(
    target_msg: Message,
    state: FSMContext,
    settings: Settings,
    letter: str,
    access_engine: ShareAccessEngine,
    *,
    access_choice: str = ACCESS_NONE,
    refresh_acl: bool = True,
) -> None:
    data = await state.get_data()
    share: ShareInfo = data["selected_share"]
    user: ADUser = data["selected_user"]
    overwrite: bool = bool(data.get("allow_overwrite_per_user", False))

    if refresh_acl or "confirm_access_status" not in data:
        report = await access_engine.inspect_share_access(share.unc_path)
        access_status = await access_engine.check_user_access(share.unc_path, user, report=report)
        has_ro = report.ro_group is not None
        has_rw = report.rw_group is not None
    else:
        access_status = data["confirm_access_status"]
        has_ro = bool(data.get("confirm_has_ro", False))
        has_rw = bool(data.get("confirm_has_rw", False))

    await state.set_state(MapWizardStates.confirming)
    await state.update_data(
        selected_letter=letter,
        selected_access_choice=access_choice,
        confirm_access_status=access_status,
        confirm_has_ro=has_ro,
        confirm_has_rw=has_rw,
    )
    text = render_confirm_step(
        settings,
        user,
        share,
        letter,
        overwrite,
        access_status=access_status,
        access_choice=access_choice,
        has_agdlp_ro=has_ro,
        has_agdlp_rw=has_rw,
    )
    edited = await safe_edit_text(
        target_msg,
        text,
        reply_markup=confirm_map_keyboard(access_choice=access_choice),
    )
    await track_panel(state, edited)


@router.callback_query(MapWizardStates.choosing_letter, F.data.startswith("ltr:locked:"))
async def cb_letter_locked(callback: CallbackQuery, state: FSMContext) -> None:
    letter = callback.data.split(":")[2]
    data = await state.get_data()
    matrix: list[LetterChoice] = data.get("letter_matrix", [])
    item = next((c for c in matrix if c.letter == letter), None)
    detail = f"{item.occupied_by_path} ({item.occupied_by_gpo})" if item else "занята"
    await callback.answer(
        f"🔒 Буква {letter}: занята ({detail}). Выберите свободную 🟢 или ⭐, чтобы не перезаписать диск отдела!",
        show_alert=True,
    )


@router.callback_query(MapWizardStates.choosing_letter, F.data.startswith("ltr:warn:"))
async def cb_letter_warn(callback: CallbackQuery, state: FSMContext, settings: Settings) -> None:
    letter = callback.data.split(":")[2]
    data = await state.get_data()
    matrix: list[LetterChoice] = data.get("letter_matrix", [])
    item = next((c for c in matrix if c.letter == letter), None)
    if not item:
        await callback.answer("Буква недоступна.", show_alert=True)
        return
    if item.occupied_by_gpo.lower() != settings.target_gpo_name.lower():
        await callback.answer(
            f"⚠️ Буква {letter}: уже задана вручную в '{item.occupied_by_gpo}' ({item.occupied_by_path}). Выберите другую свободную букву.",
            show_alert=True,
        )
        return

    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=f"⚠️ Перезаписать {letter}:", callback_data=f"ltr:overwrite:{letter}")],
            [InlineKeyboardButton(text="⬅️ Выбрать другую букву", callback_data="ltr:back")],
        ]
    )
    if callback.message:
        edited = await safe_edit_text(
            callback.message,
            render_overwrite_step(data["selected_user"], data["selected_share"], letter, item.occupied_by_path),
            reply_markup=kb,
        )
        await track_panel(state, edited)
    await callback.answer()


@router.callback_query(MapWizardStates.choosing_letter, F.data == "ltr:back")
async def cb_letter_back(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    await callback.answer()
    if callback.message:
        await _show_letter_step(callback.message, state, engine)


@router.callback_query(MapWizardStates.choosing_letter, F.data.startswith("ltr:overwrite:"))
async def cb_letter_overwrite(
    callback: CallbackQuery,
    state: FSMContext,
    settings: Settings,
    access_engine: ShareAccessEngine,
) -> None:
    letter = callback.data.split(":")[2]
    await state.update_data(allow_overwrite_per_user=True)
    await callback.answer("Проверяю текущие права...")
    if callback.message:
        await _show_confirm_step(callback.message, state, settings, letter, access_engine)


@router.callback_query(MapWizardStates.choosing_letter, F.data.startswith("ltr:pick:"))
async def cb_letter_pick(
    callback: CallbackQuery,
    state: FSMContext,
    settings: Settings,
    access_engine: ShareAccessEngine,
) -> None:
    letter = callback.data.split(":")[2]
    await state.update_data(allow_overwrite_per_user=False)
    await callback.answer("Проверяю текущие права...")
    if callback.message:
        await _show_confirm_step(callback.message, state, settings, letter, access_engine)


@router.callback_query(MapWizardStates.confirming, F.data.startswith("map:acl:"))
async def cb_map_toggle_acl(
    callback: CallbackQuery,
    state: FSMContext,
    settings: Settings,
    access_engine: ShareAccessEngine,
) -> None:
    choice = callback.data.split(":")[2]
    if choice not in (ACCESS_NONE, ACCESS_RO, ACCESS_RW):
        await callback.answer("Некорректный выбор.", show_alert=True)
        return
    data = await state.get_data()
    access_status = data.get("confirm_access_status")
    if choice in (ACCESS_RO, ACCESS_RW) and access_status is not None and not access_status.acl_readable:
        await callback.answer(
            "ACL этой шары недоступен для чтения. Проверьте права svc_drivemap_bot или скрипт Initialize-ShareAccessDelegation.ps1.",
            show_alert=True,
        )
        return
    letter: str = data["selected_letter"]
    await callback.answer()
    if callback.message:
        await _show_confirm_step(
            callback.message,
            state,
            settings,
            letter,
            access_engine,
            access_choice=choice,
            refresh_acl=False,
        )


@router.callback_query(MapWizardStates.confirming, F.data == "map:change_letter")
async def cb_change_letter(callback: CallbackQuery, state: FSMContext, engine: DriveMapEngine) -> None:
    await callback.answer()
    if callback.message:
        await _show_letter_step(callback.message, state, engine)


@router.callback_query(MapWizardStates.confirming, F.data == "map:confirm")
async def cb_confirm_apply(
    callback: CallbackQuery,
    state: FSMContext,
    engine: DriveMapEngine,
    access_engine: ShareAccessEngine,
    settings: Settings,
) -> None:
    data = await state.get_data()
    share: ShareInfo = data["selected_share"]
    user: ADUser = data["selected_user"]
    letter: str = data["selected_letter"]
    overwrite: bool = bool(data.get("allow_overwrite_per_user", False))
    access_choice: str = str(data.get("selected_access_choice", ACCESS_NONE))
    tg_user = callback.from_user

    await callback.answer("Применяю изменения в AD и SYSVOL...")
    ok = False
    try:
        res = await engine.assign_drive(
            user=user,
            unc_path=share.unc_path,
            letter=letter,
            label=share.label,
            tg_user_id=tg_user.id,
            tg_username=tg_user.username or tg_user.full_name,
            allow_overwrite_per_user=overwrite,
        )
        ok = True
        access_res = None
        access_error = ""
        if access_choice in (ACCESS_RO, ACCESS_RW):
            try:
                access_res = await access_engine.grant_access(
                    user=user,
                    unc_path=share.unc_path,
                    level=access_choice,
                    tg_user_id=tg_user.id,
                    tg_username=tg_user.username or tg_user.full_name,
                )
            except Exception as acc_exc:
                logger.warning("Share access grant after map failed: %s", acc_exc)
                access_error = str(acc_exc)
        text = render_map_result(user, res, access_res=access_res, access_error=access_error)
    except (DriveMapConflictError, DriveMapValidationError) as exc:
        text = banner_bubble("warn", f"<b>Операция отклонена</b>\n<code>{h(str(exc))}</code>")
    except Exception as exc:
        logger.exception("DriveMap assign failed")
        text = banner_bubble("err", f"<b>Ошибка записи GPO</b>\n<code>{h(str(exc))}</code>")

    await state.clear()
    if ok:
        await state.update_data(last_user=user)
    if callback.message:
        kb = map_result_keyboard() if ok else main_menu_keyboard(settings.dry_run)
        edited = await safe_edit_text(callback.message, text, reply_markup=kb)
        await track_panel(state, edited)

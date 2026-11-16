"""DriveMap dashboard menu and global utility handlers."""

from __future__ import annotations

import logging

from aiogram import F, Router
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from drivemap.config import Settings
from drivemap.keyboards.inline import (
    clear_tracked_panel,
    main_menu_keyboard,
    safe_edit_text,
    track_panel,
)
from drivemap.services.share_discovery import ShareDiscoveryService
from drivemap.ui import banner_bubble, h, render_main_menu

logger = logging.getLogger(__name__)
router = Router()


@router.message(Command("drives"))
async def cmd_drives(message: Message, state: FSMContext, settings: Settings) -> None:
    if message.bot:
        await clear_tracked_panel(message.bot, state)
    await state.clear()
    sent = await message.answer(render_main_menu(settings), reply_markup=main_menu_keyboard(settings.dry_run))
    await track_panel(state, sent)


@router.callback_query(F.data.in_({"menu:drives", "drv:home"}))
async def cb_drives_home(callback: CallbackQuery, state: FSMContext, settings: Settings) -> None:
    await state.clear()
    if callback.message:
        edited = await safe_edit_text(
            callback.message,
            render_main_menu(settings),
            reply_markup=main_menu_keyboard(settings.dry_run),
        )
        await track_panel(state, edited)
    await callback.answer()


@router.callback_query(F.data.in_({"drv:noop", "noop"}))
async def cb_noop(callback: CallbackQuery) -> None:
    await callback.answer()


@router.callback_query(F.data.in_({"drv:refresh_shares", "menu:refresh_shares"}))
async def cb_refresh_shares(
    callback: CallbackQuery,
    state: FSMContext,
    shares_svc: ShareDiscoveryService,
    settings: Settings,
) -> None:
    await callback.answer("Сканирую GPO и файловые серверы...", show_alert=False)
    try:
        items = await shares_svc.get_shares(force_refresh=True)
        banner = banner_bubble("ok", f"Кэш шар обновлён: найдено <b>{len(items)}</b> доступных ресурсов.")
    except Exception as exc:
        logger.exception("Share cache refresh failed")
        banner = banner_bubble("warn", f"Ошибка обновления кэша шар: <code>{h(str(exc))}</code>")
    if callback.message:
        edited = await safe_edit_text(
            callback.message,
            render_main_menu(settings, banner_html=banner),
            reply_markup=main_menu_keyboard(settings.dry_run),
        )
        await track_panel(state, edited)

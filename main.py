import asyncio
import sys
import ssl
from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.types import ErrorEvent

from config import settings
from services.logger_service import log
from services.db_service import init_db
from services.jit_service import start_jit_checker
from services.briefing_worker import start_briefing_worker
from services.health_watcher import start_health_watcher
from services.backup_service import start_backup_scheduler
from middlewares.admin_middleware import SuperAdminMiddleware
from middlewares.delete_message_middleware import DeleteUserMessageMiddleware
from handlers.menu_handlers import menu_router
from handlers.ad_admin_handlers import ad_admin_router
from handlers.security_handlers import security_router
from handlers.infra_handlers import infra_router
from handlers.kolins_handlers import kolins_router
from handlers.user_handlers import router as user_router
from handlers.pc_handlers import router as pc_router
from handlers.lotus_handlers import router as lotus_router
from drivemap import init_drivemap_module


def create_bot_session() -> AiohttpSession:
    """Создает сессию aiohttp с поддержкой корпоративных SSL/DLP сертификатов"""
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    session = AiohttpSession()
    session._connector_init["ssl"] = ssl_ctx
    return session


async def main():
    log.info("Starting Tauria SuperAdmin Bot v6.0...")

    if not settings.BOT_TOKEN:
        log.critical("BOT_TOKEN is not set in .env! Please create Tauria/.env with your token.")
        sys.exit(1)

    if not settings.super_admins:
        log.warning("SUPER_ADMIN_IDS is empty! No one will have access to the bot.")

    # Init SQLite DB for audit, hosts, Lotus ID and sessions
    await init_db()

    session = create_bot_session()
    bot = Bot(
        token=settings.BOT_TOKEN.strip(),
        session=session,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    dp = Dispatcher()

    # Register SuperAdmin access middleware and message cleanup middleware
    dp.message.outer_middleware(SuperAdminMiddleware())
    dp.callback_query.outer_middleware(SuperAdminMiddleware())
    dp.message.middleware(DeleteUserMessageMiddleware())

    # Include core routers
    dp.include_router(menu_router)
    dp.include_router(ad_admin_router)
    dp.include_router(security_router)
    dp.include_router(infra_router)
    dp.include_router(kolins_router)
    dp.include_router(user_router)
    dp.include_router(pc_router)
    dp.include_router(lotus_router)

    # Initialize and register DriveMap & Share ACL module
    await init_drivemap_module(dp)

    @dp.errors()
    async def global_error_handler(event: ErrorEvent):
        log.exception(f"Unhandled bot error: {event.exception}", exc_info=event.exception)
        upd = event.update
        err_text = "⚠️ Произошла внутренняя ошибка при обработке запроса. Подробности записаны в журнал."
        try:
            if upd.callback_query:
                try:
                    await upd.callback_query.answer("⚠️ Ошибка выполнения", show_alert=False)
                except Exception:
                    pass
                if upd.callback_query.message:
                    await upd.callback_query.message.answer(err_text)
            elif upd.message:
                await upd.message.answer(err_text)
        except Exception:
            pass
        return True

    # Start background workers
    jit_task = start_jit_checker(bot, check_interval_sec=30)
    briefing_task = asyncio.create_task(start_briefing_worker(bot))
    health_task = asyncio.create_task(start_health_watcher(bot, interval_sec=60))
    backup_task = asyncio.create_task(start_backup_scheduler(bot))

    log.info(f"Bot authorized. SuperAdmins count: {len(settings.super_admins)}. Starting polling...")
    try:
        await bot.delete_webhook(drop_pending_updates=True)
        await dp.start_polling(bot)
    finally:
        jit_task.cancel()
        briefing_task.cancel()
        health_task.cancel()
        backup_task.cancel()
        await bot.session.close()
        log.info("Tauria Bot shut down cleanly.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Bot execution terminated by user.")

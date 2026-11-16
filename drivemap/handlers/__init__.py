"""Handler routers registration for DriveMap & Share ACL module."""

from aiogram import Router

from drivemap.handlers import access_manager, manage_user, map_wizard, menu


def build_root_router() -> Router:
    root = Router()
    root.include_router(menu.router)
    root.include_router(map_wizard.router)
    root.include_router(access_manager.router)
    root.include_router(manage_user.router)
    return root

"""FSM states for Telegram DriveMap workflows."""

from aiogram.fsm.state import State, StatesGroup


class MapWizardStates(StatesGroup):
    choosing_share = State()
    choosing_user = State()
    choosing_letter = State()
    confirming = State()


class ManageUserStates(StatesGroup):
    searching_user = State()
    viewing_user = State()
    confirming_unmap = State()


class ShareLookupStates(StatesGroup):
    searching_share = State()


class AccessStates(StatesGroup):
    choosing_share = State()
    viewing_share = State()
    searching_user = State()
    configuring_user = State()
    viewing_members = State()
    viewing_direct = State()

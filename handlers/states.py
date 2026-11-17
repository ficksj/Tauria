from aiogram.fsm.state import State, StatesGroup

class ADActionState(StatesGroup):
    waiting_for_username = State()
    waiting_for_group_username = State()
    waiting_for_group_name = State()
    waiting_for_offboard_username = State()

class NetCheckState(StatesGroup):
    waiting_for_target = State()

class KolinsAdminState(StatesGroup):
    waiting_for_add_id = State()
    waiting_for_remove_id = State()

class KillSwitchState(StatesGroup):
    waiting_for_username = State()
    waiting_for_confirmation = State()

class JITPrivilegeState(StatesGroup):
    waiting_for_username = State()
    waiting_for_group = State()
    waiting_for_duration = State()

class UserSearchState(StatesGroup):
    waiting_for_query = State()

class PCSearchState(StatesGroup):
    waiting_for_query = State()

class GroupSearchState(StatesGroup):
    waiting_for_query = State()

class PCBindState(StatesGroup):
    waiting_for_pc = State()

class RollbackOffboardState(StatesGroup):
    waiting_for_username = State()

class CreateUserState(StatesGroup):
    waiting_for_mode = State()
    waiting_for_sz_raw_text = State()
    waiting_for_fullname = State()
    waiting_for_sz_info = State()
    waiting_for_intern_duration = State()
    waiting_for_department = State()


class ExchangeActionState(StatesGroup):
    waiting_for_delegate_user = State()
    waiting_for_forward_email = State()


class DnsRecordState(StatesGroup):
    waiting_for_dns_input = State()

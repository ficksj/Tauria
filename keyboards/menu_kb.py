from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

def get_main_menu() -> InlineKeyboardMarkup:
    keyboard = [
        [
            InlineKeyboardButton(text="🏢 Active Directory", callback_data="menu_ad"),
            InlineKeyboardButton(text="🖥 Инфраструктура", callback_data="menu_infra")
        ],
        [
            InlineKeyboardButton(text="🌐 Сеть & Порты", callback_data="menu_net"),
            InlineKeyboardButton(text="🤖 Бот Поддержки (Kolins)", callback_data="menu_kolins")
        ],
        [
            InlineKeyboardButton(text="📋 Журнал аудита", callback_data="menu_audit"),
            InlineKeyboardButton(text="⚙️ Статус бота", callback_data="menu_bot_status")
        ]
    ]
    return InlineKeyboardMarkup(inline_keyboard=keyboard)

def get_back_button(target: str = "main_menu") -> InlineKeyboardButton:
    return InlineKeyboardButton(text="⬅️ Назад", callback_data=target)

def get_confirm_keyboard(action: str, target_id: str) -> InlineKeyboardMarkup:
    """Клавиатура подтверждения опасных операций"""
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="⚠️ Подтвердить выполнение", callback_data=f"confirm_{action}_{target_id}"),
        ],
        [
            InlineKeyboardButton(text="❌ Отмена", callback_data="main_menu")
        ]
    ])

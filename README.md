# Tauria · Advanced Systems & Active Directory Administration Bot

Высоконадежный корпоративный Telegram-бот для супер-администраторов и инженеров инфраструктуры. Разработан для автоматизации критических задач Active Directory, управления серверами, сетевой диагностики и оркестрации бота техподдержки Kolins.

---

## 🏛 Архитектура и стек
- **Python:** 3.12+ (совместим с 3.14)
- **Фреймворк:** `aiogram` 3.x (чистая асинхронная архитектура)
- **Конфигурация:** `pydantic-settings` (строгая типизация `.env`)
- **LDAP:** `ldap3` (StartTLS/SSL, пулы соединений, безопасные транзакции в AD)
- **База данных аудита:** `aiosqlite` (локальный аудит действий супер-админов)
- **Интеграция с ОС:** `PowerShell` / WMI / WinRM (асинхронное выполнение задач администрирования)

---

## 🔒 Безопасность
1. **SuperAdmin Middleware:** Бот мгновенно блокирует любые запросы от пользователей, чьи `user_id` не входят в `SUPER_ADMIN_IDS`.
2. **Two-Step Confirmation (Двухэтапное подтверждение):** Деструктивные операции (увольнение пользователя, удаление из привилегированных групп, перезапуск сервисов) требуют подтверждения через Callback-кнопку.
3. **Локальный и удаленный аудит:** Все действия логируются в локальную БД `data/tauria.db` и отправляются в корпоративный канал аудита `LOG_CHAT_ID`.

---

## 📂 Структура проекта
```
Tauria/
├── config.py              # Pydantic Settings и валидация .env
├── main.py                # Точка входа, запуск бота и диспетчера
├── requirements.txt       # Зависимости
├── .env.example           # Шаблон конфигурации
├── data/                  # SQLite БД (tauria.db)
├── handlers/              # Обработчики команд и меню
│   └── menu_handlers.py
├── keyboards/             # Клавиатуры и inline-меню
│   └── menu_kb.py
├── middlewares/           # Middleware безопасности (SuperAdmin check)
│   └── admin_middleware.py
└── services/              # Сервисный слой
    ├── db_service.py      # Асинхронный аудит и БД
    ├── logger_service.py  # Цветное логирование
    └── infra_service.py   # WMI, PowerShell, Ping, TCP-проверки
```

---

## 🚀 Быстрый запуск

1. Перейдите в папку проекта:
   ```powershell
   cd c:\Users\kbeletskiy\Documents\Tauria
   ```
2. Создайте файл `.env` на основе `.env.example`:
   ```env
   BOT_TOKEN=ваш_токен_от_BotFather
   SUPER_ADMIN_IDS=ваш_telegram_id
   LOG_CHAT_ID=-100xxxxxxxxxx
   AD_SERVER=192.168.201.15
   AD_DOMAIN=kdb.kz
   AD_USER=svc_kolins@kdb.kz
   AD_PASSWORD=ваш_пароль_ad
   ```
3. Запустите бота:
   ```powershell
   python main.py
   ```

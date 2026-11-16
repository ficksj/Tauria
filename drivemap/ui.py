"""Telegram HTML bubble formatting primitives and screen renderers."""

from __future__ import annotations

import html
from typing import Sequence

from drivemap.config import Settings
from drivemap.models import (
    ACCESS_FULL,
    ACCESS_NONE,
    ACCESS_RO,
    ACCESS_RW,
    ADGroup,
    ADUser,
    AccessMutationResult,
    AuditRecord,
    EffectiveMapping,
    LetterChoice,
    MutationResult,
    ShareAccessReport,
    ShareAclEntry,
    ShareInfo,
    UserShareAccessStatus,
)

SCOPE_LABELS = {
    "GLOBAL": "Общая (DOM)",
    "OU_GPO": "Отдел (OU-GPO)",
    "ORG_UNIT_FILTER": "Отдел (Фильтр OU)",
    "GROUP_FILTER": "Группа AD",
    "PER_USER": "Персональная",
    "PER_USER_DELETE": "Удаление (action=D)",
}

BANNER_ICONS = {
    "ok": "✅",
    "dry": "🧪",
    "warn": "⚠️",
    "err": "❌",
    "info": "ℹ️",
}

SERVER_FILTERS = ("ALL", "PRIMARY", "GPO", "OTHER")
SERVER_FILTER_LABELS = {
    "ALL": "Все",
    "PRIMARY": "Основной ФС",
    "GPO": "Только GPO",
    "OTHER": "Другие ФС",
}


def h(text: object) -> str:
    """Escape dynamic text for Telegram ParseMode.HTML."""
    return html.escape(str(text), quote=False)


def bubble(body: str, title: str = "", expandable: bool = False) -> str:
    """Wrap pre-formatted HTML content in a Telegram blockquote bubble."""
    tag = "<blockquote expandable>" if expandable else "<blockquote>"
    header = f"<b>{h(title)}</b>\n" if title else ""
    return f"{tag}{header}{body.strip()}</blockquote>"


def kv_bubble(rows: Sequence[tuple[str, str]], title: str = "", expandable: bool = False) -> str:
    """Render key-value HTML rows inside a blockquote bubble (values must already be safe HTML)."""
    body = "\n".join(f"<b>{h(k)}:</b> {v}" for k, v in rows if v)
    return bubble(body, title=title, expandable=expandable)


def list_bubble(
    items: Sequence[str],
    title: str = "",
    empty_text: str = "Нет записей.",
    expandable_after: int = 5,
    max_chars: int = 2300,
) -> str:
    """Render bullet items in a blockquote bubble, auto-collapsing and truncating safely."""
    if not items:
        return bubble(f"<i>{h(empty_text)}</i>", title=title, expandable=False)

    chosen: list[str] = []
    used = 0
    for idx, line in enumerate(items):
        bullet = line if line.startswith("•") else f"• {line}"
        next_len = used + len(bullet) + 1
        if idx > 0 and next_len > max_chars:
            remaining = len(items) - idx
            chosen.append(f"<i>… и ещё {remaining}</i>")
            break
        chosen.append(bullet)
        used = next_len

    expandable = len(items) > expandable_after
    return bubble("\n".join(chosen), title=title, expandable=expandable)


def banner_bubble(kind: str, message_html: str) -> str:
    """Render a compact status or alert blockquote bubble."""
    icon = BANNER_ICONS.get(kind, "ℹ️")
    return f"<blockquote>{icon} {message_html}</blockquote>"


def progress_header(step: int, total: int, section: str, subtitle: str) -> str:
    """Render a visual step bar and title for multi-step wizards."""
    dots = " ".join("●" if i < step else "○" for i in range(total))
    return f"<b>{h(section)} · Шаг {step}/{total}</b>\n<code>{dots}</code>  <i>{h(subtitle)}</i>"


def filter_shares_by_category(
    shares: Sequence[ShareInfo],
    category: str,
    primary_server: str = "",
) -> list[ShareInfo]:
    """Filter discovered shares by UI category pill (ALL, PRIMARY, GPO, OTHER)."""
    target = (primary_server or "FS01").upper()
    target_short = target.split(".", 1)[0]
    if category == "PRIMARY":
        return [s for s in shares if s.server.upper() in (target, target_short)]
    if category == "GPO":
        return [s for s in shares if s.source in ("GPO", "BOTH")]
    if category == "OTHER":
        return [s for s in shares if s.server.upper() not in (target, target_short)]
    return list(shares)


def render_main_menu(settings: Settings, banner_html: str = "") -> str:
    """Render the root dashboard card."""
    mode_badge = "🧪 <b>DRY-RUN</b> (без записи в AD)" if settings.dry_run else "🟢 <b>LIVE</b> (запись в AD / SYSVOL)"
    parts = [f"🎛 <b>DriveMap Manager · {h(settings.ad_domain)}</b>"]
    if banner_html:
        parts.append(banner_html)
    parts.append(
        kv_bubble(
            [
                ("🌐 Домен", f"<code>{h(settings.ad_domain)}</code>"),
                ("📜 Целевая GPO", f"<code>{h(settings.target_gpo_name)}</code>"),
                ("⚙️ Режим", mode_badge),
            ],
            title="Состояние системы",
        )
    )
    parts.append(
        bubble(
            "• <b>Подключить диск</b> — пошаговый мастер с проверкой коллизий RSOP\n"
            "• <b>Доступы к дискам</b> — аудит NTFS/AGDLP-прав, выдача <code>RO</code>/<code>RW</code> и отзыв\n"
            "• <b>Диски пользователя</b> — просмотр, удаление правила и <code>action=D</code>\n"
            "• <b>Поиск по шаре</b> — обратный аудит назначений <code>&lt;FilterUser&gt;</code>\n"
            "• <b>Журнал / Откат</b> — история операций и мгновенный возврат бэкапа",
            title="Возможности",
        )
    )
    return "\n\n".join(parts)


def render_share_step(
    shares: Sequence[ShareInfo],
    total_catalog: int,
    server_filter: str = "ALL",
    query: str = "",
    banner_html: str = "",
    step_header: str = "",
    primary_label: str = "",
) -> str:
    """Render Step 1 (share selection) or Share Lookup screen in HTML bubble layout."""
    header = step_header or progress_header(1, 4, "➕ Подключение диска", "Выбор сетевой шары")
    filter_label = (
        primary_label
        if (server_filter == "PRIMARY" and primary_label)
        else SERVER_FILTER_LABELS.get(server_filter, server_filter)
    )
    info_rows = [
        ("🗂 Фильтр", f"<code>{h(filter_label)}</code>"),
        ("📊 Показано", f"<b>{len(shares)}</b> из <b>{total_catalog}</b>"),
    ]
    if query:
        info_rows.append(("🔎 Поиск", f"<code>{h(query)}</code>"))

    parts = [header]
    if banner_html:
        parts.append(banner_html)
    parts.append(kv_bubble(info_rows))
    parts.append(
        bubble(
            "Нажмите ресурс кнопкой ниже <b>или отправьте текстом</b>:\n"
            "• часть названия: <code>Finance</code>, <code>HelpDesk</code>, <code>Public</code>\n"
            "• полный UNC-путь: <code>\\\\STORAGE\\Share\\Folder</code>",
            title="Как выбрать шару",
        )
    )
    return "\n\n".join(parts)


def render_user_prompt(
    share: ShareInfo,
    query: str = "",
    users: Sequence[ADUser] | None = None,
    banner_html: str = "",
) -> str:
    """Render Step 2 (AD user search & pick) card."""
    letter_badge = f" (штатная: <code>{share.suggested_letter}:</code>)" if share.suggested_letter else ""
    parts = [progress_header(2, 4, "➕ Подключение диска", "Выбор сотрудника AD")]
    if banner_html:
        parts.append(banner_html)
    parts.append(
        kv_bubble(
            [
                ("📁 Шара", f"<b>{h(share.label)}</b> · <code>{h(share.unc_path)}</code>{letter_badge}"),
                ("📡 Источник", f"<code>{h(share.source)}</code>"),
            ],
            title="Выбранный ресурс",
        )
    )
    if users is not None:
        parts.append(
            bubble(
                f"По запросу <code>{h(query)}</code> найдено активных сотрудников: <b>{len(users)}</b>.\n"
                "Выберите нужного из списка ниже или отправьте новый запрос.",
                title="Результаты поиска в AD",
            )
        )
    else:
        parts.append(
            bubble(
                "Отправьте текстом <b>ФИО, логин (sAMAccountName)</b> или <b>отдел</b> сотрудника для поиска в Active Directory.",
                title="Поиск пользователя",
            )
        )
    return "\n\n".join(parts)


def render_letter_step(
    share: ShareInfo,
    user: ADUser,
    effective: Sequence[EffectiveMapping],
    matrix: Sequence[LetterChoice],
    recommended: str | None,
) -> str:
    """Render Step 3 (free letter choice & RSOP collision guard)."""
    parts = [
        progress_header(3, 4, "➕ Подключение диска", "Выбор свободной буквы"),
        kv_bubble(
            [
                ("👤 Сотрудник", f"<b>{h(user.display_name)}</b> (<code>{h(user.sam_account_name)}</code> · {h(user.division_label)})"),
                ("📁 Шара", f"<code>{h(share.unc_path)}</code> (метка: <b>{h(share.label)}</b>)"),
            ],
            title="Назначение",
        ),
    ]

    drive_items = []
    for m in effective:
        if m.scope_type == "PER_USER_DELETE":
            continue
        scope_ru = SCOPE_LABELS.get(m.scope_type, m.scope_type)
        drive_items.append(f"<code>{m.letter}:</code> → <code>{h(m.path)}</code> <i>({h(scope_ru)})</i>")
    parts.append(
        list_bubble(
            drive_items,
            title=f"Текущие диски пользователя ({len(drive_items)})",
            empty_text="У пользователя нет других сетевых дисков DriveMap.",
            expandable_after=5,
        )
    )

    if share.suggested_letter:
        hit = next((c for c in matrix if c.letter == share.suggested_letter), None)
        if hit and not hit.is_available:
            rec_note = f"предложена свободная буква <b>{recommended}:</b>." if recommended else "свободных букв E–Z не осталось!"
            parts.append(
                banner_bubble(
                    "warn",
                    f"Штатная буква шары <code>{share.suggested_letter}:</code> занята "
                    f"(<code>{h(hit.occupied_by_path)}</code> · {h(hit.occupied_by_gpo)}). "
                    f"Чтобы избежать конфликта, {rec_note}",
                )
            )
        elif recommended:
            parts.append(banner_bubble("info", f"Рекомендуемая штатная буква свободна: <b>{recommended}:</b>"))
    elif recommended:
        parts.append(banner_bubble("info", f"Рекомендуемая свободная буква: <b>{recommended}:</b>"))

    parts.append(
        bubble(
            "⭐ Рекомендованная   🟢 Свободна\n"
            "👤 Персональная      🔒 Занята отделом / общей GPO",
            title="Обозначения кнопок",
        )
    )
    return "\n\n".join(parts)


def render_overwrite_step(user: ADUser, share: ShareInfo, letter: str, existing_path: str) -> str:
    """Render overwrite confirmation bubble for an existing personal drive letter."""
    return "\n\n".join(
        [
            "<b>⚠️ Перезапись персонального диска</b>",
            kv_bubble(
                [
                    ("👤 Сотрудник", f"<b>{h(user.display_name)}</b> (<code>{h(user.sam_account_name)}</code>)"),
                    ("💽 Буква", f"<b>{letter}:</b>"),
                    ("📌 Текущий путь", f"<code>{h(existing_path)}</code>"),
                    ("🆕 Новый путь", f"<code>{h(share.unc_path)}</code>"),
                ]
            ),
            banner_bubble("warn", "Заменить существующее персональное сопоставление на этой букве?"),
        ]
    )


def _access_level_label(level: str) -> str:
    labels = {
        ACCESS_NONE: "⬜ Нет прав",
        ACCESS_RO: "🔒 Только чтение (RO)",
        ACCESS_RW: "✏️ Чтение и запись (RW)",
        ACCESS_FULL: "🛡 Полный доступ (FULL)",
        "DENY": "⛔ Запрет (DENY)",
        "CUSTOM": "⚙️ Особые права",
        "UNKNOWN": "❓ Не удалось проверить ACL",
    }
    return labels.get(level, h(level))


def render_confirm_step(
    settings: Settings,
    user: ADUser,
    share: ShareInfo,
    letter: str,
    overwrite: bool,
    access_status: UserShareAccessStatus | None = None,
    access_choice: str = ACCESS_NONE,
    has_agdlp_ro: bool = False,
    has_agdlp_rw: bool = False,
) -> str:
    """Render Step 4 (final transaction confirmation)."""
    mode_line = "🧪 <b>DRY-RUN</b> (AD не изменится)" if settings.dry_run else "🟢 <b>LIVE</b> (запись в AD / SYSVOL)"
    access_choice_labels = {
        ACCESS_NONE: "Не менять (только подключить букву)",
        ACCESS_RO: "🔒 Выдать Только чтение (RO)",
        ACCESS_RW: "✏️ Выдать Чтение и запись (RW)",
    }
    rows = [
        ("👤 Сотрудник", f"<b>{h(user.display_name)}</b> (<code>{h(user.qualified_name(settings.ad_netbios))}</code>)"),
        ("🏢 Отдел / OU", f"<code>{h(user.division_label)}</code>"),
        ("📁 Шара", f"<code>{h(share.unc_path)}</code>"),
        ("🏷 Метка диска", f"<b>{h(share.label)}</b>"),
        ("💽 Буква", f"<b>{letter}:</b>"),
        ("📜 Политика", f"<code>{h(settings.target_gpo_name)}</code>"),
    ]
    if access_status is not None:
        src_suffix = f" <i>({'; '.join(h(s) for s in access_status.sources[:2])})</i>" if access_status.sources else ""
        rows.append(("🔍 Текущие права", f"{_access_level_label(access_status.effective_level)}{src_suffix}"))
    rows.append(("🔐 Доступ к шаре", access_choice_labels.get(access_choice, h(access_choice))))
    rows.append(("⚙️ Режим", mode_line))

    parts = [
        progress_header(4, 4, "➕ Подключение диска", "Подтверждение операции"),
        kv_bubble(rows, title="Параметры транзакции"),
    ]
    if overwrite:
        parts.append(banner_bubble("warn", "Предыдущее персональное подключение на эту букве будет заменено."))

    if access_choice in (ACCESS_RO, ACCESS_RW):
        use_group = (access_choice == ACCESS_RO and has_agdlp_ro) or (access_choice == ACCESS_RW and has_agdlp_rw)
        mech_hint = (
            "Права будут выданы через защищённую AD-группу шары (потребуется перелогин или <code>klist purge</code>)."
            if use_group
            else "AGDLP-группа для этого уровня не найдена — будут применены прямые права NTFS (<code>RO</code>/<code>RW</code>) на шаре."
        )
        parts.append(banner_bubble("info", mech_hint))
    elif access_status is not None and access_status.effective_level in (ACCESS_RO, ACCESS_RW, ACCESS_FULL):
        parts.append(banner_bubble("ok", f"У пользователя уже есть доступ: {_access_level_label(access_status.effective_level)}."))
    else:
        parts.append(
            banner_bubble(
                "info",
                "Вы можете сразу выдать доступ <b>RO</b> / <b>RW</b> кнопками ниже или оставить только подключение буквы.",
            )
        )
    return "\n\n".join(parts)


def render_map_result(
    user: ADUser,
    res: MutationResult,
    access_res: AccessMutationResult | None = None,
    access_error: str = "",
) -> str:
    """Render transaction success bubble with gpupdate/klist command box."""
    header = "🧪 <b>Симуляция выполнена (DRY-RUN)</b>" if res.dry_run else "✅ <b>Диск подключён через DriveMap</b>"
    parts = [
        header,
        kv_bubble(
            [
                ("👤 Сотрудник", f"<b>{h(user.display_name)}</b> (<code>{h(user.sam_account_name)}</code>)"),
                ("💽 Диск", f"<b>{res.letter}:</b> → <code>{h(res.unc_path)}</code> (<i>{h(res.label)}</i>)"),
                ("🆔 Транзакция", f"<code>{h(res.tx_id)}</code>"),
                ("🔢 Версия GPO", f"<code>{res.gpo_version_before}</code> → <code>{res.gpo_version_after}</code>"),
            ],
            title="Детали DriveMap",
        ),
    ]
    if access_res is not None:
        mech_txt = (
            f"AD-группа <code>{h(access_res.group_name)}</code>"
            if access_res.mechanism == "AD_GROUP" and access_res.group_name
            else f"Прямой NTFS ACL (объектов: {access_res.propagated_objects})"
        )
        parts.append(
            kv_bubble(
                [
                    ("🔐 Уровень прав", _access_level_label(access_res.level)),
                    ("⚙️ Механизм", mech_txt),
                    ("🆔 Транзакция ACL", f"<code>{h(access_res.tx_id)}</code>"),
                ],
                title="Права доступа к шаре",
            )
        )
        if access_res.truncated_propagation:
            parts.append(
                banner_bubble(
                    "warn",
                    f"Обход NTFS ограничен лимитом (обновлено {access_res.propagated_objects} объектов). "
                    "Крупные подкаталоги проверьте отдельно.",
                )
            )
    elif access_error:
        parts.append(
            banner_bubble(
                "warn",
                f"<b>Диск подключён, но права не выданы</b>\n<code>{h(access_error)}</code>",
            )
        )

    cmds = "gpupdate /force\nklist purge" if (access_res and access_res.requires_relogon) else "gpupdate /force"
    relogon_note = " и обновление Kerberos-токена группы (или перелогин)" if (access_res and access_res.requires_relogon) else ""
    parts.append(
        f"<blockquote>⚡ <b>Мгновенное применение на ПК пользователя{relogon_note}:</b> "
        "выполните в командной строке</blockquote>\n"
        f"<pre><code>{cmds}</code></pre>"
    )
    return "\n\n".join(parts)


def render_user_search_screen(query: str = "", users: Sequence[ADUser] | None = None, banner_html: str = "") -> str:
    """Render Manage User search prompt or search results card."""
    parts = ["👤 <b>Управление дисками пользователя</b>"]
    if banner_html:
        parts.append(banner_html)
    if users is not None:
        parts.append(
            bubble(
                f"По запросу <code>{h(query)}</code> найдено: <b>{len(users)}</b>.\n"
                "Выберите сотрудника ниже или отправьте новый запрос.",
                title="Результаты поиска в AD",
            )
        )
    else:
        parts.append(
            bubble(
                "Отправьте <b>ФИО, логин (sAMAccountName)</b> или <b>отдел</b> сотрудника, чтобы посмотреть все его сетевые диски и управлять персональными подключениями.",
                title="Поиск сотрудника",
            )
        )
    return "\n\n".join(parts)


def render_user_drives_screen(
    user: ADUser,
    mappings: Sequence[EffectiveMapping],
    banner_html: str = "",
) -> str:
    """Render a user's RSOP drives card with HTML bubbles."""
    parts = ["👤 <b>Профиль и диски пользователя</b>"]
    if banner_html:
        parts.append(banner_html)
    parts.append(
        kv_bubble(
            [
                ("Имя", f"<b>{h(user.display_name)}</b>"),
                ("Логин", f"<code>{h(user.sam_account_name)}</code>"),
                ("Отдел / OU", f"<code>{h(user.division_label)}</code>"),
            ]
        )
    )
    items: list[str] = []
    for m in mappings:
        if m.scope_type == "PER_USER_DELETE":
            items.append(f"🚫 <code>{m.letter}:</code> — активен Delete-маркер (<code>action=D</code>)")
        elif m.removable_by_bot:
            items.append(f"👤 <code>{m.letter}:</code> → <code>{h(m.path)}</code> <i>({h(m.label)} · можно отключить)</i>")
        else:
            items.append(f"🔒 <code>{m.letter}:</code> → <code>{h(m.path)}</code> <i>({h(m.source_gpo)})</i>")

    parts.append(
        list_bubble(
            items,
            title=f"Сетевые диски ({len(items)})",
            empty_text="Активных политик DriveMap для этого пользователя не найдено.",
            expandable_after=6,
        )
    )
    return "\n\n".join(parts)


def render_unmap_confirm(user: ADUser, mapping: EffectiveMapping, is_delete_marker: bool) -> str:
    """Render confirmation bubble for removing or hard-deleting a user drive rule."""
    if is_delete_marker:
        return "\n\n".join(
            [
                "🧹 <b>Очистка delete-маркера</b>",
                kv_bubble(
                    [
                        ("👤 Сотрудник", f"<b>{h(user.display_name)}</b> (<code>{h(user.sam_account_name)}</code>)"),
                        ("💽 Буква", f"<b>{mapping.letter}:</b>"),
                    ]
                ),
                banner_bubble("info", "Убрать временное правило <code>action=D</code> из целевой GPO?"),
            ]
        )

    return "\n\n".join(
        [
            "🗑 <b>Отключение сетевого диска</b>",
            kv_bubble(
                [
                    ("👤 Сотрудник", f"<b>{h(user.display_name)}</b> (<code>{h(user.sam_account_name)}</code>)"),
                    ("💽 Диск", f"<b>{mapping.letter}:</b> → <code>{h(mapping.path)}</code>"),
                ]
            ),
            bubble(
                "• <b>Снять правило</b> — убирает пользователя из GPO (действует на новые сеансы).\n"
                "• <b>Отключить жёстко (<code>action=D</code>)</b> — удалит закэшированную букву из профиля Windows при <code>gpupdate</code>.",
                title="Выберите режим",
            ),
        ]
    )


def render_share_users_screen(unc_path: str, hits: Sequence[tuple[str, str, str, str]]) -> str:
    """Render reverse share lookup results in an HTML bubble card."""
    items = [
        f"<b>{h(uname)}</b> — диск <code>{letter}:</code> <i>({h(gpo_name)})</i>"
        for gpo_name, letter, uname, _sid in hits
    ]
    return "\n\n".join(
        [
            "📁 <b>Персональные подключения к шаре</b>",
            kv_bubble([("Путь UNC", f"<code>{h(unc_path)}</code>")]),
            list_bubble(
                items,
                title=f"Назначения <FilterUser> ({len(items)})",
                empty_text="Персональных правил (<FilterUser>) для этой шары не найдено.",
                expandable_after=6,
            ),
        ]
    )


def render_audit_screen(records: Sequence[AuditRecord], banner_html: str = "") -> str:
    """Render recent audit transactions and rollback card."""
    items: list[str] = []
    for r in records:
        icon = "✅" if r.status == "SUCCESS" else "❌"
        is_acl = r.operation.startswith("ACCESS_")
        unit = h(r.letter) if is_acl else f"{h(r.letter)}:"
        ver_txt = "" if is_acl else f" <i>(v.{r.gpo_version_before}→{r.gpo_version_after})</i>"
        items.append(
            f"{icon} <code>{h(r.tx_id)}</code> · <b>{h(r.operation)}</b> · "
            f"<code>{h(r.target_sam)}</code> → <code>{unit}</code> "
            f"<code>{h(r.unc_path or '-')}</code>{ver_txt}"
        )
    parts = ["📜 <b>Журнал аудита операций</b>"]
    if banner_html:
        parts.append(banner_html)
    parts.append(
        list_bubble(
            items,
            title=f"Последние операции ({len(items)})",
            empty_text="Записей в журнале пока нет.",
            expandable_after=5,
        )
    )
    return "\n\n".join(parts)


def _short_acl_badge(entry: ShareAclEntry) -> str:
    base = {
        ACCESS_RO: "RO",
        ACCESS_RW: "RW",
        ACCESS_FULL: "FULL",
        "CUSTOM": "CUSTOM",
    }.get(entry.level, entry.level)
    return f"⛔ DENY {base}" if entry.is_deny else base


def render_access_share_view(report: ShareAccessReport, banner_html: str = "") -> str:
    """Render live NTFS ACL & AGDLP groups view for a network share."""
    parts = ["🔐 <b>Доступы к сетевой шаре</b>"]
    if banner_html:
        parts.append(banner_html)

    ro_desc = (
        f"<code>{h(report.ro_group.sam_account_name)}</code> ({len(report.ro_group.member_dns)} уч.)"
        if report.ro_group
        else "<i>не найдена</i>"
    )
    rw_desc = (
        f"<code>{h(report.rw_group.sam_account_name)}</code> ({len(report.rw_group.member_dns)} уч.)"
        if report.rw_group
        else "<i>не найдена</i>"
    )
    kv_rows = [
        ("📁 Шара", f"<code>{h(report.unc_path)}</code>"),
        ("🔒 Группа RO", ro_desc),
        ("✏️ Группа RW", rw_desc),
    ]
    if report.ro_group is None or report.rw_group is None:
        kv_rows.append(("⚙️ Fallback", "Прямой NTFS ACL (если AGDLP-группы нет)"))
    parts.append(kv_bubble(kv_rows, title="Сводка прав и AGDLP"))

    if not report.readable:
        parts.append(
            banner_bubble(
                "err",
                f"Не удалось прочитать NTFS ACL шары.\n<code>{h(report.error)}</code>\n"
                "Проверьте SMB/NTFS права сервисной учётной записи (скрипт <code>Initialize-ShareAccessDelegation.ps1</code>).",
            )
        )
        return "\n\n".join(parts)

    items: list[str] = []
    for e in report.entries:
        badge = h(_short_acl_badge(e))
        inh = " <i>[унасл.]</i>" if e.is_inherited else ""
        if e.is_manageable_group:
            items.append(
                f"👥 <b>{h(e.display_name)}</b> — <code>{badge}</code> · {e.group_member_count} уч.{inh}"
            )
        elif e.principal_type == "USER" and not e.is_protected:
            items.append(f"👤 <b>{h(e.display_name)}</b> (<code>{h(e.principal_name)}</code>) — <code>{badge}</code>{inh}")
        elif e.principal_type == "GROUP" and not e.is_protected:
            items.append(f"🛡 <b>{h(e.display_name)}</b> — <code>{badge}</code> <i>(защищена от авто-правки)</i>{inh}")
        else:
            items.append(f"⚙️ <code>{h(e.principal_name)}</code> — <code>{badge}</code>{inh}")

    parts.append(
        list_bubble(
            items,
            title=f"Записи NTFS DACL ({len(items)})",
            empty_text="Явных разрешений NTFS на корне шары не обнаружено.",
            expandable_after=7,
            max_chars=2400,
        )
    )
    return "\n\n".join(parts)


def render_access_user_prompt(
    unc_path: str,
    query: str = "",
    users: Sequence[ADUser] | None = None,
    banner_html: str = "",
) -> str:
    """Render prompt or search results for picking a user in the Access Manager."""
    parts = [
        "🔐 <b>Проверка / выдача прав пользователю</b>",
        kv_bubble([("📁 Шара", f"<code>{h(unc_path)}</code>")]),
    ]
    if banner_html:
        parts.append(banner_html)
    if users is None:
        parts.append(
            bubble(
                "Введите <b>ФИО</b>, <code>samAccountName</code> или <b>email</b> сотрудника (минимум 2 символа).",
                title="Поиск в Active Directory",
            )
        )
    else:
        parts.append(
            banner_bubble(
                "ok" if users else "warn",
                f"По запросу <code>{h(query)}</code> найдено пользователей: <b>{len(users)}</b>"
                if users
                else f"По запросу <code>{h(query)}</code> никого не найдено. Попробуйте другой запрос.",
            )
        )
    return "\n\n".join(parts)


def render_access_user_grant(
    netbios_domain: str,
    unc_path: str,
    status: UserShareAccessStatus,
    report: ShareAccessReport,
    banner_html: str = "",
) -> str:
    """Render effective share access status and RO/RW/Revoke controls for a user."""
    parts = ["🔐 <b>Управление правами на шару</b>"]
    if banner_html:
        parts.append(banner_html)

    ro_mech = f"AD-группа <code>{h(report.ro_group.sam_account_name)}</code>" if report.ro_group else "Прямой NTFS ACE (RO)"
    rw_mech = f"AD-группа <code>{h(report.rw_group.sam_account_name)}</code>" if report.rw_group else "Прямой NTFS ACE (RW)"

    rows = [
        ("👤 Сотрудник", f"<b>{h(status.user.display_name)}</b> (<code>{h(status.user.qualified_name(netbios_domain))}</code>)"),
        ("🏢 Отдел / OU", f"<code>{h(status.user.division_label)}</code>"),
        ("📁 Шара", f"<code>{h(unc_path)}</code>"),
        ("🔍 Эффективный доступ", _access_level_label(status.effective_level)),
        ("🔒 Механизм RO", ro_mech),
        ("✏️ Механизм RW", rw_mech),
    ]
    parts.append(kv_bubble(rows, title="Статус доступа"))

    if not status.acl_readable:
        parts.append(
            banner_bubble(
                "err",
                f"Не удалось прочитать ACL шары: <code>{h(report.error)}</code>",
            )
        )
        return "\n\n".join(parts)

    if status.sources:
        parts.append(
            list_bubble(
                [h(s) for s in status.sources],
                title="Источники прав",
                expandable_after=5,
            )
        )
    else:
        parts.append(banner_bubble("info", "У пользователя сейчас нет прав на эту шару."))

    if status.blocked_by_protected_group:
        parts.append(
            banner_bubble(
                "warn",
                "Права (или часть прав) наследуются через общую/отдельскую группу, "
                "которую бот не редактирует. Отзыв затронет только персональные права (<code>Share_*</code> / прямой NTFS).",
            )
        )
    return "\n\n".join(parts)


def render_access_group_members(
    unc_path: str,
    group: ADGroup,
    level: str,
    members: Sequence[ADUser],
    banner_html: str = "",
) -> str:
    """Render AD group membership manager for a Share_* group."""
    parts = [f"👥 <b>Участники группы {h(group.sam_account_name)}</b>"]
    if banner_html:
        parts.append(banner_html)
    parts.append(
        kv_bubble(
            [
                ("📁 Шара", f"<code>{h(unc_path)}</code>"),
                ("🔐 Уровень", _access_level_label(level)),
                ("🛡 Группа AD", f"<code>{h(group.sam_account_name)}</code>"),
            ]
        )
    )
    items = [
        f"👤 <b>{h(u.display_name)}</b> (<code>{h(u.sam_account_name)}</code>) · <i>{h(u.division_label)}</i>"
        for u in members
    ]
    parts.append(
        list_bubble(
            items,
            title=f"Прямые участники ({len(members)})",
            empty_text="В группе пока нет ни одного участника.",
            expandable_after=8,
            max_chars=2400,
        )
    )
    parts.append(banner_bubble("info", "Нажмите на сотрудника в списке ниже, чтобы удалить его из группы."))
    return "\n\n".join(parts)


def render_access_direct_users(
    unc_path: str,
    entries: Sequence[ShareAclEntry],
    banner_html: str = "",
) -> str:
    """Render direct user NTFS ACE list for quick inspection & removal."""
    parts = ["🧾 <b>Прямые пользовательские NTFS ACE</b>"]
    if banner_html:
        parts.append(banner_html)
    parts.append(kv_bubble([("📁 Шара", f"<code>{h(unc_path)}</code>")]))
    items = []
    for e in entries:
        badge = h(_short_acl_badge(e))
        inh = " <i>(унасл., не удаляется здесь)</i>" if e.is_inherited else ""
        items.append(f"👤 <b>{h(e.display_name)}</b> (<code>{h(e.principal_name)}</code>) — <code>{badge}</code>{inh}")
    parts.append(
        list_bubble(
            items,
            title=f"Пользователи в DACL ({len(entries)})",
            empty_text="Прямых пользовательских ACE на этой шаре нет.",
            expandable_after=8,
            max_chars=2400,
        )
    )
    return "\n\n".join(parts)


def render_access_result(res: AccessMutationResult, display_name: str = "") -> str:
    """Render outcome bubble of a share access grant, revoke, or rollback."""
    if res.dry_run:
        header = "🧪 <b>Симуляция прав выполнена (DRY-RUN)</b>"
    elif res.operation == "ACCESS_ROLLBACK":
        header = "↩️ <b>Откат прав выполнен</b>"
    elif res.level == ACCESS_NONE or "REVOKE" in res.operation:
        header = "🗑 <b>Доступ к шаре отозван</b>"
    else:
        header = "✅ <b>Права доступа применены</b>"

    who = f"<b>{h(display_name)}</b> (<code>{h(res.target_user)}</code>)" if display_name else f"<code>{h(res.target_user)}</code>"
    mech_map = {
        "AD_GROUP": f"AD-группа {h(res.group_name)}",
        "NTFS_DIRECT": f"Прямой NTFS ACL (объектов: {res.propagated_objects})",
        "HYBRID": "Комбинированный (AD-группа + NTFS)",
    }
    rows = [
        ("👤 Сотрудник", who),
        ("📁 Шара", f"<code>{h(res.unc_path)}</code>"),
        ("🔐 Уровень", _access_level_label(res.level)),
        ("⚙️ Механизм", mech_map.get(res.mechanism, h(res.mechanism))),
        ("🆔 Транзакция", f"<code>{h(res.tx_id)}</code>"),
    ]
    if res.message:
        rows.append(("📝 Результат", h(res.message)))

    parts = [header, kv_bubble(rows, title="Детали операции")]
    if res.truncated_propagation:
        parts.append(
            banner_bubble(
                "warn",
                f"Обновление NTFS остановлено по лимиту объектов ({res.propagated_objects}). "
                "Часть глубоких вложенных файлов могла сохранить старый унаследованный ACL.",
            )
        )
    if res.requires_relogon:
        parts.append(
            "<blockquote>⚡ <b>Изменилось членство в AD-группе:</b> для применения прав без перезагрузки "
            "сотрудник может сбросить Kerberos-билеты или перелогиниться:</blockquote>\n"
            "<pre><code>klist purge</code></pre>"
        )
    return "\n\n".join(parts)

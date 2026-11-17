import csv
import html
import io
import json
import os
import tempfile
import zipfile
from datetime import datetime
from typing import Any

from services.ad_service import ad_service
from services.exchange_service import get_exchange_forwarding_audit, get_exchange_overview


def _to_csv_bytes(headers: list[str], rows: list[list[Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=",", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8-sig")


async def generate_kpmg_audit_zip() -> str:
    """Формирует единый ZIP-архив для аудита KPMG / ГТС и возвращает путь к нему."""
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_path = os.path.join(tempfile.gettempdir(), f"kpmg_gts_audit_{stamp}.zip")

    # 1. Привилегированные группы AD
    try:
        priv_res = await ad_service.inspect_privileged_groups()
        groups_map = priv_res.get("groups", {}) if isinstance(priv_res, dict) else {}
        priv_error = None if (isinstance(priv_res, dict) and priv_res.get("success", True)) else (
            priv_res.get("error", "Unknown error") if isinstance(priv_res, dict) else "Invalid response"
        )
    except Exception as exc:
        groups_map = {}
        priv_error = str(exc)

    priv_rows: list[list[Any]] = []
    for group_name, members in groups_map.items():
        if members:
            for member in members:
                priv_rows.append([group_name, member])
        else:
            priv_rows.append([group_name, "(нет участников)"])
    priv_csv = _to_csv_bytes(["Group", "Member"], priv_rows)

    # 2. Неактивные УЗ > 60 дней
    try:
        inactive_users = await ad_service.get_inactive_users(days=60)
        inactive_error = None
    except Exception as exc:
        inactive_users = []
        inactive_error = str(exc)

    inactive_rows = [
        [
            u.get("username", ""),
            u.get("display_name", ""),
            u.get("department", ""),
            u.get("last_logon", ""),
            u.get("dn", ""),
        ]
        for u in inactive_users
    ]
    inactive_csv = _to_csv_bytes(
        ["Username", "DisplayName", "Department", "LastLogon", "DistinguishedName"],
        inactive_rows,
    )

    # 3. УЗ с PasswordNeverExpires
    try:
        never_expire_users = await ad_service.get_never_expire_password_users()
        never_expire_error = None
    except Exception as exc:
        never_expire_users = []
        never_expire_error = str(exc)

    never_expire_rows = [
        [
            u.get("username", ""),
            u.get("display_name", ""),
            u.get("department", ""),
            u.get("dn", ""),
        ]
        for u in never_expire_users
    ]
    never_expire_csv = _to_csv_bytes(
        ["Username", "DisplayName", "Department", "DistinguishedName"],
        never_expire_rows,
    )

    # 4. Срез безопасности Exchange (с безопасным fallback)
    exchange_summary: dict[str, Any] = {
        "generated_at": generated_at,
        "overview": None,
        "forwarding_audit": None,
        "errors": [],
    }
    try:
        exchange_summary["overview"] = await get_exchange_overview()
    except Exception as exc:
        exchange_summary["overview"] = {"available": False, "error": str(exc)}
        exchange_summary["errors"].append(f"overview: {exc}")

    try:
        exchange_summary["forwarding_audit"] = await get_exchange_forwarding_audit()
    except Exception as exc:
        exchange_summary["forwarding_audit"] = {"available": False, "error": str(exc)}
        exchange_summary["errors"].append(f"forwarding_audit: {exc}")

    exchange_json_bytes = json.dumps(exchange_summary, ensure_ascii=False, indent=2, default=str).encode("utf-8")

    # 5. Сводный HTML-отчет
    total_priv_members = sum(len(m) for m in groups_map.values())
    ex_status = "OK" if not exchange_summary["errors"] else f"Частично / Недоступен ({len(exchange_summary['errors'])} ош.)"

    html_content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <title>KPMG / ГТС Audit Pack Summary</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 32px; color: #1f2937; background: #f9fafb; }}
    h1 {{ color: #111827; margin-bottom: 4px; }}
    .meta {{ color: #6b7280; margin-bottom: 24px; font-size: 14px; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 900px; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    th, td {{ border: 1px solid #e5e7eb; padding: 12px 14px; text-align: left; font-size: 14px; }}
    th {{ background: #f3f4f6; font-weight: 600; }}
    .ok {{ color: #059669; font-weight: 600; }}
    .warn {{ color: #d97706; font-weight: 600; }}
  </style>
</head>
<body>
  <h1>KPMG / ГТС Audit Pack — Сводный отчёт</h1>
  <div class="meta">Дата генерации: {html.escape(generated_at)}</div>
  <table>
    <thead>
      <tr>
        <th>Файл</th>
        <th>Описание</th>
        <th>Статистика</th>
        <th>Статус</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td><code>01_privileged_groups.csv</code></td>
        <td>Состав привилегированных групп AD</td>
        <td>Групп: {len(groups_map)}, записей: {total_priv_members}</td>
        <td class="{"warn" if priv_error else "ok"}">{html.escape(priv_error or "OK")}</td>
      </tr>
      <tr>
        <td><code>02_inactive_users_60d.csv</code></td>
        <td>Неактивные УЗ (&gt; 60 дней)</td>
        <td>Найдено УЗ: {len(inactive_users)}</td>
        <td class="{"warn" if inactive_error else "ok"}">{html.escape(inactive_error or "OK")}</td>
      </tr>
      <tr>
        <td><code>03_never_expire_passwords.csv</code></td>
        <td>УЗ с флагом PasswordNeverExpires</td>
        <td>Найдено УЗ: {len(never_expire_users)}</td>
        <td class="{"warn" if never_expire_error else "ok"}">{html.escape(never_expire_error or "OK")}</td>
      </tr>
      <tr>
        <td><code>04_exchange_gts_summary.json</code></td>
        <td>Срез безопасности Exchange (overview + forwarding)</td>
        <td>Ошибок: {len(exchange_summary["errors"])}</td>
        <td class="{"warn" if exchange_summary["errors"] else "ok"}">{html.escape(ex_status)}</td>
      </tr>
    </tbody>
  </table>
</body>
</html>
"""

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("00_KPMG_GTS_Summary.html", html_content.encode("utf-8"))
        zf.writestr("01_privileged_groups.csv", priv_csv)
        zf.writestr("02_inactive_users_60d.csv", inactive_csv)
        zf.writestr("03_never_expire_passwords.csv", never_expire_csv)
        zf.writestr("04_exchange_gts_summary.json", exchange_json_bytes)

    return zip_path

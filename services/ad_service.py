import asyncio
import datetime
import hashlib
import ssl
import struct
import threading
from typing import Any, Dict, List, Optional
import ldap3
from ldap3 import ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, Connection, Server
from ldap3.utils.conv import escape_filter_chars

import config
from config import settings
from services.logger_service import get_logger

TZ_LOCAL = datetime.timezone(datetime.timedelta(hours=5))


# --- ЧИСТАЯ РЕАЛИЗАЦИЯ MD4 ДЛЯ PYTHON 3.14+ ---
class PureMD4:
    def __init__(self, data=b''):
        self.buf = bytearray()
        if data:
            self.update(data)

    def update(self, data):
        self.buf.extend(data)

    def digest(self):
        msg = self.buf
        orig_len_in_bits = (len(msg) * 8) & 0xffffffffffffffff
        msg.append(0x80)
        while len(msg) % 64 != 56:
            msg.append(0)
        msg += struct.pack('<Q', orig_len_in_bits)

        A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

        def F(x, y, z): return (x & y) | (~x & z)
        def G(x, y, z): return (x & y) | (x & z) | (y & z)
        def H(x, y, z): return x ^ y ^ z

        def lrot(val, n): return ((val << n) & 0xffffffff) | (val >> (32 - n))

        for i in range(0, len(msg), 64):
            X = list(struct.unpack('<16I', msg[i:i+64]))
            a, b, c, d = A, B, C, D

            # Round 1
            for s, k in zip([3, 7, 11, 19]*4, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]):
                a = lrot((a + F(b, c, d) + X[k]) & 0xffffffff, s)
            for s, k in zip([3, 7, 11, 19]*4, [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]):
                d = lrot((d + F(a, b, c) + X[k]) & 0xffffffff, s)
            for s, k in zip([3, 7, 11, 19]*4, [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]):
                c = lrot((c + F(d, a, b) + X[k]) & 0xffffffff, s)
            for s, k in zip([3, 7, 11, 19]*4, [0, 12, 1, 13, 2, 14, 3, 15, 4, 8, 5, 9, 6, 10, 7, 11]):
                b = lrot((b + F(c, d, a) + X[k]) & 0xffffffff, s)

            # Round 2
            for s, k in zip([3, 5, 9, 13]*4, [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]):
                a = lrot((a + G(b, c, d) + X[k] + 0x5a827999) & 0xffffffff, s)
            for s, k in zip([3, 5, 9, 13]*4, [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]):
                d = lrot((d + G(a, b, c) + X[k] + 0x5a827999) & 0xffffffff, s)
            for s, k in zip([3, 5, 9, 13]*4, [0, 12, 1, 13, 2, 14, 3, 15, 4, 8, 5, 9, 6, 10, 7, 11]):
                c = lrot((c + G(d, a, b) + X[k] + 0x5a827999) & 0xffffffff, s)
            for s, k in zip([3, 5, 9, 13]*4, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]):
                b = lrot((b + G(c, d, a) + X[k] + 0x5a827999) & 0xffffffff, s)

            # Round 3
            for s, k in zip([3, 9, 11, 15]*4, [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]):
                a = lrot((a + H(b, c, d) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            for s, k in zip([3, 9, 11, 15]*4, [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]):
                d = lrot((d + H(a, b, c) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            for s, k in zip([3, 9, 11, 15]*4, [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]):
                c = lrot((c + H(d, a, b) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            for s, k in zip([3, 9, 11, 15]*4, [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]):
                b = lrot((b + H(c, d, a) + X[k] + 0x6ed9eba1) & 0xffffffff, s)

            A = (A + a) & 0xffffffff
            B = (B + b) & 0xffffffff
            C = (C + c) & 0xffffffff
            D = (D + d) & 0xffffffff

        return struct.pack('<4I', A, B, C, D)

    def hexdigest(self):
        return self.digest().hex()


_original_hash_new = hashlib.new


def _patched_hash_new(name, string=b'', *args, **kwargs):
    if name.lower() == 'md4':
        return PureMD4(string)
    return _original_hash_new(name, string, *args, **kwargs)


hashlib.new = _patched_hash_new
# ----------------------------------------------------

log = get_logger("ADService")
logger = log


def _parse_ad_dt(val) -> datetime.datetime | None:
    """Преобразует дату-время из атрибута ldap3 в aware datetime (UTC)."""
    if val is None:
        return None
    if isinstance(val, datetime.datetime):
        if val.year <= 1601:
            return None
        return val if val.tzinfo else val.replace(tzinfo=datetime.timezone.utc)
    s = str(val).strip()
    if not s or s.startswith("1601") or s == "0":
        return None
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.year <= 1601:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)
    except Exception:
        return None


def _fmt_local_dt(val, date_only: bool = False) -> str:
    """Форматирует AD datetime в локальный часовой пояс (UTC+5)."""
    dt = _parse_ad_dt(val)
    if not dt:
        return "—"
    local_dt = dt.astimezone(TZ_LOCAL)
    return local_dt.strftime("%d.%m.%Y" if date_only else "%d.%m.%Y %H:%M")


def _extract_cn(dn: str) -> str:
    for part in str(dn).split(","):
        if part.upper().startswith("CN="):
            return part[3:]
    return str(dn)


def _attr_val(attrs: dict, key: str, default=None):
    val = attrs.get(key, default)
    if isinstance(val, list):
        return val[0] if val else default
    return val if val is not None else default


def datetime_to_ad_filetime(dt: datetime.datetime) -> int:
    """Конвертирует дату в Windows FileTime (100-ns интервалы с 01.01.1601 UTC)."""
    if dt.tzinfo is None:
        dt_local = dt.replace(hour=23, minute=59, second=59, microsecond=0, tzinfo=TZ_LOCAL)
    else:
        dt_local = dt.astimezone(TZ_LOCAL).replace(hour=23, minute=59, second=59, microsecond=0)
    dt_utc = dt_local.astimezone(datetime.timezone.utc)
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return int((dt_utc - epoch).total_seconds() * 10_000_000)


class TauriaADService:
    def __init__(self):
        self.server_ip = settings.AD_SERVER
        self.server_uri = settings.AD_SERVER
        self.domain = settings.AD_DOMAIN
        self.user = settings.AD_USER
        self.password = settings.AD_PASSWORD
        self.search_base = settings.AD_SEARCH_BASE
        self.base_dn = settings.AD_SEARCH_BASE
        self.use_ssl = settings.AD_USE_SSL
        self.disabled_ou = settings.AD_DISABLED_USERS_OU
        self.conn = None
        self._lock = threading.RLock()
        self._max_pwd_age_days: int | None = None
        self.connect()

    def connect(self):
        """Подключение к Active Directory (NTLM -> StartTLS + SIMPLE)."""
        with self._lock:
            try:
                if self.conn:
                    try:
                        self.conn.unbind()
                    except Exception:
                        pass

                server_host = self.server_ip.replace("ldap://", "").replace("ldaps://", "")
                tls_req = ldap3.Tls(validate=ssl.CERT_NONE)
                server = ldap3.Server(
                    server_host,
                    port=636 if self.use_ssl else 389,
                    use_ssl=self.use_ssl,
                    tls=tls_req,
                    get_info=ldap3.ALL,
                )

                user_ntlm = self.user
                if "@" in user_ntlm:
                    user_ntlm = f"{self.domain.split('.')[0].upper()}\\{user_ntlm.split('@')[0]}"
                elif "\\" not in user_ntlm:
                    user_ntlm = f"{self.domain.split('.')[0].upper()}\\{user_ntlm}"

                # 1. Сначала пробуем обычный NTLM
                self.conn = ldap3.Connection(
                    server,
                    user=user_ntlm,
                    password=self.password,
                    authentication=ldap3.NTLM,
                    auto_bind=False,
                )

                if not self.conn.bind():
                    log.warning(f"NTLM bind не прошел ({self.conn.result.get('description')}). Пробуем StartTLS + SIMPLE...")

                    username = self.user.split("\\")[-1] if "\\" in self.user else self.user
                    bind_user = f"{username}@{self.domain}" if "@" not in username else username

                    self.conn = ldap3.Connection(
                        server,
                        user=bind_user,
                        password=self.password,
                        authentication=ldap3.SIMPLE,
                        auto_bind=False,
                    )

                    if not self.use_ssl:
                        try:
                            self.conn.start_tls()
                        except Exception as tls_err:
                            log.error(f"Ошибка активации StartTLS: {tls_err}")

                    if not self.conn.bind():
                        log.error(f"StartTLS + SIMPLE bind также отклонен: {self.conn.result}")
                        self.conn = None
                        return

                log.info("Успешное подключение и авторизация в Active Directory")
            except Exception as e:
                log.error(f"Ошибка подключения к AD: {e}")
                self.conn = None

    def ensure_connection(self):
        """Автоматическое переподключение при отвалившемся сокете."""
        with self._lock:
            if not self.conn or not self.conn.bound or self.conn.closed:
                self.connect()

    def is_connected(self) -> bool:
        """Безопасная проверка активности LDAP-соединения."""
        with self._lock:
            return bool(self.conn and self.conn.bound and not self.conn.closed)

    async def test_connection(self) -> bool:
        loop = asyncio.get_running_loop()

        def _test():
            with self._lock:
                self.ensure_connection()
                return bool(self.conn and self.conn.bound)

        return await loop.run_in_executor(None, _test)

    def _safe_search(self, search_base, search_filter, attributes):
        """Потокобезопасный поиск с реконектом при разорванном сокете."""
        with self._lock:
            self.ensure_connection()
            if not self.conn:
                return False
            try:
                return self.conn.search(
                    search_base=search_base,
                    search_filter=search_filter,
                    attributes=attributes,
                )
            except (ldap3.core.exceptions.LDAPSocketSendError, ldap3.core.exceptions.LDAPCommunicationError):
                log.warning("Сокет AD был разорван. Выполняем переподключение...")
                self.connect()
                if self.conn:
                    return self.conn.search(
                        search_base=search_base,
                        search_filter=search_filter,
                        attributes=attributes,
                    )
            return False

    def _safe_paged_search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str],
        paged_size: int = 500,
    ) -> list[dict]:
        """Постраничный потокобезопасный поиск для обхода лимита AD в 1000 объектов."""
        with self._lock:
            self.ensure_connection()
            if not self.conn:
                return []
            for attempt in range(2):
                try:
                    results = []
                    generator = self.conn.extend.standard.paged_search(
                        search_base=search_base,
                        search_filter=search_filter,
                        search_scope=ldap3.SUBTREE,
                        attributes=attributes,
                        paged_size=paged_size,
                        generator=True,
                    )
                    for item in generator:
                        if item.get("type") == "searchResEntry":
                            results.append(item)
                    return results
                except (ldap3.core.exceptions.LDAPSocketSendError, ldap3.core.exceptions.LDAPCommunicationError):
                    if attempt == 0:
                        log.warning("Сокет AD разорван в paged_search, переподключение...")
                        self.connect()
                        if not self.conn:
                            return []
                    else:
                        return []
                except Exception as e:
                    log.error(f"Ошибка paged_search: {e}")
                    return []
        return []

    def get_max_pwd_age_days(self) -> int:
        """Получает политику домена maxPwdAge (в днях)."""
        if self._max_pwd_age_days is not None:
            return self._max_pwd_age_days
        try:
            with self._lock:
                if self._safe_search(self.base_dn, "(objectClass=domainDNS)", ["maxPwdAge"]) and self.conn.entries:
                    raw_age = self.conn.entries[0].maxPwdAge.value
                    if isinstance(raw_age, datetime.timedelta):
                        days = abs(int(raw_age.total_seconds() // 86400))
                        if days > 0:
                            self._max_pwd_age_days = days
                            return days
                    elif isinstance(raw_age, int) and raw_age != 0:
                        days = abs(int(raw_age)) // (10_000_000 * 86400)
                        if days > 0:
                            self._max_pwd_age_days = days
                            return days
        except Exception as e:
            log.debug(f"Не удалось получить maxPwdAge: {e}")
        self._max_pwd_age_days = 90
        return 90

    # --- ПОИСК И ДЕТАЛИ СОТРУДНИКОВ ---

    def search_users(self, query: str) -> list[dict]:
        """Умный поиск пользователей в AD: ANR + транслитерация (ru<->en) + раскладка + wildcard со статусами УЗ."""
        query_clean = query.strip()
        if not query_clean:
            return []

        en_layout = "`qwertyuiop[]asdfghjkl;'zxcvbnm,./~QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?"
        ru_layout = "ёйцукенгшщзхъфывапролджэячсмитьбю.ЁЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ,"
        en2ru = str.maketrans(en_layout, ru_layout)
        ru2en = str.maketrans(ru_layout, en_layout)

        variants = [query_clean]
        alt_ru = query_clean.translate(en2ru)
        alt_en = query_clean.translate(ru2en)
        if alt_ru != query_clean and alt_ru not in variants:
            variants.append(alt_ru)
        if alt_en != query_clean and alt_en not in variants:
            variants.append(alt_en)

        en_ru_map = {
            "kirill": "Кирилл", "beletskiy": "Белецкий", "alexander": "Александр", "ivan": "Иван",
            "dmitriy": "Дмитрий", "sergey": "Сергей", "mikhail": "Михаил", "andrey": "Андрей",
            "artem": "Артем", "maksim": "Максим", "vladimir": "Владимир", "evgeniy": "Евгений"
        }
        low = query_clean.lower()
        if low in en_ru_map and en_ru_map[low] not in variants:
            variants.append(en_ru_map[low])

        attrs = ['sAMAccountName', 'displayName', 'name', 'department', 'userAccountControl', 'lockoutTime']
        users = []
        seen = set()

        with self._lock:
            for q in variants:
                safe_q = escape_filter_chars(q)
                filter_str = f"(&(objectCategory=person)(objectClass=user)(anr={safe_q}))"
                log.info(f"Выполняем поиск AD через ANR: {filter_str}")
                found_entries = []
                if self._safe_search(self.base_dn, filter_str, attrs):
                    found_entries = list(self.conn.entries)

                if not found_entries:
                    wildcard_filter = f"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*{safe_q}*)(displayName=*{safe_q}*)(mail=*{safe_q}*)))"
                    log.info(f"Пробуем wildcard поиск: {wildcard_filter}")
                    if self._safe_search(self.base_dn, wildcard_filter, attrs):
                        found_entries = list(self.conn.entries)

                for entry in found_entries:
                    if not hasattr(entry, 'sAMAccountName') or not entry.sAMAccountName:
                        continue
                    username = str(entry.sAMAccountName)
                    if username.endswith("$") or username.lower() in seen:
                        continue
                    seen.add(username.lower())

                    if hasattr(entry, 'displayName') and entry.displayName:
                        display_name = str(entry.displayName)
                    elif hasattr(entry, 'name') and entry.name:
                        display_name = str(entry.name)
                    else:
                        display_name = username

                    uac = int(entry.userAccountControl.value) if hasattr(entry, 'userAccountControl') and entry.userAccountControl else 0
                    is_disabled = bool(uac & 2)
                    lt_dt = _parse_ad_dt(entry.lockoutTime.value) if hasattr(entry, 'lockoutTime') and entry.lockoutTime else None
                    is_locked = lt_dt is not None

                    users.append({
                        "username": username,
                        "display_name": display_name,
                        "department": str(entry.department) if hasattr(entry, 'department') and entry.department else "—",
                        "is_disabled": is_disabled,
                        "is_locked": is_locked,
                    })

                if users:
                    break

        log.info(f"Найдено пользователей: {len(users)}")
        return users

    def get_user_details(self, username: str) -> dict | None:
        """Получение расширенной информации о пользователе."""
        safe_username = escape_filter_chars(username)
        filter_str = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_username}))"
        attrs = [
            'sAMAccountName', 'displayName', 'mail', 'department', 'title',
            'telephoneNumber', 'mobile', 'manager', 'company', 'whenCreated',
            'pwdLastSet', 'lastLogonTimestamp', 'badPwdCount', 'lockoutTime',
            'userAccountControl', 'distinguishedName', 'physicalDeliveryOfficeName',
            'scriptPath', 'logonWorkstation', 'memberOf'
        ]

        with self._lock:
            if not self._safe_search(self.base_dn, filter_str, attrs) or not self.conn.entries:
                return None

            entry = self.conn.entries[0]
            uac = int(entry.userAccountControl.value) if entry.userAccountControl else 0
            is_disabled = bool(uac & 2)
            pwd_never_expires = bool(uac & 0x10000)

            manager_raw = str(entry.manager) if hasattr(entry, 'manager') and entry.manager else ""
            manager_name = _extract_cn(manager_raw) if manager_raw else ""

            groups = []
            group_dns = []
            if hasattr(entry, 'memberOf') and entry.memberOf:
                raw_groups = entry.memberOf.values if hasattr(entry.memberOf, 'values') else entry.memberOf
                for g in raw_groups:
                    g_dn = str(g)
                    g_cn = _extract_cn(g_dn)
                    groups.append(g_cn)
                    group_dns.append({"name": g_cn, "dn": g_dn})
            groups.sort(key=str.lower)
            group_dns.sort(key=lambda x: x["name"].lower())

            lt_dt = _parse_ad_dt(entry.lockoutTime.value) if hasattr(entry, 'lockoutTime') and entry.lockoutTime else None
            is_locked = lt_dt is not None

            pwd_dt = _parse_ad_dt(entry.pwdLastSet.value) if hasattr(entry, 'pwdLastSet') and entry.pwdLastSet else None
            pwd_set = _fmt_local_dt(pwd_dt) if pwd_dt else "Требуется смена при входе"

            pwd_expiry_str = "Бессрочный"
            if pwd_never_expires:
                pwd_expiry_str = "Бессрочный (Never Expires)"
            elif pwd_dt:
                max_days = self.get_max_pwd_age_days()
                exp_dt = pwd_dt + datetime.timedelta(days=max_days)
                days_left = (exp_dt - datetime.datetime.now(datetime.timezone.utc)).days
                exp_local = exp_dt.astimezone(TZ_LOCAL).strftime("%d.%m.%Y")
                if days_left < 0:
                    pwd_expiry_str = f"Истек ({exp_local})"
                else:
                    pwd_expiry_str = f"{exp_local} (осталось {days_left} дн.)"

            last_logon = _fmt_local_dt(entry.lastLogonTimestamp.value) if hasattr(entry, 'lastLogonTimestamp') and entry.lastLogonTimestamp else "—"
            created_at = _fmt_local_dt(entry.whenCreated.value, date_only=True) if hasattr(entry, 'whenCreated') and entry.whenCreated else "—"

            return {
                "username": str(entry.sAMAccountName),
                "display_name": str(entry.displayName) if entry.displayName else str(entry.sAMAccountName),
                "mail": str(entry.mail) if entry.mail else "—",
                "department": str(entry.department) if entry.department else "—",
                "title": str(entry.title) if hasattr(entry, 'title') and entry.title else "—",
                "manager_name": manager_name or "—",
                "manager_dn": manager_raw,
                "company": str(entry.company) if hasattr(entry, 'company') and entry.company else 'АО "Банк Развития Казахстана"',
                "telephone_number": str(entry.telephoneNumber) if entry.telephoneNumber else "—",
                "mobile": str(entry.mobile) if hasattr(entry, 'mobile') and entry.mobile else "—",
                "physical_delivery_office_name": str(entry.physicalDeliveryOfficeName) if hasattr(entry, 'physicalDeliveryOfficeName') and entry.physicalDeliveryOfficeName else "—",
                "script_path": str(entry.scriptPath) if hasattr(entry, 'scriptPath') and entry.scriptPath else "—",
                "logon_workstation": str(entry.logonWorkstation) if hasattr(entry, 'logonWorkstation') and entry.logonWorkstation else "—",
                "pwd_last_set": pwd_set,
                "pwd_expiry": pwd_expiry_str,
                "last_logon": last_logon,
                "bad_pwd_count": int(entry.badPwdCount.value) if hasattr(entry, 'badPwdCount') and entry.badPwdCount else 0,
                "created_at": created_at,
                "groups": groups,
                "group_dns": group_dns,
                "uac": uac,
                "is_disabled": is_disabled,
                "is_locked": is_locked,
                "dn": str(entry.entry_dn),
            }

    def reset_password(self, username: str, new_password: str, must_change: bool = True) -> bool:
        """Сброс пароля пользователя в AD с опцией смены при следующем входе (pwdLastSet=0) и разблокировкой."""
        with self._lock:
            details = self.get_user_details(username)
            if not details:
                log.error(f"Пользователь {username} не найден для сброса пароля.")
                return False

            user_dn = details["dn"]
            password_quoted = f'"{new_password}"'
            unicode_password = password_quoted.encode('utf-16-le')

            try:
                if not self.use_ssl and not getattr(self.conn, 'tls_started', False):
                    try:
                        self.conn.start_tls()
                    except Exception:
                        pass

                status = self.conn.modify(user_dn, {'unicodePwd': [(MODIFY_REPLACE, [unicode_password])]})
                if not status:
                    log.error(f"Ошибка AD при сбросе пароля {username}: {self.conn.result['description']} - {self.conn.result.get('message')}")
                    return False

                mods = {}
                if must_change:
                    mods['pwdLastSet'] = [(MODIFY_REPLACE, [0])]
                if details.get("is_locked"):
                    mods['lockoutTime'] = [(MODIFY_REPLACE, [0])]
                if mods:
                    self.conn.modify(user_dn, mods)
                return True
            except Exception as e:
                log.error(f"Исключение при сбросе пароля: {e}")
                return False

    def unlock_user(self, username: str) -> bool:
        """Разблокировка учетной записи."""
        with self._lock:
            details = self.get_user_details(username)
            if not details:
                return False
            try:
                res = self.conn.modify(details["dn"], {'lockoutTime': [(MODIFY_REPLACE, [0])]})
                return bool(res and self.conn.result['result'] == 0)
            except Exception as e:
                log.error(f"Ошибка разблокировки: {e}")
                return False

    async def unlock_user_async(self, username: str) -> bool:
        """Асинхронная обертка над unlock_user."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.unlock_user, username)

    def set_user_enabled(self, username: str, enabled: bool) -> bool:
        """Включает или отключает учетную запись пользователя через userAccountControl."""
        with self._lock:
            details = self.get_user_details(username)
            if not details:
                return False
            uac = int(details.get("uac", 512))
            new_uac = (uac & ~2) if enabled else (uac | 2)
            try:
                res = self.conn.modify(details["dn"], {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})
                if not res:
                    log.error(f"Ошибка изменения статуса УЗ {username}: {self.conn.result}")
                return bool(res and self.conn.result['result'] == 0)
            except Exception as e:
                log.error(f"Исключение set_user_enabled для {username}: {e}")
                return False

    def search_groups(self, query: str, limit: int = 20) -> list[dict]:
        """Поиск групп безопасности AD по имени или CN."""
        safe_q = escape_filter_chars(query.strip())
        filter_str = f"(&(objectClass=group)(|(cn=*{safe_q}*)(name=*{safe_q}*)))"
        with self._lock:
            if not self._safe_search(self.base_dn, filter_str, ['cn', 'name', 'description']):
                return []
            groups = []
            for entry in self.conn.entries:
                name = str(entry.cn) if hasattr(entry, 'cn') and entry.cn else str(entry.name)
                if name.lower() in config.PROTECTED_AD_GROUPS:
                    continue
                groups.append({
                    "name": name,
                    "dn": str(entry.entry_dn),
                    "description": str(entry.description) if hasattr(entry, 'description') and entry.description else "—",
                })
                if len(groups) >= limit:
                    break
            return groups

    def get_group_cn_by_dn(self, group_dn: str) -> str:
        """Возвращает CN группы по её Distinguished Name (с fallback на разбор RDN)."""
        if not group_dn:
            return ""
        if "," not in group_dn and "=" not in group_dn:
            return group_dn.strip()
        with self._lock:
            safe_dn = escape_filter_chars(group_dn)
            if self._safe_search(self.base_dn, f"(&(objectClass=group)(distinguishedName={safe_dn}))", ["cn"]) and self.conn.entries:
                cn_val = getattr(self.conn.entries[0], "cn", None)
                if cn_val and cn_val.value:
                    return str(cn_val.value)
        return _extract_cn(group_dn)

    def move_user(self, user_dn: str, target_ou_dn: str) -> bool:
        """Перемещение пользователя в другое подразделение (OU)."""
        with self._lock:
            self.ensure_connection()
            if not self.conn:
                return False
            try:
                rdn = user_dn.split(',')[0]
                res = self.conn.modify_dn(
                    dn=user_dn,
                    relative_dn=rdn,
                    delete_old_dn=True,
                    new_superior=target_ou_dn
                )
                if not res:
                    log.error(f"Ошибка AD при перемещении: {self.conn.result}")
                    return False
                return True
            except Exception as e:
                log.error(f"Исключение при перемещении пользователя: {e}")
                return False

    def move_user_for_cert(self, username: str, target_ou: str | None = None) -> tuple[bool, str]:
        """
        Перемещение сотрудника в целевой OU для выдачи сертификатов.
        Возвращает (success, original_ou).
        """
        target_ou = target_ou or settings.CERT_USER_OU
        details = self.get_user_details(username)
        if not details:
            return False, ""
        original_ou = ",".join(details["dn"].split(",")[1:])
        success = self.move_user(details["dn"], target_ou)
        return success, original_ou

    def rollback_user_ou(self, username: str, original_ou: str) -> bool:
        """Возврат сотрудника в исходный OU после сертификации."""
        if not original_ou:
            return False
        details = self.get_user_details(username)
        if not details:
            return False
        return self.move_user(details["dn"], original_ou)

    def find_ou_dn_by_name(self, ou_name: str) -> str | None:
        """Поиск DN организационного юнита (OU) по имени."""
        safe_ou_name = escape_filter_chars(ou_name)
        filter_ou = f"(&(objectClass=organizationalUnit)(ou={safe_ou_name}))"
        with self._lock:
            if not self._safe_search(self.base_dn, filter_ou, ['distinguishedName']) or not self.conn.entries:
                filter_name = f"(&(objectClass=organizationalUnit)(name={safe_ou_name}))"
                if not self._safe_search(self.base_dn, filter_name, ['distinguishedName']) or not self.conn.entries:
                    log.error(f"OU '{ou_name}' не найдена в base_dn: {self.base_dn}")
                    return None
            return str(self.conn.entries[0].entry_dn)

    def get_users_in_ou(self, ou_dn: str) -> list[dict]:
        """Возвращает список пользователей, находящихся в указанном подразделении (OU)."""
        if not ou_dn:
            return []
        entries = self._safe_paged_search(
            ou_dn,
            "(&(objectCategory=person)(objectClass=user))",
            ['sAMAccountName', 'displayName', 'department', 'title', 'distinguishedName'],
        )
        users = []
        for item in entries:
            a = item.get("attributes", {})
            uname = str(_attr_val(a, "sAMAccountName", "") or "")
            if not uname or uname.endswith("$"):
                continue
            users.append({
                "username": uname,
                "display_name": str(_attr_val(a, "displayName") or uname),
                "department": str(_attr_val(a, "department") or "—"),
                "title": str(_attr_val(a, "title") or "—"),
                "dn": str(item.get("dn") or ""),
            })
        users.sort(key=lambda x: x["display_name"].lower())
        return users

    # --- КОМПЬЮТЕРЫ ---

    def search_computers(self, query: str) -> list[dict]:
        """Поиск компьютеров в AD."""
        safe_query = escape_filter_chars(query)
        filter_str = f"(&(objectClass=computer)(|(name=*{safe_query}*)(description=*{safe_query}*)))"
        with self._lock:
            if not self._safe_search(self.base_dn, filter_str, ['name', 'description', 'dNSHostName']):
                return []

            computers = []
            for entry in self.conn.entries:
                computers.append({
                    "Name": str(entry.name),
                    "Description": str(entry.description) if entry.description else "Без описания",
                    "DnsName": str(entry.dNSHostName) if hasattr(entry, 'dNSHostName') and entry.dNSHostName else "",
                })
            return computers

    def get_computer_details(self, pc_name: str) -> dict | None:
        """Получение детальной информации о компьютере."""
        safe_pc_name = escape_filter_chars(pc_name)
        filter_str = f"(&(objectClass=computer)(name={safe_pc_name}))"
        attrs = [
            'name', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion',
            'description', 'whenCreated', 'lastLogonTimestamp', 'distinguishedName'
        ]
        with self._lock:
            if not self._safe_search(self.base_dn, filter_str, attrs) or not self.conn.entries:
                return None

            entry = self.conn.entries[0]
            return {
                "name": str(entry.name),
                "dns_name": str(entry.dNSHostName) if entry.dNSHostName else "—",
                "os": str(entry.operatingSystem) if entry.operatingSystem else "—",
                "os_version": str(entry.operatingSystemVersion) if entry.operatingSystemVersion else "",
                "description": str(entry.description) if entry.description else "—",
                "created": _fmt_local_dt(entry.whenCreated.value, date_only=True) if entry.whenCreated else "—",
                "last_logon": _fmt_local_dt(entry.lastLogonTimestamp.value) if hasattr(entry, 'lastLogonTimestamp') and entry.lastLogonTimestamp else "—",
                "dn": str(entry.entry_dn),
            }

    def move_computer(self, pc_name: str, target_ou_dn: str) -> bool:
        """Перемещение компьютера в другое OU."""
        with self._lock:
            details = self.get_computer_details(pc_name)
            if not details:
                return False
            try:
                rdn = f"CN={pc_name}"
                return bool(self.conn.modify_dn(dn=details["dn"], relative_dn=rdn, delete_old_dn=True, new_superior=target_ou_dn))
            except Exception as e:
                log.error(f"Ошибка перемещения ПК: {e}")
                return False

    def delete_computer(self, pc_name: str) -> bool:
        """Удаление учётной записи компьютера из домена."""
        with self._lock:
            details = self.get_computer_details(pc_name)
            if not details:
                return False
            try:
                result = self.conn.delete(details["dn"])
                if not result:
                    log.error(f"Ошибка AD при удалении ПК {pc_name}: {self.conn.result}")
                return bool(result)
            except Exception as e:
                log.error(f"Исключение при удалении ПК {pc_name}: {e}")
                return False

    def get_target_computers(self) -> list[str]:
        """Динамический сбор компьютеров из целевых контейнеров конфига."""
        computers = []
        for ou_dn in settings.target_pc_ous_list:
            entries = self._safe_paged_search(ou_dn, "(&(objectClass=computer))", ['dNSHostName', 'name'])
            for item in entries:
                attrs = item.get("attributes", {})
                dns = _attr_val(attrs, "dNSHostName")
                name = _attr_val(attrs, "name")
                if dns:
                    computers.append(str(dns))
                elif name:
                    computers.append(str(name))
        return list(set(computers))

    def get_stale_computers(self, days: int = 90) -> list[dict]:
        """Компьютеры, не выходившие на связь с доменом более N дней."""
        cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        stale = []
        seen = set()
        for ou_dn in settings.target_pc_ous_list:
            entries = self._safe_paged_search(
                ou_dn,
                "(objectClass=computer)",
                ['name', 'operatingSystem', 'lastLogonTimestamp', 'distinguishedName'],
            )
            for item in entries:
                a = item.get("attributes", {})
                name = str(_attr_val(a, "name", "") or "")
                if not name or name.upper() in seen:
                    continue
                seen.add(name.upper())
                dt = _parse_ad_dt(_attr_val(a, "lastLogonTimestamp"))
                if dt is None or dt < cutoff:
                    days_ago = (datetime.datetime.now(datetime.timezone.utc) - dt).days if dt else 9999
                    stale.append({
                        "name": name,
                        "os": str(_attr_val(a, "operatingSystem") or "—"),
                        "last_logon": _fmt_local_dt(dt, date_only=True) if dt else "Никогда",
                        "days_ago": days_ago,
                        "dn": str(item.get("dn") or ""),
                    })
        stale.sort(key=lambda x: x["days_ago"], reverse=True)
        return stale

    def get_domain_stats(self) -> dict | None:
        """Точная постраничная статистика по пользователям (без компьютеров) и ПК домена."""
        try:
            user_entries = self._safe_paged_search(
                self.base_dn,
                "(&(objectCategory=person)(objectClass=user))",
                ['sAMAccountName', 'userAccountControl', 'lockoutTime'],
            )
            total_users = len(user_entries)
            disabled_users = 0
            locked_users = 0
            for item in user_entries:
                attrs = item.get("attributes", {})
                uac = int(_attr_val(attrs, "userAccountControl", 0) or 0)
                is_dis = bool(uac & 2)
                if is_dis:
                    disabled_users += 1
                else:
                    lt = _parse_ad_dt(_attr_val(attrs, "lockoutTime"))
                    if lt is not None:
                        locked_users += 1
            active_users = total_users - disabled_users

            pc_entries = self._safe_paged_search(
                self.base_dn,
                "(objectClass=computer)",
                ['name', 'lastLogonTimestamp'],
            )
            total_computers = len(pc_entries)
            cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)
            stale_computers = 0
            for item in pc_entries:
                attrs = item.get("attributes", {})
                dt = _parse_ad_dt(_attr_val(attrs, "lastLogonTimestamp"))
                if dt is None or dt < cutoff:
                    stale_computers += 1

            return {
                "total_users": total_users,
                "active_users": active_users,
                "disabled_users": disabled_users,
                "locked_users": locked_users,
                "total_computers": total_computers,
                "stale_computers": stale_computers,
            }
        except Exception as e:
            log.error(f"Ошибка получения статистики: {e}")
            return None

    def get_user_photo(self, username: str) -> bytes | None:
        """Получение фото пользователя из AD (thumbnailPhoto)."""
        safe_username = escape_filter_chars(username)
        filter_str = f"(&(objectCategory=person)(objectClass=user)(sAMAccountName={safe_username}))"
        with self._lock:
            if not self._safe_search(self.base_dn, filter_str, ['thumbnailPhoto']):
                return None
            if not self.conn.entries or not hasattr(self.conn.entries[0], 'thumbnailPhoto'):
                return None
            photo_data = self.conn.entries[0].thumbnailPhoto.value
            return photo_data if photo_data else None

    # --- МЕТОДЫ ДЛЯ СУПЕРАДМИН-ФУНКЦИЙ TAURIA ---

    def get_locked_users_sync(self) -> List[Dict[str, Any]]:
        """Синхронный поиск всех заблокированных активных учетных записей (lockoutTime > 0)."""
        search_filter = (
            "(&(objectCategory=person)(objectClass=user)"
            "(lockoutTime>=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        attributes = ["sAMAccountName", "displayName", "lockoutTime", "mail", "department", "title", "badPwdCount"]
        entries = self._safe_paged_search(self.base_dn, search_filter, attributes)
        results = []
        for item in entries:
            a = item.get("attributes", {})
            lt_dt = _parse_ad_dt(_attr_val(a, "lockoutTime"))
            if not lt_dt:
                continue
            uname = str(_attr_val(a, "sAMAccountName", "") or "")
            if not uname:
                continue
            disp = str(_attr_val(a, "displayName") or uname)
            results.append({
                "username": uname,
                "name": disp,
                "display_name": disp,
                "lockout_time": _fmt_local_dt(lt_dt),
                "lockout_ts": lt_dt.timestamp(),
                "mail": str(_attr_val(a, "mail") or "—"),
                "department": str(_attr_val(a, "department") or "—"),
                "title": str(_attr_val(a, "title") or "—"),
                "bad_pwd_count": int(_attr_val(a, "badPwdCount", 0) or 0),
                "dn": str(item.get("dn") or ""),
            })
        results.sort(key=lambda x: x["lockout_ts"], reverse=True)
        return results

    async def get_locked_users(self) -> List[Dict[str, Any]]:
        """Поиск всех заблокированных активных учетных записей (lockoutTime > 0)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.get_locked_users_sync)

    async def get_user_groups(self, username: str) -> List[str]:
        """Получение списка групп пользователя."""
        loop = asyncio.get_running_loop()

        def _get():
            with self._lock:
                safe_username = escape_filter_chars(username)
                if not self._safe_search(self.base_dn, f"(&(objectCategory=person)(sAMAccountName={safe_username}))", ["memberOf"]):
                    return []
                if not self.conn.entries:
                    return []
                member_of = self.conn.entries[0].memberOf.values if self.conn.entries[0].memberOf else []
                groups = []
                for dn in member_of:
                    parts = str(dn).split(",")
                    for p in parts:
                        if p.upper().startswith("CN="):
                            groups.append(p[3:])
                            break
                return sorted(groups)

        return await loop.run_in_executor(None, _get)

    def add_user_to_group_sync(self, username: str, group_name_or_dn: str, enforce_protected: bool = False) -> tuple[bool, str]:
        """Синхронное добавление пользователя в группу по CN или DN."""
        group_cn = _extract_cn(group_name_or_dn).lower()
        if enforce_protected and group_cn in config.PROTECTED_AD_GROUPS:
            return False, "Изменение привилегированной группы запрещено политикой безопасности бота."
        with self._lock:
            safe_user = escape_filter_chars(username)
            if not self._safe_search(self.base_dn, f"(&(objectCategory=person)(sAMAccountName={safe_user}))", ["distinguishedName"]) or not self.conn.entries:
                return False, "Пользователь не найден в AD."
            user_dn = str(self.conn.entries[0].entry_dn)

            if "=" in group_name_or_dn and "," in group_name_or_dn:
                group_dn = group_name_or_dn
            else:
                safe_group = escape_filter_chars(group_name_or_dn)
                if not self._safe_search(self.base_dn, f"(&(objectCategory=group)(cn={safe_group}))", ["distinguishedName"]) or not self.conn.entries:
                    return False, "Группа не найдена в AD."
                group_dn = str(self.conn.entries[0].entry_dn)

            try:
                res = self.conn.modify(group_dn, {'member': [(MODIFY_ADD, [user_dn])]})
                if res:
                    return True, "ok"
                desc = self.conn.result.get("description", "error")
                if desc in ("entryAlreadyExists", "attributeOrValueExists"):
                    return True, "Пользователь уже состоит в этой группе."
                return False, f"Ошибка AD: {desc}"
            except Exception as e:
                return False, str(e)

    def remove_user_from_group_sync(self, username: str, group_name_or_dn: str, enforce_protected: bool = False) -> tuple[bool, str]:
        """Синхронное удаление пользователя из группы по CN или DN."""
        group_cn = _extract_cn(group_name_or_dn).lower()
        if enforce_protected and group_cn in config.PROTECTED_AD_GROUPS:
            return False, "Изменение привилегированной группы запрещено политикой безопасности бота."
        with self._lock:
            safe_user = escape_filter_chars(username)
            if not self._safe_search(self.base_dn, f"(&(objectCategory=person)(sAMAccountName={safe_user}))", ["distinguishedName"]) or not self.conn.entries:
                return False, "Пользователь не найден в AD."
            user_dn = str(self.conn.entries[0].entry_dn)

            if "=" in group_name_or_dn and "," in group_name_or_dn:
                group_dn = group_name_or_dn
            else:
                safe_group = escape_filter_chars(group_name_or_dn)
                if not self._safe_search(self.base_dn, f"(&(objectCategory=group)(cn={safe_group}))", ["distinguishedName"]) or not self.conn.entries:
                    return False, "Группа не найдена в AD."
                group_dn = str(self.conn.entries[0].entry_dn)

            try:
                res = self.conn.modify(group_dn, {'member': [(MODIFY_DELETE, [user_dn])]})
                if res:
                    return True, "ok"
                return False, f"Ошибка AD: {self.conn.result.get('description', 'error')}"
            except Exception as e:
                return False, str(e)

    async def add_user_to_group(self, username: str, group_name: str) -> bool:
        """Добавление пользователя в группу безопасности (асинхронно)."""
        loop = asyncio.get_running_loop()
        ok, _ = await loop.run_in_executor(None, self.add_user_to_group_sync, username, group_name, False)
        return ok

    async def remove_user_from_group(self, username: str, group_name: str) -> bool:
        """Удаление пользователя из группы (асинхронно)."""
        loop = asyncio.get_running_loop()
        ok, _ = await loop.run_in_executor(None, self.remove_user_from_group_sync, username, group_name, False)
        return ok

    async def offboard_user(self, username: str, offboarded_by: int | None = None) -> Dict[str, Any]:
        """
        Процедура полного увольнения (Offboarding):
        1. Отключение аккаунта (userAccountControl bit 2 = ACCOUNTDISABLE)
        2. Очистка описания / добавление отметки [TERMINATED]
        3. Перемещение в Disabled OU (если настроено)
        4. Сохранение снапшота в БД
        """
        from services.db_service import save_offboard_snapshot

        loop = asyncio.get_running_loop()

        def _offboard():
            with self._lock:
                safe_user = escape_filter_chars(username)
                if not self._safe_search(
                    self.base_dn,
                    f"(&(objectCategory=person)(sAMAccountName={safe_user}))",
                    ["distinguishedName", "userAccountControl", "description", "memberOf"]
                ):
                    return {"success": False, "error": "Ошибка поиска в AD"}

                if not self.conn.entries:
                    return {"success": False, "error": "Пользователь не найден"}

                entry = self.conn.entries[0]
                user_dn = str(entry.entry_dn)
                raw_groups = list(entry.memberOf.values) if hasattr(entry, "memberOf") and entry.memberOf else []
                groups = []
                for g_dn in raw_groups:
                    first_rdn = str(g_dn).split(",")[0]
                    if "=" in first_rdn:
                        groups.append(first_rdn.split("=", 1)[1])
                    else:
                        groups.append(first_rdn)

                uac = int(entry.userAccountControl.value or 512)
                new_uac = uac | 2

                self.conn.modify(user_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})

                old_desc = str(entry.description or "")
                new_desc = old_desc if "[TERMINATED]" in old_desc else f"[TERMINATED] {old_desc}".strip()
                self.conn.modify(user_dn, {'description': [(MODIFY_REPLACE, [new_desc])]})

                moved = False
                if self.disabled_ou and self.disabled_ou.lower() not in user_dn.lower():
                    try:
                        rdn = user_dn.split(",")[0]
                        if self.conn.modify_dn(user_dn, rdn, new_superior=self.disabled_ou):
                            moved = True
                    except Exception as ex:
                        log.warning(f"Could not move user to {self.disabled_ou}: {ex}")

                return {
                    "success": True,
                    "disabled": True,
                    "moved": moved,
                    "user": username,
                    "_snapshot_dn": user_dn,
                    "_snapshot_groups": groups,
                }

        res = await loop.run_in_executor(None, _offboard)
        if res.get("success"):
            await save_offboard_snapshot(
                username=username,
                dn=res.pop("_snapshot_dn", None),
                groups=res.pop("_snapshot_groups", []),
                offboarded_by=offboarded_by,
            )
        return res

    async def disable_user(self, username: str) -> bool:
        """Отключение учетной записи (ACCOUNTDISABLE, bit 2)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.set_user_enabled, username, False)

    async def set_user_password(self, username: str, new_password: str) -> bool:
        """Установка нового пароля для пользователя (unicodePwd)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.reset_password, username, new_password, False)

    async def rollback_offboard(self, username: str) -> dict:
        """Откат увольнения: восстановление учетки, description, OU и групп из последнего снапшота."""
        from services.db_service import get_offboard_snapshots, mark_snapshot_restored

        snapshots = await get_offboard_snapshots(username)
        pending = [s for s in snapshots if not s.get("restored")]
        if not pending:
            return {"success": False, "error": "Не найден не восстановленный снапшот увольнения"}

        snapshot = pending[0]
        snapshot_id = snapshot["id"]
        orig_dn = snapshot.get("dn", "")
        orig_ou = ",".join(orig_dn.split(",")[1:]) if "," in orig_dn else ""
        groups = snapshot.get("groups") or []

        loop = asyncio.get_running_loop()

        def _restore_ad():
            with self._lock:
                safe_user = escape_filter_chars(username)
                if not self._safe_search(
                    self.base_dn,
                    f"(&(objectCategory=person)(sAMAccountName={safe_user}))",
                    ["distinguishedName", "userAccountControl", "description"]
                ):
                    return {"success": False, "error": "Ошибка поиска в AD"}

                if not self.conn.entries:
                    return {"success": False, "error": "Пользователь не найден в AD"}

                entry = self.conn.entries[0]
                current_dn = str(entry.entry_dn)
                uac = int(entry.userAccountControl.value or 514)
                new_uac = uac & ~2  # Убираем ACCOUNTDISABLE (0x0002)
                self.conn.modify(current_dn, {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]})

                old_desc = str(entry.description or "")
                new_desc = old_desc.replace("[TERMINATED]", "").strip()
                self.conn.modify(current_dn, {'description': [(MODIFY_REPLACE, [new_desc])]})

                moved = False
                if orig_ou:
                    current_parent = ",".join(current_dn.split(",")[1:])
                    if current_parent.lower() != orig_ou.lower():
                        try:
                            rdn = current_dn.split(",")[0]
                            if self.conn.modify_dn(current_dn, rdn, new_superior=orig_ou):
                                moved = True
                        except Exception as ex:
                            log.warning(f"Could not move user {username} back to {orig_ou}: {ex}")

                return {"success": True, "moved": moved}

        ad_res = await loop.run_in_executor(None, _restore_ad)
        if not ad_res.get("success"):
            return ad_res

        restored_groups = []
        failed_groups = []
        for grp in groups:
            if await self.add_user_to_group(username, grp):
                restored_groups.append(grp)
            else:
                failed_groups.append(grp)

        await mark_snapshot_restored(snapshot_id)

        return {
            "success": True,
            "user": username,
            "snapshot_id": snapshot_id,
            "moved": ad_res.get("moved", False),
            "restored_groups": restored_groups,
            "failed_groups": failed_groups,
        }

    async def inspect_privileged_groups(self) -> dict:
        """
        Оптимизированная инспекция привилегированных групп AD без N+1 LDAP-запросов:
        1) Одним запросом получает список привилегированных групп и их member DN.
        2) Одним пакетным запросом (|(distinguishedName=...)) разрешает все уникальные DN в sAMAccountName.
        """
        target_groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "VPN_Users"]
        loop = asyncio.get_running_loop()

        def _inspect():
            with self._lock:
                groups_result: Dict[str, List[str]] = {g: [] for g in target_groups}
                group_clauses = "".join(f"(cn={escape_filter_chars(g)})" for g in target_groups)
                group_filter = f"(&(objectCategory=group)(|{group_clauses}))"

                if not self._safe_search(self.base_dn, group_filter, ["cn", "member"]):
                    return {"success": False, "error": "Ошибка поиска привилегированных групп в AD", "groups": groups_result}

                group_members_map: Dict[str, List[str]] = {}
                unique_member_dns: set[str] = set()

                for entry in self.conn.entries:
                    cn_val = str(entry.cn.value) if hasattr(entry, "cn") and entry.cn else ""
                    matched_key = next((g for g in target_groups if g.lower() == cn_val.lower()), cn_val)
                    members_dn = [str(m) for m in (entry.member.values if hasattr(entry, "member") and entry.member else [])]
                    group_members_map[matched_key] = members_dn
                    unique_member_dns.update(members_dn)

                dn_to_sam: Dict[str, str] = {}
                if unique_member_dns:
                    dn_list = list(unique_member_dns)
                    chunk_size = 80
                    for i in range(0, len(dn_list), chunk_size):
                        chunk = dn_list[i:i + chunk_size]
                        or_filter = "(|" + "".join(f"(distinguishedName={escape_filter_chars(dn)})" for dn in chunk) + ")"
                        if self._safe_search(self.base_dn, or_filter, ["distinguishedName", "sAMAccountName"]):
                            for u_entry in self.conn.entries:
                                dn_str = str(u_entry.entry_dn).lower()
                                sam_str = str(u_entry.sAMAccountName.value or "") if hasattr(u_entry, "sAMAccountName") and u_entry.sAMAccountName else ""
                                if sam_str:
                                    dn_to_sam[dn_str] = sam_str

                for grp in target_groups:
                    members_dn = group_members_map.get(grp, [])
                    resolved = []
                    for m_dn in members_dn:
                        sam = dn_to_sam.get(m_dn.lower()) or _extract_cn(m_dn)
                        if sam:
                            resolved.append(sam)
                    groups_result[grp] = sorted(resolved, key=str.lower)

                return {"success": True, "groups": groups_result}

        return await loop.run_in_executor(None, _inspect)

    def get_expiring_passwords_sync(self, days: int = 7) -> list[dict]:
        """Синхронный постраничный поиск активных сотрудников с истекающим сроком пароля."""
        max_days = self.get_max_pwd_age_days()
        filter_str = (
            "(&(objectCategory=person)(objectClass=user)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=65536)))"
        )
        attrs = ['sAMAccountName', 'displayName', 'department', 'pwdLastSet']
        entries = self._safe_paged_search(self.base_dn, filter_str, attrs)
        now = datetime.datetime.now(datetime.timezone.utc)
        expiring = []
        for item in entries:
            a = item.get("attributes", {})
            uname = str(_attr_val(a, "sAMAccountName", "") or "")
            if not uname or uname.lower().startswith(("krbtgt", "guest", "default", "iusr", "tsinternet")):
                continue
            pwd_dt = _parse_ad_dt(_attr_val(a, "pwdLastSet"))
            if not pwd_dt:
                continue
            exp_dt = pwd_dt + datetime.timedelta(days=max_days)
            days_left = (exp_dt - now).days
            if -30 <= days_left <= days:
                expiring.append({
                    "username": uname,
                    "display_name": str(_attr_val(a, "displayName") or uname),
                    "department": str(_attr_val(a, "department") or "—"),
                    "days_left": days_left,
                    "expires_at": exp_dt.astimezone(TZ_LOCAL).strftime("%d.%m.%Y"),
                })
        expiring.sort(key=lambda x: x["days_left"])
        return expiring

    get_expiring_passwords = get_expiring_passwords_sync

    async def get_expiring_password_users(self, days: int = 7) -> dict:
        """Поиск активных пользователей AD с истекающим сроком действия пароля."""
        loop = asyncio.get_running_loop()
        users = await loop.run_in_executor(None, self.get_expiring_passwords_sync, days)
        return {"success": True, "users": users}

    async def get_inactive_users(self, days: int = 60) -> list[dict]:
        """Поиск активных пользователей, у которых lastLogonTimestamp старше N дней."""
        from datetime import datetime as dt_cls, timedelta

        loop = asyncio.get_running_loop()

        def _query():
            cutoff_dt = dt_cls.utcnow() - timedelta(days=days)
            filetime_epoch = dt_cls(1601, 1, 1)
            cutoff_ft = int((cutoff_dt - filetime_epoch).total_seconds() * 10_000_000)

            search_filter = (
                f"(&(objectCategory=person)(objectClass=user)"
                f"(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                f"(lastLogonTimestamp<={cutoff_ft}))"
            )
            entries = self._safe_paged_search(
                self.base_dn,
                search_filter,
                ["sAMAccountName", "displayName", "department", "lastLogonTimestamp", "distinguishedName"]
            )
            results = []
            for item in entries:
                a = item.get("attributes", {})
                uname = str(_attr_val(a, "sAMAccountName") or "")
                if not uname:
                    continue
                results.append({
                    "username": uname,
                    "display_name": str(_attr_val(a, "displayName") or uname),
                    "department": str(_attr_val(a, "department") or ""),
                    "last_logon": _fmt_local_dt(_attr_val(a, "lastLogonTimestamp")),
                    "dn": str(item.get("dn") or ""),
                })
            return results

        return await loop.run_in_executor(None, _query)

    async def get_never_expire_password_users(self) -> list[dict]:
        """Поиск активных пользователей с флагом DONT_EXPIRE_PASSWORD (65536)."""
        loop = asyncio.get_running_loop()

        def _query():
            search_filter = (
                "(&(objectCategory=person)(objectClass=user)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                "(userAccountControl:1.2.840.113556.1.4.803:=65536))"
            )
            entries = self._safe_paged_search(
                self.base_dn,
                search_filter,
                ["sAMAccountName", "displayName", "department", "userAccountControl", "distinguishedName"]
            )
            results = []
            for item in entries:
                a = item.get("attributes", {})
                uname = str(_attr_val(a, "sAMAccountName") or "")
                if not uname:
                    continue
                results.append({
                    "username": uname,
                    "display_name": str(_attr_val(a, "displayName") or uname),
                    "department": str(_attr_val(a, "department") or ""),
                    "dn": str(item.get("dn") or ""),
                })
            return results

        return await loop.run_in_executor(None, _query)

    async def create_ad_user(
        self,
        full_name: str,
        username: str,
        password: str,
        ou_dn: str,
        department: str = "",
        title: str = "",
        description: str = "",
        groups: list[str] | None = None,
        account_expires_dt: datetime.datetime | None = None,
    ) -> dict:
        """Создание нового пользователя в AD, установка пароля, включение учетки и добавление в группы."""
        loop = asyncio.get_running_loop()

        def _create():
            with self._lock:
                self.ensure_connection()
                if not self.conn:
                    return {"success": False, "error": "Нет подключения к AD"}

                # 1. Подбор свободного sAMAccountName
                base_username = username.strip()
                actual_username = base_username
                suffix = 2
                while True:
                    safe_u = escape_filter_chars(actual_username)
                    if self._safe_search(self.base_dn, f"(sAMAccountName={safe_u})", ["sAMAccountName"]) and self.conn.entries:
                        actual_username = f"{base_username[:18]}{suffix}"
                        suffix += 1
                    else:
                        break

                # 2. Проверка существования целевого OU (с fallback)
                target_ou = ou_dn
                ou_candidates = [
                    ou_dn,
                    f"OU=KDB Users,{self.base_dn}",
                    f"CN=Users,{self.base_dn}",
                ]
                for cand_ou in ou_candidates:
                    if not cand_ou:
                        continue
                    try:
                        if self.conn.search(search_base=cand_ou, search_filter="(objectClass=*)", search_scope=ldap3.BASE, attributes=["distinguishedName"]):
                            target_ou = cand_ou
                            break
                    except Exception:
                        continue

                user_dn = f"CN={full_name},{target_ou}"
                parts = full_name.strip().split()
                if len(parts) >= 2:
                    sn = parts[0]
                    given_name = " ".join(parts[1:])
                elif parts:
                    given_name = parts[0]
                    sn = ""
                else:
                    given_name = full_name
                    sn = ""

                attrs = {
                    "sAMAccountName": actual_username,
                    "userPrincipalName": f"{actual_username}@{self.domain}" if getattr(self, "domain", None) else actual_username,
                    "displayName": full_name,
                    "givenName": given_name,
                    "userAccountControl": 514,  # Disabled initially until password is set
                }
                if sn:
                    attrs["sn"] = sn
                if department:
                    attrs["department"] = department
                if title:
                    attrs["title"] = title
                if description:
                    attrs["description"] = description
                if account_expires_dt is not None:
                    filetime = datetime_to_ad_filetime(account_expires_dt)
                    attrs["accountExpires"] = str(filetime)

                created = self.conn.add(
                    user_dn,
                    ["top", "person", "organizationalPerson", "user"],
                    attrs,
                )
                if not created:
                    return {"success": False, "error": f"Ошибка создания в AD: {self.conn.result}"}

                if not self.reset_password(actual_username, password, must_change=True):
                    return {"success": False, "error": "Пользователь создан, но не удалось установить пароль"}

                enabled = self.conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})
                if not enabled:
                    return {"success": False, "error": f"Пароль установлен, но не удалось включить учетку: {self.conn.result}"}

                return {"success": True, "dn": user_dn, "username": actual_username}

        res = await loop.run_in_executor(None, _create)
        if not res.get("success"):
            return res

        actual_username = res.get("username", username)
        added_groups = []
        failed_groups = []
        for grp in (groups or []):
            if await self.add_user_to_group(actual_username, grp):
                added_groups.append(grp)
            else:
                failed_groups.append(grp)

        res["added_groups"] = added_groups
        res["failed_groups"] = failed_groups
        return res

    def get_computer_laps_password(self, pc_name: str) -> dict:
        """Возвращает LAPS-пароль и срок его действия для компьютера из AD."""
        safe_pc = escape_filter_chars(pc_name.strip())
        search_filter = f"(&(objectCategory=computer)(|(cn={safe_pc})(sAMAccountName={safe_pc}$)))"
        attrs = ["cn", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "msLAPS-Password"]

        with self._lock:
            self.ensure_connection()
            entries = self._safe_search(self.base_dn, search_filter, attrs)

        if not entries:
            return {"ok": False, "error": "Компьютер не найден в AD"}

        entry = entries[0]
        entry_attrs = entry.entry_attributes_as_dict
        cn = str(_attr_val(entry_attrs, "cn", pc_name))
        pwd = _attr_val(entry_attrs, "ms-Mcs-AdmPwd") or _attr_val(entry_attrs, "msLAPS-Password")
        if not pwd:
            return {"ok": False, "error": "LAPS-пароль не задан или нет прав чтения ms-Mcs-AdmPwd"}

        exp_raw = _attr_val(entry_attrs, "ms-Mcs-AdmPwdExpirationTime")
        exp_str = "—"
        if exp_raw is not None:
            try:
                ft = int(exp_raw)
                if ft > 0:
                    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
                    dt_utc = epoch + datetime.timedelta(microseconds=ft // 10)
                    exp_str = dt_utc.astimezone(TZ_LOCAL).strftime("%d.%m.%Y %H:%M")
            except Exception:
                pass

        return {"ok": True, "pc_name": cn, "password": str(pwd), "expires": exp_str}


ad_service = TauriaADService()

import asyncio
import secrets
import string
from datetime import datetime
from typing import Dict, Any, List

from config import settings
from services.logger_service import log
from services.ad_service import ad_service
from services.db_service import log_audit_action, save_offboard_snapshot


class SecurityService:
    @staticmethod
    def generate_secure_password(length: int = 32) -> str:
        """Генерирует криптостойкий пароль заданной длины, удовлетворяющий политикам сложности AD."""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}<>?"
        chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+[]{}<>?"),
        ]
        chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
        system_random = secrets.SystemRandom()
        system_random.shuffle(chars)
        return "".join(chars)

    async def emergency_kill_switch(self, username: str, admin_id: int) -> Dict[str, Any]:
        """
        Тревожная кнопка / Изоляция учетной записи (Emergency Kill Switch):
        - Сохраняет снапшот исходного DN и всех групп пользователя в БД (save_offboard_snapshot).
        - Отключает аккаунт в AD (ACCOUNTDISABLE) и ставит отметку [TERMINATED] в description.
        - Генерирует случайный криптостойкий пароль (32 символа) и перезаписывает его в AD.
        - Удаляет пользователя из всех VPN групп (любые группы, содержащие 'vpn' в названии).
        - Перемещает учетную запись в карантинный контейнер settings.AD_DISABLED_USERS_OU (если задан).
        - Логирует действие в audit_logs со статусом EMERGENCY_ISOLATION.
        """
        start_time = datetime.utcnow()
        log.warning(f"🚨 EMERGENCY KILL SWITCH triggered for user '{username}' by admin {admin_id}")

        results: Dict[str, Any] = {
            "success": False,
            "username": username,
            "admin_id": admin_id,
            "account_disabled": False,
            "password_reset": False,
            "moved": False,
            "vpn_groups_removed": [],
            "vpn_groups_failed": [],
            "status": "FAILED",
            "error": None,
            "started_at": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "completed_at": None,
            "duration_sec": 0.0,
        }

        try:
            # 0. Получаем текущие данные пользователя и сохраняем снапшот для возможного отката
            details = await asyncio.to_thread(ad_service.get_user_details, username)
            if not details:
                raise RuntimeError(f"Пользователь '{username}' не найден в Active Directory")

            orig_dn = details.get("dn", "")
            user_groups = details.get("groups") or await ad_service.get_user_groups(username)

            await save_offboard_snapshot(
                username=username,
                dn=orig_dn,
                groups=list(user_groups),
                offboarded_by=admin_id,
            )

            # 1. Отключаем учетную запись в AD (+ метка [TERMINATED] и перемещение в AD_DISABLED_USERS_OU)
            offboard_res = await ad_service.offboard_user(username, offboarded_by=admin_id)
            disabled = bool(offboard_res.get("disabled")) or await ad_service.disable_user(username)
            results["account_disabled"] = disabled
            results["moved"] = bool(offboard_res.get("moved", False))
            if not disabled:
                raise RuntimeError(f"Не удалось отключить аккаунт '{username}' в AD")

            # Если offboard_user еще не переместил, но задан AD_DISABLED_USERS_OU — пробуем переместить явно
            if not results["moved"] and settings.AD_DISABLED_USERS_OU and orig_dn:
                if settings.AD_DISABLED_USERS_OU.lower() not in orig_dn.lower():
                    moved_ok = await asyncio.to_thread(
                        ad_service.move_user, orig_dn, settings.AD_DISABLED_USERS_OU
                    )
                    results["moved"] = bool(moved_ok)

            # 2. Генерируем случайный криптостойкий пароль и перезаписываем его
            new_password = self.generate_secure_password(32)
            pwd_reset = await ad_service.set_user_password(username, new_password)
            results["password_reset"] = pwd_reset
            if not pwd_reset:
                log.warning(f"Failed to reset password for user '{username}' during kill-switch")

            # 3. Удаляем из всех VPN групп
            vpn_groups = [g for g in user_groups if "vpn" in g.lower()]
            for vpn_group in vpn_groups:
                removed = await ad_service.remove_user_from_group(username, vpn_group)
                if removed:
                    results["vpn_groups_removed"].append(vpn_group)
                else:
                    results["vpn_groups_failed"].append(vpn_group)

            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            results["completed_at"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
            results["duration_sec"] = duration
            results["status"] = "SUCCESS" if (disabled and (not results["vpn_groups_failed"])) else "PARTIAL"
            results["success"] = results["status"] in ("SUCCESS", "PARTIAL")

            details_str = (
                f"Account disabled: {results['account_disabled']}; "
                f"Password reset: {results['password_reset']}; "
                f"Moved to Disabled OU: {results['moved']}; "
                f"VPN groups removed: {results['vpn_groups_removed']}; "
                f"VPN groups failed: {results['vpn_groups_failed']}; "
                f"Duration: {duration:.2f}s"
            )
            await log_audit_action(
                admin_id=admin_id,
                admin_username="SuperAdmin",
                action="EMERGENCY_KILL_SWITCH",
                target=username,
                status="EMERGENCY_ISOLATION",
                details=details_str,
            )

            log.info(f"Emergency kill switch completed for '{username}' in {duration:.2f}s. Status: {results['status']}")
            return results

        except Exception as e:
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            results["completed_at"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
            results["duration_sec"] = duration
            results["error"] = str(e)
            results["status"] = "ERROR"
            results["success"] = False

            await log_audit_action(
                admin_id=admin_id,
                admin_username="SuperAdmin",
                action="EMERGENCY_KILL_SWITCH",
                target=username,
                status="EMERGENCY_ISOLATION",
                details=f"FAILED: {e}",
            )
            log.error(f"Error during emergency kill switch for '{username}': {e}", exc_info=True)
            return results


security_service = SecurityService()


async def emergency_kill_switch(username: str, admin_id: int) -> Dict[str, Any]:
    return await security_service.emergency_kill_switch(username, admin_id)

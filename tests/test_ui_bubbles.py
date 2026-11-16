"""Unit tests for HTML bubble rendering, tag balance, escaping, and inline keyboards."""

from __future__ import annotations

import re

from drivemap.config import Settings
from drivemap.keyboards.inline import (
    access_direct_users_keyboard,
    access_members_keyboard,
    access_result_keyboard,
    access_share_keyboard,
    access_user_grant_keyboard,
    audit_keyboard,
    confirm_map_keyboard,
    confirm_unmap_keyboard,
    letters_keyboard,
    main_menu_keyboard,
    map_result_keyboard,
    shares_keyboard,
    user_mappings_keyboard,
    users_keyboard,
)
from drivemap.models import (
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
from drivemap.ui import (
    banner_bubble,
    filter_shares_by_category,
    list_bubble,
    render_access_direct_users,
    render_access_group_members,
    render_access_result,
    render_access_share_view,
    render_access_user_grant,
    render_access_user_prompt,
    render_audit_screen,
    render_confirm_step,
    render_letter_step,
    render_main_menu,
    render_map_result,
    render_overwrite_step,
    render_share_step,
    render_share_users_screen,
    render_unmap_confirm,
    render_user_drives_screen,
    render_user_prompt,
    render_user_search_screen,
)

BLOCKQUOTE_TOKEN_RE = re.compile(r"<blockquote(?:\s+expandable)?>|</blockquote>")


def _assert_valid_telegram_bubbles(text: str) -> None:
    assert len(text) <= 4096, f"Message too long for Telegram: {len(text)}"
    depth = 0
    for m in BLOCKQUOTE_TOKEN_RE.finditer(text):
        tok = m.group(0)
        if tok.startswith("<blockquote"):
            depth += 1
            assert depth == 1, f"Nested blockquote forbidden by Telegram API: {text}"
        else:
            depth -= 1
            assert depth >= 0, f"Unmatched closing blockquote: {text}"
    assert depth == 0, f"Unclosed blockquote tag: {text}"


def _assert_callback_data_limits(markup) -> None:
    for row in markup.inline_keyboard:
        for btn in row:
            assert btn.text
            if btn.callback_data is not None:
                assert len(btn.callback_data.encode("utf-8")) <= 64


def test_all_bubble_screens_balanced_and_escaped() -> None:
    settings = Settings(_env_file=None, bot_token="123456:ABCDEF_fake_test_token", allowed_tg_user_ids="100000001")
    xss_user = ADUser(
        sam_account_name="bad<user>",
        display_name="Test <script> & User",
        distinguished_name="CN=Test,OU=IT&Security,OU=Users,DC=corp,DC=example,DC=com",
        sid="S-1-5-21-1-2-3-999",
    )
    share = ShareInfo(
        server="FS01",
        share_name="BI$",
        unc_path=r"\\FS01\BI$<tag>",
        label="BI & <Analytics>",
        suggested_letter="M",
        source="BOTH",
    )
    eff = [
        EffectiveMapping("M", r"\\FS01\BI$", "BI", "U", "DOM-CFG-MapNetworkDrives", "GLOBAL", False, "{1}"),
        EffectiveMapping("G", r"\\FS01\Share<1>", "Share", "U", "USR-CFG-DriveMaps-PerUser-U", "PER_USER", True, "{2}"),
    ]
    matrix = [
        LetterChoice("C", "PROTECTED"),
        LetterChoice("G", "FREE"),
        LetterChoice("M", "CONFLICT_GLOBAL", r"\\FS01\BI$", "DOM-CFG-MapNetworkDrives"),
        LetterChoice("J", "MAPPED_PER_USER", r"\\FS01\Transfer$", "USR-CFG-DriveMaps-PerUser-U"),
    ]
    res = MutationResult("tx_1", "MAP", False, "bad<user>", xss_user.sid, share.unc_path, "G", share.label, 1, 2)
    rec = AuditRecord("tx_1", "2026-11-11T12:00:00Z", 100000001, "admin", "MAP", "bad<user>", xss_user.sid, share.unc_path, "G", share.label, 1, 2, "/tmp/b", "SUCCESS")

    screens = [
        render_main_menu(settings, banner_html=banner_bubble("ok", "Обновлено")),
        render_share_step([share], total_catalog=10, server_filter="PRIMARY", query="<q>", primary_label="FS01"),
        render_user_prompt(share, query="<xss>", users=[xss_user]),
        render_letter_step(share, xss_user, eff, matrix, "G"),
        render_overwrite_step(xss_user, share, "J", r"\\FS01\Transfer$"),
        render_confirm_step(settings, xss_user, share, "G", overwrite=True),
        render_map_result(xss_user, res),
        render_user_search_screen(query="<q>", users=[xss_user]),
        render_user_drives_screen(xss_user, eff, banner_html=banner_bubble("dry", "Test")),
        render_unmap_confirm(xss_user, eff[1], is_delete_marker=False),
        render_unmap_confirm(xss_user, eff[1], is_delete_marker=True),
        render_share_users_screen(share.unc_path, [("USR-CFG-DriveMaps-PerUser-U", "G", "CORP\\bad<user>", xss_user.sid)]),
        render_audit_screen([rec], banner_html=banner_bubble("info", "Audit")),
    ]

    for s in screens:
        _assert_valid_telegram_bubbles(s)
        assert "<script>" not in s
        assert "<tag>" not in s

    assert "<FilterUser>" not in render_share_users_screen(share.unc_path, [])

    markups = [
        main_menu_keyboard(dry_run=True),
        shares_keyboard([share], page=0, prefix="sh", server_filter="PRIMARY", has_query=True, primary_label="FS01"),
        users_keyboard([xss_user], page=0, prefix="usr", back_callback="usr:back_share"),
        letters_keyboard(matrix, "G"),
        confirm_map_keyboard(),
        map_result_keyboard(),
        user_mappings_keyboard(eff, username="jdoe"),
        confirm_unmap_keyboard(1, is_delete_marker=False),
        confirm_unmap_keyboard(1, is_delete_marker=True),
        audit_keyboard([rec]),
    ]
    for kb in markups:
        _assert_callback_data_limits(kb)


def test_list_bubble_auto_expands_and_truncates_safely() -> None:
    many = [f"<code>{chr(65 + (i % 26))}:</code> → <code>\\\\FS01\\Share_{i}_Long_Name_{'x' * 40}</code>" for i in range(80)]
    rendered = list_bubble(many, title="Большой список", expandable_after=5, max_chars=900)
    assert rendered.startswith("<blockquote expandable>")
    assert "… и ещё" in rendered
    _assert_valid_telegram_bubbles(rendered)


def test_filter_shares_by_category() -> None:
    items = [
        ShareInfo("FS01", "BI$", r"\\FS01\BI$", "BI", "M", "BOTH"),
        ShareInfo("FS01", "NewShare", r"\\FS01\NewShare", "NewShare", "", "SMB"),
        ShareInfo("FS02", "stat", r"\\FS02\stat", "stat", "", "SMB"),
        ShareInfo("NAS01", "FileServer", r"\\NAS01\FileServer", "FileServer", "S", "GPO"),
    ]
    assert len(filter_shares_by_category(items, "ALL")) == 4
    assert [s.share_name for s in filter_shares_by_category(items, "PRIMARY", primary_server="FS01")] == ["BI$", "NewShare"]
    assert [s.share_name for s in filter_shares_by_category(items, "GPO")] == ["BI$", "FileServer"]
    assert [s.share_name for s in filter_shares_by_category(items, "OTHER", primary_server="FS01")] == ["stat", "FileServer"]


def test_access_manager_bubbles_and_keyboards() -> None:
    settings = Settings(_env_file=None, bot_token="123456:ABCDEFGHIJKLMNOP", allowed_tg_user_ids="100000001", dry_run=True)
    xss_user = ADUser(
        sam_account_name="bad<user>",
        display_name="User <X>",
        distinguished_name="CN=User,OU=IT,OU=Users,DC=corp,DC=example,DC=com",
        sid="S-1-5-21-100-200-300-1001",
    )
    share = ShareInfo("FS01", "Help<Dir>", r"\\FS01\Help<Dir>", "Help", "W", "SMB")
    ro_grp = ADGroup("Share_Help_RO", "CN=Share_Help_RO,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com", "S-1-5-21-1-2-3-501", member_dns=(xss_user.distinguished_name,))
    rw_grp = ADGroup("Share_Help_RW", "CN=Share_Help_RW,OU=ShareAccess,OU=Groups,OU=Users,DC=corp,DC=example,DC=com", "S-1-5-21-1-2-3-502")
    acl_entry = ShareAclEntry(
        sid=xss_user.sid,
        principal_name="CORP\\bad<user>",
        display_name="User <X>",
        principal_type="USER",
        level=ACCESS_RO,
        is_inherited=False,
    )
    report = ShareAccessReport(
        unc_path=share.unc_path,
        readable=True,
        entries=(acl_entry,),
        ro_group=ro_grp,
        rw_group=rw_grp,
    )
    unreadable_report = ShareAccessReport(unc_path=share.unc_path, readable=False, error="ACCESS_<DENIED>")
    status = UserShareAccessStatus(
        user=xss_user,
        unc_path=share.unc_path,
        effective_level=ACCESS_RW,
        sources=("Прямой NTFS: RO", "Группа <Share> (RW)"),
        direct_level=ACCESS_RO,
        can_revoke_direct=True,
        member_of_manageable_groups=(ro_grp.distinguished_name,),
        blocked_by_protected_group=True,
    )
    res_map = MutationResult("tx_m", "MAP", True, "bad<user>", xss_user.sid, share.unc_path, "W", share.label, 1, 2)
    res_acl = AccessMutationResult(
        tx_id="tx_a",
        operation="ACCESS_GRANT_AD",
        dry_run=False,
        target_user="bad<user>",
        target_sid=xss_user.sid,
        unc_path=share.unc_path,
        level=ACCESS_RW,
        mechanism="AD_GROUP",
        group_name="Share_<RW>",
        requires_relogon=True,
        truncated_propagation=True,
        propagated_objects=2500,
        message="Права <выданы>",
    )
    acl_audit = AuditRecord(
        "tx_a", "2026-11-11T12:00:00Z", 100000001, "admin", "ACCESS_GRANT_NTFS",
        "bad<user>", xss_user.sid, share.unc_path, ACCESS_RW, "NTFS", 0, 0, "/tmp/acl_b", "SUCCESS"
    )

    screens = [
        render_confirm_step(settings, xss_user, share, "W", False, access_status=status, access_choice=ACCESS_RO, has_agdlp_ro=True),
        render_map_result(xss_user, res_map, access_res=res_acl, access_error="<err>"),
        render_access_share_view(report, banner_html=banner_bubble("ok", "OK")),
        render_access_share_view(unreadable_report),
        render_access_user_prompt(share.unc_path, query="<q>", users=[xss_user]),
        render_access_user_grant("CORP", share.unc_path, status, report),
        render_access_group_members(share.unc_path, ro_grp, ACCESS_RO, [xss_user]),
        render_access_direct_users(share.unc_path, [acl_entry]),
        render_access_result(res_acl, display_name=xss_user.display_name),
        render_audit_screen([acl_audit]),
    ]
    for s in screens:
        _assert_valid_telegram_bubbles(s)
        assert "<X>" not in s
        assert "<Dir>" not in s
        assert "<user>" not in s

    audit_rendered = render_audit_screen([acl_audit])
    assert "<code>RW:</code>" not in audit_rendered
    assert "<code>RW</code>" in audit_rendered

    markups = [
        confirm_map_keyboard(access_choice=ACCESS_RW),
        access_share_keyboard(report),
        access_user_grant_keyboard(status, report),
        access_members_keyboard([xss_user], page=0),
        access_direct_users_keyboard([acl_entry], page=0),
        access_result_keyboard(),
        audit_keyboard([acl_audit]),
    ]
    for kb in markups:
        _assert_callback_data_limits(kb)

"""Unit tests for binary Windows SD/DACL encoding, decoding, and canonical ACL sorting."""

from __future__ import annotations

from smbprotocol.security_descriptor import AceFlags, SDControl

from drivemap.models import ACCESS_FULL, ACCESS_NONE, ACCESS_RO, ACCESS_RW
from drivemap.services.ad_ldap import bytes_to_sid_str, sid_str_to_bytes
from drivemap.services.smb_acl import (
    RIGHT_FULL_CONTROL,
    RIGHT_MODIFY,
    RIGHT_READ_EXECUTE,
    build_dacl_only_sd_bytes,
    classify_access_mask,
    decode_sd_bytes,
    mutate_dacl_bytes,
    split_unc_share,
)


def test_sid_string_bytes_roundtrip() -> None:
    for sid in [
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-21-1000000001-2000000002-3000000003-1001",
    ]:
        raw = sid_str_to_bytes(sid)
        assert bytes_to_sid_str(raw) == sid


def test_split_unc_share() -> None:
    assert split_unc_share(r"\\FS01\HelpDesk") == ("FS01", r"\\FS01\HelpDesk", "")
    assert split_unc_share(r"\\FS01\Transfer$\Sub") == ("FS01", r"\\FS01\Transfer$", "Sub")


def test_classify_access_mask() -> None:
    assert classify_access_mask(RIGHT_READ_EXECUTE) == ACCESS_RO
    assert classify_access_mask(RIGHT_MODIFY) == ACCESS_RW
    assert classify_access_mask(RIGHT_FULL_CONTROL) == ACCESS_FULL
    assert classify_access_mask(0x80000000 | 0x20000000) == ACCESS_RO  # GENERIC_READ | GENERIC_EXECUTE
    assert classify_access_mask(0x10000000) == ACCESS_FULL  # GENERIC_ALL
    assert classify_access_mask(0x00120089) == ACCESS_RO  # Read without Execute+Synchronize bit variations
    assert classify_access_mask(0x00020000) == "CUSTOM"  # READ_CONTROL only


def test_mutate_dacl_add_upgrade_remove_and_canonical_order() -> None:
    admin_sid = "S-1-5-32-544"
    user_sid = "S-1-5-21-100-200-300-1101"

    base_sd = build_dacl_only_sd_bytes([], SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT)
    # Add inherited-looking Admin FULL and direct user RO
    sd1, ch1 = mutate_dacl_bytes(base_sd, admin_sid, ACCESS_FULL, inherited_mode=True)
    assert ch1 is True
    sd2, ch2 = mutate_dacl_bytes(sd1, user_sid, ACCESS_RO, inherited_mode=False)
    assert ch2 is True

    # Idempotent re-apply returns changed=False
    _, ch_same = mutate_dacl_bytes(sd2, user_sid, ACCESS_RO, inherited_mode=False)
    assert ch_same is False

    dec2 = decode_sd_bytes(sd2)
    assert len(dec2.aces) == 2
    # Canonical order: explicit ACE comes BEFORE inherited ACE
    assert dec2.aces[0].sid == user_sid
    assert dec2.aces[0].level == ACCESS_RO
    assert dec2.aces[0].is_inherited is False
    assert dec2.aces[1].sid == admin_sid
    assert dec2.aces[1].level == ACCESS_FULL
    assert dec2.aces[1].is_inherited is True

    # Upgrade explicit user to RW (no duplicate user ACE)
    sd3, ch3 = mutate_dacl_bytes(sd2, user_sid, ACCESS_RW, inherited_mode=False)
    assert ch3 is True
    dec3 = decode_sd_bytes(sd3)
    user_aces = [a for a in dec3.aces if a.sid == user_sid]
    assert len(user_aces) == 1
    assert user_aces[0].level == ACCESS_RW

    # Revoke explicit user ACE while preserving inherited Admin ACE
    sd4, ch4 = mutate_dacl_bytes(sd3, user_sid, ACCESS_NONE, inherited_mode=False)
    assert ch4 is True
    dec4 = decode_sd_bytes(sd4)
    assert [a.sid for a in dec4.aces] == [admin_sid]

    # Idempotent revoke
    _, ch5 = mutate_dacl_bytes(sd4, user_sid, ACCESS_NONE, inherited_mode=False)
    assert ch5 is False


def test_mutate_preserves_dacl_protected_and_explicit_deny_first() -> None:
    from smbprotocol.security_descriptor import AccessDeniedAce, SIDPacket

    user_a = "S-1-5-21-100-200-300-10"
    user_b = "S-1-5-21-100-200-300-20"

    deny = AccessDeniedAce()
    sid_b = SIDPacket()
    sid_b.from_string(user_b)
    deny["ace_flags"].set_value(AceFlags.OBJECT_INHERIT_ACE | AceFlags.CONTAINER_INHERIT_ACE)
    deny["mask"].set_value(RIGHT_MODIFY)
    deny["sid"] = sid_b

    base = build_dacl_only_sd_bytes(
        [deny],
        SDControl.SELF_RELATIVE | SDControl.DACL_PRESENT | SDControl.DACL_PROTECTED,
    )
    sd_next, changed = mutate_dacl_bytes(base, user_a, ACCESS_RO)
    assert changed is True
    dec = decode_sd_bytes(sd_next)
    assert bool(dec.control & SDControl.DACL_PROTECTED) is True
    # Explicit DENY must remain ordered BEFORE explicit ALLOW per MS-DTYP
    assert dec.aces[0].is_deny is True
    assert dec.aces[0].sid == user_b
    assert dec.aces[1].is_deny is False
    assert dec.aces[1].sid == user_a

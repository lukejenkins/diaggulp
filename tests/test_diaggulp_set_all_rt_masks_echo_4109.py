"""SET_ALL_RT_MASKS reply must be INSPECTED, not trusted non-None.

`_enable_ext_msg_f3` printed "enabled ..." on any non-None response and never
read the body, so a firmware that CLAMPED or REJECTED the requested F3 mask was
indistinguishable in the capture log from one that accepted it. The reply is
`05 <status> 00 <u32 echoed mask>` (measured on a live EG25-G / MDM9607), so the
echoed u32 tells you what the firmware actually stored. These pin: the parser on
the real observed bytes, the truncation guard, and the caller warning on an echo
mismatch instead of claiming success.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


class _ReplyClient:
    """DiagClient stand-in returning a fixed (op, body) reply."""

    def __init__(self, body: bytes):
        self._body = body
        self.sent: list[tuple[int, bytes]] = []

    def _send_recv(self, cmd_code, payload, timeout=None):
        self.sent.append((cmd_code, payload))
        return (d.DIAG_EXT_MSG_CONFIG_F, self._body)


# ── the parser, on the issue's real observed replies ────────────────────────
def test_parse_reply_recovers_echoed_mask_le():
    # SET_ALL 0x0000001F replied 05 01 00 1f000000
    sub, status, echoed = d.parse_set_all_rt_masks_reply(bytes.fromhex("0501001f000000"))
    assert sub == d.EXT_MSG_SET_ALL_RT_MASKS
    assert status == 1
    assert echoed == 0x0000001F


def test_parse_reply_full_mask():
    sub, status, echoed = d.parse_set_all_rt_masks_reply(bytes.fromhex("050100ffffffff"))
    assert echoed == 0xFFFFFFFF and status == 1


def test_parse_reply_bit19_mask():
    # SET_ALL 0x00080000 replied 05 01 00 00000800
    _, _, echoed = d.parse_set_all_rt_masks_reply(bytes.fromhex("05010000000800"))
    assert echoed == 0x00080000


def test_truncated_reply_is_None_not_a_confirmed_zero():
    # A reply cut short by F3 saturating the port must NOT read as "mask = 0".
    assert d.parse_set_all_rt_masks_reply(b"\x05\x01\x00") is None


def test_wrong_subcommand_echo_is_None():
    assert d.parse_set_all_rt_masks_reply(bytes.fromhex("0201002f000000")) is None


# ── the caller inspects the reply ───────────────────────────────────────────
def test_matching_echo_confirms_without_warning(capsys):
    c = _ReplyClient(bytes.fromhex("050100ffffffff"))  # echoes 0xFFFFFFFF
    d._enable_ext_msg_f3(c, 0xFFFFFFFF)
    err = capsys.readouterr().err
    assert "echo 0xFFFFFFFF confirmed" in err
    assert "WARNING" not in err


def test_clamped_echo_warns_instead_of_claiming_success(capsys):
    # Request 0x0000001F, firmware echoes a DIFFERENT value (0x00000003) — a clamp.
    c = _ReplyClient(b"\x05\x01\x00" + (0x00000003).to_bytes(4, "little"))
    d._enable_ext_msg_f3(c, 0x0000001F)
    err = capsys.readouterr().err
    assert "WARNING" in err and "CLAMPED or REJECTED" in err
    assert "0x0000001F" in err and "0x00000003" in err


def test_unparseable_reply_warns_unconfirmed(capsys):
    c = _ReplyClient(b"\x13")  # BAD_CMD-shaped stub, not a SET_ALL echo
    d._enable_ext_msg_f3(c, 0xFFFFFFFF)
    err = capsys.readouterr().err
    assert "WARNING" in err and "UNCONFIRMED" in err


def test_request_bytes_still_correct(capsys):
    """The fix must not disturb the request it sends — only how the reply is read."""
    c = _ReplyClient(b"\x05\x01\x00" + (0xFFFFFFFF).to_bytes(4, "little"))
    d._enable_ext_msg_f3(c, 0xFFFFFFFF)
    cmd, payload = c.sent[0]
    assert cmd == d.DIAG_EXT_MSG_CONFIG_F
    assert payload == d.build_ext_msg_config_set_all_rt_masks_request(0xFFFFFFFF)

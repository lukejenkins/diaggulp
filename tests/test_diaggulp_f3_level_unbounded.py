"""--ext-msg-f3-level must apply on the UNBOUNDED (working) F3 path.

Before the fix, ``--ext-msg-f3-level`` was consumed only by the bounded SSID path
(``_enable_ext_msg_f3_bounded``), which is documented inert on SDX55.
The unbounded default path — ``_enable_ext_msg_f3`` — hardcoded
``build_ext_msg_config_set_all_rt_masks_request()`` with no arg (0xFFFFFFFF),
so a user running ``diaggulp --ext-msg-f3 --ext-msg-f3-level error`` (no ``-ss``)
got the FULL F3 surface while believing they floored it. On SDX55-class parts
the two conditions *"the floor takes effect"* and *"F3 actually flows"* were
mutually exclusive via the CLI.

These tests pin the fix's wire behaviour: the level threads into the unbounded
``SET_ALL_RT_MASKS`` request. The all-levels default stays byte-identical so no
existing capture changes.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


class _RecordingClient:
    """Minimal DiagClient stand-in that records the last _send_recv payload."""

    def __init__(self):
        self.sent: list[tuple[int, bytes]] = []

    def _send_recv(self, cmd_code, payload, timeout=None):
        self.sent.append((cmd_code, payload))
        # Non-None so _enable_ext_msg_f3 doesn't raise on "timeout".
        return (cmd_code, b"\x05\x00\x00\x00\x00\x00\x00\x00")


def test_default_is_byte_identical_to_all_levels():
    """No-arg call must still emit the 0xFFFFFFFF SET_ALL_RT_MASKS request."""
    c = _RecordingClient()
    d._enable_ext_msg_f3(c)
    assert len(c.sent) == 1
    cmd, payload = c.sent[0]
    assert cmd == d.DIAG_EXT_MSG_CONFIG_F
    assert payload == d.build_ext_msg_config_set_all_rt_masks_request(0xFFFFFFFF)


def test_level_mask_threads_into_unbounded_request():
    """A reduced level mask must reach the SET_ALL_RT_MASKS request bytes."""
    c = _RecordingClient()
    error_mask = d._f3_set_all_level_mask("error")
    d._enable_ext_msg_f3(c, error_mask)
    assert len(c.sent) == 1
    _, payload = c.sent[0]
    assert payload == d.build_ext_msg_config_set_all_rt_masks_request(error_mask)
    # The regression this guards: it must NOT be the all-levels default.
    assert payload != d.build_ext_msg_config_set_all_rt_masks_request(0xFFFFFFFF)


def test_set_all_floor_matches_celldiag_verified_values():
    """SET_ALL floor mask = "all bits on, clear below floor" — the celldiag form
    hardware-verified on the LM960A18/SDX20, NOT _f3_level_mask's
    set-only-defined-bits form.
    """
    assert d._f3_set_all_level_mask("all") == 0xFFFFFFFF
    assert d._f3_set_all_level_mask("high") == 0xFFFFFFFC   # clears low|med
    assert d._f3_set_all_level_mask("error") == 0xFFFFFFF8  # clears low|med|high
    assert d._f3_set_all_level_mask("fatal") == 0xFFFFFFF0  # clears low..error
    # This is the load-bearing distinction from the bounded-path encoding:
    assert d._f3_set_all_level_mask("error") != d._f3_level_mask("error")


def test_error_floor_encodes_expected_u32():
    """The unbounded request's u32 level field equals the celldiag error mask."""
    from struct import unpack_from

    c = _RecordingClient()
    d._enable_ext_msg_f3(c, d._f3_set_all_level_mask("error"))
    _, payload = c.sent[0]
    # payload: sub_cmd(1) + 2 pad + u32 level
    assert payload[0] == d.EXT_MSG_SET_ALL_RT_MASKS
    assert unpack_from("<I", payload, 3)[0] == 0xFFFFFFF8
    assert 0xFFFFFFF8 != 0xFFFFFFFF


def test_set_all_floor_rejects_unknown_level():
    import pytest
    with pytest.raises(ValueError):
        d._f3_set_all_level_mask("bogus")

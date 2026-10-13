"""``--ext-msg-f3-level-mask`` arms an ARBITRARY F3 runtime mask.

Why a raw mask, when ``--ext-msg-f3-level`` already exists: the named
levels only ever move bits 0-4, the chipset's five ``MSG_LVL_*`` bits. Measured
on a live EG25-G (MDM9607, ``EG25GGBR07A08M2G_01.003.01.003``) the dominant F3
plane does not live there at all — 86% of the capture's frames are ``0x92``
``DIAG_QSR_EXT_MSG_TERSE_F``, and their ``ss_mask`` sits on ``MSG_MASK_15/16/19/
21/22`` (bit 19 alone is 42.6%). So ``--ext-msg-f3-level error`` (0xFFFFFFF8,
clearing bits 0-2) removes 98.7% of the frames whose mask lies *entirely* in
bits 0-2 — and only 1.0% of everything else, i.e. **15% of total volume**. The
flag reads as "quiet capture" and on this class of part it is nearly inert.

A raw mask is what lets a capture bound (or silence) the plane that actually
dominates, and it is what made the leg-2 arming ladder measurable at all:
``0xFFFFFFFF`` / ``0xFFFFFFF8`` / ``0x0000001F`` / ``0x00000000``.

⚠️ The load-bearing case is ``0``. ``--ext-msg-f3-level-mask 0`` is *commanded
silence* — a SET_ALL_RT_MASKS request carrying level 0 — which is a different
thing from ``--no-ext-msg-f3``, where no request is sent at all and the modem
keeps whatever mask a previous run left armed. That is the "omitting is
not clearing" lesson on the F3 mask instead of the log mask. A ``if raw:``
falsy-zero check turns the one into the other silently, so the zero case is
pinned explicitly here.
"""
from __future__ import annotations

import sys
from pathlib import Path
from struct import unpack_from

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


class _RecordingClient:
    """Minimal DiagClient stand-in that records every _send_recv payload."""

    def __init__(self):
        self.sent: list[tuple[int, bytes]] = []

    def _send_recv(self, cmd_code, payload, timeout=None):
        self.sent.append((cmd_code, payload))
        return (cmd_code, b"\x05\x00\x00\x00\x00\x00\x00\x00")


# --- the resolver ---------------------------------------------------------

def test_no_raw_mask_falls_back_to_the_named_level():
    """Back-compat: with no raw mask the named level decides, byte-identically."""
    for level in ("all", "high", "error", "fatal"):
        assert d._resolve_set_all_mask(level, None) == d._f3_set_all_level_mask(level)


def test_raw_mask_overrides_the_named_level():
    """An explicit mask wins over --ext-msg-f3-level, including its default."""
    assert d._resolve_set_all_mask("all", 0x0000001F) == 0x0000001F
    assert d._resolve_set_all_mask("error", 0x00080000) == 0x00080000


def test_raw_mask_of_zero_is_honoured_not_treated_as_absent():
    """⚠️ The falsy-zero trap: 0 means SILENCE, never "fall back to default".

    ``0`` is the one mask a ``if raw_mask:`` guard would swallow, and it is
    precisely the commanded-silence arm that makes an arming experiment a
    measurement rather than an inference.
    """
    assert d._resolve_set_all_mask("all", 0) == 0
    assert d._resolve_set_all_mask("all", 0) != d._f3_set_all_level_mask("all")


def test_raw_mask_rejects_values_outside_u32():
    """The wire field is a u32; a wider value must fail loudly, not truncate."""
    with pytest.raises(ValueError):
        d._resolve_set_all_mask("all", -1)
    with pytest.raises(ValueError):
        d._resolve_set_all_mask("all", 0x1_0000_0000)
    # The boundary itself is legal.
    assert d._resolve_set_all_mask("all", 0xFFFFFFFF) == 0xFFFFFFFF


def test_unknown_named_level_still_raises_when_no_raw_mask():
    """The raw path must not smuggle a bad level through unvalidated."""
    with pytest.raises(ValueError):
        d._resolve_set_all_mask("bogus", None)


# --- the wire ------------------------------------------------------------

def test_raw_mask_reaches_the_set_all_rt_masks_request_bytes():
    c = _RecordingClient()
    d._enable_ext_msg_f3(c, d._resolve_set_all_mask("all", 0x0000001F))
    assert len(c.sent) == 1
    cmd, payload = c.sent[0]
    assert cmd == d.DIAG_EXT_MSG_CONFIG_F
    assert payload[0] == d.EXT_MSG_SET_ALL_RT_MASKS
    assert unpack_from("<I", payload, 3)[0] == 0x0000001F


def test_zero_mask_still_SENDS_a_request():
    """Commanded silence is an emitted frame — not a skipped arming step.

    ``--no-ext-msg-f3`` sends nothing and leaves a previous run's mask armed;
    ``--ext-msg-f3-level-mask 0`` must actively set the runtime mask to 0.
    """
    c = _RecordingClient()
    d._enable_ext_msg_f3(c, d._resolve_set_all_mask("all", 0))
    assert len(c.sent) == 1
    _, payload = c.sent[0]
    assert unpack_from("<I", payload, 3)[0] == 0


# --- "a raw mask implies arming" -----------------------------------------

def test_raw_mask_implies_arming_even_with_no_ext_msg_f3():
    """``--no-ext-msg-f3 --ext-msg-f3-level-mask X`` must still arm X.

    Otherwise the pair parses cleanly, prints nothing and arms nothing — the
    same silent-no-op shape as an earlier bug, where the level reached a code path that
    never ran. ``--ext-msg-f3-ss`` already implies arming; this matches it.
    """
    assert _d_should_arm(ext_msg_f3=False, raw_mask=0x00080000) is True
    # ...including the zero mask, which is a real request (commanded silence).
    assert _d_should_arm(ext_msg_f3=False, raw_mask=0) is True


def test_no_raw_mask_leaves_the_ext_msg_f3_flag_in_charge():
    assert _d_should_arm(ext_msg_f3=True, raw_mask=None) is True
    assert _d_should_arm(ext_msg_f3=False, raw_mask=None) is False


def _d_should_arm(*, ext_msg_f3, raw_mask):
    return d._should_arm_unbounded_f3(ext_msg_f3, raw_mask)


# --- the bounded path ----------------------------------------------------

def test_raw_mask_also_overrides_the_bounded_path_encoding():
    """A raw mask is literal on BOTH paths — it is not re-encoded per path.

    The two paths otherwise use different encodings (``_f3_level_mask`` sets
    only the defined level bits; ``_f3_set_all_level_mask`` clears below the
    floor). An explicit mask means "arm exactly these bits", so neither
    encoding may reinterpret it.
    """
    raw = 0x00080000
    assert d._resolve_set_all_mask("error", raw) == raw
    assert raw != d._f3_level_mask("error")
    assert raw != d._f3_set_all_level_mask("error")


# --- plan -> wire, the seam main() actually uses -------------------------
#
# The mutation pass found this uncovered: hardcoding EXT_MSG_ALL_LEVELS at the
# arming call SURVIVED every test above, because the args->_enable_ext_msg_f3
# wiring lived inline in main() and no test drove it. That is exactly the earlier
# defect (a level that reaches a request nothing sends). These pin the seam.


class _Args:
    """Stand-in for the argparse namespace the arming plan reads."""

    def __init__(self, **kw):
        self.ext_msg_f3 = kw.get("ext_msg_f3", True)
        self.ext_msg_f3_ss = kw.get("ext_msg_f3_ss")
        self.ext_msg_f3_preset = kw.get("ext_msg_f3_preset")
        self.ext_msg_f3_level = kw.get("ext_msg_f3_level", "all")
        self.ext_msg_f3_level_mask = kw.get("ext_msg_f3_level_mask")


def _set_all_payload(client):
    """The SET_ALL_RT_MASKS request the arm sent.

    ⚠️ Not ``client.sent[0]``: every arm first READS the
    runtime mask it is about to destroy (DIAG_EXT_MSG_CONFIG_F sub_cmd 3), so
    the arm is no longer the first request on the wire. Selecting by sub_cmd is
    also the more honest assertion — it pins *the request that arms*, not a
    position in a sequence.
    """
    armed = [pl for _op, pl in client.sent if pl and pl[0] == d.EXT_MSG_SET_ALL_RT_MASKS]
    assert len(armed) == 1, f"expected exactly one SET_ALL_RT_MASKS, got {len(armed)}"
    return armed[0]


def test_plan_carries_the_raw_mask_to_the_unbounded_wire():
    plan = d._plan_f3_arming(_Args(ext_msg_f3_level_mask=0x00080000))
    assert plan.mode == "unbounded"
    assert plan.rt_mask == 0x00080000
    c = _RecordingClient()
    d._apply_f3_arming(c, plan)
    payload = _set_all_payload(c)
    assert unpack_from("<I", payload, 3)[0] == 0x00080000


def test_plan_carries_the_named_level_to_the_unbounded_wire():
    """The regression itself: the level must reach the request bytes."""
    plan = d._plan_f3_arming(_Args(ext_msg_f3_level="error"))
    c = _RecordingClient()
    d._apply_f3_arming(c, plan)
    payload = _set_all_payload(c)
    assert unpack_from("<I", payload, 3)[0] == 0xFFFFFFF8
    assert unpack_from("<I", payload, 3)[0] != d.EXT_MSG_ALL_LEVELS


def test_plan_carries_a_zero_mask_to_the_wire():
    plan = d._plan_f3_arming(_Args(ext_msg_f3_level_mask=0))
    c = _RecordingClient()
    d._apply_f3_arming(c, plan)
    payload = _set_all_payload(c)
    assert unpack_from("<I", payload, 3)[0] == 0


def test_plan_is_none_when_arming_is_declined_and_sends_nothing():
    plan = d._plan_f3_arming(_Args(ext_msg_f3=False))
    assert plan.mode == "none"
    c = _RecordingClient()
    d._apply_f3_arming(c, plan)
    assert c.sent == []


def test_bounded_ss_takes_precedence_over_the_unbounded_arm():
    plan = d._plan_f3_arming(_Args(ext_msg_f3_ss=[1007, 3001]))
    assert plan.mode == "bounded"
    assert plan.bounded_ss == (1007, 3001)


def test_reconnect_rearm_raises_instead_of_warning():
    """warn_only=False must propagate, so slurp() retries the re-open.

    A reconnect that swallows an arming failure leaves the new client capturing
    an unarmed stream for the rest of the run.
    """
    class _Failing:
        def _send_recv(self, *a, **kw):
            return None          # -> _enable_ext_msg_f3 raises RuntimeError

    plan = d._plan_f3_arming(_Args())
    with pytest.raises(RuntimeError):
        d._apply_f3_arming(_Failing(), plan, warn_only=False)
    # ...and the initial arm still degrades to a warning rather than aborting.
    d._apply_f3_arming(_Failing(), plan, warn_only=True)


# --- the CLI -------------------------------------------------------------

def test_cli_accepts_hex_and_decimal_mask_values():
    """The flag's ``type=`` takes both spellings a mask is naturally written in."""
    assert d._parse_int_arg("0x80000") == 0x80000
    assert d._parse_int_arg("31") == 31
    assert d._parse_int_arg("0") == 0


def test_cli_exposes_the_flag():
    """The flag is actually wired into the real parser, not just the resolver.

    Driven through the CLI's own ``--help`` rather than a extracted parser
    object: ``main()`` builds its parser inline, and pulling ~400 lines of
    ``add_argument`` out of it is a refactor this change does not need.
    """
    import subprocess

    out = subprocess.run(
        [sys.executable, str(Path(d.__file__)), "--help"],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "--ext-msg-f3-level-mask" in out.stdout
    # The named-level flag must survive alongside it — this is additive.
    assert "--ext-msg-f3-level " in out.stdout or "--ext-msg-f3-level\n" in out.stdout

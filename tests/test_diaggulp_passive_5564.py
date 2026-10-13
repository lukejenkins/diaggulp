"""diaggulp ``--passive``: arm nothing, on any transport.

``--no-mask`` skips only the LOG mask; F3 all-levels, the QSH trace maskset,
QSH metrics and the event mask are each default-ON and still ran. Found by a
qlc validation run on an RM520N-GL: a ``--no-mask`` read of a qlc-armed
modem overwrote qlc's arm (0x79 4 → 125 frames/s, 0x9D 1,189 → 345/s), and the
Tier-1 pre-run "as-found" probe had been arming the modem the same way.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


def _args(*argv: str):
    return d.build_arg_parser().parse_args(list(argv))


def _arms(a) -> dict:
    """What main() will arm, read from the same objects main() reads."""
    return {"log_mask": not a.no_mask, "f3": d._plan_f3_arming(a).mode != "none",
            "qsh_trace": a.qsh_trace, "qsh_metrics": a.qsh_enable,
            "events": a.events_enable}


def test_no_mask_alone_still_arms_everything_but_the_log_mask():
    # The semantics the old help text hid. Pinned so the help stays truthful.
    a = _args("/dev/null", "--no-mask")
    assert d._apply_passive_flag(a) is None
    assert _arms(a) == {"log_mask": False, "f3": True, "qsh_trace": True,
                        "qsh_metrics": True, "events": True}


def test_passive_arms_nothing():
    a = _args("/dev/null", "--passive")
    assert d._apply_passive_flag(a) is None
    assert not any(_arms(a).values()), _arms(a)


def test_passive_leaves_read_only_requests_alone():
    a = _args("/dev/null", "--passive")
    d._apply_passive_flag(a)
    assert a.anchor_frame != "none"
    assert a.diag_id_binding is True


@pytest.mark.parametrize("extra,flag", [
    (("--log-code", "0xB0C0"), "--log-code"),
    (("--ext-msg-f3-ss", "5000"), "--ext-msg-f3-ss"),
    (("--ext-msg-f3-level-mask", "0x1F"), "--ext-msg-f3-level-mask"),
    (("--enable-oemdre",), "--enable-oemdre"),
])
def test_an_explicit_arm_contradicts_passive(extra, flag):
    a = _args("/dev/null", "--passive", *extra)
    err = d._apply_passive_flag(a)
    assert err and flag in err


def test_the_usage_error_exits_2_before_opening_a_transport(monkeypatch, capsys):
    def _boom(*a, **kw):
        raise AssertionError("a transport was opened")
    monkeypatch.setattr(d.DiagClient, "from_serial", _boom)
    assert d.main(["/dev/null", "--passive", "--log-code", "0xB0C0"]) == 2
    assert "--passive arms nothing" in capsys.readouterr().err


def test_without_passive_nothing_is_forced():
    a = _args("/dev/null")
    snapshot = dict(vars(a))
    assert d._apply_passive_flag(a) is None
    assert vars(a) == snapshot


def test_passive_transport_clears_the_level_mask_arm_too():
    # The shared helper also closes a hole: --ext-msg-f3-level-mask implies an
    # F3 arm, and the passive transports did not clear it.
    a = _args("--transport", "udp-listen", "--ext-msg-f3-level-mask", "0x1F")
    assert d._apply_passive_transport_policy(a) is True
    assert d._plan_f3_arming(a).mode == "none"


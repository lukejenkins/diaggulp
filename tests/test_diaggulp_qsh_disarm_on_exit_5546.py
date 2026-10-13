"""diaggulp ``--disarm-qsh-on-exit``: disarm only what this run armed, prove it on the stream.

The QSH-trace 0x9001 maskset is modem-side sticky and has no GET. A
one-shot capture that leaves it armed floods every later reader of the port:
on the RM500Q-AE that was 27,186 ``0x9D`` frames in 10 s against 41 ``0x1476``.
"""

import importlib.util
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_SPEC = importlib.util.spec_from_file_location(
    "diaggulp_5546", os.path.join(os.path.dirname(__file__), "..", "diaggulp.py"))
diaggulp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diaggulp)

#: The empty (count=0) maskset SET, byte for byte — the only disarm there is.
DISARM_WIRE = bytes.fromhex("4b44019003000000010000000100000000000000")

# Escaped HDLC frames (0x7E-terminated). Bodies are short stand-ins; only the head is peeked.
F_9D = bytes.fromhex("9d01020304") + b"\x7e"
F_LOG_1476 = bytes.fromhex("1000120012007614") + b"\x00" * 8 + b"\x7e"
from diagmunge.framefilter import MULTI_RADIO_WRAPPER_OFFSET  # noqa: E402

#: 0x98 multi-radio wrapper carrying an inner 0x9D at the wrapper offset.
F_98_9D = (b"\x98" + b"\x00" * (MULTI_RADIO_WRAPPER_OFFSET[0x98] - 1)
           + bytes.fromhex("9d0102030405")) + b"\x7e"


def _reply(status: int) -> tuple:
    return (0x4B, bytes.fromhex("440190") + status.to_bytes(4, "little"))


class FakeClient:
    """A modem whose 0x9D flow follows the maskset the fake was last sent."""

    def __init__(self, *, armed=True, disarm_status=0, disarm_result="reply",
                 keeps_flowing=False):
        self.armed = armed
        self.disarm_status = disarm_status
        self.disarm_result = disarm_result
        self.keeps_flowing = keeps_flowing
        self.sent = []

    def _send_recv(self, op, payload, timeout=5.0):
        self.sent.append(bytes([op]) + payload)
        if self.disarm_result == "timeout":
            return None
        if self.disarm_result == "badcmd":
            return (0x13, b"")
        if self.disarm_result == "raise":
            raise OSError("port gone")
        if self.disarm_status == 0 and not self.keeps_flowing:
            self.armed = False
        return _reply(self.disarm_status)

    def read_raw(self, timeout=1.0):
        time.sleep(0.01)
        return (F_9D * 3 + F_LOG_1476) if self.armed else F_LOG_1476


def test_count_sees_bare_9d_and_ignores_log_frames():
    c = FakeClient(armed=True)
    n = diaggulp._count_qsh_trace_frames(c, 0.05)
    assert n and n % 3 == 0          # 3 per chunk, the 0x1476 LOG frames never counted


def test_count_sees_0x98_wrapped_9d():
    """SDX72-class parts wrap every frame; a top-level-only check would read 0."""
    class Wrapped:
        def read_raw(self, timeout=1.0):
            time.sleep(0.01)
            return F_98_9D * 2
    assert diaggulp._count_qsh_trace_frames(Wrapped(), 0.05) >= 2


def test_count_is_zero_on_a_stream_without_9d():
    assert diaggulp._count_qsh_trace_frames(FakeClient(armed=False), 0.05) == 0


def test_count_returns_none_when_the_transport_closes():
    class Closed:
        def read_raw(self, timeout=1.0):
            raise EOFError
    assert diaggulp._count_qsh_trace_frames(Closed(), 0.05) is None


def test_disarm_sends_the_empty_maskset_and_verifies_on_the_stream(capsys):
    c = FakeClient(armed=True)
    assert diaggulp._disarm_qsh_trace(c, sample_s=0.05, settle_s=0.02) is True
    assert c.sent == [DISARM_WIRE]
    assert "VERIFIED on the stream" in capsys.readouterr().err


def test_status_zero_is_not_proof_while_9d_still_flows(capsys):
    c = FakeClient(armed=True, keeps_flowing=True)
    assert diaggulp._disarm_qsh_trace(c, sample_s=0.05, settle_s=0.02) is False
    assert "STILL flowing" in capsys.readouterr().err


def test_no_9d_before_the_disarm_means_unverified_not_verified(capsys):
    """The positive control: a gauge that never read positive cannot read negative."""
    c = FakeClient(armed=False)
    assert diaggulp._disarm_qsh_trace(c, sample_s=0.05, settle_s=0.02) is False
    assert "NOT verified" in capsys.readouterr().err


def test_nonzero_disarm_status_is_reported_as_armed(capsys):
    c = FakeClient(armed=True, disarm_status=1)
    assert diaggulp._disarm_qsh_trace(c, sample_s=0.05, settle_s=0.02) is False
    assert "status 1" in capsys.readouterr().err


def test_timeout_badcmd_and_raise_never_escape_and_say_left_armed(capsys):
    for kind in ("timeout", "badcmd", "raise"):
        c = FakeClient(armed=True, disarm_result=kind)
        assert diaggulp._disarm_qsh_trace(c, sample_s=0.02, settle_s=0.01) is False
        assert "LEFT ARMED" in capsys.readouterr().err


def test_enable_reports_whether_this_run_armed_it():
    class Arm:
        def __init__(self, res):
            self.res = res

        def _send_recv(self, op, payload, timeout=5.0):
            return self.res
    assert diaggulp._enable_qsh_trace(Arm(_reply(0))) is True
    assert diaggulp._enable_qsh_trace(Arm(_reply(2))) is False     # SDX20
    assert diaggulp._enable_qsh_trace(Arm((0x13, b""))) is False   # pre-SDX
    assert diaggulp._enable_qsh_trace(Arm(None)) is False


def test_the_flag_parses_and_defaults_off():
    """Opt-in, like --restore-f3-mask-on-exit: a run meant to leave QSH armed must keep it."""
    src = open(os.path.join(os.path.dirname(__file__), "..", "diaggulp.py")).read()
    assert '"--disarm-qsh-on-exit", action="store_true"' in src
    # teardown gates on THIS run's arm, never on the flag alone
    assert "if not qsh_armed_here:" in src
    assert "qsh_armed_here = _enable_qsh_trace(" in src

"""diaggulp ``--disarm-logs-on-exit``: clear the log mask + event reporting, prove it on the stream.

Both are modem-side sticky. A MiFi 6620L (MDM9625) kept streaming ~600 KB/s of
log + event frames after a ``--seconds 60`` run, until LOG_CONFIG op 0 and
``0x60 00`` were sent by hand.
"""

import importlib.util
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_SPEC = importlib.util.spec_from_file_location(
    "diaggulp_6464", os.path.join(os.path.dirname(__file__), "..", "diaggulp.py"))
diaggulp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diaggulp)

from diagmunge.framefilter import MULTI_RADIO_WRAPPER_OFFSET  # noqa: E402

#: The two disarm commands, byte for byte (opcode + payload).
LOG_DISABLE_WIRE = bytes.fromhex("7300000000000000")
EVENTS_OFF_WIRE = bytes.fromhex("6000")

# Escaped HDLC frames (0x7E-terminated). Only the head is peeked.
F_LOG = bytes.fromhex("1000120012007614") + b"\x00" * 8 + b"\x7e"
F_EVT = bytes.fromhex("6004000102030405") + b"\x7e"
F_F3 = bytes.fromhex("7901020304") + b"\x7e"
F_98_LOG = (b"\x98" + b"\x00" * (MULTI_RADIO_WRAPPER_OFFSET[0x98] - 1)
            + bytes.fromhex("1000120012007614")) + b"\x7e"

LOG_REPLY = (0x73, b"\x00\x00\x00" + struct.pack("<II", 0, 0))


class FakeModem:
    """Log and event flow follow the last LOG_CONFIG / EVENT_REPORT command."""

    def __init__(self, *, log=True, events=True, lose_replies=0, ignore=(),
                 ignore_once=(), result="reply", wrapped=False):
        self.log, self.events = log, events
        self.lose_replies = lose_replies     # first N commands get no reply
        self.ignore = set(ignore)            # planes the modem never stops
        self.ignore_once = set(ignore_once)  # planes that stop only on a re-send
        self.result = result
        self.wrapped = wrapped
        self.sent = []

    def _send_recv(self, op, payload, timeout=5.0, *, match=None):
        self.sent.append(bytes([op]) + payload)
        if self.result == "raise":
            raise OSError("port gone")
        if self.result == "badcmd":
            return (0x13, b"")
        if self.lose_replies:
            self.lose_replies -= 1
            return None
        plane = "log" if op == 0x73 else "events"
        if plane in self.ignore:
            pass
        elif plane in self.ignore_once:
            self.ignore_once.discard(plane)
        elif plane == "log":
            self.log = False
        else:
            self.events = False
        reply = LOG_REPLY if op == 0x73 else (0x60, b"\x00\x00")
        assert match is None or match(*reply)
        return reply

    def read_raw(self, timeout=1.0):
        time.sleep(0.01)
        out = F_F3                       # F3 is not this flag's business, never counted
        if self.log:
            out += (F_98_LOG if self.wrapped else F_LOG) * 2
        if self.events:
            out += F_EVT
        return out


def _run(m):
    return diaggulp._disarm_logs_and_events(m, sample_s=0.05, settle_s=0.02)


def test_both_planes_cleared_and_verified_on_the_stream(capsys):
    m = FakeModem()
    r = _run(m)
    assert m.sent == [LOG_DISABLE_WIRE, EVENTS_OFF_WIRE]
    assert r["log"]["verdict"] == "verified" and r["log"]["after"] == 0
    assert r["events"]["verdict"] == "verified" and r["events"]["after"] == 0
    assert r["log"]["before"] > 0 and r["events"]["before"] > 0
    err = capsys.readouterr().err
    assert err.count("VERIFIED on the stream") == 2


def test_counts_0x98_wrapped_log_frames():
    """SDX72-class parts wrap every frame; a top-level-only census reads 0."""
    counts = diaggulp._count_opcode_frames(FakeModem(wrapped=True), 0.05, (0x10, 0x60))
    assert counts[0x10] >= 2 and counts[0x60] >= 1


def test_f3_frames_are_not_counted_as_log_or_events():
    counts = diaggulp._count_opcode_frames(FakeModem(log=False, events=False), 0.05,
                                           (0x10, 0x60))
    assert counts == {0x10: 0, 0x60: 0}


def test_an_unanswered_command_is_re_sent(capsys):
    """On a flooding port one LOG DISABLE reply was lost; a second send worked."""
    m = FakeModem(lose_replies=2)
    r = _run(m)
    assert m.sent[:3] == [LOG_DISABLE_WIRE] * 3
    assert r["log"]["command"] == "ok" and r["log"]["verdict"] == "verified"


def test_a_plane_still_flowing_is_re_sent_once_and_can_then_verify():
    m = FakeModem(ignore_once={"events"})
    r = _run(m)
    assert m.sent == [LOG_DISABLE_WIRE, EVENTS_OFF_WIRE, EVENTS_OFF_WIRE]
    assert r["events"]["resent"] is True and r["events"]["verdict"] == "verified"
    assert r["log"]["resent"] is False


def test_a_plane_that_never_stops_reads_still_flowing_and_left_armed(capsys):
    m = FakeModem(ignore={"log"})
    r = _run(m)
    assert r["log"]["verdict"] == "still-flowing" and r["log"]["resent"] is True
    assert r["events"]["verdict"] == "verified"
    err = capsys.readouterr().err
    assert "STILL-FLOWING" in err and "LEFT ARMED" in err


def test_nothing_flowing_before_is_unverified_not_verified(capsys):
    """The positive control: a gauge that never read positive cannot read negative."""
    r = _run(FakeModem(log=False, events=False))
    assert r["log"]["verdict"] == r["events"]["verdict"] == "unverified"
    assert capsys.readouterr().err.count("NOT verified") == 2


def test_transport_close_is_unknown_and_never_raises(capsys):
    class Closed(FakeModem):
        def read_raw(self, timeout=1.0):
            raise EOFError
    r = _run(Closed())
    assert r["log"]["verdict"] == r["events"]["verdict"] == "unknown"
    assert "LEFT ARMED" in capsys.readouterr().err


def test_a_raising_transport_never_escapes_teardown(capsys):
    r = _run(FakeModem(result="raise"))
    assert "error" in r
    assert "still armed" in capsys.readouterr().err


def test_rejected_commands_are_reported_and_stream_decides():
    r = _run(FakeModem(result="badcmd"))
    assert r["log"]["command"] == "rejected"
    assert r["log"]["verdict"] == "still-flowing"


def test_the_flag_parses_defaults_off_and_skips_passive_transports():
    """Opt-in, like --restore-f3-mask-on-exit / --disarm-qsh-on-exit."""
    ns = diaggulp.build_arg_parser().parse_args(["/dev/null"])
    assert ns.disarm_logs_on_exit is False
    ns = diaggulp.build_arg_parser().parse_args(["/dev/null", "--disarm-logs-on-exit"])
    assert ns.disarm_logs_on_exit is True
    src = open(os.path.join(os.path.dirname(__file__), "..", "diaggulp.py")).read()
    i = src.index('if getattr(args, "disarm_logs_on_exit", False):')
    assert "if passive:" in src[i:i + 200]
    # runs inside the capture's finally, before the client is closed
    assert i < src.index("client.close()", i)

"""diaggulp ``--wait-ready``: reopen until DIAG answers after re-enumeration.

On the T99W640 X01 in a USB-only boot, the tty for the DIAG function
appears before the function answers. The boot-time ``-71`` enumeration storm and
the gadget re-compose mean a diaggulp started right after a (re)enumeration died
on its **first** DIAG write with::

    serial.serialutil.SerialException: device reports readiness to read but
    returned no data (device disconnected or multiple access on port?)

That blocked capturing the first attach after a cold boot. The mask
retries cannot help: they catch ``RuntimeError`` from a timed-out handshake, and
this is a transport exception from a port that has to be reopened.

``--wait-ready SECONDS`` opens the port, probes ``DIAG_VERNO_F``, and on any
transport error (pyserial's ``SerialException`` is an ``OSError``) or an
unanswered probe closes, backs off, and reopens until the deadline. The fakes
below raise the exact exception class and message from the incident.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

_SPEC = importlib.util.spec_from_file_location(
    "diaggulp_6129", str(TOOLS / "diaggulp.py")
)
diaggulp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diaggulp)

serial = pytest.importorskip("serial")

_INCIDENT = ("device reports readiness to read but returned no data (device "
             "disconnected or multiple access on port?)")


class _FakeClient:
    """A DiagClient stand-in whose probe reply (or exception) is scripted."""

    def __init__(self, reply=None, exc=None):
        self.reply, self.exc, self.closed, self.probes = reply, exc, False, []

    def _send_recv(self, opcode, payload, timeout=5.0, **_kw):
        self.probes.append((opcode, payload, timeout))
        if self.exc is not None:
            raise self.exc
        return self.reply

    def close(self):
        self.closed = True


class _Clock:
    """Fake monotonic clock; sleep() advances it, so no test really waits."""

    def __init__(self):
        self.now, self.sleeps = 0.0, []

    def __call__(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def _opener(script):
    """Return an open_client() that yields scripted clients (or raises)."""
    opened = []

    def open_client():
        item = script.pop(0)
        if isinstance(item, BaseException):
            raise item
        opened.append(item)
        return item

    return open_client, opened


def _wait(open_client, clock, wait_s=10.0):
    return diaggulp._wait_diag_ready(open_client, wait_s, sleep=clock.sleep, clock=clock)


def test_the_incident_exception_on_first_probe_is_retried_until_verno_answers(capsys):
    dead = _FakeClient(exc=serial.SerialException(_INCIDENT))
    live = _FakeClient(reply=(diaggulp.DIAG_VERNO_F, b"\x00" * 8))
    open_client, opened = _opener([dead, live])
    clock = _Clock()

    got = _wait(open_client, clock)

    assert got is live
    assert dead.closed and not live.closed
    assert dead.probes[0][0] == diaggulp.DIAG_VERNO_F
    err = capsys.readouterr().err
    assert "SerialException" in err and "attempt 1" in err and "reopening" in err


def test_an_open_that_fails_because_the_node_is_not_there_yet_is_retried():
    live = _FakeClient(reply=(diaggulp.DIAG_VERNO_F, b""))
    open_client, _ = _opener([FileNotFoundError(2, "No such file", "/dev/ttyUSB21"), live])
    assert _wait(open_client, _Clock()) is live


def test_bad_cmd_counts_as_ready_because_the_function_is_answering():
    bad = _FakeClient(reply=(diaggulp.DIAG_BAD_CMD_F, bytes([diaggulp.DIAG_VERNO_F])))
    open_client, _ = _opener([bad])
    assert _wait(open_client, _Clock()) is bad


def test_a_silent_probe_is_not_ready_and_the_client_is_reopened():
    silent = _FakeClient(reply=None)
    live = _FakeClient(reply=(diaggulp.DIAG_VERNO_F, b""))
    open_client, _ = _opener([silent, live])
    assert _wait(open_client, _Clock()) is live
    assert silent.closed


def test_backoff_doubles_and_caps(capsys):
    script = [_FakeClient(exc=serial.SerialException(_INCIDENT)) for _ in range(6)]
    script.append(_FakeClient(reply=(diaggulp.DIAG_VERNO_F, b"")))
    open_client, _ = _opener(list(script))
    clock = _Clock()
    assert _wait(open_client, clock, wait_s=60.0) is script[-1]
    assert clock.sleeps == [0.5, 1.0, 2.0, 4.0, 4.0, 4.0]


def test_deadline_gives_up_with_none_and_closes_every_client(capsys):
    clients = [_FakeClient(exc=serial.SerialException(_INCIDENT)) for _ in range(50)]
    open_client, opened = _opener(list(clients))
    clock = _Clock()

    assert _wait(open_client, clock, wait_s=3.0) is None

    assert opened and all(c.closed for c in opened)
    assert sum(clock.sleeps) <= 3.0 + 1e-9
    err = capsys.readouterr().err
    assert "did not answer" in err and "3.0" in err


def test_flag_defaults_off_and_takes_seconds():
    p = diaggulp.build_arg_parser()
    assert p.parse_args(["/dev/ttyUSB0"]).wait_ready == 0.0
    assert p.parse_args(["/dev/ttyUSB0", "--wait-ready", "30"]).wait_ready == 30.0


def test_main_reopens_on_the_incident_and_exits_1_at_the_deadline(monkeypatch, tmp_path, capsys):
    opens = []

    def from_serial(port, baud):
        opens.append(port)
        raise serial.SerialException(_INCIDENT)

    monkeypatch.setattr(diaggulp.DiagClient, "from_serial", staticmethod(from_serial))
    rc = diaggulp.main(["/dev/ttyUSB21", "--wait-ready", "0.6", "--no-nmea",
                        "--no-disk-check", "-o", str(tmp_path / "cap.hdlc")])
    assert rc == 1
    assert len(opens) >= 2
    assert "did not answer within --wait-ready" in capsys.readouterr().err


def test_without_the_flag_main_still_opens_once_and_raises(monkeypatch, tmp_path):
    opens = []

    def from_serial(port, baud):
        opens.append(port)
        raise serial.SerialException(_INCIDENT)

    monkeypatch.setattr(diaggulp.DiagClient, "from_serial", staticmethod(from_serial))
    with pytest.raises(serial.SerialException):
        diaggulp.main(["/dev/ttyUSB21", "--no-nmea", "--no-disk-check",
                       "-o", str(tmp_path / "cap.hdlc")])
    assert opens == ["/dev/ttyUSB21"]

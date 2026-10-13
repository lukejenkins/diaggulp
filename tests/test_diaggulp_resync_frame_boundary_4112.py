# SPDX-License-Identifier: Apache-2.0
"""diaggulp terminates a stale partial frame before its first request.

The modem keeps an unterminated partial frame in its DIAG RX buffer across host
sessions. diaggulp's first request was glued onto it, the modem answered
``DIAG_BAD_CMD_F`` echoing ``<stale><our 0x73 request>``, and the run died on an
assertion naming neither. Hit on an EG25-G and on a Fibocom NL668-AM
(stale prefix ``6174690d`` = ``"ati\\r"`` written by a port-sweeping
prober). The fix sends a lone ``0x7E`` and drains before any request.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


class _Transport:
    def __init__(self, log):
        self.log = log

    def write(self, data: bytes) -> None:
        self.log.append(("write", bytes(data)))


class _Client:
    """recv() yields ``frames`` scripted replies, then times out (or never, if
    ``stream`` — a modem already firehosing sticky-masked logs)."""

    def __init__(self, frames=0, *, stream=False, log=None):
        self.log = [] if log is None else log
        self._transport = _Transport(self.log)
        self._frames = frames
        self._stream = stream
        self._pend = b"\x13\x61\x74"   # a partial frame left over from the drain

    def recv(self, timeout=None):
        if self._stream or self._frames:
            self._frames -= 1
            self.log.append(("recv", None))
            return 0x13, b"ati\r"
        raise TimeoutError

    def close(self):
        self.log.append(("close", None))


def test_resync_writes_one_lone_flag_byte_and_nothing_else():
    c = _Client()
    assert d._resync_frame_boundary(c) == 0
    assert [e for e in c.log if e[0] == "write"] == [("write", b"\x7e")]


def test_resync_discards_the_modems_reply_to_the_stale_frame():
    c = _Client(frames=1)
    assert d._resync_frame_boundary(c) == 1
    assert c._pend == b"", "a partial frame read during the drain must not prefix the next reply"


def test_resync_is_bounded_on_a_modem_that_is_already_streaming():
    c = _Client(stream=True)
    assert d._resync_frame_boundary(c, max_total=5.0, max_frames=50) == 50


def test_main_resyncs_before_its_first_request(monkeypatch):
    log: list = []
    client = _Client(log=log)
    monkeypatch.setattr(d.DiagClient, "from_serial", staticmethod(lambda *a, **k: client))
    monkeypatch.setattr(d, "_query_ext_msg_ss_ranges",
                        lambda c: log.append(("first_request", None)) or [(0, 1)])
    d.main(["/dev/ttyUSBX", "--ext-msg-f3-list-ss"])
    kinds = [k for k, _ in log]
    assert kinds.index("write") < kinds.index("first_request")


def test_passive_transports_never_write_the_flag(monkeypatch):
    """A passive diagbarf consumer has no command channel."""
    log: list = []
    client = _Client(log=log)
    monkeypatch.setattr(d.DiagClient, "from_udp_listen",
                        staticmethod(lambda *a, **k: client))
    monkeypatch.setattr(d, "_query_ext_msg_ss_ranges",
                        lambda c: log.append(("first_request", None)) or [(0, 1)])
    d.main(["--transport", "udp-listen", "--host", "127.0.0.1", "--port", "1",
            "--ext-msg-f3-list-ss"])
    assert ("first_request", None) in log, "vacuous: main() never reached a request"
    assert ("write", b"\x7e") not in log

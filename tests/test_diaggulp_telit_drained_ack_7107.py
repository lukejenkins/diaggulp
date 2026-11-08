"""Telit flush-on-OUT: a reply read DURING the pumped write is the answer.

On an LM960A18 (fw 32.01.110) every SET_MASK ack, and the DIAG_VERNO_F reply,
arrived ~0.2 s after the write, inside ``_telit_write_pumped``'s between-slice
drain, which discarded them. Each of the 7 narrow-mask groups then waited out
the 4 s timeout ("no SET_MASK ack"), so Start logging took ~33 s, and the
version anchor fell back to ``host_bracket``. With the drained frames checked,
the same modem armed in ~2.1 s and the anchor answered with a 1.4 ms RTT.

The fake client models the quirk: the reply to a command is queued when the
command's LAST slice is written (flush-on-OUT), and every flush-kick queues a
RETRIEVE_RANGES (op 1) reply.
"""
from __future__ import annotations

import collections
import struct
import time

import pytest

import diaggulp as d


class FlushOnOutClient:
    def __init__(self, reply_for):
        self.reply_for = reply_for      # (opcode, payload) -> [(opcode, body), ...]
        self.inbox = collections.deque()
        self.buf = b""
        self.recv_calls = 0
        self._transport = self

    def _hdlc_encapsulate(self, raw: bytes) -> bytes:
        return raw + b"\x7e"            # framing detail is irrelevant here

    def write(self, piece: bytes) -> None:  # transport.write
        self.buf += piece
        if self.buf.endswith(b"\x7e"):
            raw, self.buf = self.buf[:-1], b""
            self.inbox.extend(self.reply_for(raw[0], raw[1:]))

    def send(self, opcode: int, payload: bytes) -> None:  # the flush-kick
        self.inbox.extend(self.reply_for(opcode, payload))

    def recv(self, timeout=None):
        self.recv_calls += 1
        if self.inbox:
            return self.inbox.popleft()
        time.sleep(min(timeout or 0, 0.005))
        raise TimeoutError


def _ranges_reply() -> tuple[int, bytes]:
    return (d._DIAG_LOG_CONFIG_F,
            struct.pack("<3xII", d._LOG_CFG_RETRIEVE_RANGES, 0) + b"\x00" * 64)


def _setmask_ack(log_type: int, status: int = 0) -> tuple[int, bytes]:
    return (d._DIAG_LOG_CONFIG_F,
            struct.pack("<3xIIII", d._LOG_CFG_SET_MASK, status, log_type, 16) + b"\x00\x00")


def _lm960(opcode, payload):
    """Acks SET_MASK and answers VERNO, as the LM960A18 does on the wire."""
    if opcode == d._DIAG_LOG_CONFIG_F:
        op = struct.unpack_from("<3xI", payload)[0]
        if op == d._LOG_CFG_SET_MASK:
            return [_setmask_ack(struct.unpack_from("<3xII", payload)[1])]
        return [_ranges_reply()]
    if opcode == d.DIAG_VERNO_F:
        return [(d.DIAG_VERNO_F, b"\x01" * 20)]
    return []


def test_set_mask_ack_read_during_the_write_is_used_not_waited_for(capsys):
    c = FlushOnOutClient(_lm960)
    t = time.monotonic()
    d._telit_set_mask(c, 0xB, 16, b"\x00" * 300)    # 300-byte mask: many slices
    took = time.monotonic() - t
    assert "no SET_MASK ack" not in capsys.readouterr().err
    assert took < 1.0, f"waited {took:.1f} s for an ack it had already read"


def test_a_failed_ack_read_during_the_write_still_raises():
    c = FlushOnOutClient(lambda op, p: [_setmask_ack(0xB, status=1)]
                         if op == d._DIAG_LOG_CONFIG_F else [])
    with pytest.raises(RuntimeError, match="SET_MASK failed"):
        d._telit_set_mask(c, 0xB, 16, b"\x00" * 300)


def test_another_groups_ack_is_not_bound():
    # A stray ack for log type 0x4 must not satisfy the SET_MASK for 0xB.
    def stray(op, p):
        if op == d._DIAG_LOG_CONFIG_F and struct.unpack_from("<3xI", p)[0] == d._LOG_CFG_SET_MASK:
            return [_setmask_ack(0x4)]
        return [_ranges_reply()]
    body = d._telit_log_config_xact(
        FlushOnOutClient(stray), d._LOG_CFG_SET_MASK,
        struct.pack("<3xIII", d._LOG_CFG_SET_MASK, 0xB, 16) + b"\x00\x00",
        timeout=0.3, kick_every=0.05, log_type=0xB)
    assert body is None


def test_reply_matcher_checks_log_type_only_when_asked():
    op, ack = _setmask_ack(0xB)
    assert d._telit_logconfig_reply_matches(op, ack, d._LOG_CFG_SET_MASK)
    assert d._telit_logconfig_reply_matches(op, ack, d._LOG_CFG_SET_MASK, 0xB)
    assert not d._telit_logconfig_reply_matches(op, ack, d._LOG_CFG_SET_MASK, 0x4)
    assert not d._telit_logconfig_reply_matches(op, ack[:10], d._LOG_CFG_SET_MASK, 0xB)


def test_pumped_write_returns_what_it_drained_with_a_timestamp():
    c = FlushOnOutClient(_lm960)
    before = time.monotonic_ns()
    got = d._telit_write_pumped(c, d.DIAG_VERNO_F, b"")
    assert [(op, len(x)) for op, x, _ in got] == [(d.DIAG_VERNO_F, 20)]
    assert got[0][2] >= before


def test_version_anchor_answered_during_the_write():
    a = d._telit_version_anchor(FlushOnOutClient(_lm960), timeout=0.3)
    assert a is not None and a["opcode"] == d.DIAG_VERNO_F
    assert a["response_bytes_hex"] == ("01" * 20)
    assert 0 <= a["rtt_ns"] < 100_000_000


def test_a_modem_that_never_answers_still_times_out_to_none(capsys):
    # The fire-and-forget tolerance stays for parts that really do not ack.
    c = FlushOnOutClient(lambda op, p: [_ranges_reply()] if op == d._DIAG_LOG_CONFIG_F else [])
    assert d._telit_version_anchor(c, timeout=0.2, kick_every=0.05) is None
    body = d._telit_log_config_xact(
        c, d._LOG_CFG_SET_MASK,
        struct.pack("<3xIII", d._LOG_CFG_SET_MASK, 0xB, 16) + b"\x00\x00",
        timeout=0.2, kick_every=0.05, log_type=0xB)
    assert body is None


def test_set_mask_does_not_take_another_groups_ack(monkeypatch, capsys):
    # Through _telit_set_mask itself: it must pass its log type down, so a stray
    # ack for 0x4 leaves the 0xB write unacknowledged (warned), not "acked".
    real = d._telit_log_config_xact
    monkeypatch.setattr(d, "_telit_log_config_xact",
                        lambda *a, **k: real(*a, **{**k, "timeout": 0.3, "kick_every": 0.05}))
    def stray(op, p):
        if op == d._DIAG_LOG_CONFIG_F and struct.unpack_from("<3xI", p)[0] == d._LOG_CFG_SET_MASK:
            return [_setmask_ack(0x4, status=1)]   # would raise if it were bound
        return [_ranges_reply()]
    d._telit_set_mask(FlushOnOutClient(stray), 0xB, 16, b"\x00" * 300)
    assert "no SET_MASK ack for log type 0xb" in capsys.readouterr().err

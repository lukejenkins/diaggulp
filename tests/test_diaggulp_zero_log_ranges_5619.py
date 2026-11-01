# SPDX-License-Identifier: Apache-2.0
"""A RETRIEVE_RANGES reply of success-with-all-zero bitsizes is a FAILED
log-mask handshake, not a successful one.

A modem can answer ``DIAG_LOG_CONFIG_F`` RETRIEVE_RANGES with status 0 and all
16 per-log-type bitsizes = 0. The all-logs arm then set no mask at all, yet
printed ``subscribed to all 0 log codes across 0 log groups``, a line that reads
like success. The capture that followed had no classic ``0x10`` log plane, and
nothing said so. Both all-logs paths (the default one and the flush-on-OUT
quirk path) must now raise, so the caller's retry loop gets another try and the
operator sees why the log plane will be empty.
"""
from __future__ import annotations

import sys
from pathlib import Path
from struct import pack

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402
from diagmunge.transport import DiagClient  # noqa: E402

_OP = d.DIAG_LOG_CONFIG_F
_ZERO = (0,) * 16
_ONE_GROUP = tuple([0, 8] + [0] * 14)


def _retrieve_reply(bitsizes: "tuple[int, ...]") -> bytes:
    return pack("<3xII", d.LOG_CFG_RETRIEVE_RANGES, d.LOG_CFG_SUCCESS) + pack("<16I", *bitsizes)


def _set_mask_reply() -> bytes:
    return pack("<3xII", d.LOG_CFG_SET_MASK, d.LOG_CFG_SUCCESS)


class _ScriptedTransport:
    """One read() per scripted reply; records every write."""

    def __init__(self, framer: DiagClient, replies):
        self._chunks = [framer._hdlc_encapsulate(bytes([op]) + body) for op, body in replies]
        self._i = 0
        self.writes: list[bytes] = []

    def fileno(self) -> int:
        return 0

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))

    def read(self, n: int) -> bytes:
        if self._i >= len(self._chunks):
            return b""
        chunk = self._chunks[self._i]
        self._i += 1
        return chunk


def _client(replies):
    framer = DiagClient(None, no_crc=False)
    transport = _ScriptedTransport(framer, replies)
    return DiagClient(transport, no_crc=False), transport


def test_all_zero_ranges_fail_the_default_handshake(capsys):
    client, transport = _client([(_OP, _retrieve_reply(_ZERO))])
    with pytest.raises(RuntimeError, match=r"all 16 log-type bitsizes are 0"):
        d._build_all_logs_mask(client)
    # Only the RETRIEVE_RANGES request went out: no SET_MASK was attempted.
    assert len(transport.writes) == 1
    assert "subscribed to all 0" not in capsys.readouterr().err


def test_the_zero_range_error_says_the_log_plane_will_be_empty():
    client, _ = _client([(_OP, _retrieve_reply(_ZERO))])
    with pytest.raises(RuntimeError) as exc:
        d._build_all_logs_mask(client)
    assert "EMPTY" in str(exc.value)


def test_a_nonzero_range_still_subscribes(capsys):
    client, transport = _client([(_OP, _retrieve_reply(_ONE_GROUP)), (_OP, _set_mask_reply())])
    d._build_all_logs_mask(client)
    assert len(transport.writes) == 2      # RETRIEVE_RANGES + one SET_MASK
    assert "subscribed to all 8 log codes across 1 log groups" in capsys.readouterr().err


def test_all_zero_ranges_fail_the_flush_on_out_handshake(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(d, "_telit_retrieve_ranges", lambda client: _ZERO)
    monkeypatch.setattr(d, "_telit_set_mask", lambda *a: calls.append(a))
    with pytest.raises(RuntimeError, match=r"all 16 log-type bitsizes are 0"):
        d._build_all_logs_mask_telit(object())
    assert calls == []
    assert "subscribed to all 0" not in capsys.readouterr().err


def test_a_nonzero_range_still_subscribes_on_the_flush_on_out_path(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(d, "_telit_retrieve_ranges", lambda client: _ONE_GROUP)
    monkeypatch.setattr(d, "_telit_set_mask", lambda *a: calls.append(a))
    d._build_all_logs_mask_telit(object())
    assert len(calls) == 1
    assert "subscribed to all 8 log codes across 1 log groups" in capsys.readouterr().err

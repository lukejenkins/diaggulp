# SPDX-License-Identifier: Apache-2.0
"""diaggulp's 0x73 handshakes drain a one-behind aliased sub-operation reply
instead of asserting on it.

Both ``_build_narrow_mask`` and ``_build_all_logs_mask`` run the
RETRIEVE_RANGES → per-type SET_MASK handshake over the shared
``DiagClient._send_recv``. On a firehosing modem a late RETRIEVE reply used to
satisfy the next SET_MASK request (same opcode 0x73), tripping
``assert operation == LOG_CFG_RETRIEVE_RANGES``. These drive the real functions
over a transport that precedes every real reply with an aliased one, and assert
the handshake completes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from struct import pack

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402
from diagmunge.transport import DiagClient  # noqa: E402


def _retrieve_reply(bitsizes: "tuple[int, ...]") -> bytes:
    return pack("<3xII", d.LOG_CFG_RETRIEVE_RANGES, d.LOG_CFG_SUCCESS) + pack("<16I", *bitsizes)


def _set_mask_reply() -> bytes:
    return pack("<3xII", d.LOG_CFG_SET_MASK, d.LOG_CFG_SUCCESS)


class _ScriptedTransport:
    """One read() per chunk; each chunk is a transaction's [aliased, real]
    frames concatenated, so a single _send_recv must drain the alias."""

    def __init__(self, framer: DiagClient, chunks):
        self._chunks = [
            b"".join(framer._hdlc_encapsulate(bytes([op]) + body) for op, body in frames)
            for frames in chunks
        ]
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


def _client(chunks) -> DiagClient:
    framer = DiagClient(None, no_crc=False)
    return DiagClient(_ScriptedTransport(framer, chunks), no_crc=False)


# one non-zero log group (type 1, 8 codes) → RETRIEVE + exactly one SET_MASK
_BITSIZES = tuple([0, 8] + [0] * 14)
_OP = d.DIAG_LOG_CONFIG_F


def _aliasing_chunks():
    return [
        # RETRIEVE transaction: a stale SET_MASK reply arrives first
        [(_OP, _set_mask_reply()), (_OP, _retrieve_reply(_BITSIZES))],
        # SET_MASK transaction: a stale RETRIEVE reply arrives first
        [(_OP, _retrieve_reply(_BITSIZES)), (_OP, _set_mask_reply())],
    ]


def test_build_narrow_mask_survives_aliased_replies():
    client = _client(_aliasing_chunks())
    # code 0x1001 lives in group 1; must complete without AssertionError
    d._build_narrow_mask(client, [0x1001])
    assert len(client._transport.writes) == 2


def test_build_all_logs_mask_survives_aliased_replies():
    client = _client(_aliasing_chunks())
    d._build_all_logs_mask(client)
    assert len(client._transport.writes) == 2

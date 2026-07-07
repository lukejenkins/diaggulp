"""#N — live/streaming DIAG decode in diaggulp (LiveDecoder).

Decode a SELECTED set of log codes inline as frames arrive, on a side thread
fed by a bounded queue. The contract: the raw capture is NEVER affected — under
load the DECODE copy is dropped (counted), never raw bytes; the decoder runs off
the hot path entirely. These tests drive LiveDecoder directly with synthetic
HDLC LOG frames (the same wire shape diaggulp captures).
"""
from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

import pytest

# This module imports diaggrok at top level — it exercises diaggulp's optional
# --decode path (the future `diaggulp[decode]` extra, #N). Mark the whole
# module so the base capture suite runs green with `-m "not decode"` on a host
# where diaggrok is absent, and skip cleanly rather than erroring at collection.
pytestmark = pytest.mark.decode

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import diaggulp  # noqa: E402

pytest.importorskip("diaggrok", reason="diaggulp[decode] extra — diaggrok not installed")
from diaggrok.hdlc import crc16_ccitt  # noqa: E402


def _build_log_f_body(log_code: int, ts64: int, payload: bytes) -> bytes:
    """DIAG_LOG_F (0x10) frame body — no CRC, no HDLC framing."""
    inner = struct.pack("<HH", 2 + 8 + len(payload), log_code) \
        + struct.pack("<Q", ts64) + payload
    return bytes([0x10, 0x00]) + struct.pack("<H", len(inner)) + inner


def _wrap_hdlc(body: bytes) -> bytes:
    framed = body + struct.pack("<H", crc16_ccitt(body))
    escaped = bytearray()
    for b in framed:
        if b in (0x7D, 0x7E):
            escaped += bytes([0x7D, b ^ 0x20])
        else:
            escaped.append(b)
    return bytes(escaped) + b"\x7e"


def _frame(code: int, ts: int = 0, payload: bytes = b"\x00\x00\x00\x00") -> bytes:
    return _wrap_hdlc(_build_log_f_body(code, ts, payload))


def test_decodes_selected_codes_and_emits_jsonl():
    import json
    out = io.StringIO()
    dec = diaggulp.LiveDecoder(codes={0xB0C0}, out=out)
    dec.start()
    for ts in range(3):
        dec.feed(_frame(0xB0C0, ts=ts))
    dec.stop()
    assert dec.decoded == 3
    assert dec.code_counts.get(0xB0C0) == 3
    lines = [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 3
    assert all(rec["code"] == "0xB0C0" for rec in lines)


def test_code_filter_excludes_unselected_codes():
    out = io.StringIO()
    dec = diaggulp.LiveDecoder(codes={0xB0C0}, out=out)
    dec.start()
    dec.feed(_frame(0xB0C0))          # selected
    dec.feed(_frame(0xB193))          # NOT selected → must be skipped
    dec.stop()
    assert dec.decoded == 1
    assert set(dec.code_counts) == {0xB0C0}


def test_decode_live_none_decodes_every_code():
    out = io.StringIO()
    dec = diaggulp.LiveDecoder(codes=None, out=out)  # --decode-live form
    dec.start()
    dec.feed(_frame(0xB0C0))
    dec.feed(_frame(0xB193))
    dec.stop()
    assert dec.decoded == 2
    assert set(dec.code_counts) == {0xB0C0, 0xB193}


def test_frames_split_across_feed_chunks_reassemble():
    # A frame spanning two feed() calls must still decode (the streaming
    # reassembler holds the residual until the 0x7E delimiter arrives).
    out = io.StringIO()
    dec = diaggulp.LiveDecoder(codes={0xB0C0}, out=out)
    frame = _frame(0xB0C0)
    cut = len(frame) // 2
    dec.start()
    dec.feed(frame[:cut])
    dec.feed(frame[cut:])
    dec.stop()
    assert dec.decoded == 1


def test_overload_drops_decode_copy_not_raw_bytes():
    # feed() must NEVER block: with the consumer not started, the bounded queue
    # fills to _MAXSIZE then drops the excess (counted), proving the hot-path
    # tee can't stall on a slow/saturated decoder.
    dec = diaggulp.LiveDecoder(codes={0xB0C0})  # NOT started → queue never drains
    extra = 7
    for _ in range(dec._MAXSIZE + extra):
        dec.feed(b"x" * 16)
    assert dec.dropped_chunks == extra
    assert dec.dropped_bytes == extra * 16


def test_unparsed_code_triggers_one_time_novelty_alert(capsys):
    out = io.StringIO()
    dec = diaggulp.LiveDecoder(codes={0xFFFE}, out=out)  # 0xFFFE: no parser
    dec.start()
    dec.feed(_frame(0xFFFE))
    dec.feed(_frame(0xFFFE))   # second time must NOT re-alert
    dec.stop()
    err = capsys.readouterr().err
    assert err.count("NEW unparsed log code 0xFFFE") == 1
    # still counted + emitted (decoded=null), just no parser
    assert dec.decoded == 2


def test_stop_without_start_is_safe():
    dec = diaggulp.LiveDecoder(codes={0xB0C0})
    dec.stop()  # no thread → no-op, no exception

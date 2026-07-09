"""Live-decode --pcap-out test: synthetic HDLC log frames -> GSMTAP pcap.

Marked `decode` (needs diaggrok), consistent with test_diaggulp_live_decode.py.
Feeds the LiveDecoder tee directly (no real device), then re-reads the pcap.

The synthetic-log-frame construction reuses the proven builders from
test_diaggulp_live_decode.py (DIAG_LOG_F 0x10 body + HDLC frame) — the exact
wire shape diaggrok.hdlc.iter_log_records_stream reassembles. There is no
`hdlc_encapsulate` helper; framing goes through crc16_ccitt + byte-stuffing.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.decode

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

import diaggulp  # noqa: E402

pytest.importorskip("diaggrok", reason="diaggulp[decode] extra — diaggrok not installed")

from diaggrok.hdlc import crc16_ccitt  # noqa: E402
from diagmunge.munge import dlf_to_pcap  # noqa: E402
from diaggrok.parsers.diag_0xb0c0 import (  # noqa: E402
    LTE_RRC_V20_CHANNEL_OFFSET,
    LTE_RRC_V20_CHANNEL_PCCH,
)

LOG_LTE_RRC_OTA_MSG = 0xB0C0


def _b0c0_v20_pcch(body: bytes) -> bytes:
    buf = bytearray(19)
    buf[0] = 20
    buf[1] = 15
    buf[2] = 0x30
    struct.pack_into("<H", buf, 4, 100)      # pci
    struct.pack_into("<H", buf, 6, 2300)     # earfcn
    struct.pack_into("<H", buf, 8, (512 << 4) | 3)
    buf[10] = 1
    buf[LTE_RRC_V20_CHANNEL_OFFSET] = LTE_RRC_V20_CHANNEL_PCCH
    struct.pack_into("<H", buf, 17, len(body))
    return bytes(buf) + body


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


def _diag_log_frame(code: int, payload: bytes, ts: int = 0) -> bytes:
    return _wrap_hdlc(_build_log_f_body(code, ts, payload))


def _iter_pcap_payloads(pcap_bytes: bytes):
    off, n = 24, len(pcap_bytes)
    while off + 16 <= n:
        _s, _u, incl, _o = struct.unpack_from("<IIII", pcap_bytes, off)
        off += 16
        yield pcap_bytes[off + 14 + 20 + 8 + 16: off + incl]
        off += incl


def test_pcap_out_writes_gsmtap_from_live_tee(tmp_path):
    out = tmp_path / "live.pcap"
    writer, nr_writer, files, nr_path = dlf_to_pcap._open_outputs(out)
    sink = dlf_to_pcap.PcapSink(writer, nr_writer=nr_writer)
    dec = diaggulp.LiveDecoder(
        codes=None, pcap_sink=sink, emit_jsonl=False)
    dec.start()
    payload = _b0c0_v20_pcch(b"\xca\xfe")
    dec.feed(_diag_log_frame(LOG_LTE_RRC_OTA_MSG, payload))
    dec.stop()
    dlf_to_pcap._finalize_outputs(files, nr_path, sink.nr_written)

    payloads = list(_iter_pcap_payloads(out.read_bytes()))
    assert payloads == [b"\xca\xfe"]

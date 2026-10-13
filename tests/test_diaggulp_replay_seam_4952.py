"""diaggulp flags the 8 KiB MHI replay seam at capture time.

An MHI UCI ``read()`` returns at most one transfer buffer (TRE). On a host whose
OOT ``pcie_mhi`` posts 8 KiB DIAG TREs, a DIAG packet longer than one TRE
arrives as a read of exactly 8192 bytes (its head) followed by a read that
REPLAYS that head instead of carrying the tail. The tail never reaches the host.

These tests model the read sequence ``/dev/mhi_DIAG`` delivers: one TRE per
read. The geometry is the measured one (10589-byte escaped packet, seam at
8192). The bytes are synthetic.
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
sys.modules.setdefault("serial", MagicMock())

import diaggulp  # noqa: E402

SEAM = diaggulp.MHI_REPLAY_SEAM


def _packet(n: int, code: int = 0x1CC8, ts: int = 0x0123456789) -> bytes:
    """A DIAG-shaped packet of ``n`` wire bytes ending in 0x7E: 0x98 wrapper,
    LOG_F header with code + timestamp, filler body. No 0x7E/0x7D in the body."""
    head = bytes([0x98, 1, 0, 0, 1, 0, 0, 0, 0x10, 0]) + struct.pack("<HHHQ", n, n, code, ts)
    body = bytes((i % 0x7C) for i in range(n - len(head) - 1))
    return head + body + b"\x7e"


def _seam_reads(big: bytes, trailer: bytes) -> list[bytes]:
    """The reads an 8 KiB-MTU host delivers for ``big`` then ``trailer``."""
    assert len(big) > SEAM
    return [big[:SEAM], big[: len(big) - SEAM] + trailer]


def _run(loop: str, reads: list[bytes], tmp_path, capsys):
    transport = MagicMock()
    transport.fileno.return_value = -999
    transport.read.side_effect = reads + [b""]
    client = MagicMock()
    client._transport = transport
    stop_info: dict = {}
    out = tmp_path / "cap.bin"
    with patch("diaggulp.select.select", return_value=([-999], [], [])):
        if loop == "slurp":
            fd = os.open(str(out), os.O_WRONLY | os.O_CREAT, 0o644)
            try:
                diaggulp.slurp(client, fd, stop_info=stop_info)
            finally:
                os.close(fd)
        else:
            writer = diaggulp._RotatingWriter(str(out))
            try:
                diaggulp.slurp_rotating(client, writer, stop_info=stop_info)
            finally:
                writer.close()
    return out.read_bytes(), stop_info, capsys.readouterr().err


def test_seam_is_counted_and_announced(tmp_path, capsys):
    big, small = _packet(10589), _packet(60, code=0x19B7, ts=7)
    reads = [_packet(300, code=0x1874)] + _seam_reads(big, small)
    raw, info, err = _run("slurp", reads, tmp_path, capsys)
    assert raw == b"".join(reads)                 # bytes written unchanged
    assert info["replay_seams"] == 1
    assert "LOST to the 8 KiB MHI replay seam" in err
    assert "0010-fix-sdx7x-diag-mtu-32k.patch" in err
    assert f"first at byte {300 + SEAM}" in err   # offset of the replay read


def test_rotating_loop_counts_seams_too(tmp_path, capsys):
    """The twin loop must not silently miss it (the one-copy trap)."""
    reads = _seam_reads(_packet(10589), _packet(60, code=0x19B7, ts=7)) \
        + _seam_reads(_packet(9000, ts=99), _packet(40, ts=100))
    _, info, err = _run("rotating", reads, tmp_path, capsys)
    assert info["replay_seams"] == 2
    assert "2 DIAG packet(s) LOST" in err


def test_fixed_driver_one_read_per_packet_is_clean(tmp_path, capsys):
    """With the 32 KiB MTU the whole packet arrives in one read: no seam."""
    reads = [_packet(10589), _packet(60, code=0x19B7, ts=7)]
    _, info, err = _run("slurp", reads, tmp_path, capsys)
    assert info["replay_seams"] == 0
    assert "LOST" not in err


def test_full_tre_of_distinct_packets_is_not_a_seam(tmp_path, capsys):
    """A read of exactly 8192 bytes followed by a DIFFERENT packet is normal."""
    reads = [_packet(SEAM), _packet(SEAM, ts=0x55), _packet(100, ts=0x56)]
    _, info, _ = _run("slurp", reads, tmp_path, capsys)
    assert info["replay_seams"] == 0


def test_same_head_after_a_short_read_is_not_a_seam(tmp_path, capsys):
    """The replay only follows a FULL 8 KiB TRE; an identical head after a
    shorter read (e.g. a USB tty's coalesced read) is not counted."""
    p = _packet(SEAM - 1)
    _, info, _ = _run("slurp", [p, p], tmp_path, capsys)
    assert info["replay_seams"] == 0


def test_reads_starting_inside_a_zero_run_are_not_a_seam(tmp_path, capsys):
    """A live false positive: behind diagbarf's TCP sink a read is a stream
    chunk, not a TRE, so it can start mid-frame. An RM500Q-AE 0x1476 frame is
    mostly zero padding; two consecutive full 8192-byte reads both began inside
    that run, their 24-byte heads matched (all 0x00), and a capture with 0
    CRC-bad frames reported "2 DIAG packet(s) LOST". A real replay repeats a
    packet HEAD (opcode, length, code, timestamp), which is never one repeated
    byte."""
    frame = _packet(300) + b"\x00" * (3 * SEAM)        # long zero run, then more
    stream = frame + _packet(60, code=0x19B7, ts=7)
    off = 400                                          # chunking lands inside the run
    reads = [stream[:off], stream[off:off + SEAM], stream[off + SEAM:off + 2 * SEAM],
             stream[off + 2 * SEAM:]]
    assert reads[1][:24] == reads[2][:24] == b"\x00" * 24   # the live geometry
    _, info, err = _run("slurp", reads, tmp_path, capsys)
    assert info["replay_seams"] == 0
    assert "LOST" not in err

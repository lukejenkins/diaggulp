"""Tests for the diaggulp offline pcap replay path (--transport pcap).

These build synthetic classic-pcap captures of the diagbarf DGE1 UDP broadcast
and assert that the replay reassembles the same raw-HDLC byte stream the live
``udp-listen`` path produces, with identical gap accounting. A synthetic pcap
is the correct test artifact here: this exercises a standard-file-format reader
+ the shared DGE1 deframer, not on-wire parser correctness (no real diagbarf
pcap was archived from the hardware validation).
"""
from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
try:
    import serial  # noqa: F401  # real pyserial is in .venv
except ImportError:
    sys.modules["serial"] = MagicMock()

import diaggulp  # noqa: E402
from diagmunge import Dge1SeqTracker, parse_dge1_header  # noqa: E402

import pytest  # noqa: E402

# The pcap replay core is diagmunge.diag_source, which needs diaggrok's HDLC
# framer. An install without either refuses --pcap cleanly.
needs_pcap_replay = pytest.mark.skipif(
    not diaggulp.pcap_replay_available(),
    reason="diagmunge.diag_source absent: no --pcap replay in this install")


# --- synthetic frame builders -------------------------------------------------

def dge1(seq: int, payload: bytes, flags: int = 0) -> bytes:
    return (b"DGE1" + bytes([1, flags]) + struct.pack("<I", seq)
            + struct.pack("<H", len(payload)) + payload)


def _udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def _ipv4(udp: bytes) -> bytes:
    total = 20 + len(udp)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                       bytes([10, 0, 0, 1]), bytes([10, 0, 0, 255])) + udp


def _ipv6(udp: bytes) -> bytes:
    return (struct.pack(">IHBB", (6 << 28), len(udp), 17, 64)
            + b"\x20\x01" + b"\x00" * 14 + b"\x20\x01" + b"\x00" * 14 + udp)


def eth_ipv4_udp(dst_port: int, payload: bytes, src_port: int = 40000,
                 vlan: int | None = None) -> bytes:
    eth = b"\xff" * 6 + b"\x02" * 6
    if vlan is not None:
        eth += b"\x81\x00" + struct.pack(">H", vlan)
    eth += b"\x08\x00" + _ipv4(_udp(src_port, dst_port, payload))
    return eth


def eth_ipv6_udp(dst_port: int, payload: bytes, src_port: int = 40000) -> bytes:
    return b"\xff" * 6 + b"\x02" * 6 + b"\x86\xdd" + _ipv6(_udp(src_port, dst_port, payload))


def sll_ipv4_udp(dst_port: int, payload: bytes) -> bytes:
    # Linux SLL (linktype 113): 16-byte header, protocol at [14:16] big-endian.
    return struct.pack(">HHH8sH", 0, 0, 0, b"\x00" * 8, 0x0800) + _ipv4(
        _udp(40000, dst_port, payload))


def make_pcap(frames, linktype: int = 1, endian: str = "little") -> bytes:
    fmt = "<" if endian == "little" else ">"
    magic = 0xA1B2C3D4
    out = struct.pack(fmt + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype)
    for f in frames:
        out += struct.pack(fmt + "IIII", 0, 0, len(f), len(f)) + f
    return out


def _write_tmp(data: bytes, suffix: str = ".pcap") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, data)
    os.close(fd)
    return path


# --- shared deframer (diag.py) ------------------------------------------------

def test_parse_dge1_header_valid():
    payload = b"\x7e\xAA\xBB"
    payload_seq_restart = parse_dge1_header(dge1(42, payload, flags=0x01))
    assert payload_seq_restart == (payload, 42, True)


def test_parse_dge1_header_bad_magic_and_short():
    assert parse_dge1_header(b"XXXX" + b"\x00" * 12) is None
    assert parse_dge1_header(b"DGE1") is None  # too short for header


def test_parse_dge1_header_length_overrun():
    # declared plen (99) overruns the actual payload
    dg = b"DGE1" + bytes([1, 0]) + struct.pack("<I", 1) + struct.pack("<H", 99) + b"short"
    assert parse_dge1_header(dg) is None


def test_seq_tracker_gap_and_dup():
    t = Dge1SeqTracker()
    assert t.track(5, False) is True
    assert t.track(6, False) is True
    assert t.track(8, False) is True       # forward gap of 1 (seq 7 lost)
    assert t.track(7, False) is False      # behind expected -> late/dup, dropped
    r = t.gap_report()
    assert r["received"] == 3 and r["missing"] == 1 and r["duplicates_dropped"] == 1
    assert r["first_seq"] == 5 and r["last_seq"] == 7
    # The dropped seq 7 is a REORDER (never seen before), not a true copy.
    assert r["reordered"] == 1 and r["true_duplicates"] == 0


def test_seq_tracker_true_duplicate_vs_reorder():
    """A repeated seq is a true (on-wire/stack) duplicate; an out-of-order
    never-seen seq is a reorder."""
    t = Dge1SeqTracker()
    t.track(5, False)
    t.track(6, False)
    t.track(7, False)
    assert t.track(7, False) is False      # exact repeat of a delivered seq
    r = t.gap_report()
    assert r["duplicates_dropped"] == 1
    assert r["true_duplicates"] == 1 and r["reordered"] == 0


def test_seq_tracker_pure_reordering_signature():
    """Core case: a stream delivered ONCE each but heavily out of order is
    scored as many duplicates + much 'loss' with ZERO true duplicates — the
    signature that the CFW-3212 ~8x/99.8% pattern is reordering, not real
    duplication or real loss."""
    t = Dge1SeqTracker()
    seqs = list(range(0, 40, 2)) + list(range(1, 40, 2))  # evens then odds, each once
    for s in seqs:
        t.track(s, False)
    r = t.gap_report()
    # No seq was ever sent twice -> zero true duplicates despite many drops.
    assert r["true_duplicates"] == 0
    assert r["reordered"] == r["duplicates_dropped"] > 0
    # Every distinct seq was seen exactly once on the wire.
    assert r["received"] + r["reordered"] == len(seqs)


def test_seq_tracker_restart_no_loss():
    t = Dge1SeqTracker()
    t.track(100, False)
    t.track(5, True)                       # RESTART re-baselines without counting loss
    r = t.gap_report()
    assert r["missing"] == 0 and r["restarts"] == 1 and r["received"] == 2


# --- reorder buffer ---------------------------------------------------

def _pl(seq: int) -> bytes:
    """A distinguishable payload per seq so we can assert delivery ORDER."""
    return b"P%d" % seq


def test_reorder_window_zero_feed_matches_track():
    """With reorder_window == 0 (the default), feed() must be byte-identical to
    the legacy track() path: in-order seqs delivered, behind-expected dropped."""
    t = Dge1SeqTracker()  # default window 0
    assert t.feed(_pl(5), 5, False) == [_pl(5)]
    assert t.feed(_pl(6), 6, False) == [_pl(6)]
    assert t.feed(_pl(8), 8, False) == [_pl(8)]   # forward gap (7 lost)
    assert t.feed(_pl(7), 7, False) == []         # behind expected -> dropped
    assert t.flush() == []                        # no buffer when window 0
    r = t.gap_report()
    assert r["received"] == 3 and r["missing"] == 1
    assert r["reordered"] == 1 and r["true_duplicates"] == 0


def test_reorder_buffer_resequences_within_window():
    """The core fix: an out-of-order-but-present stream is delivered
    IN ORDER with zero loss and zero reordered, when the displacement fits the
    window — matching the clean --transport pcap result."""
    # Window must exceed the max reorder displacement: seq 1 is "expected" early
    # but arrives only after every even up to 18 is buffered (~18 ahead).
    t = Dge1SeqTracker(reorder_window=32)
    # evens then odds (each seq exactly once, heavily reordered) — the same
    # pattern test_seq_tracker_pure_reordering_signature scores as ~50% "loss".
    seqs = list(range(0, 20, 2)) + list(range(1, 20, 2))
    delivered = []
    for s in seqs:
        delivered.extend(t.feed(_pl(s), s, False))
    delivered.extend(t.flush())
    r = t.gap_report()
    # Every datagram recovered, delivered strictly in seq order, no false loss.
    assert delivered == [_pl(s) for s in range(0, 20)]
    assert r["received"] == 20
    assert r["missing"] == 0
    assert r["reordered"] == 0 and r["true_duplicates"] == 0


def test_reorder_buffer_flush_counts_real_holes():
    """A seq that genuinely never arrives is a real hole: it is held until
    flush, then counted as missing (not silently recovered)."""
    t = Dge1SeqTracker(reorder_window=16)
    out = []
    out.extend(t.feed(_pl(0), 0, False))   # in order
    out.extend(t.feed(_pl(2), 2, False))   # 1 is missing — buffer 2, deliver nothing yet
    assert out == [_pl(0)]
    out.extend(t.feed(_pl(3), 3, False))   # still waiting on 1
    assert out == [_pl(0)]
    out.extend(t.flush())                  # EOF: 1 never came -> lost, drain 2,3
    assert out == [_pl(0), _pl(2), _pl(3)]
    r = t.gap_report()
    assert r["received"] == 3 and r["missing"] == 1


def test_reorder_buffer_window_bound_forces_loss():
    """A seq beyond the window forces the base forward: the unfilled hole is
    declared lost and buffered datagrams within reach are delivered. Bounds
    both memory and latency."""
    t = Dge1SeqTracker(reorder_window=4)
    out = []
    out.extend(t.feed(_pl(0), 0, False))   # base advances to 1
    # 1 is missing; 5 arrives — (5 - 1) == 4 >= window -> force the base past 1
    out.extend(t.feed(_pl(5), 5, False))
    r = t.gap_report()
    assert r["missing"] >= 1               # seq 1 declared lost by window bound
    # seq 5 still buffered (no contiguous run yet); later in-order fill drains
    out.extend(t.feed(_pl(2), 2, False))   # late filler for the forced hole
    # 2 is now behind the advanced base -> dropped as reordered, not delivered
    out.extend(t.flush())
    assert _pl(0) in out and _pl(5) in out


def test_reorder_buffer_true_duplicate_dropped():
    """A real on-wire duplicate of a buffered or delivered seq is still scored
    as a true duplicate and dropped — reorder buffering must not turn a genuine
    copy into a second delivery."""
    t = Dge1SeqTracker(reorder_window=16)
    t.feed(_pl(0), 0, False)               # delivered
    t.feed(_pl(2), 2, False)               # buffered
    assert t.feed(_pl(2), 2, False) == []  # copy of a buffered seq -> dropped
    assert t.feed(_pl(0), 0, False) == []  # copy of a delivered seq -> dropped
    r = t.gap_report()
    assert r["true_duplicates"] == 2 and r["reordered"] == 0


class _StubSock:
    """Feeds a fixed list of datagrams, then b'' (socket EOF)."""

    def __init__(self, datagrams):
        self._dgs = list(datagrams)

    def recv(self, n):
        return self._dgs.pop(0) if self._dgs else b""

    def fileno(self):
        return -1

    def close(self):
        pass


def _drain_transport(tp):
    out = []
    while True:
        try:
            out.append(tp.read(65536))
        except EOFError:
            return out


def test_udp_listen_transport_reorders_end_to_end():
    """End-to-end through _UdpListenTransport.read(): a reordered DGE1 stream
    with the window enabled is delivered in order and flushed at EOF, matching
    the acceptance criterion: live udp-listen approaches the clean pcap result."""
    from diagmunge.transport import _UdpListenTransport
    # seq 0 first establishes the baseline, then later seqs swap in pairs.
    order = [0, 2, 1, 4, 3, 6, 5, 7]
    dgs = [dge1(s, b"P%d" % s) for s in order]
    tp = _UdpListenTransport(_StubSock(dgs), reorder_window=8)
    assert _drain_transport(tp) == [b"P%d" % s for s in range(8)]
    r = tp.gap_report()
    assert r["received"] == 8 and r["missing"] == 0 and r["reordered"] == 0


def test_udp_listen_transport_window_zero_drops_reorder():
    """Default (window 0): the transport keeps legacy behavior — a behind-
    expected datagram is dropped, not resequenced."""
    from diagmunge.transport import _UdpListenTransport
    dgs = [dge1(s, b"P%d" % s) for s in [1, 0, 2, 3]]  # 0 arrives behind 1
    tp = _UdpListenTransport(_StubSock(dgs), reorder_window=0)
    delivered = _drain_transport(tp)
    assert b"P0" not in delivered            # the reordered 0 is dropped
    r = tp.gap_report()
    assert r["reordered"] == 1 and r["true_duplicates"] == 0


# --- pcap reader --------------------------------------------------------------

@needs_pcap_replay
def test_roundtrip_ethernet_ipv4():
    payloads = [b"\x7e\xAA\xBB", b"\x7e\xCC", b"\x7e\xDD\xEE"]
    frames = [eth_ipv4_udp(12399, dge1(i, p)) for i, p in enumerate(payloads, start=1)]
    pcap = _write_tmp(make_pcap(frames))
    fd, out = tempfile.mkstemp(suffix=".dlf")
    written, report = diaggulp.replay_pcap_dge1(pcap, 12399, fd)
    os.close(fd)
    assert Path(out).read_bytes() == b"".join(payloads)
    assert written == sum(len(p) for p in payloads)
    assert report["received"] == 3 and report["missing"] == 0


def test_port_filter_excludes_other_ports():
    frames = [
        eth_ipv4_udp(12399, dge1(1, b"\x7e\x01")),
        eth_ipv4_udp(9999, dge1(2, b"\x7e\xFF")),   # other port — ignored
        eth_ipv4_udp(12399, dge1(2, b"\x7e\x02")),
    ]
    pcap = _write_tmp(make_pcap(frames))
    got = list(diaggulp.iter_pcap_udp_payloads(pcap, port=12399))
    assert len(got) == 2
    # with no filter, all three UDP datagrams surface
    assert len(list(diaggulp.iter_pcap_udp_payloads(pcap, port=None))) == 3


@needs_pcap_replay
def test_malformed_and_gap_counts():
    frames = [
        eth_ipv4_udp(12399, dge1(5, b"\x7e\xAA")),
        eth_ipv4_udp(12399, b"BADMAGIC-not-dge1"),   # right port, bad magic
        eth_ipv4_udp(12399, dge1(7, b"\x7e\xBB")),    # seq 6 missing
    ]
    pcap = _write_tmp(make_pcap(frames))
    fd, out = tempfile.mkstemp(suffix=".dlf")
    _, report = diaggulp.replay_pcap_dge1(pcap, 12399, fd)
    os.close(fd)
    assert report["received"] == 2 and report["missing"] == 1 and report["malformed"] == 1
    assert Path(out).read_bytes() == b"\x7e\xAA\x7e\xBB"


def test_vlan_tagged_ethernet():
    frames = [eth_ipv4_udp(12399, dge1(1, b"\x7e\xAB"), vlan=46)]
    pcap = _write_tmp(make_pcap(frames))
    assert [p for _ts, p in diaggulp.iter_pcap_udp_payloads(pcap, port=12399)] == [dge1(1, b"\x7e\xAB")]


def test_ipv6_udp():
    frames = [eth_ipv6_udp(12399, dge1(1, b"\x7e\xCD"))]
    pcap = _write_tmp(make_pcap(frames))
    assert [p for _ts, p in diaggulp.iter_pcap_udp_payloads(pcap, port=12399)] == [dge1(1, b"\x7e\xCD")]


def test_linux_sll_linktype():
    frames = [sll_ipv4_udp(12399, dge1(1, b"\x7e\xEF"))]
    pcap = _write_tmp(make_pcap(frames, linktype=113))
    assert [p for _ts, p in diaggulp.iter_pcap_udp_payloads(pcap, port=12399)] == [dge1(1, b"\x7e\xEF")]


def test_big_endian_pcap():
    frames = [eth_ipv4_udp(12399, dge1(1, b"\x7e\x99"))]
    pcap = _write_tmp(make_pcap(frames, endian="big"))
    assert [p for _ts, p in diaggulp.iter_pcap_udp_payloads(pcap, port=12399)] == [dge1(1, b"\x7e\x99")]


def test_pcapng_rejected():
    import pytest
    pcapng = b"\x0a\x0d\x0d\x0a" + b"\x00" * 20
    path = _write_tmp(pcapng, suffix=".pcapng")
    with pytest.raises(ValueError, match="pcapng is not supported"):
        list(diaggulp.iter_pcap_udp_payloads(path))


def test_bad_magic_rejected():
    import pytest
    path = _write_tmp(b"NOTPCAP!" + b"\x00" * 16)
    with pytest.raises(ValueError, match="not a pcap"):
        list(diaggulp.iter_pcap_udp_payloads(path))


# --- CLI end-to-end -----------------------------------------------------------

@needs_pcap_replay
def test_main_pcap_writes_dlf_and_sidecar():
    payloads = [b"\x7e\xAA\xBB", b"\x7e\xCC"]
    frames = [eth_ipv4_udp(12399, dge1(i, p)) for i, p in enumerate(payloads, start=1)]
    pcap = _write_tmp(make_pcap(frames))
    out = tempfile.mktemp(suffix=".dlf")
    rc = diaggulp.main(["--transport", "pcap", "--pcap", pcap, "-o", out, "--quiet"])
    assert rc == 0
    assert Path(out).read_bytes() == b"".join(payloads)
    sidecar = json.loads(Path(out + ".udpgaps.json").read_text())
    assert sidecar["transport"] == "pcap" and sidecar["framing"] == "DGE1"
    assert sidecar["port"] == 12399          # default diagbarf port
    assert sidecar["received"] == 2 and sidecar["missing"] == 0


def test_main_live_pcap_out_does_not_clobber_the_capture_writer():
    """--pcap-out must not rebind main()'s rotating-capture ``writer``.

    The pcap sink once unpacked into ``writer``, so a plain (non-rotating)
    live capture took the slurp_rotating path and called PcapWriter.write()
    (AttributeError, 0-byte capture) — hit on the EM061K-GL uecap run.
    Driven through the real live loop via udp-listen on loopback.
    """
    import socket
    import threading
    import time
    pytest.importorskip("diagmunge.munge.dlf_to_pcap")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    payloads = [b"\x7e\xAA\xBB", b"\x7e\xCC"]

    def _send():
        time.sleep(0.5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tx:
            for i, pl in enumerate(payloads, start=1):
                tx.sendto(dge1(i, pl), ("127.0.0.1", port))
    threading.Thread(target=_send, daemon=True).start()

    out = tempfile.mktemp(suffix=".dlf")
    pcap_out = tempfile.mktemp(suffix=".pcap")
    rc = diaggulp.main(["--transport", "udp-listen", "--host", "127.0.0.1",
                        "--port", str(port), "--no-mask", "--seconds", "2",
                        "-o", out, "--pcap-out", pcap_out, "--quiet",
                        "--no-disk-check"])
    assert rc == 0
    assert Path(out).read_bytes() == b"".join(payloads)
    assert Path(pcap_out).exists()


@needs_pcap_replay
def test_main_pcap_explicit_port_override():
    frames = [eth_ipv4_udp(2500, dge1(1, b"\x7e\x42"))]
    pcap = _write_tmp(make_pcap(frames))
    out = tempfile.mktemp(suffix=".dlf")
    rc = diaggulp.main(["--transport", "pcap", "--pcap", pcap, "--port", "2500",
                        "-o", out, "--quiet"])
    assert rc == 0
    assert Path(out).read_bytes() == b"\x7e\x42"
    sidecar = json.loads(Path(out + ".udpgaps.json").read_text())
    assert sidecar["port"] == 2500


@needs_pcap_replay
def test_main_pcap_replay_is_exempt_from_the_free_space_floor():
    """An offline pcap replay must NOT inherit the live-capture disk floor.

    The floor exists to refuse to *start* a live capture of unbounded length on a
    nearly-full filesystem (a full disk wedges syncthing's corpus folder fleet-
    wide). A replay's output is bounded by an input pcap that already fits on that
    same disk, so the hazard does not apply — which is what the guard's own comment
    has claimed since it was written, without the code ever checking the transport.

    ``--min-free-pct 100`` is unsatisfiable on any real filesystem, so this fails
    on every host if the exemption regresses — unlike the host-dependent red the
    two CLI end-to-end tests above used to produce.
    """
    frames = [eth_ipv4_udp(12399, dge1(1, b"\x7e\x42"))]
    pcap = _write_tmp(make_pcap(frames))
    out = tempfile.mktemp(suffix=".dlf")
    rc = diaggulp.main(["--transport", "pcap", "--pcap", pcap, "-o", out,
                        "--min-free-pct", "100", "--quiet"])
    assert rc == 0
    assert Path(out).read_bytes() == b"\x7e\x42"


@pytest.mark.diaggulp_real_disk
def test_main_live_transport_still_honours_the_free_space_floor():
    """Positive control for the exemption above: a LIVE transport must still be
    refused below the floor. A fix that simply weakened the guard would pass the
    exemption test and silently delete the protection this guard exists for."""
    rc = diaggulp.main(["/dev/null", "--transport", "serial",
                        "-o", tempfile.mktemp(suffix=".dlf"),
                        "--min-free-pct", "100", "--quiet"])
    assert rc == 2


def test_main_pcap_missing_file():
    rc = diaggulp.main(["--transport", "pcap", "--pcap", "/no/such/file.pcap",
                        "-o", tempfile.mktemp(), "--quiet"])
    assert rc == 2


def test_main_pcap_requires_pcap_arg():
    rc = diaggulp.main(["--transport", "pcap", "--quiet"])
    assert rc == 2


def test_replay_is_unavailable_when_diaggrok_is_missing(monkeypatch):
    """diagmunge.diag_source is findable without importing it, so a diagmunge
    without diaggrok must not report --pcap as available: the import would fail
    at replay time instead of being refused up front."""
    import importlib.util
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec",
                        lambda name, *a: None if name == "diaggrok.hdlc" else real(name, *a))
    assert diaggulp.pcap_replay_available() is False


def test_main_pcap_refuses_cleanly_without_the_replay_core(monkeypatch, capsys):
    monkeypatch.setattr(diaggulp, "pcap_replay_available", lambda: False)
    pcap = _write_tmp(make_pcap([eth_ipv4_udp(12399, dge1(1, b"\x7e\x42"))]))
    out = tempfile.mktemp(suffix=".dlf")
    rc = diaggulp.main(["--transport", "pcap", "--pcap", pcap, "-o", out, "--quiet"])
    assert rc == 2
    assert "diagmunge.diag_source" in capsys.readouterr().err
    assert not Path(out).exists(), "a refusal must not leave an output file behind"

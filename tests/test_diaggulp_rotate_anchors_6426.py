"""diaggulp anchors every segment of a rotating capture.

Before this, ``--rotate-size`` / ``--rotate-interval`` skipped anchor emission
entirely, so every segment of a rotated drive capture had 0 anchors and no
DIAG↔host/UTC mapping. Now: the VERNO pre-anchor starts segment 0, the VERNO
post-anchor ends the last segment, and every cut writes a ``rotation_boundary``
anchor (host time, no modem exchange, no lost bytes) that ends one segment and
starts the next. A closed segment's sidecar is written at the cut.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

_SPEC = importlib.util.spec_from_file_location("diaggulp_6426", str(TOOLS / "diaggulp.py"))
d = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(d)


# --- the writer hook ---------------------------------------------------------
def test_on_rotate_fires_per_cut_with_both_paths_and_a_boundary_instant(tmp_path):
    w = d._RotatingWriter(str(tmp_path / "cap_%s.bin"), rotate_size=1000)
    seen = []
    w.on_rotate = lambda closed, new, mono, unix: seen.append((closed, new, mono, unix))
    first = w._current_path
    t0 = time.monotonic_ns()
    w.write(b"x" * 1000)                 # crosses the threshold -> one cut
    w.close()
    assert len(seen) == 1
    closed, new, mono, unix = seen[0]
    assert closed == first and new == w._current_path and new != first
    assert t0 <= mono <= time.monotonic_ns()
    assert abs(unix - time.time_ns()) < 5e9
    # the bytes that crossed the threshold stayed in the CLOSED segment
    assert os.path.getsize(closed) == 1000 and os.path.getsize(new) == 0


def test_no_hook_still_rotates(tmp_path):
    w = d._RotatingWriter(str(tmp_path / "cap_%s.bin"), rotate_size=10)
    w.write(b"y" * 10)
    w.close()
    assert len(list(tmp_path.iterdir())) == 2


def test_rotation_boundary_anchor_has_no_fabricated_recv_half():
    """_anchor_mono_ns must fall through to host_mono_ns alone, as for host_bracket."""
    a = d._rotation_boundary_anchor(123, 456)
    assert a == {"method": "rotation_boundary", "host_mono_ns": 123, "host_unix_ns": 456}


# --- main() end to end, over a real pipe -------------------------------------
class _PipeTransport:
    def __init__(self, fd):
        self._fd = fd

    def fileno(self):
        return self._fd

    def read(self, n):
        return os.read(self._fd, n)

    def close(self):
        pass


class _FakeClient:
    def __init__(self, fd):
        self._transport = _PipeTransport(fd)

    def close(self):
        pass


def _run_rotating_main(monkeypatch, tmp_path, *extra, total=5000, chunk=500):
    rfd, wfd = os.pipe()
    monkeypatch.setattr(d.DiagClient, "from_serial",
                        classmethod(lambda cls, dev, baud=None: _FakeClient(rfd)))
    for name in ("_build_all_logs_mask", "_enable_qsh_metrics", "_enable_events"):
        monkeypatch.setattr(d, name, lambda *a, **k: None)
    monkeypatch.setattr(d, "_resync_frame_boundary", lambda *a, **k: 0)
    monkeypatch.setattr(d, "_apply_f3_arming", lambda *a, **k: None)
    monkeypatch.setattr(d, "_enable_qsh_trace", lambda *a, **k: False)
    monkeypatch.setattr(d, "_arm_event_mask", lambda *a, **k: {"version": 1, "fake": True})
    monkeypatch.setattr(d, "_request_diag_id_binding", lambda *a, **k: {"fake_binding": True})
    anchors = iter([{"host_mono_ns": 1, "host_mono_recv_ns": 2},
                    {"host_mono_ns": 9_000_000_000_000, "host_mono_recv_ns": 9_000_000_000_001}])
    monkeypatch.setattr(d, "_emit_boundary_anchor", lambda *a, **k: next(anchors))

    def _feed():
        for _ in range(total // chunk):
            os.write(wfd, b"\x7e" * chunk)
            time.sleep(0.01)          # separate reads, so each can trigger a cut
        os.close(wfd)                 # EOF ends the loop
    threading.Thread(target=_feed, daemon=True).start()
    d.main(["/dev/null", "-o", str(tmp_path / "seg_%s.bin"), "--rotate-size", "1000",
            "--no-nmea", "--no-disk-check", "--no-qsh-trace", "--quiet", *extra])
    os.close(rfd)
    segs = sorted(p for p in tmp_path.iterdir() if p.suffix == ".bin")
    side = {p: json.loads(Path(str(p) + ".anchors.json").read_text())
            for p in segs if Path(str(p) + ".anchors.json").exists()}
    return segs, side


def _order(segs, side):
    """Segments in capture order, by following the prev/next chain."""
    by_name = {p.name: p for p in segs}
    head = next(p for p in segs if side[p]["segment"]["prev"] is None)
    out = [head]
    while side[out[-1]]["segment"]["next"]:
        out.append(by_name[side[out[-1]]["segment"]["next"]])
    return out


def test_every_segment_gets_a_start_and_end_anchor(monkeypatch, tmp_path):
    # Several cuts land in one Unix second here, so this also exercises
    # _open_output's O_EXCL `_N` suffix: each segment's sidecar must be its own.
    segs, side = _run_rotating_main(monkeypatch, tmp_path)
    assert len(segs) >= 3, segs
    assert set(side) == set(segs), "a segment has no anchor sidecar"
    chain = _order(segs, side)
    assert len(chain) == len(segs)
    for i, p in enumerate(chain):
        doc = side[p]
        kinds = [a["kind"] for a in doc["anchors"]]
        assert kinds == ["start", "end"], (p.name, kinds)
        assert doc["segment"]["index"] == i
        start, end = doc["anchors"]
        assert start["method"] == ("diag_verno_response" if i == 0 else "rotation_boundary")
        assert end["method"] == ("diag_verno_response" if i == len(chain) - 1
                                 else "rotation_boundary")
        if i:   # one boundary anchor ends segment i-1 and starts segment i
            prev_end = side[chain[i - 1]]["anchors"][1]
            strip = lambda a: {k: v for k, v in a.items() if k != "kind"}  # noqa: E731
            assert strip(prev_end) == strip(start)
    # the run-level records ride segment 0 only
    assert "diag_id_binding" in side[chain[0]] and "event_mask" in side[chain[0]]
    assert all("diag_id_binding" not in side[p] and "event_mask" not in side[p]
               for p in chain[1:])
    # nothing was lost: every byte fed is in some segment
    assert sum(p.stat().st_size for p in segs) == 5000


def test_anchor_frame_none_writes_no_anchors_on_rotation(monkeypatch, tmp_path):
    segs, side = _run_rotating_main(monkeypatch, tmp_path, "--anchor-frame", "none")
    assert len(segs) >= 3
    for doc in side.values():
        assert doc["anchors"] == []
    # only segment 0 carries the run-level records, so only it has a sidecar
    assert len(side) == 1


def test_main_no_longer_skips_anchors_for_rotation():
    src = (TOOLS / "diaggulp.py").read_text()
    assert "not yet supported with" not in src
    i = src.index("anchor_enabled = (")
    assert "writer is None" not in src[i:i + 200]

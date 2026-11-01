"""diaggulp ``-o /dev/null`` is a valid sink.

The quiesce recipe (``--passive --disarm-logs-on-exit``, then ``--no-mask
--no-events-enable --ext-msg-f3-level-mask 0 --disarm-qsh-on-exit``) wants the
disarm side effects and no output. ``_open_output`` ran ``os.ftruncate`` on
every path, which raises EINVAL on a character device, so diaggulp died before
it disarmed anything and the modem kept streaming.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


def test_dev_null_opens_without_truncating():
    fd, path = d._open_output(os.devnull)
    try:
        assert path == os.devnull
        assert os.write(fd, b"\x7e" * 16) == 16
    finally:
        os.close(fd)


def test_dev_null_is_never_ftruncated(monkeypatch):
    # Linux raises EINVAL here; macOS accepts it silently, so a plain open
    # would pass on a Mac with the bug in place. Spy on the call itself.
    calls = []
    monkeypatch.setattr(d.os, "ftruncate", lambda fd, n: calls.append((fd, n)))
    fd, _ = d._open_output(os.devnull)
    os.close(fd)
    assert calls == []


def test_two_concurrent_dev_null_sinks_do_not_refuse_each_other():
    # Two quiesce runs on two modems both point at /dev/null. The capture flock
    # guards a capture; there is none here, so the second must not be refused.
    fd1, _ = d._open_output(os.devnull)
    try:
        fd2, _ = d._open_output(os.devnull)
        os.close(fd2)
    finally:
        os.close(fd1)


def test_a_regular_file_is_still_truncated(tmp_path):
    p = tmp_path / "cap.bin"
    p.write_bytes(b"old capture bytes")
    fd, _ = d._open_output(str(p))
    os.close(fd)
    assert p.read_bytes() == b""


def test_a_regular_file_is_still_locked_against_a_second_writer(tmp_path):
    p = tmp_path / "cap.bin"
    fd, _ = d._open_output(str(p))
    try:
        with pytest.raises(SystemExit, match="refusing to share it"):
            d._open_output(str(p))
    finally:
        os.close(fd)


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


def test_main_with_dev_null_output_and_seconds_exits_zero(monkeypatch):
    # A held-open, never-written pipe is a silent modem: --seconds 1 must end it.
    rfd, wfd = os.pipe()
    monkeypatch.setattr(d.DiagClient, "from_serial",
                        classmethod(lambda cls, dev, baud=None: _FakeClient(rfd)))
    monkeypatch.setattr(d, "_resync_frame_boundary", lambda *a, **k: 0)
    monkeypatch.setattr(d, "_request_diag_id_binding", lambda *a, **k: None)
    monkeypatch.setattr(d, "_emit_boundary_anchor", lambda *a, **k: None)
    try:
        rc = d.main(["/dev/null", "-o", os.devnull, "--passive", "--seconds", "1",
                     "--no-nmea", "--no-disk-check", "--quiet"])
    finally:
        os.close(wfd)
        os.close(rfd)
    assert rc in (0, None)

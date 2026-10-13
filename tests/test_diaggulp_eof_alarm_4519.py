# SPDX-License-Identifier: Apache-2.0
"""An unexpected mid-capture transport EOF is a LOUD, NON-ZERO failure.

A CARCOM-G1 wardrive took `[Errno 5]` → `transport closed (EOF)`
~9 min in when the USB DIAG interface dropped. diaggulp broke its read loop,
wrote its sidecar, and returned **0** — so a moving wardrive kept running while
the tty had gone silent and recorded nothing for the rest of the drive.

The fix: `slurp` / `slurp_rotating` record WHY the loop stopped in an optional
`stop_info` out-dict (`"eof"` / `"deadline"` / `"signal"` / `"broken_pipe"`), and
`main()` exits with a distinct non-zero code (3) plus a loud banner on `"eof"`,
while a `--seconds` deadline or a signal stays a clean 0. These pin the reason
attribution — the half a wrapper reconnect loop or an operator alarm keys off.
"""
from __future__ import annotations

import importlib.util
import os
import threading
from pathlib import Path

import pytest

# The test dir's parent holds diaggulp.py in-tree (tools/) and in the carve (root).
TOOLS = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "diaggulp_4519", str(TOOLS / "diaggulp.py")
)
diaggulp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diaggulp)


class _PipeTransport:
    def __init__(self, read_fd: int) -> None:
        self._fd = read_fd

    def fileno(self) -> int:
        return self._fd

    def read(self, n: int) -> bytes:
        return os.read(self._fd, n)


class _FakeClient:
    def __init__(self, read_fd: int) -> None:
        self._transport = _PipeTransport(read_fd)


class _RecordingWriter:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.chunks.append(data)


def _run_bounded(fn, *, wall_limit: float):
    box: dict = {}

    def _target():
        try:
            box["result"] = fn()
        except BaseException as exc:      # noqa: BLE001
            box["error"] = exc

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(wall_limit)
    return t, box


# ── slurp() reason attribution ──────────────────────────────────────────────
def test_slurp_records_eof_when_the_transport_closes(tmp_path):
    r, w = os.pipe()
    out_fd = os.open(tmp_path / "cap.bin", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.write(w, b"abc")
        os.close(w)                       # writer closed → read() returns b"" (EOF)
        info: dict = {}
        t, box = _run_bounded(
            lambda: diaggulp.slurp(_FakeClient(r), out_fd, stop_info=info),
            wall_limit=5.0,
        )
        assert not t.is_alive() and "error" not in box, box.get("error")
        assert info.get("reason") == "eof"
    finally:
        os.close(r)
        os.close(out_fd)


def test_slurp_records_deadline_not_eof_on_a_timed_stop(tmp_path):
    r, w = os.pipe()
    out_fd = os.open(tmp_path / "cap.bin", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        info: dict = {}
        t, box = _run_bounded(
            lambda: diaggulp.slurp(_FakeClient(r), out_fd, max_seconds=0.3,
                                   stop_info=info),
            wall_limit=5.0,
        )
        assert not t.is_alive() and "error" not in box, box.get("error")
        assert info.get("reason") == "deadline", (
            "a --seconds stop must NOT be reported as an EOF failure"
        )
    finally:
        os.close(w)
        os.close(r)
        os.close(out_fd)


def test_slurp_stop_info_is_optional(tmp_path):
    """Backward compat: no stop_info ⇒ unchanged 2-tuple return, no crash."""
    r, w = os.pipe()
    out_fd = os.open(tmp_path / "cap.bin", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.write(w, b"abc")
        os.close(w)
        t, box = _run_bounded(
            lambda: diaggulp.slurp(_FakeClient(r), out_fd), wall_limit=5.0
        )
        assert not t.is_alive() and "error" not in box, box.get("error")
        bytes_written, _elapsed = box["result"]
        assert bytes_written == 3
    finally:
        os.close(r)
        os.close(out_fd)


# ── slurp_rotating() reason attribution ─────────────────────────────────────
def test_slurp_rotating_records_eof_when_the_transport_closes():
    r, w = os.pipe()
    try:
        os.write(w, b"abc")
        os.close(w)
        info: dict = {}
        t, box = _run_bounded(
            lambda: diaggulp.slurp_rotating(_FakeClient(r), _RecordingWriter(),
                                            stop_info=info),
            wall_limit=5.0,
        )
        assert not t.is_alive() and "error" not in box, box.get("error")
        assert info.get("reason") == "eof"
    finally:
        os.close(r)


def test_slurp_rotating_records_deadline_not_eof_on_a_timed_stop():
    r, w = os.pipe()
    try:
        info: dict = {}
        t, box = _run_bounded(
            lambda: diaggulp.slurp_rotating(_FakeClient(r), _RecordingWriter(),
                                            max_seconds=0.3, stop_info=info),
            wall_limit=5.0,
        )
        assert not t.is_alive() and "error" not in box, box.get("error")
        assert info.get("reason") == "deadline"
    finally:
        os.close(w)
        os.close(r)


# ── the exit decision main() uses ───────────────────────────────────────────
def test_capture_exit_is_loud_and_nonzero_on_eof():
    code, alarm = diaggulp._capture_exit({"reason": "eof"}, bytes_written=2605005290)
    assert code == 3, "an unexpected mid-capture EOF must be a NON-ZERO exit"
    assert alarm is not None
    assert "EOF" in alarm and "2605005290" in alarm, (
        "the alarm must be operator-visible and name the bytes captured before "
        "the drop"
    )


@pytest.mark.parametrize("reason", ["deadline", "signal", "broken_pipe", None])
def test_capture_exit_is_clean_zero_on_every_non_eof_stop(reason):
    info = {} if reason is None else {"reason": reason}
    code, alarm = diaggulp._capture_exit(info, bytes_written=100)
    assert code == 0, f"{reason!r} is a clean stop and must exit 0"
    assert alarm is None


def test_capture_exit_tolerates_a_none_stop_info():
    """A caller that never populated stop_info (e.g. a signal before the loop)
    must not crash the exit path."""
    assert diaggulp._capture_exit(None, bytes_written=0) == (0, None)

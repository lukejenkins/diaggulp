"""diaggulp's disarming teardown runs to the end once it has started.

Measured on an M3100 (SDX65): a ``--disarm-logs-on-exit
--disarm-qsh-on-exit --restore-f3-mask-on-exit`` capture stopped from outside
printed its F3 restore line, then left log, events and QSH armed: 8.5 MB in 6 s
to nobody. Three things can cut a ``finally:`` short after the first stop
signal, and each is pinned here:

* a second SIGTERM/SIGINT, which re-raised ``KeyboardInterrupt`` mid-disarm;
* a SIGHUP from the dropped shell, which had no handler and killed outright;
* a closed stderr pipe, which turned the next teardown ``print`` into a
  ``BrokenPipeError``.
"""
from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


class _Transport:
    def fileno(self):
        return -1

    def read(self, n):
        return b""

    def close(self):
        pass


class _FakeClient:
    def __init__(self):
        self._transport = _Transport()

    def close(self):
        pass


class _BrokenPipeStream:
    def write(self, s):
        raise BrokenPipeError(32, "Broken pipe")

    def flush(self):
        raise BrokenPipeError(32, "Broken pipe")


def _stub_capture(monkeypatch, *, loop):
    monkeypatch.setattr(d.DiagClient, "from_serial",
                        classmethod(lambda cls, dev, baud=None: _FakeClient()))
    for name in ("_build_all_logs_mask", "_enable_qsh_metrics", "_enable_events"):
        monkeypatch.setattr(d, name, lambda *a, **k: None)
    monkeypatch.setattr(d, "_resync_frame_boundary", lambda *a, **k: 0)
    monkeypatch.setattr(d, "_apply_f3_arming", lambda *a, **k: None)
    monkeypatch.setattr(d, "_enable_qsh_trace", lambda *a, **k: True)
    monkeypatch.setattr(d, "_arm_event_mask", lambda *a, **k: None)
    monkeypatch.setattr(d, "_request_diag_id_binding", lambda *a, **k: None)
    monkeypatch.setattr(d, "_emit_boundary_anchor", lambda *a, **k: None)
    monkeypatch.setattr(d, "slurp", loop)
    done = []
    monkeypatch.setattr(d, "_disarm_qsh_trace", lambda *a, **k: done.append("qsh"))
    return done


def _main(tmp_path):
    return d.main(["/dev/null", "-o", str(tmp_path / "cap.bin"), "--no-nmea",
                   "--no-disk-check", "--quiet", "--disarm-qsh-on-exit",
                   "--disarm-logs-on-exit"])


def _first_stop(*a, **k):
    # The read loop ends the way a first SIGTERM ends it.
    raise KeyboardInterrupt


def test_a_second_sigterm_during_a_disarm_does_not_abort_the_rest(monkeypatch, tmp_path, capsys):
    done = _stub_capture(monkeypatch, loop=_first_stop)

    def _qsh_then_signalled(*a, **k):
        os.kill(os.getpid(), signal.SIGTERM)   # the supervisor's impatient re-send
        done.append("qsh")
    monkeypatch.setattr(d, "_disarm_qsh_trace", _qsh_then_signalled)
    monkeypatch.setattr(d, "_disarm_logs_and_events", lambda *a, **k: done.append("logs"))
    try:
        _main(tmp_path)
    except KeyboardInterrupt:
        pass
    assert done == ["qsh", "logs"]
    assert "held until the disarms finished" in capsys.readouterr().err


def test_a_closed_stderr_pipe_does_not_skip_the_disarms(monkeypatch, tmp_path):
    def _harness_closes_stderr(*a, **k):
        sys.stderr = _BrokenPipeStream()
        raise KeyboardInterrupt
    done = _stub_capture(monkeypatch, loop=_harness_closes_stderr)

    def _logs_that_print(*a, **k):
        print("diaggulp: log + events disarm …", file=sys.stderr)
        done.append("logs")
    monkeypatch.setattr(d, "_disarm_logs_and_events", _logs_that_print)
    saved = sys.stderr
    try:
        _main(tmp_path)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stderr = saved
    assert done == ["qsh", "logs"]


def test_sighup_is_a_stop_and_handlers_are_put_back(monkeypatch, tmp_path):
    seen = {}

    def _loop(*a, **k):
        seen["hup"] = signal.getsignal(signal.SIGHUP)
        raise KeyboardInterrupt
    _stub_capture(monkeypatch, loop=_loop)
    monkeypatch.setattr(d, "_disarm_logs_and_events", lambda *a, **k: None)
    before = signal.signal(signal.SIGHUP, signal.SIG_DFL)
    try:
        try:
            _main(tmp_path)
        except KeyboardInterrupt:
            pass
        assert callable(seen["hup"]) and seen["hup"] is not signal.SIG_DFL
        # Not the teardown's deferring handler: a later signal must still stop.
        after = signal.getsignal(signal.SIGTERM)
        assert after.__name__ != "_defer"
    finally:
        signal.signal(signal.SIGHUP, before)


def test_nohup_keeps_sighup_ignored(monkeypatch, tmp_path):
    seen = {}

    def _loop(*a, **k):
        seen["hup"] = signal.getsignal(signal.SIGHUP)
        raise KeyboardInterrupt
    _stub_capture(monkeypatch, loop=_loop)
    monkeypatch.setattr(d, "_disarm_logs_and_events", lambda *a, **k: None)
    before = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        try:
            _main(tmp_path)
        except KeyboardInterrupt:
            pass
        assert seen["hup"] is signal.SIG_IGN
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, before)

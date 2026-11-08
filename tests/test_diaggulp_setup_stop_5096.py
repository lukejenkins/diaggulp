"""A stop that lands while diaggulp is ARMING still reaches the disarms.

The teardown shield (``test_diaggulp_teardown_shield_5096.py``) covers stops
that arrive once the read loop is running. This file covers the window before
it. The log mask, F3, QSH and events are armed, then the anchors, binding
request and sinks are set up, and only then does the ``try:`` whose
``finally:`` disarms begin. Before the fix:

* SIGTERM / SIGHUP had no handler in that window, so the default action
  killed the process with every plane latched;
* SIGINT raised ``KeyboardInterrupt`` outside the ``try:``, skipping the
  teardown the same way.

Each test signals from INSIDE one setup stage by calling the handler that is
installed at that moment, the same thing a delivered signal runs. A real
``os.kill`` is not used: on the unfixed code a SIGTERM would kill pytest
itself, and the mutation pass needs a clean RED.
"""
from __future__ import annotations

import signal
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402

STOPS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


@pytest.fixture(autouse=True)
def _restore_signal_handlers():
    saved = {s: signal.getsignal(s) for s in STOPS}
    yield
    for s, h in saved.items():
        signal.signal(s, h)


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


def _deliver(sig):
    """Run the handler installed for ``sig`` right now, as delivery would."""
    h = signal.getsignal(sig)
    if not callable(h):
        raise AssertionError(f"signal {sig} has no handler while arming: its "
                             "default action would kill the process, armed")
    try:
        h(sig, None)
    except KeyboardInterrupt:
        raise AssertionError(f"signal {sig} raised while arming: the stop "
                             "would skip the disarming teardown") from None


def _stub(monkeypatch, *, stage, sig, calls):
    """Stub every modem touch; ``stage`` delivers ``sig`` when it runs."""
    monkeypatch.setattr(d.DiagClient, "from_serial",
                        classmethod(lambda cls, dev, baud=None: _FakeClient()))
    monkeypatch.setattr(d, "_resync_frame_boundary", lambda *a, **k: 0)

    def make(name, ret=None):
        def f(*a, **k):
            if name == "_emit_boundary_anchor" and k.get("which") != "pre":
                calls.append("post_anchor")
                return None
            calls.append(name)
            if name == stage:
                _deliver(sig)
            return ret
        return f

    for name, ret in (("_build_all_logs_mask", None), ("_apply_f3_arming", None),
                      ("_enable_qsh_trace", True), ("_enable_qsh_metrics", None),
                      ("_enable_events", None), ("_arm_event_mask", None),
                      ("_request_diag_id_binding", None), ("_emit_boundary_anchor", None)):
        monkeypatch.setattr(d, name, make(name, ret))

    def _loop(*a, **k):
        calls.append("READ_LOOP")
        return 0, 0.0
    monkeypatch.setattr(d, "slurp", _loop)
    monkeypatch.setattr(d, "_disarm_qsh_trace", lambda *a, **k: calls.append("disarm_qsh"))
    monkeypatch.setattr(d, "_disarm_logs_and_events",
                        lambda *a, **k: calls.append("disarm_logs"))


def _main(tmp_path, *extra):
    return d.main(["/dev/null", "-o", str(tmp_path / "cap.bin"), "--no-nmea",
                   "--no-disk-check", "--quiet", "--disarm-qsh-on-exit",
                   "--disarm-logs-on-exit", *extra])


@pytest.mark.parametrize("sig", STOPS, ids=lambda s: signal.Signals(s).name)
@pytest.mark.parametrize("stage", ["_build_all_logs_mask", "_apply_f3_arming",
                                   "_enable_qsh_trace", "_arm_event_mask",
                                   "_emit_boundary_anchor"])
def test_a_stop_while_arming_skips_the_capture_and_still_disarms(
        monkeypatch, tmp_path, capsys, stage, sig):
    calls: list[str] = []
    _stub(monkeypatch, stage=stage, sig=sig, calls=calls)
    rc = _main(tmp_path)
    assert stage in calls, f"stage {stage} never ran: the test would be vacuous"
    assert "READ_LOOP" not in calls
    assert calls[-2:] == ["disarm_qsh", "disarm_logs"]
    assert rc == 0                     # an operator stop, not a failure
    err = capsys.readouterr().err
    assert "stop received while arming" in err
    assert "no capture was taken" in err


def test_several_stops_while_arming_still_run_one_teardown(monkeypatch, tmp_path, capsys):
    calls: list[str] = []
    _stub(monkeypatch, stage="_apply_f3_arming", sig=signal.SIGTERM, calls=calls)
    real = d._enable_qsh_trace

    def _qsh_and_more(*a, **k):
        _deliver(signal.SIGTERM)       # the supervisor's impatient re-send
        _deliver(signal.SIGINT)
        return real(*a, **k)
    monkeypatch.setattr(d, "_enable_qsh_trace", _qsh_and_more)
    assert _main(tmp_path) == 0
    assert calls.count("disarm_logs") == 1 and "READ_LOOP" not in calls
    assert "3 stop signal(s) arrived while arming" in capsys.readouterr().err


def test_without_a_stop_the_read_loop_runs_with_the_raising_handler(monkeypatch, tmp_path):
    calls: list[str] = []
    _stub(monkeypatch, stage="none", sig=signal.SIGTERM, calls=calls)
    seen = {}

    def _loop(*a, **k):
        calls.append("READ_LOOP")
        seen.update({s: signal.getsignal(s) for s in STOPS})
        return 0, 0.0
    monkeypatch.setattr(d, "slurp", _loop)
    assert _main(tmp_path) == 0
    assert "READ_LOOP" in calls
    for s in STOPS:   # in the loop a stop must END it, not be held
        with pytest.raises(KeyboardInterrupt):
            seen[s](s, None)


def test_the_hold_is_gone_once_main_returns(monkeypatch, tmp_path):
    """A caller's later Ctrl-C must not be swallowed by a leftover hold."""
    calls: list[str] = []
    _stub(monkeypatch, stage="_build_all_logs_mask", sig=signal.SIGINT, calls=calls)
    _main(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        signal.getsignal(signal.SIGINT)(signal.SIGINT, None)


def test_an_invalid_log_code_return_puts_the_callers_handlers_back(monkeypatch, tmp_path):
    calls: list[str] = []
    _stub(monkeypatch, stage="none", sig=signal.SIGTERM, calls=calls)

    def sentinel(signum, frame):
        pass
    signal.signal(signal.SIGTERM, sentinel)
    assert _main(tmp_path, "--log-code", "zz") == 2
    assert signal.getsignal(signal.SIGTERM) is sentinel


def test_nohup_keeps_sighup_ignored_while_arming(monkeypatch, tmp_path):
    calls: list[str] = []
    _stub(monkeypatch, stage="none", sig=signal.SIGTERM, calls=calls)
    seen = {}
    real = d._apply_f3_arming

    def _f3(*a, **k):
        seen["hup"] = signal.getsignal(signal.SIGHUP)
        return real(*a, **k)
    monkeypatch.setattr(d, "_apply_f3_arming", _f3)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    _main(tmp_path)
    assert seen["hup"] is signal.SIG_IGN
    assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN

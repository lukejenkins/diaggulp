# SPDX-License-Identifier: Apache-2.0
"""``--disarm-qsh-on-exit`` verification on a modem that delivers DIAG in bursts.

Measured on a Foxconn T99W175 (SDX55, T99W175.F0.1.0.0.9.GC.004):
the port delivers DIAG in flushes every ~1.27 s (largest armed ``0x9D``
inter-arrival gap 1.26-1.29 s across the sweep, a measured pairs file and the
bundled retail maskset). Frames generated before the disarm still arrive in
the next flush, up to ~0.6 s after the disarm reply in 5 runs. The verify's
old 0.5 s settle let that tail into the after-window, so a working disarm
printed "STILL flowing" (2 of 3 runs). Its 1.5 s sample left only 0.23 s of
margin over the flush period for catching a modem that stays armed. An
RM500Q-AE (SDX55) streams continuously, its tail ends within 20 ms, and it
never showed either problem.

These tests drive ``_disarm_qsh_trace`` on a fake clock, so every flush phase
is covered without sleeping.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp  # noqa: E402

PERIOD = 1.27                     # measured T99W175 flush period, seconds
F_9D = bytes.fromhex("9d01020304") + b"\x7e"
F_LOG = bytes.fromhex("1000120012007614") + b"\x00" * 8 + b"\x7e"


class _Clock:
    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t


class _BurstyModem:
    """Delivers everything generated since the previous flush, every PERIOD s.

    A flush carries ``0x9D`` if the maskset was armed at any point in the
    interval it covers, so the frames generated just before a disarm arrive
    up to one PERIOD after it. ``keeps_flowing`` models a disarm the modem
    acknowledges but does not honour.
    """

    def __init__(self, clock, phase, *, keeps_flowing=False):
        self.clock = clock
        self.next_flush = phase
        self.armed_in_interval = True
        self.armed = True
        self.keeps_flowing = keeps_flowing

    def _send_recv(self, op, payload, timeout=5.0):
        if not self.keeps_flowing:
            self.armed = False      # frames already generated still flush later
        return (0x4B, bytes.fromhex("440190") + (0).to_bytes(4, "little"))

    def read_raw(self, timeout=1.0):
        until = self.clock.t + timeout
        if self.next_flush > until:
            self.clock.t = until
            return b""
        self.clock.t = self.next_flush
        self.next_flush += PERIOD
        out = (F_9D * 5 if self.armed_in_interval else b"") + F_LOG
        self.armed_in_interval = self.armed
        return out


@pytest.fixture
def clock(monkeypatch):
    c = _Clock()
    monkeypatch.setattr(diaggulp, "time", types.SimpleNamespace(monotonic=c.monotonic))
    return c


PHASES = [i * PERIOD / 24 for i in range(1, 25)]


@pytest.mark.parametrize("phase", PHASES)
def test_a_honoured_disarm_verifies_at_every_flush_phase(clock, phase, capsys):
    assert diaggulp._disarm_qsh_trace(_BurstyModem(clock, phase)) is True
    assert "VERIFIED on the stream" in capsys.readouterr().err


@pytest.mark.parametrize("phase", PHASES)
def test_a_disarm_the_modem_ignores_is_caught_at_every_flush_phase(clock, phase, capsys):
    m = _BurstyModem(clock, phase, keeps_flowing=True)
    assert diaggulp._disarm_qsh_trace(m) is False
    assert "STILL flowing" in capsys.readouterr().err


def test_the_old_half_second_settle_reproduces_the_false_alarm(clock, capsys):
    """The pre-fix constants, with a flush just before the disarm: the tail
    lands ~1.26 s later, inside the after-window."""
    m = _BurstyModem(clock, phase=1.5 - 0.01)
    assert diaggulp._disarm_qsh_trace(m, sample_s=1.5, settle_s=0.5) is False
    assert "STILL flowing" in capsys.readouterr().err


def test_the_default_windows_clear_the_measured_flush_period():
    import inspect
    params = inspect.signature(diaggulp._disarm_qsh_trace).parameters
    assert params["settle_s"].default > PERIOD
    assert params["sample_s"].default > PERIOD

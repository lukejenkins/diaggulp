"""Bounded F3 (SET_RT_MASK) arming must warn that an ACK is not F3 flow.

The bounded ``--ext-msg-f3-preset ml1`` / ``--ext-msg-f3-ss`` path arms one
``SET_RT_MASK`` per SSID. On SDX55 (RM500Q-AE) every arm ACKed (no
``DIAG_BAD_CMD_F``) yet the capture carried ZERO F3 frames, while the unbounded
``SET_ALL_RT_MASKS`` on the same modem gave millions — the bounded path is
acked-but-inert on that build, and the failure is silent and in the
safe-looking direction (arm succeeds, log line reads affirmative, capture is
large, absence only visible in the ``.scan.json`` ``f3`` block).

So the success path itself must carry the caveat. This pins that a clean bounded
arm still prints the acked-but-inert warning pointing at the unbounded fallback —
a regression that dropped it would restore the exact silent trap described above.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


class _FakeClient:
    """Minimal DiagClient stand-in: every SET_RT_MASK ACKs (op != BAD_CMD),
    mirroring the SDX55 behaviour where arming succeeds but F3 never flows."""

    def __init__(self):
        self.sent = []

    def _send_recv(self, cmd_code, payload, timeout=None):
        self.sent.append((cmd_code, payload))
        # Echo the command code as a benign ACK opcode (anything != BAD_CMD).
        return (cmd_code, b"")


def test_bounded_arm_acks_but_warns_about_zero_f3(capsys):
    client = _FakeClient()
    d._enable_ext_msg_f3_bounded(client, [1007, 3001, 9509, 9520], 0xFFFFFFFF)

    err = capsys.readouterr().err
    # It armed all four (the ACK path), and it warned about the acked-but-inert
    # risk, naming the unbounded fallback.
    assert "armed bounded F3" in err
    assert "NOT confirmed" in err
    assert "SET_ALL_RT_MASKS" in err or "--ext-msg-f3-level all" in err
    # All four SSIDs were actually sent (one SET_RT_MASK each).
    assert len(client.sent) == 4

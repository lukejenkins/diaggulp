#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""The anchor sidecar must not depend on modem cooperation.

Before this, a modem that never answers DIAG_VERNO_F (the LM960A18 /
SDX20 flush-on-OUT firmware, whose quirk path force-disabled the anchor
outright) produced **no** ``<output>.anchors.json`` at all — the 1.87 GB
LM960A18 leg of a three-modem wardrive had no DIAG↔host
clock mapping, so 342 gpsd fixes could not be tied to 2.4 M DIAG records
except by inference.

Two guarantees are tested here:

1. A boundary anchor is **always** produced — the real VERNO round trip
   when the modem answers (including over the pumped telit path), a
   host-side bracket when it does not.
2. The precision class is **stated, not implied** — per-anchor and
   summarised at the top of the sidecar — so a consumer can tell a
   modem-acknowledged anchor from a host-side one.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
try:
    import serial  # noqa: F401  # real pyserial is in .venv
except ImportError:
    sys.modules["serial"] = MagicMock()

import diaggulp  # noqa: E402

VERNO = diaggulp.DIAG_VERNO_F


def _verno_anchor(mono=1_000, rtt=500):
    """A dict shaped like DiagClient.emit_version_anchor()'s return."""
    return {
        "opcode": VERNO,
        "host_mono_ns": mono,
        "host_mono_recv_ns": mono + rtt,
        "response_bytes_hex": "4d32303030",
        "rtt_ns": rtt,
    }


class _Client:
    """Duck-typed DiagClient: emit_version_anchor answers, times out, or raises."""

    def __init__(self, result=None, raises=None):
        self._result = result
        self._raises = raises
        self.calls = 0

    def emit_version_anchor(self, timeout=2.0):
        self.calls += 1
        if self._raises is not None:
            raise self._raises
        return self._result


class TestHostBracketAnchor:
    def test_self_labels_its_precision_class(self):
        a = diaggulp._host_bracket_anchor()
        assert a["method"] == "host_bracket"

    def test_carries_both_monotonic_and_wall_clock(self):
        """monotonic pins it to the capture; unix_ns is what makes it
        comparable to gpsd fixes and to the other modems on the drive."""
        a = diaggulp._host_bracket_anchor()
        assert a["host_mono_ns"] > 0
        assert a["host_unix_ns"] > 1_700_000_000_000_000_000

    def test_omits_host_mono_recv_ns(self):
        """There is no response, so there is no recv instant. Emitting one
        would make the consumer's _anchor_mono_ns average a fabricated pair
        instead of falling through to the single known timestamp."""
        assert "host_mono_recv_ns" not in diaggulp._host_bracket_anchor()


class TestEmitBoundaryAnchor:
    def test_passes_through_a_real_verno_anchor(self):
        client = _Client(result=_verno_anchor())
        got = diaggulp._emit_boundary_anchor(
            client, which="pre", timeout=2.0, telit_quirk=False, quiet=True)
        assert got["opcode"] == VERNO
        assert "method" not in got   # defaulted at sidecar-build time

    def test_falls_back_to_host_bracket_on_timeout(self):
        client = _Client(result=None)
        got = diaggulp._emit_boundary_anchor(
            client, which="pre", timeout=0.1, telit_quirk=False, quiet=True)
        assert got["method"] == "host_bracket"

    def test_falls_back_to_host_bracket_on_transport_exception(self):
        """A dead transport at tN must not cost the capture its sidecar —
        host time at the boundary is still a true fact about the capture."""
        client = _Client(raises=OSError("device gone"))
        got = diaggulp._emit_boundary_anchor(
            client, which="post", timeout=0.1, telit_quirk=False, quiet=True)
        assert got["method"] == "host_bracket"

    def test_never_returns_none(self):
        for client in (_Client(None), _Client(raises=RuntimeError("x"))):
            assert diaggulp._emit_boundary_anchor(
                client, which="pre", timeout=0.1,
                telit_quirk=False, quiet=True) is not None

    def test_telit_quirk_routes_to_the_pumped_anchor(self, monkeypatch):
        """The plain write+read path is exactly what the LM960A18 does not
        answer; the quirk flag must select the pumped/kicked variant."""
        seen = {}
        client = _Client(result=_verno_anchor(mono=7))

        def fake(c, *, timeout=2.0, kick_every=0.4):
            seen["called"] = True
            return _verno_anchor(mono=42)

        monkeypatch.setattr(diaggulp, "_telit_version_anchor", fake)
        got = diaggulp._emit_boundary_anchor(
            client, which="pre", timeout=2.0, telit_quirk=True, quiet=True)
        assert seen.get("called") is True
        assert client.calls == 0          # plain path not used
        assert got["host_mono_ns"] == 42

    def test_telit_quirk_silence_still_yields_a_sidecar_anchor(self, monkeypatch):
        """The regression this suite exists for."""
        monkeypatch.setattr(
            diaggulp, "_telit_version_anchor",
            lambda c, **kw: None)
        got = diaggulp._emit_boundary_anchor(
            _Client(None), which="pre", timeout=0.1,
            telit_quirk=True, quiet=True)
        assert got["method"] == "host_bracket"

    def test_fallback_warning_is_printed_even_when_quiet(self, capsys):
        """Losing anchor precision is an operator-visible degradation, not
        chatter — --quiet must not hide it."""
        diaggulp._emit_boundary_anchor(
            _Client(None), which="pre", timeout=0.1,
            telit_quirk=False, quiet=True)
        err = capsys.readouterr().err
        assert "host_bracket" in err


class TestTelitVersionAnchor:
    """The pumped/kicked VERNO exchange — the 'try to make it work'
    half of the fix, before any fallback."""

    def _client(self, frames):
        """frames: list of (opcode, body) to hand back, then silence."""
        class C:
            def __init__(self):
                self.sent = []
                self._frames = list(frames)

            def send(self, opcode, payload):
                self.sent.append((opcode, payload))

            def recv(self, timeout=None):
                if not self._frames:
                    raise TimeoutError
                return self._frames.pop(0)
        return C()

    def test_returns_anchor_when_verno_reply_arrives(self, monkeypatch):
        monkeypatch.setattr(diaggulp, "_telit_write_pumped", lambda *a, **k: None)
        client = self._client([(VERNO, b"M2000B")])
        got = diaggulp._telit_version_anchor(client, timeout=1.0)
        assert got is not None
        assert got["opcode"] == VERNO
        assert got["response_bytes_hex"] == b"M2000B".hex()
        assert got["rtt_ns"] == got["host_mono_recv_ns"] - got["host_mono_ns"]

    def test_ignores_unrelated_frames_until_the_verno_reply(self, monkeypatch):
        """The kick loop's own LOG_CONFIG replies (and any log traffic) must
        not be mistaken for the anchor response."""
        monkeypatch.setattr(diaggulp, "_telit_write_pumped", lambda *a, **k: None)
        client = self._client([
            (diaggulp._DIAG_LOG_CONFIG_F, b"\x00" * 8),
            (0x10, b"log"),
            (VERNO, b"OK"),
        ])
        got = diaggulp._telit_version_anchor(client, timeout=1.0)
        assert got is not None
        assert got["response_bytes_hex"] == b"OK".hex()

    def test_returns_none_on_silence(self, monkeypatch):
        monkeypatch.setattr(diaggulp, "_telit_write_pumped", lambda *a, **k: None)
        assert diaggulp._telit_version_anchor(
            self._client([]), timeout=0.2) is None

    def test_returns_none_when_the_pumped_write_wedges(self, monkeypatch):
        """A wedged OUT is a known failure mode; here it must degrade to
        None (-> host_bracket), never propagate and kill the capture."""
        def boom(*a, **k):
            raise RuntimeError("modem refused OUT (IN buffer wedged)")
        monkeypatch.setattr(diaggulp, "_telit_write_pumped", boom)
        assert diaggulp._telit_version_anchor(
            self._client([(VERNO, b"x")]), timeout=1.0) is None


class TestAnchorSidecarDoc:
    def test_verno_pair_summarises_as_diag_verno_response(self):
        doc = diaggulp._anchor_sidecar_doc(_verno_anchor(1), _verno_anchor(2))
        assert doc["method"] == "diag_verno_response"
        assert [a["kind"] for a in doc["anchors"]] == ["start", "end"]
        assert all(a["method"] == "diag_verno_response" for a in doc["anchors"])

    def test_host_bracket_pair_summarises_as_host_bracket(self):
        b = diaggulp._host_bracket_anchor()
        doc = diaggulp._anchor_sidecar_doc(dict(b), dict(b))
        assert doc["method"] == "host_bracket"

    def test_disagreeing_boundaries_summarise_as_mixed(self):
        """Answered VERNO at t0, wedged/unplugged by tN. Neither label is
        true of the pair, so the summary must not pick one."""
        doc = diaggulp._anchor_sidecar_doc(
            _verno_anchor(1), diaggulp._host_bracket_anchor())
        assert doc["method"] == "mixed"
        assert doc["anchors"][0]["method"] == "diag_verno_response"
        assert doc["anchors"][1]["method"] == "host_bracket"

    def test_shape_is_stable_for_existing_consumers(self):
        doc = diaggulp._anchor_sidecar_doc(_verno_anchor(), _verno_anchor())
        assert doc["version"] == 1
        assert doc["tool"] == "diaggulp.py"
        assert set(doc) == {"version", "method", "tool", "anchors"}


class TestConsumerReadsHostBracket:
    """The sidecar is only worth writing if diaggrok_at_correlate can use it."""

    def test_anchor_mono_ns_uses_the_single_host_timestamp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_corr_for_test", TOOLS / "diaggrok_at_correlate.py")
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception as exc:                      # pragma: no cover
            pytest.skip(f"diaggrok_at_correlate not importable here: {exc}")
        a = diaggulp._host_bracket_anchor()
        assert mod._anchor_mono_ns(a) == a["host_mono_ns"]

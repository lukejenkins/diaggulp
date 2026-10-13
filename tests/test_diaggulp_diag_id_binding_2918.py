"""diaggulp asks the modem for its QSHRINK4 diag_id binding table.

The ``0x4B / subsys 0x12 / cmd 0x0222`` table (DIAGNOSTIC_SERVICES_DIAGID_TABLE)
only ever appeared in on-device ``diag_mdlog`` captures — 0 of 271 measured
host-tool captures carried it — because it is the RESPONSE to a client's
session-start request. Measured live on EM9190 / T99W175 (SDX55) and
two RM520N-GL builds (SDX62): the bare 4-byte request is silently dropped, and
``4B 12 22 02 01`` (payload = u8 version 1) returns the table. SDX20 / MDM9607
answer ``0x13``.

These pin the request bytes, the four recorded outcomes, and that the record
rides the existing ``<output>.anchors.json`` sidecar, so a DLF capture — whose
container cannot hold a command response — still carries its binding.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402

# The response body observed byte-identical on all four serving units.
TABLE_BODY = bytes.fromhex(
    "12220201020105415050530002126d646d2f6d6f64656d2f726f6f745f706400")


class _Client:
    """DiagClient stand-in: records what was sent, returns a fixed reply."""

    def __init__(self, reply=None, raise_exc: Exception | None = None):
        self._reply = reply
        self._raise = raise_exc
        self.sent: list[tuple[int, bytes]] = []

    def _send_recv(self, opcode, payload, timeout=None):
        self.sent.append((opcode, payload))
        if self._raise is not None:
            raise self._raise
        return self._reply


# ── the request ─────────────────────────────────────────────────────────────

def test_request_is_the_versioned_five_byte_form():
    c = _Client(reply=(0x4B, TABLE_BODY))
    d._request_diag_id_binding(c, timeout=1.0, quiet=True)
    assert c.sent == [(0x4B, bytes.fromhex("12220201"))]


# ── the four outcomes ───────────────────────────────────────────────────────

def test_table_reply_is_recorded_verbatim():
    rec = d._request_diag_id_binding(_Client(reply=(0x4B, TABLE_BODY)),
                                     timeout=1.0, quiet=True)
    assert rec["status"] == "table"
    assert rec["request_hex"] == "4b12220201"
    assert rec["response_hex"] == "4b" + TABLE_BODY.hex()
    assert rec["rtt_ns"] >= 0 and rec["host_mono_ns"] > 0


def test_bad_cmd_reply_is_a_measured_negative():
    rec = d._request_diag_id_binding(_Client(reply=(d.DIAG_BAD_CMD_F, bytes.fromhex("4b12220201"))),
                                     timeout=1.0, quiet=True)
    assert rec["status"] == "bad_cmd"
    assert rec["response_hex"] == "134b12220201"


def test_timeout_is_recorded_not_raised():
    rec = d._request_diag_id_binding(_Client(reply=None), timeout=0.01, quiet=True)
    assert rec["status"] == "timeout"
    assert rec["response_hex"] is None


def test_unexpected_reply_is_kept_but_not_called_a_table():
    rec = d._request_diag_id_binding(_Client(reply=(0x4B, bytes.fromhex("12230202"))),
                                     timeout=1.0, quiet=True)
    assert rec["status"] == "unexpected"
    assert rec["response_hex"] == "4b12230202"


def test_transport_error_is_recorded_not_raised():
    rec = d._request_diag_id_binding(_Client(raise_exc=OSError("gone")),
                                     timeout=1.0, quiet=True)
    assert rec["status"] == "error"
    assert "gone" in rec["detail"]


def test_telit_quirk_path_skips_and_says_why():
    c = _Client(reply=(0x4B, TABLE_BODY))
    rec = d._request_diag_id_binding(c, timeout=1.0, quiet=True, telit_quirk=True)
    assert rec["status"] == "skipped"
    assert "telit" in rec["detail"].lower()
    assert c.sent == []


def test_log_line_names_the_outcome(capsys):
    d._request_diag_id_binding(_Client(reply=(0x4B, TABLE_BODY)), timeout=1.0, quiet=False)
    err = capsys.readouterr().err
    assert "diag_id binding" in err and "table" in err
    assert TABLE_BODY.hex() in err


# ── the sidecar ─────────────────────────────────────────────────────────────

def test_sidecar_doc_carries_the_binding_record():
    pre = {"opcode": 0, "host_mono_ns": 1, "host_mono_recv_ns": 2,
           "response_bytes_hex": "", "rtt_ns": 1}
    rec = {"status": "table", "request_hex": "4b12220201",
           "response_hex": "4b" + TABLE_BODY.hex()}
    doc = d._anchor_sidecar_doc(pre, None, diag_id_binding=rec)
    assert doc["diag_id_binding"] == rec
    assert doc["anchors"][0]["kind"] == "start"


def test_sidecar_doc_without_a_record_has_no_key():
    doc = d._anchor_sidecar_doc(None, None)
    assert "diag_id_binding" not in doc
    assert doc["anchors"] == []


# ── the flag ────────────────────────────────────────────────────────────────

def test_flag_is_default_on_and_negatable():
    p = d.build_arg_parser()
    assert p.parse_args(["--output", "x.dlf"]).diag_id_binding is True
    assert p.parse_args(["--output", "x.dlf", "--no-diag-id-binding"]).diag_id_binding is False

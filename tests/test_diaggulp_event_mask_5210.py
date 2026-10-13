"""diaggulp records, and optionally narrows, the DIAG event mask.

Behaviour measured live, which ``_FakeModem`` below emulates:

- ``0x60`` on sets EVERY event bit; ``0x60`` off clears every bit (Sierra
  EM9291 SDX62, num_bits 3428; Quectel EM160R-GL, num_bits 3240).
- The EM9291 answers ``0x81`` only as exactly ``81 00 00 00`` and silently
  drops the bare opcode. The EM160R answers both.
- A ``0x82`` SET must carry ``num_bits//8 + 1`` mask bytes. When num_bits is a
  multiple of 8 (EM160R: 3240) a SET of the GET width (``ceil``) is REFUSED,
  but the modem still replies, echoing the unchanged mask at the SET width.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


class _FakeModem:
    """A DiagClient stand-in emulating the measured event-mask firmware rules."""

    def __init__(self, num_bits: int, *, strict_get: bool, all_on: bool = False):
        self.num_bits = num_bits
        self.strict_get = strict_get
        self.bits = set(range(num_bits)) if all_on else set()
        self.sent: list[tuple[int, bytes]] = []

    def _body(self, width: int) -> bytes:
        m = bytearray(width)
        for i in self.bits:
            m[i // 8] |= 1 << (i % 8)
        return struct.pack("<BHH", 0, 0, self.num_bits) + bytes(m)

    def _send_recv(self, opcode, payload, timeout=None):
        self.sent.append((opcode, payload))
        if opcode == 0x60:
            self.bits = set(range(self.num_bits)) if payload[:1] == b"\x01" else set()
            return 0x60, b"\x00\x00"
        if opcode == 0x81:
            if self.strict_get and payload != b"\x00\x00\x00":
                return None                      # silently dropped
            return 0x81, self._body((self.num_bits + 7) // 8)
        if opcode == 0x82:
            nb = struct.unpack_from("<H", payload, 3)[0]
            mask = payload[5:]
            if nb == self.num_bits and len(mask) == self.num_bits // 8 + 1:
                self.bits = {i for i in range(nb) if mask[i // 8] >> (i % 8) & 1}
            return 0x82, self._body(self.num_bits // 8 + 1)
        raise AssertionError(f"unexpected opcode {opcode:#x}")


# ── recording (no --event-ids) ──────────────────────────────────────────────

def test_records_the_all_on_mask_after_the_0x60_switch():
    m = _FakeModem(3428, strict_get=True)
    d._enable_events(m)
    rec = d._arm_event_mask(m, None)
    assert rec["status"] == "ok"
    assert rec["armed"]["num_bits"] == 3428
    assert rec["armed"]["enabled_count"] == 3428
    assert rec["get_request_hex"] == "81000000"
    assert "requested_ids" not in rec
    assert not any(op == 0x82 for op, _ in m.sent)   # recording never SETs


def test_strict_get_part_is_read_with_the_four_byte_form_first():
    m = _FakeModem(3428, strict_get=True, all_on=True)
    d._arm_event_mask(m, None)
    assert m.sent[0] == (0x81, b"\x00\x00\x00")


def test_unanswered_get_is_recorded_not_fatal():
    class _Silent:
        def _send_recv(self, opcode, payload, timeout=None):
            return None
    rec = d._arm_event_mask(_Silent(), [0xA30])
    assert rec["status"] == "get_unanswered"
    assert rec["requested_ids"] == [0xA30]


def test_bad_cmd_is_recorded_not_fatal():
    class _Bad:
        def _send_recv(self, opcode, payload, timeout=None):
            return 0x13, bytes([opcode]) + payload
    assert d._arm_event_mask(_Bad(), None)["status"] == "get_unanswered"


def test_transport_exception_is_swallowed():
    class _Boom:
        def _send_recv(self, opcode, payload, timeout=None):
            raise OSError("EIO")
    rec = d._arm_event_mask(_Boom(), None)
    assert rec["status"] == "transport_error"
    assert "EIO" in rec["error"]


def test_telit_quirk_path_is_skipped():
    m = _FakeModem(3428, strict_get=True, all_on=True)
    rec = d._arm_event_mask(m, None, telit_quirk=True)
    assert rec["status"] == "skipped_telit_quirk"
    assert m.sent == []


# ── narrowing (--event-ids) ─────────────────────────────────────────────────

@pytest.mark.parametrize("num_bits,strict", [(3428, True), (3240, False)])
def test_narrows_to_exactly_the_requested_ids(num_bits, strict):
    m = _FakeModem(num_bits, strict_get=strict)
    d._enable_events(m)
    rec = d._arm_event_mask(m, [0xA30, 0x10])
    assert rec["status"] == "ok"
    assert rec["narrowed_verified"] is True
    assert rec["requested_ids"] == [0x10, 0xA30]
    assert rec["armed"]["enabled_count"] == 2
    assert m.bits == {0x10, 0xA30}


def test_em160r_multiple_of_8_width_is_actually_applied():
    # The live bug: at num_bits 3240 a GET-width SET is refused yet replies.
    # The narrowing is only real if the SET used num_bits//8 + 1 bytes.
    m = _FakeModem(3240, strict_get=False, all_on=True)
    rec = d._arm_event_mask(m, [0xA30])
    assert rec["narrowed_verified"] is True
    (set_payload,) = [p for op, p in m.sent if op == 0x82]
    assert len(set_payload) == 5 + 406


def test_unverified_narrow_is_flagged():
    # A modem that refuses every SET (always echoes the old mask): the record
    # must say not-verified, never claim success from the 0x82 reply.
    class _Refuser(_FakeModem):
        def _send_recv(self, opcode, payload, timeout=None):
            if opcode == 0x82:
                self.sent.append((opcode, payload))
                return 0x82, self._body(self.num_bits // 8 + 1)
            return super()._send_recv(opcode, payload, timeout)
    m = _Refuser(3428, strict_get=True, all_on=True)
    rec = d._arm_event_mask(m, [0xA30])
    assert rec["status"] == "ok"
    assert rec["narrowed_verified"] is False
    assert rec["armed"]["enabled_count"] == 3428


def test_out_of_range_ids_leave_the_mask_untouched():
    m = _FakeModem(3240, strict_get=False, all_on=True)
    rec = d._arm_event_mask(m, [0xA30, 3240, 5000])
    assert rec["status"] == "ids_out_of_range"
    assert rec["out_of_range_ids"] == [3240, 5000]
    assert not any(op == 0x82 for op, _ in m.sent)
    assert len(m.bits) == 3240


def test_a_later_0x60_undoes_the_narrowing():
    # Why the reconnect path re-applies the mask after its own 0x60.
    m = _FakeModem(3428, strict_get=True)
    d._enable_events(m)
    d._arm_event_mask(m, [0xA30])
    assert m.bits == {0xA30}
    d._enable_events(m)
    assert len(m.bits) == 3428


# ── sidecar + CLI ───────────────────────────────────────────────────────────

def test_record_rides_the_anchors_sidecar():
    rec = {"version": 1, "status": "ok"}
    doc = d._anchor_sidecar_doc(None, None, event_mask=rec)
    assert doc["event_mask"] == rec
    json.dumps(doc)
    assert "event_mask" not in d._anchor_sidecar_doc(None, None)


def test_event_ids_parse_hex_and_decimal():
    args = d.build_arg_parser().parse_args(["--event-ids", "0xA30,16"])
    assert args.event_ids == [0xA30, 16]
    assert d.build_arg_parser().parse_args([]).event_ids is None


def test_event_ids_with_no_events_enable_is_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        d.main(["--event-ids", "0xA30", "--no-events-enable"])
    assert exc.value.code == 2
    # the specific refusal, not argparse's "unrecognized arguments"
    assert "cannot be combined with --no-events-enable" in capsys.readouterr().err


# ── MDM9625: 0x60 on does NOT fill the mask ─────────────────────────
#
# Measured on the T77W595 / HP lt4120 (MDM9625, num_bits 2825): 0x60 on is acked, but the 0x81 readback afterwards has 0 of
# 2825 ids set, and the capture carries zero 0x60 frames. Without --event-ids the
# capture must fill the mask itself, or "events on" arms nothing.

class _EmptyAfterEnableModem(_FakeModem):
    def _send_recv(self, opcode, payload, timeout=None):
        if opcode == 0x60:
            self.sent.append((opcode, payload))
            return 0x60, b"\x00\x00"             # acked, mask untouched
        return super()._send_recv(opcode, payload, timeout)


def test_empty_mask_after_0x60_is_filled_with_every_id():
    m = _EmptyAfterEnableModem(2825, strict_get=True)
    d._enable_events(m)
    rec = d._arm_event_mask(m, None)
    assert rec["status"] == "ok"
    assert rec["auto_filled"] is True
    assert rec["fill_verified"] is True
    assert rec["armed"]["enabled_count"] == 2825
    assert m.bits == set(range(2825))
    (set_payload,) = [p for op, p in m.sent if op == 0x82]
    assert len(set_payload) == 5 + 2825 // 8 + 1


def test_unverified_fill_is_flagged():
    class _Refuser(_EmptyAfterEnableModem):
        def _send_recv(self, opcode, payload, timeout=None):
            if opcode == 0x82:
                self.sent.append((opcode, payload))
                return 0x82, self._body(self.num_bits // 8 + 1)   # replies, ignores
            return super()._send_recv(opcode, payload, timeout)
    m = _Refuser(2825, strict_get=True)
    d._enable_events(m)
    rec = d._arm_event_mask(m, None)
    assert rec["auto_filled"] is True
    assert rec["fill_verified"] is False
    assert rec["armed"]["enabled_count"] == 0


def test_a_full_mask_is_never_rewritten():
    m = _FakeModem(3428, strict_get=True)
    d._enable_events(m)
    rec = d._arm_event_mask(m, None)
    assert "auto_filled" not in rec
    assert not any(op == 0x82 for op, _ in m.sent)

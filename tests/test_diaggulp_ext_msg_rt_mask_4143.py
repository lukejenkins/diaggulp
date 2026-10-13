"""0x7D mask-table readback, the corrected SET_RT_MASK wire, and the F3 mask restore.

Every byte string in this file is a **verbatim capture from a live Quectel
EG25-G** (MDM9607, ``EG25GGBR07A08M2G``, ``/dev/ttyUSB0``), not a
body synthesised to match the parser's own assumptions.

⚠️ That distinction is the whole point here. An audit found that the two
pre-existing ``QUERY_SSID_RANGES`` tests "could never have caught" a wrong
layout because they built their fixtures from the parser's belief — the parser
and the test agreed with each other and both disagreed with the modem. The
offset-7-vs-9 bug fixed in this change is the same shape: a *uniform* table of
byte-splat values is invariant under the 16-bit rotation a 2-byte misalignment
produces, so a fixture built from splat values cannot distinguish the two
offsets at all. The non-uniform rows below are the ones that can, and they are
here for exactly that reason.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import importlib.util

_SPEC = importlib.util.spec_from_file_location(
    "diaggulp_4143",
    os.path.join(os.path.dirname(__file__), "..", "diaggulp.py"),
)
diaggulp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diaggulp)


# --------------------------------------------------------------------------
# Verbatim wire, EG25-G
# --------------------------------------------------------------------------

#: sub_cmd 3 reply on a modem whose F3 plane is at its post-enumeration default.
#: 495 bytes == 7 + 4*122, all-zero payload.
RT_REPLY_ALL_ZERO = bytes.fromhex("0300000000010000") + b"\x00" * 487

#: sub_cmd 2 reply for the request ``02 0000 7800`` (ss 0..120): 491 bytes
#: == 7 + 4*121. Header + the first eight capability entries as measured.
CAP_REPLY_HEAD = bytes.fromhex(
    "020000790001"          # sub_cmd=2, first=0, last=121(constant), status=1
    "00"                    # status high byte
    "1f0000001e0000001f000000180000001f0000001f0000001e0000001c000000"
)

#: A bare 1-byte request returns a header with NO array — the "short reply
#: was a short REQUEST" finding, which must parse as "unreadable", not as zero.
RT_REPLY_HEADER_ONLY = bytes.fromhex("03607d7e000000")


def test_the_mask_table_array_starts_at_offset_seven_not_nine():
    """495 == 7 + 4*122 exactly; offset 9 would not divide evenly."""
    parsed = diaggulp.parse_ext_msg_mask_table_reply(RT_REPLY_ALL_ZERO)
    assert parsed is not None
    sub_cmd, first, last, status, masks = parsed
    assert sub_cmd == diaggulp.EXT_MSG_GET_RT_MASK
    assert len(RT_REPLY_ALL_ZERO) == 495
    assert len(masks) == 122
    assert 7 + 4 * len(masks) == len(RT_REPLY_ALL_ZERO)
    assert status == 1
    assert set(masks) == {0}


def test_the_capability_table_is_121_entries_and_last_is_a_constant_not_a_length():
    """sub_cmd 2's [3:5] reads 121 (size of SSID range 0), not the array length.

    Reading it as a length is the natural mistake and it is wrong in the
    dangerous direction: for the ``ss 0..0`` request the reply holds ONE entry
    while that field still says 121.
    """
    body = CAP_REPLY_HEAD + b"\x00" * (491 - len(CAP_REPLY_HEAD))
    parsed = diaggulp.parse_ext_msg_mask_table_reply(body)
    assert parsed is not None
    sub_cmd, first, last, status, masks = parsed
    assert sub_cmd == diaggulp.EXT_MSG_GET_BUILD_MASK
    assert last == 121
    assert len(masks) == 121          # 121 entries, and `last` also reads 121…
    assert masks[:8] == [0x1F, 0x1E, 0x1F, 0x18, 0x1F, 0x1F, 0x1E, 0x1C]

    # …but for the 1-entry reply the field STILL says 121, so it is not a length.
    one = bytes.fromhex("020000790001001f000000")
    parsed_one = diaggulp.parse_ext_msg_mask_table_reply(one)
    assert parsed_one is not None
    assert parsed_one[2] == 121
    assert parsed_one[4] == [0x1F]


def test_a_header_only_reply_parses_as_unreadable_never_as_zero():
    """The failure this exists to close: "unreadable" must not read as "silent"."""
    assert diaggulp.parse_ext_msg_mask_table_reply(RT_REPLY_HEADER_ONLY) is None
    assert diaggulp.parse_ext_msg_mask_table_reply(b"") is None
    assert diaggulp.parse_ext_msg_mask_table_reply(b"\x03\x00\x00") is None
    # A trailing partial u32 is also not a table.
    assert diaggulp.parse_ext_msg_mask_table_reply(
        RT_REPLY_ALL_ZERO + b"\x00\x00") is None
    # A different sub-command's reply is not a mask table.
    assert diaggulp.parse_ext_msg_mask_table_reply(
        bytes.fromhex("0501001f000000")) is None


# --------------------------------------------------------------------------
# SET_ALL_RT_MASKS stores a cumulative prefix-OR
# --------------------------------------------------------------------------

#: requested -> stored, measured by sub_cmd 3 readback after each arm. The last
#: five rows were stated as PREDICTIONS before the arm and all five held.
SET_ALL_STORED = [
    (0x00000000, 0x00000000),
    (0x0000001F, 0x1F1F1F1F),
    (0x000000AB, 0xABABABAB),
    (0x00000078, 0x78787878),
    (0x000F041F, 0x1F1F1F1F),
    (0xFFFFFFFF, 0xFFFFFFFF),
    (0x12345678, 0x7E7E7E78),
    (0xAABBCCDD, 0xFFFFDDDD),
    (0x0000FF7E, 0xFFFFFF7E),
    (0x01020408, 0x0F0E0C08),
    (0x80402010, 0xF0703010),
    (0x0000FF00, 0xFFFFFF00),
    (0x00FF0000, 0xFFFF0000),
    (0x00008001, 0x81818101),
    (0x08040201, 0x0F070301),
    (0x0000C003, 0xC3C3C303),
]


@pytest.mark.parametrize("requested,stored", SET_ALL_STORED)
def test_set_all_stores_a_cumulative_prefix_or_of_the_request_bytes(requested, stored):
    assert diaggulp.ext_msg_set_all_stored_mask(requested) == stored


def test_the_low_byte_splat_is_only_the_special_case_not_the_rule():
    """The older "low byte replicated x4" reading is a subset, and it is wrong
    on every request with more than one non-zero byte."""
    splat = lambda v: int.from_bytes(bytes([v & 0xFF]) * 4, "little")
    single_byte = [r for r, _ in SET_ALL_STORED if r <= 0xFF]
    assert single_byte, "fixture must contain single-byte requests"
    for req in single_byte:
        assert diaggulp.ext_msg_set_all_stored_mask(req) == splat(req)
    # …and diverges wherever a second byte is set.
    diverging = [(r, s) for r, s in SET_ALL_STORED if r > 0xFF and r != 0xFFFFFFFF]
    assert diverging
    assert any(splat(r) != s for r, s in diverging)


def test_the_prefix_or_is_little_endian_cumulative_not_big_endian():
    """0x08040201 -> 0x0F070301 (LE). A big-endian fold gives 0x080C0E0F."""
    assert diaggulp.ext_msg_set_all_stored_mask(0x08040201) == 0x0F070301
    assert diaggulp.ext_msg_set_all_stored_mask(0x08040201) != 0x080C0E0F


def test_the_two_exact_endpoints_are_fixed_points():
    """Only all-zero and all-ones survive SET_ALL unchanged — which is why a
    *reduced* mask silently arms more than asked."""
    fixed = [v for v in (0x00000000, 0xFFFFFFFF)]
    for v in fixed:
        assert diaggulp.ext_msg_set_all_stored_mask(v) == v
    assert diaggulp.ext_msg_set_all_stored_mask(0x0000001F) != 0x0000001F


# --------------------------------------------------------------------------
# The corrected SET_RT_MASK wire
# --------------------------------------------------------------------------

def test_set_rt_mask_request_carries_the_status_u16_and_puts_the_mask_at_offset_7():
    req = diaggulp._build_ext_msg_set_rt_mask(7, 7, 0x01020408)
    assert req == bytes.fromhex("0407000700000008040201")
    assert req[0] == diaggulp.EXT_MSG_SET_RT_MASK
    assert len(req) == diaggulp.EXT_MSG_MASK_TABLE_HDR_LEN + 4
    assert int.from_bytes(req[5:7], "little") == 0        # the status field
    assert int.from_bytes(req[7:11], "little") == 0x01020408


def test_the_old_wire_form_put_our_own_bytes_7_and_8_into_the_stored_mask():
    """Regression pin for the bug, stated as the modem's own arithmetic.

    The old ``<BHHI`` request for ss 7 <- 0x01020408 was
    ``04 0700 0700 08040201`` — 9 bytes. The firmware reads the mask at offset
    7, i.e. bytes 7 and 8 (``02 01``) plus two bytes past the buffer. The modem
    stored ``0xA2CC0102``: its low half is exactly those two bytes.
    """
    from struct import pack

    old = pack("<BHHI", diaggulp.EXT_MSG_SET_RT_MASK, 7, 7, 0x01020408)
    assert old == bytes.fromhex("040700070008040201")
    assert len(old) == 9                       # too short to hold a mask at 7
    assert old[7:9] == bytes.fromhex("0201")
    assert (0xA2CC0102 & 0xFFFF).to_bytes(2, "little") == old[7:9]

    # The shipped builder must no longer produce it.
    assert diaggulp._build_ext_msg_set_rt_mask(7, 7, 0x01020408) != old


def test_a_range_replicates_the_mask_one_word_per_ss_id():
    """Measured: a single u32 for 30..35 set entry 30 and corrupted 31; six
    copies set all six."""
    req = diaggulp._build_ext_msg_set_rt_mask(30, 35, 0x0000ABCD)
    assert req == bytes.fromhex(
        "041e0023000000" + "cdab0000" * 6
    )
    body = req[diaggulp.EXT_MSG_MASK_TABLE_HDR_LEN:]
    assert len(body) == 4 * (35 - 30 + 1)
    assert set(body[i:i + 4] for i in range(0, len(body), 4)) == {
        bytes.fromhex("cdab0000")
    }


def test_the_explicit_array_builder_sizes_ss_id_last_from_the_list():
    req = diaggulp.build_ext_msg_set_rt_mask_array(0, [0x11, 0x22, 0x33])
    assert int.from_bytes(req[1:3], "little") == 0
    assert int.from_bytes(req[3:5], "little") == 2      # first + len - 1
    assert len(req) == diaggulp.EXT_MSG_MASK_TABLE_HDR_LEN + 12
    with pytest.raises(ValueError):
        diaggulp.build_ext_msg_set_rt_mask_array(0, [])


def test_the_get_request_is_five_bytes_and_rejects_a_non_read_sub_command():
    assert diaggulp.build_ext_msg_config_get_mask_request(
        diaggulp.EXT_MSG_GET_RT_MASK, 0, 120) == bytes.fromhex("0300007800")
    assert diaggulp.build_ext_msg_config_get_mask_request(
        diaggulp.EXT_MSG_GET_BUILD_MASK, 0, 120) == bytes.fromhex("0200007800")
    for bad in (diaggulp.EXT_MSG_SET_RT_MASK, diaggulp.EXT_MSG_SET_ALL_RT_MASKS,
                diaggulp.EXT_MSG_QUERY_SSID_RANGES):
        with pytest.raises(ValueError):
            diaggulp.build_ext_msg_config_get_mask_request(bad)
    with pytest.raises(ValueError):
        diaggulp.build_ext_msg_config_get_mask_request(
            diaggulp.EXT_MSG_GET_RT_MASK, 10, 5)


# --------------------------------------------------------------------------
# The readback helper and the restore
# --------------------------------------------------------------------------

class _FakeClient:
    """Records requests; replies from a scripted queue keyed by sub_cmd."""

    def __init__(self, replies):
        self.replies = dict(replies)
        self.sent = []

    def _send_recv(self, opcode, payload, timeout=5.0):
        self.sent.append((opcode, bytes(payload)))
        sub = payload[0]
        reply = self.replies.get(sub)
        if callable(reply):
            reply = reply(payload)
        if reply is None:
            return None
        return reply


def test_read_returns_none_on_timeout_rather_than_a_zero_filled_table():
    c = _FakeClient({diaggulp.EXT_MSG_GET_RT_MASK: None})
    assert diaggulp.read_ext_msg_rt_mask(c) is None


def test_read_returns_none_on_a_bad_cmd_rejection():
    c = _FakeClient({
        diaggulp.EXT_MSG_GET_RT_MASK: (diaggulp.DIAG_BAD_CMD_F, b"\x7d\x03"),
    })
    assert diaggulp.read_ext_msg_rt_mask(c) is None


def test_read_parses_the_verbatim_all_zero_reply():
    c = _FakeClient({
        diaggulp.EXT_MSG_GET_RT_MASK: (0x7D, RT_REPLY_ALL_ZERO),
    })
    masks = diaggulp.read_ext_msg_rt_mask(c)
    assert masks == [0] * 122
    assert c.sent[0] == (0x7D, bytes.fromhex("0300007800"))


def test_describe_distinguishes_unreadable_from_armed_to_zero():
    """These are the two readings the whole issue is about keeping apart."""
    assert diaggulp.describe_ext_msg_rt_mask(None) == "UNREADABLE"
    assert "uniform 0x00000000" in diaggulp.describe_ext_msg_rt_mask([0] * 122)
    assert diaggulp.describe_ext_msg_rt_mask(None) != \
        diaggulp.describe_ext_msg_rt_mask([0] * 122)


def test_describe_summarises_a_non_uniform_table():
    got = diaggulp.describe_ext_msg_rt_mask([0x1F] * 3 + [0x18] * 2 + [0])
    assert "6 ss_id(s)" in got
    assert "3 distinct" in got
    assert "0x0000001F×3" in got


def test_the_pre_arm_read_logs_the_value_and_warns_when_unreadable(capsys):
    """No range query answer → range 0 alone, logged, and marked PARTIAL."""
    c = _FakeClient({diaggulp.EXT_MSG_GET_RT_MASK: (0x7D, RT_REPLY_ALL_ZERO)})
    snap = diaggulp.log_pre_arm_ext_msg_rt_mask(c)
    assert snap is not None
    assert snap.complete is False
    assert snap.all_masks() == [0] * (diaggulp.EXT_MSG_SS_RANGE0_LAST + 1)
    err = capsys.readouterr().err
    assert "pre-arm F3 runtime mask" in err
    assert "uniform 0x00000000" in err
    assert "PARTIAL" in err

    c2 = _FakeClient({diaggulp.EXT_MSG_GET_RT_MASK: None})
    assert diaggulp.log_pre_arm_ext_msg_rt_mask(c2) is None
    err2 = capsys.readouterr().err
    assert "UNRECORDED" in err2
    assert "could not read the pre-arm F3 runtime mask" in err2


# --------------------------------------------------------------------------
# Whole-device snapshot + restore — the range-0-only bug
# --------------------------------------------------------------------------

#: Verbatim QUERY_SSID_RANGES reply from a live EP06-A (MDM9240 silicon,
#: ``EP06ALAR02A08M4G_01.009.01.009``). 25 ranges, 669 SSIDs.
EP06A_RANGES_REPLY = bytes.fromhex(
    "0101001900000000007900f401fa01e803ef03d007d807b80bc60ba00faa0f9411e811"
    "f81107128813a9137c158c157017c11764197919581b5b1bbc1bc71b201c211c401f40"
    "1f34215121282330231c253125d827e2270b280f283c283c286e288928a028af2800c0"
    "63c0"
)

#: Verbatim sub_cmd 3 reply for ``03 f401 fa01`` (range 500..506), all zero.
EP06A_R500_ALL_ZERO = bytes.fromhex(
    "03f401fa010100" + "00" * 28
)


def test_the_ep06a_range_table_parses_to_25_ranges_and_669_ssids():
    ranges = diaggulp._parse_ext_msg_ss_ranges(EP06A_RANGES_REPLY)
    assert len(ranges) == 25
    assert sum(l - f + 1 for f, l in ranges) == 669
    assert ranges[0] == (0, 121)
    assert ranges[-1] == (49152, 49251)
    p = diaggulp.parse_ext_msg_mask_table_reply(EP06A_R500_ALL_ZERO)
    assert p is not None and p[1:3] == (500, 506) and p[4] == [0] * 7


#: The trailing range replies with this many entries on the EP06-A although it
#: is advertised as 100 SSIDs (measured: 807-byte reply == 7 + 4*200).
_EP06A_LAST_RANGE_REPLY_ENTRIES = 200


class _FakeModem:
    """A stateful 0x7D responder shaped like the measured EP06-A.

    sub_cmd 1 returns the verbatim range table. sub_cmd 3 returns the whole
    range containing ``ss_id_first`` (the request's ``last`` is ignored), and
    the trailing range returns 200 entries. sub_cmd 4 stores its array verbatim.
    sub_cmd 5 stores the prefix-OR transform into EVERY entry, including the
    unadvertised tail. ``ignore_writes_to`` drops SET_RT_MASK for named ranges,
    which models a restore that does not take.
    """

    def __init__(self, ignore_writes_to=(), reject=False):
        self.ranges = diaggulp._parse_ext_msg_ss_ranges(EP06A_RANGES_REPLY)
        self.table = {}
        for first, last in self.ranges:
            n = last - first + 1
            if first == 49152:
                n = _EP06A_LAST_RANGE_REPLY_ENTRIES
            self.table[first] = [0] * n
        self.ignore = set(ignore_writes_to)
        self.reject = reject
        self.sent = []

    def _range_of(self, ss_id):
        for first, last in self.ranges:
            if first <= ss_id <= last:
                return first
        raise AssertionError(f"ss_id {ss_id} is in no advertised range")

    def _send_recv(self, opcode, payload, timeout=5.0):
        from struct import pack, unpack_from
        payload = bytes(payload)
        self.sent.append((opcode, payload))
        sub = payload[0]
        if sub == diaggulp.EXT_MSG_QUERY_SSID_RANGES:
            return (0x7D, EP06A_RANGES_REPLY)
        if sub == diaggulp.EXT_MSG_GET_RT_MASK:
            first, last = unpack_from("<HH", payload, 1)
            masks = self.table[self._range_of(first)]
            return (0x7D, pack("<BHHH", 3, first, last, 1)
                    + b"".join(pack("<I", m) for m in masks))
        if self.reject:
            return (diaggulp.DIAG_BAD_CMD_F, b"\x7d" + payload[:1])
        if sub == diaggulp.EXT_MSG_SET_ALL_RT_MASKS:
            stored = diaggulp.ext_msg_set_all_stored_mask(
                unpack_from("<I", payload, 3)[0])
            for k in self.table:
                self.table[k] = [stored] * len(self.table[k])
            return (0x7D, payload[:7])
        if sub == diaggulp.EXT_MSG_SET_RT_MASK:
            first, last = unpack_from("<HH", payload, 1)
            if first not in self.ignore:
                arr = [unpack_from("<I", payload, 7 + 4 * i)[0]
                       for i in range(last - first + 1)]
                self.table[first][: len(arr)] = arr
            return (0x7D, payload[:7])
        raise AssertionError(f"unexpected sub_cmd {sub}")

    def armed_ssids(self):
        """Count advertised SSIDs whose runtime mask is non-zero."""
        return sum(1 for first, last in self.ranges
                   for m in self.table[first][: last - first + 1] if m)


def test_the_snapshot_reads_every_advertised_range_and_trims_the_oversize_tail():
    m = _FakeModem()
    snap = diaggulp.read_ext_msg_rt_mask_snapshot(m)
    assert snap.complete is True
    assert len(snap.ranges) == 25
    assert len(snap.all_masks()) == 669       # not 769: the 200-entry tail is trimmed
    reads = [p for _op, p in m.sent if p[0] == diaggulp.EXT_MSG_GET_RT_MASK]
    assert len(reads) == 25


def test_session_45c2_a_set_all_arm_is_fully_undone_and_only_then_verified(capsys):
    """The bug: SET_ALL armed 669 SSIDs, the restore covered range 0's 122,
    printed VERIFIED, and F3 kept flowing from the other 547."""
    m = _FakeModem()
    snap = diaggulp.log_pre_arm_ext_msg_rt_mask(m)
    m._send_recv(0x7D, diaggulp.build_ext_msg_config_set_all_rt_masks_request(
        0xFFFFFFFF))
    assert m.armed_ssids() == 669

    assert diaggulp.restore_ext_msg_rt_mask(m, snap) is True
    assert m.armed_ssids() == 0
    err = capsys.readouterr().err
    assert "VERIFIED by readback of all 25 range(s)" in err
    # A uniform, SET_ALL-exact table goes back in one SET_ALL, which also
    # clears the unadvertised tail of the trailing range.
    assert m.table[49152] == [0] * _EP06A_LAST_RANGE_REPLY_ENTRIES


def test_a_non_uniform_table_goes_back_range_by_range():
    m = _FakeModem()
    m.table[500] = [0x11 + i for i in range(7)]
    m.table[4500] = [0x1F] * 85
    snap = diaggulp.read_ext_msg_rt_mask_snapshot(m)
    m._send_recv(0x7D, diaggulp.build_ext_msg_config_set_all_rt_masks_request(
        0xFFFFFFFF))

    assert diaggulp.restore_ext_msg_rt_mask(m, snap) is True
    assert m.table[500] == [0x11 + i for i in range(7)]
    assert m.table[4500] == [0x1F] * 85
    assert m.table[0] == [0] * 122
    writes = [p for _op, p in m.sent[-60:]
              if p[0] == diaggulp.EXT_MSG_SET_RT_MASK]
    assert len(writes) == 25


def test_a_uniform_value_set_all_cannot_store_exactly_goes_back_per_range():
    """SET_ALL 0x1F stores 0x1F1F1F1F (prefix-OR), so it cannot restore 0x1F."""
    m = _FakeModem()
    for k in m.table:
        m.table[k] = [0x1F] * len(m.table[k])
    snap = diaggulp.read_ext_msg_rt_mask_snapshot(m)
    m._send_recv(0x7D, diaggulp.build_ext_msg_config_set_all_rt_masks_request(
        0xFFFFFFFF))
    n_before = len(m.sent)

    assert diaggulp.restore_ext_msg_rt_mask(m, snap) is True
    assert m.table[0] == [0x1F] * 122
    subs = {p[0] for _op, p in m.sent[n_before:]}
    assert diaggulp.EXT_MSG_SET_ALL_RT_MASKS not in subs


def test_one_unreadable_range_makes_the_snapshot_partial():
    m = _FakeModem()
    real = m._send_recv

    def _drop_6000(opcode, payload, timeout=5.0):
        if payload[0] == diaggulp.EXT_MSG_GET_RT_MASK and payload[1:3] == (6000).to_bytes(2, "little"):
            m.sent.append((opcode, bytes(payload)))
            return None
        return real(opcode, payload, timeout)

    m._send_recv = _drop_6000
    snap = diaggulp.read_ext_msg_rt_mask_snapshot(m)
    assert snap.complete is False
    assert snap.unreadable() == 1
    assert "1 range(s) UNREADABLE" in diaggulp.describe_ext_msg_rt_snapshot(snap)
    assert diaggulp.restore_ext_msg_rt_mask(m, snap) is False


def test_restore_reports_failure_when_one_range_does_not_come_back(capsys):
    m = _FakeModem(ignore_writes_to={4500})
    m.table[500] = [0x11] * 7                 # non-uniform → per-range writes
    snap = diaggulp.read_ext_msg_rt_mask_snapshot(m)
    m._send_recv(0x7D, diaggulp.build_ext_msg_config_set_all_rt_masks_request(
        0xFFFFFFFF))

    assert diaggulp.restore_ext_msg_rt_mask(m, snap) is False
    err = capsys.readouterr().err
    assert "NOT verified" in err
    assert "1 range(s) differ: 4500..4584" in err
    assert "treat this modem's F3 state as unknown" in err


def test_a_partial_snapshot_never_certifies_a_restore(capsys):
    """Range 0 matching is not evidence about the other 24 ranges."""
    c = _FakeClient({
        diaggulp.EXT_MSG_GET_RT_MASK: (0x7D, RT_REPLY_ALL_ZERO),
        diaggulp.EXT_MSG_SET_RT_MASK: (0x7D, b"\x04\x00"),
    })
    snap = diaggulp.read_ext_msg_rt_mask_snapshot(c)
    assert snap.complete is False
    assert diaggulp.restore_ext_msg_rt_mask(c, snap) is False
    err = capsys.readouterr().err
    assert "VERIFIED" not in err
    assert "PARTIAL" in err


def test_restore_reports_failure_on_a_rejected_write(capsys):
    m = _FakeModem()
    snap = diaggulp.read_ext_msg_rt_mask_snapshot(m)
    m.reject = True
    assert diaggulp.restore_ext_msg_rt_mask(m, snap) is False
    assert "LEFT AT THE ARMED MASK" in capsys.readouterr().err


def test_restore_is_a_no_op_with_nothing_saved():
    c = _FakeClient({})
    assert diaggulp.restore_ext_msg_rt_mask(c, None) is False
    assert diaggulp.restore_ext_msg_rt_mask(
        c, diaggulp.F3MaskSnapshot((), False)) is False
    assert c.sent == []


# --------------------------------------------------------------------------
# Wiring: every arm reads first, and the restore stays opt-in
# --------------------------------------------------------------------------


def test_apply_f3_arming_reads_the_pre_arm_mask_and_returns_it(monkeypatch, capsys):
    seen = {}

    def _fake_enable(client, mask):
        seen["armed"] = mask
        seen["sent_before_arm"] = len(client.sent)

    monkeypatch.setattr(diaggulp, "_enable_ext_msg_f3", _fake_enable)
    m = _FakeModem()
    plan = diaggulp._F3ArmPlan("unbounded", 0xFFFFFFFF, ())

    pre = diaggulp._apply_f3_arming(m, plan)

    assert pre.complete is True
    assert pre.all_masks() == [0] * 669
    assert seen["armed"] == 0xFFFFFFFF
    # The whole read must happen BEFORE the arm — otherwise it records this
    # run's own mask, which is the failure the issue describes.
    assert m.sent[0][1][0] == diaggulp.EXT_MSG_QUERY_SSID_RANGES
    assert seen["sent_before_arm"] == 26          # 1 range query + 25 reads
    assert "pre-arm F3 runtime mask" in capsys.readouterr().err


def test_a_none_plan_reads_nothing_because_it_destroys_nothing():
    c = _FakeClient({})
    assert diaggulp._apply_f3_arming(c, diaggulp._F3ArmPlan("none", 0, ())) is None
    assert c.sent == []


def test_an_unreadable_pre_arm_mask_does_not_block_the_arm(monkeypatch, capsys):
    """The read is a record, not a gate — a capture must still happen."""
    armed = {}
    monkeypatch.setattr(diaggulp, "_enable_ext_msg_f3",
                        lambda client, mask: armed.setdefault("mask", mask))
    c = _FakeClient({diaggulp.EXT_MSG_GET_RT_MASK: None})
    pre = diaggulp._apply_f3_arming(c, diaggulp._F3ArmPlan("unbounded", 0x1F, ()))
    assert pre is None
    assert armed["mask"] == 0x1F
    assert "UNRECORDED" in capsys.readouterr().err


def test_the_restore_flag_is_offered_and_says_it_is_opt_in(capsys):
    """⛔ Opt-in by design: an automatic restore would silently break a capture
    meant to leave the modem armed for a following passive tap."""
    with pytest.raises(SystemExit):
        diaggulp.main(["--help"])
    out = capsys.readouterr().out
    assert "--restore-f3-mask-on-exit" in out
    # store_true, so argparse renders it with no metavar.
    assert "--restore-f3-mask-on-exit METAVAR" not in out
    assert "Deliberately opt-in" in " ".join(out.split())


def test_the_teardown_restore_is_gated_on_the_flag_and_on_having_a_reading():
    """The teardown reads the flag with ``getattr(args, ..., False)``, so an
    args namespace that predates the flag must NOT restore."""
    import argparse

    source = open(
        os.path.join(os.path.dirname(__file__), "..", "diaggulp.py"),
        encoding="utf-8",
    ).read()
    assert 'getattr(args, "restore_f3_mask_on_exit", False)' in source, (
        "teardown must default to NOT restoring when the attribute is absent"
    )
    # And the default really is off for a namespace without the attribute.
    assert getattr(argparse.Namespace(), "restore_f3_mask_on_exit", False) is False

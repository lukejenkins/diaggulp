"""`0x7D` sub_cmd 1/2/3 wire layouts, pinned to real EG25-G bytes.

Every fixture here is a **verbatim reply body** captured from a live Quectel
EG25-G (`2c7c:0125`, MDM9607) over
`/dev/ttyUSB0`, with the F3 plane silenced first (`SET_ALL_RT_MASKS 0`) so no
reply is truncated. Each was read 5× and came back byte-identical.

⚠️ **An earlier instrument caveat blamed F3 saturation for the varying reply
lengths. That is refuted.** On a quiet port the length is a *deterministic
function of the request*: sub_cmd 2 returns ``min(n, 121) + 1`` u32 entries for
the ``n`` at request offset [3:5], sub_cmd 3 returns a fixed 488-byte payload,
and a **bare 1-byte** sub_cmd 2/3 request returns a header with no array at all.
The short replies were short *requests*.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
for p in (REPO_ROOT / "tools", REPO_ROOT / "libs" / "diaggrok" / "src",
          REPO_ROOT / "libs" / "diagmunge" / "src", REPO_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

#: QUERY_SSID_RANGES (sub_cmd 1) reply body — 107 bytes, EG25-G A08M2G.
SUB1_BODY = bytes.fromhex(
    "0101001900000000007800f401fa01e803ef03d007d807b80bc60ba00faa0f9411dd11"
    "f81107128813a9137c158c157017c11764197919581b5b1bbc1bc71b201c211c401f40"
    "1f34215121282330231c252625d827e2270b280f283c283c286e288928a028b02800c0"
    "63c0"
)

#: The 25 ranges SUB1_BODY actually carries, read at the corrected offset.
EXPECTED_RANGES = [
    (0, 120), (500, 506), (1000, 1007), (2000, 2008), (3000, 3014),
    (4000, 4010), (4500, 4573), (4600, 4615), (5000, 5033), (5500, 5516),
    (6000, 6081), (6500, 6521), (7000, 7003), (7100, 7111), (7200, 7201),
    (8000, 8000), (8500, 8529), (9000, 9008), (9500, 9510), (10200, 10210),
    (10251, 10255), (10300, 10300), (10350, 10377), (10400, 10416),
    (49152, 49251),
]


def test_ssid_ranges_parse_recovers_all_twenty_five_ranges():
    """The shipped parser read ``num`` at the wrong offset and lost 24 of 25.

    It took ``num = u16 @1`` (which is 1 here) and started the array at offset 3,
    yielding the single pair ``(25, 0)`` — a range whose *last* is below its
    *first*, i.e. self-evidently not a range — and silently dropped the rest.
    """
    from diaggulp import _parse_ext_msg_ss_ranges

    assert _parse_ext_msg_ss_ranges(SUB1_BODY) == EXPECTED_RANGES


def test_every_parsed_ssid_range_is_ascending():
    """A ``last < first`` pair is the tell that the offset is wrong.

    Cheap invariant, and the one that would have caught the shipped bug without
    knowing the correct layout: no firmware enumerates a descending range.
    """
    from diaggulp import _parse_ext_msg_ss_ranges

    assert all(last >= first for first, last in _parse_ext_msg_ss_ranges(SUB1_BODY))


def test_the_ssid_range_array_accounts_for_the_whole_body():
    """``7 + 4 * num_ranges`` must equal the body length exactly.

    This is the layout's own integrity check — the same discipline as
    ``walk_event_items`` returning ``None`` unless the walk consumes the region
    exactly. It is what makes "25 ranges at offset 7" a measurement rather than
    a reading that merely happens to produce plausible numbers.
    """
    from diaggulp import _parse_ext_msg_ss_ranges

    assert 7 + 4 * len(_parse_ext_msg_ss_ranges(SUB1_BODY)) == len(SUB1_BODY)


def test_a_truncated_ssid_range_body_degrades_instead_of_raising():
    """A short body must yield the well-formed prefix, never raise mid-capture."""
    from diaggulp import _parse_ext_msg_ss_ranges

    got = _parse_ext_msg_ss_ranges(SUB1_BODY[:19])   # header + 3 whole pairs

    assert got == EXPECTED_RANGES[:3]


def test_an_empty_or_headerless_body_yields_no_ranges():
    from diaggulp import _parse_ext_msg_ss_ranges

    assert _parse_ext_msg_ss_ranges(b"") == []
    assert _parse_ext_msg_ss_ranges(b"\x01\x01") == []

    # A 4-byte body is the load-bearing case for the 7-byte header guard: it is
    # long enough to index but too short to hold the u16 at [3:5], so a relaxed
    # guard reaches `unpack_from` and raises instead of degrading.
    assert _parse_ext_msg_ss_ranges(b"\x01\x01\x00\x19") == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))

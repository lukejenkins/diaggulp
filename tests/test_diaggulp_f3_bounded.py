"""Tests for diaggulp's bounded F3 arming — per-subsystem SET_RT_MASK (#N).

``_enable_ext_msg_f3`` arms the modem's *entire* F3 surface with
DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS (sub_cmd 5). #N adds the bounded
primitive — SET_RT_MASK (sub_cmd 4) — so a capture can arm F3 for just the
SSIDs of interest at a chosen severity, instead of the all-or-nothing default
that emitted ~660k 0x99 frames in 30s on the RM500Q-AE pilot.

These tests pin the *wire format* of the request builders and the severity-mask
arithmetic — the parts verifiable offline. The protocol's live behaviour
(does the modem accept SET_RT_MASK and arm exactly the requested SSIDs?) is the
≥2-chipset hardware-validation item that stays open on #N.
"""
from __future__ import annotations

import sys
from pathlib import Path
from struct import pack

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


# --- SET_RT_MASK request builder (sub_cmd 4) --------------------------------

def test_set_rt_mask_wire_format():
    # cmd_code (0x7D) is prepended by _send_recv, so the payload starts at
    # sub_cmd: 04 | ss_id_first(LE u16) | ss_id_last(LE u16) | rt_mask(LE u32).
    payload = d._build_ext_msg_set_rt_mask(0x0009, 0x0009, 0x0000001C)
    assert payload == bytes.fromhex("04" "0900" "0900" "1c000000")


def test_set_rt_mask_distinct_range():
    payload = d._build_ext_msg_set_rt_mask(0x0008, 0x000A, 0xFFFFFFFF)
    assert payload == pack("<BHHI", 4, 0x0008, 0x000A, 0xFFFFFFFF)


def test_set_rt_mask_rejects_out_of_range_ssid():
    with pytest.raises(ValueError):
        d._build_ext_msg_set_rt_mask(0x1_0000, 0x1_0000, 0x1)


def test_set_rt_mask_rejects_inverted_range():
    with pytest.raises(ValueError):
        d._build_ext_msg_set_rt_mask(0x000A, 0x0008, 0x1)


# --- severity floor → runtime mask ------------------------------------------

def test_level_all_is_set_all_value():
    # "all" must equal the value the proven SET_ALL_RT_MASKS path sends.
    assert d._f3_level_mask("all") == 0xFFFFFFFF


def test_level_is_cumulative_and_above():
    # low is the most verbose: every defined level bit set.
    assert d._f3_level_mask("low") == 0x01 | 0x02 | 0x04 | 0x08 | 0x10  # 0x1F
    # high arms HIGH|ERROR|FATAL only — a quiet capture.
    assert d._f3_level_mask("high") == 0x04 | 0x08 | 0x10  # 0x1C
    # fatal is the single most-severe bit.
    assert d._f3_level_mask("fatal") == 0x10


def test_level_ordering_is_monotonic_in_bitcount():
    # Walking least→most severe, each floor enables a strict subset of the
    # previous one (fewer bits as the floor rises).
    masks = [d._f3_level_mask(name) for name in d._F3_LEVEL_ORDER]
    counts = [bin(m).count("1") for m in masks]
    assert counts == sorted(counts, reverse=True)


def test_level_unknown_raises():
    with pytest.raises(ValueError):
        d._f3_level_mask("verbose")


# --- QUERY_SSID_RANGES (sub_cmd 1) ------------------------------------------

def test_query_ss_ranges_request_byte():
    # Matches the request tools/diag_probe_log_gen.py already sends.
    assert d._build_ext_msg_query_ss_ranges() == b"\x01"


def test_parse_ss_ranges_roundtrip():
    body = pack("<BH", 1, 2) + pack("<HH", 0x0008, 0x000A) + pack("<HH", 0x0200, 0x0203)
    assert d._parse_ext_msg_ss_ranges(body) == [(0x0008, 0x000A), (0x0200, 0x0203)]


def test_parse_ss_ranges_tolerates_short_buffer():
    # num_ranges claims 3 but only 1 pair present → return what's well-formed,
    # never raise on a garbled tail (the response shape is hardware-unverified).
    body = pack("<BH", 1, 3) + pack("<HH", 0x0010, 0x0010)
    assert d._parse_ext_msg_ss_ranges(body) == [(0x0010, 0x0010)]


def test_parse_ss_ranges_empty():
    assert d._parse_ext_msg_ss_ranges(b"") == []
    assert d._parse_ext_msg_ss_ranges(b"\x01\x00") == []  # too short for num


# --- hex/decimal arg parsing -------------------------------------------------

def test_parse_int_arg_hex_and_decimal():
    assert d._parse_int_arg("0x09") == 9
    assert d._parse_int_arg("9") == 9
    import argparse
    with pytest.raises(argparse.ArgumentTypeError):
        d._parse_int_arg("notanint")


def test_f3_preset_ml1_is_grounded_ssids():
    # #N named preset: 'ml1' expands to the qdb-grounded LTE/NR ML1 + search
    # ss_ids (verified stable across SDX55 WLSN/SIM8202 + SDX62 RM520N-GL).
    assert d._F3_PRESETS["ml1"] == (1007, 3001, 9509, 9520)


def test_f3_preset_ssids_are_u16_set_rt_mask_armable():
    # every preset ss_id must be a valid SET_RT_MASK single-subsystem request
    for name, ssids in d._F3_PRESETS.items():
        for sid in ssids:
            assert 0 <= sid <= 0xFFFF, f"{name} ss_id {sid} out of u16 range"
            # building the single-subsystem (first==last) request must not raise
            req = d._build_ext_msg_set_rt_mask(sid, sid, 0x1F)
            assert isinstance(req, (bytes, bytearray)) and len(req) >= 7

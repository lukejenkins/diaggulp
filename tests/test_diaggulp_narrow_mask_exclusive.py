"""``--log-code`` must be EXCLUSIVE, not additive.

Two captures each wrote a
strict SUPERSET of the codes their ``--log-code`` flags requested, and they
leaked in OPPOSITE directions on two different vendors:

===============  ====================  ==========================  ============
capture          requested (log type)  leaked                      leaked type
===============  ====================  ==========================  ============
Quectel EG25-G   0x1476 0x14D8   (1)   0x4116 0xB0C0 0xB192 0xB193  4, B, B, B
Telit LM960A18   0xB192/93/95    (B)   0x1476 0x14D8                1, 1
===============  ====================  ==========================  ============

A DIAG log code is ``(equipment_id << 12) | item``, so the "log type" is the top
nibble. **Every leaked code lives in a log type its own run never wrote.** That
is the whole mechanism: :func:`_narrow_mask_bytes` returned entries only for the
types that had a requested code, so :func:`_build_narrow_mask` (and the Telit
variant, which shares the pure builder) sent ``SET_MASK`` for those types alone
and left every other type holding whatever the PREVIOUS run had armed. The two
captures leaked in opposite directions because each inherited the other's type.

The fix is clear-then-set: emit an explicit ALL-ZERO mask for every log type the
modem advertises that has no requested code, so the arming is exclusive against
whatever the modem already held.

⚠️ Types advertising a bitsize of 0 are still omitted — there is nothing to
clear, and a ``SET_MASK`` over 0 items is meaningless.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402

# A plausible advertised range table: types 1, 4 and 0xB carry codes, the rest
# advertise none. Sized past the items the tests name (0x476, 0x116, 0x195).
BITSIZES = tuple(
    0x800 if t in (1, 4, 0xB) else 0 for t in range(16)
)


def _is_all_zero(mask: bytes) -> bool:
    return all(b == 0 for b in mask)


def test_unrequested_type_gets_an_explicit_zero_mask():
    """The core contract: a type with no requested code is CLEARED, not skipped."""
    masks = d._narrow_mask_bytes(BITSIZES, [0x1476])
    assert 0xB in masks, (
        "log type 0xB advertises codes and none were requested, so it must be "
        "sent an explicit zero mask — skipping it leaves the previous run's "
        "mask armed"
    )
    assert _is_all_zero(masks[0xB])


def test_zero_bitsize_types_are_omitted():
    """Nothing to clear where the modem advertises no codes."""
    masks = d._narrow_mask_bytes(BITSIZES, [0x1476])
    for log_type in range(16):
        if BITSIZES[log_type] == 0:
            assert log_type not in masks


def test_requested_bits_are_still_set():
    """Positive control — a green run above must not come from an all-zero dict."""
    masks = d._narrow_mask_bytes(BITSIZES, [0x1476, 0x14D8])
    assert not _is_all_zero(masks[1]), "the requested type must NOT be zeroed"
    assert masks[1][0x476 // 8] & (1 << (0x476 % 8))
    assert masks[1][0x4D8 // 8] & (1 << (0x4D8 % 8))


def test_only_requested_bits_are_set_in_the_requested_type():
    """Exclusivity within a type, not just across types."""
    masks = d._narrow_mask_bytes(BITSIZES, [0x1476])
    set_bits = [
        i for i in range(BITSIZES[1]) if masks[1][i // 8] & (1 << (i % 8))
    ]
    assert set_bits == [0x476]


def test_eg25g_capture_cannot_leak_cell_codes():
    """Replay of the measured EG25-G capture.

    Requested two type-1 GNSS codes; the run picked up 0x4116 (type 4) and
    0xB0C0/0xB192/0xB193 (type 0xB). Both foreign types must now be zeroed.
    """
    masks = d._narrow_mask_bytes(BITSIZES, [0x1476, 0x14D8])
    for leaked in (0x4116, 0xB0C0, 0xB192, 0xB193):
        log_type, item = leaked >> 12, leaked & 0xFFF
        assert log_type in masks, f"0x{leaked:04X}'s type 0x{log_type:X} unwritten"
        assert not masks[log_type][item // 8] & (1 << (item % 8)), (
            f"0x{leaked:04X} is still subscribed"
        )


def test_lm960_capture_cannot_leak_gnss_codes():
    """Replay of the measured LM960A18 capture.

    The opposite direction: three type-0xB cell codes requested, 0x1476 and
    0x14D8 (type 1) leaked in.
    """
    masks = d._narrow_mask_bytes(BITSIZES, [0xB192, 0xB193, 0xB195])
    for leaked in (0x1476, 0x14D8):
        log_type, item = leaked >> 12, leaked & 0xFFF
        assert log_type in masks, f"0x{leaked:04X}'s type 0x{log_type:X} unwritten"
        assert not masks[log_type][item // 8] & (1 << (item % 8)), (
            f"0x{leaked:04X} is still subscribed"
        )


def test_mask_length_matches_the_advertised_bitsize():
    """A cleared type's mask must be full-width, or the tail stays armed."""
    masks = d._narrow_mask_bytes(BITSIZES, [0x1476])
    for log_type, mask in masks.items():
        assert len(mask) == (BITSIZES[log_type] + 7) // 8


def test_out_of_range_code_still_raises_before_any_mask_is_built():
    """The loud-failure contract survives the clear-then-set change."""
    import pytest

    with pytest.raises(ValueError):
        d._narrow_mask_bytes(BITSIZES, [0x2476])  # type 2 advertises 0 codes
    with pytest.raises(ValueError):
        d._narrow_mask_bytes(BITSIZES, [0x1FFF])  # item past type 1's bitsize

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""
diaggulp.py — low-CPU host-side DIAG capture for wardriving and bulk dumps.

Reads raw DIAG bytes from a connected modem (USB serial, TCP, or UDP) and
writes them to a file or stdout. The output is the same HDLC-framed byte
stream the modem emits — drop it into any downstream tool that consumes
DIAG (QCSuper's --dlf, SCAT, the diaggrok decoders, or your own parser).

Output format
-------------

**The output is raw HDLC, not the QCSuper DLF record format.** The default
``-o capture.dlf`` extension is historical; the file is a concatenation of
0x7E-delimited HDLC frames exactly as emitted by the modem, with no
per-record length headers, CRC envelope, or DLF metadata. See issue #N.

Downstream decoders must pick the matching input mode:

- **raw-HDLC / binary mode with CRC validation** — the correct path for
  diaggulp output (the consumer does the HDLC framing + CRC check itself)
- **DLF record mode** — for a true QCSuper DLF file, where per-record
  length/type headers carry the framing instead

Misusing the default QCSuper DLF mode on diaggulp output yields a near-zero
parse rate (the HDLC delimiter bytes are not a valid DLF record header).

Why this exists
---------------

QCSuper's pyserial input does ``self.serial.read()`` (one byte per call),
appended to a Python bytes string with ``+=`` in a tight loop, then runs
HDLC unescape + CRC-16 validation in pure Python on every frame. At
sustained DIAG rates (~1 MB/s on SDX55+ modems with full LTE+GNSS+NR
masks) this is **20-30% of a modern laptop CPU per modem** plus the
buffer-overrun drops documented in #N (3700 dropped frames per
5-minute capture on FN980m).

diaggulp.py is the minimum viable replacement:

  1. Read in 64 KB chunks via ``select() + read()``
  2. Send the bytes straight to the output destination — **no HDLC
     decap, no CRC validation, no Python-side per-frame processing**
  3. Optional file rotation by size or time
  4. Optional ``--qmdl2`` framing for compatibility with diag_mdlog
     consumers (4-byte LE length prefix per record)

The HDLC framing is preserved as-is in the output, so any downstream
parser can re-tokenize the stream. CRC validation moves to the
consumer (which can do it in batches or skip it entirely if it
trusts the modem).

Architectural reuse
-------------------

This tool builds on the ``diagmunge`` package's ``DiagClient`` for the
log mask handshake and transport abstraction (serial / TCP / UDP),
but **bypasses** ``DiagClient.recv()`` for the read path — recv()
does HDLC framing extraction and per-frame Python work, which is
exactly what we want to avoid for slurp mode.

Usage
-----

    # Pipe raw DIAG to stdout, parse downstream
    diaggulp.py /dev/ttyUSB0 | your-diag-decoder - parsed.jsonl

    # Capture to a single file (no rotation)
    diaggulp.py /dev/ttyUSB0 -o capture.dlf

    # Wardriving: rotate every 100 MB or 10 minutes, whichever comes first
    diaggulp.py /dev/ttyUSB0 -o /data/wardrive_%s.dlf \\
                  --rotate-size 100M --rotate-interval 600

    # TCP transport (for diag_socket_log)
    diaggulp.py --transport tcp --host 192.168.1.1 --port 2500 -o capture.dlf

    # UDP transport (for diag_udp_fwd on the modem)
    diaggulp.py --transport udp --port 2500 -o capture.dlf

CPU expectations
----------------

On a current laptop reading from an SDX55 modem at 1 MB/s with all
log codes enabled, this tool should sit at **<2 % CPU**. The
work per byte is exactly: a kernel read() into a Python bytes
object, then a kernel write() to the output fd. There is no
per-byte Python interpreter work in the read loop.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import queue
import select
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Reuse the existing DiagClient for transport abstraction + log mask handshake
from diagmunge import (
    DIAG_BAD_CMD_F,
    DiagClient,
    Dge1SeqTracker,
    parse_dge1_header,
)

# How many bytes to ask the kernel for per read(). 64 KB matches DiagClient's
# default and is large enough that read syscall overhead is negligible at any
# realistic DIAG byte rate.
READ_CHUNK = 64 * 1024

# Transient MHI DIAG channel reset survival (#N). A reset surfaces as
# ERESTARTSYS(512)/EAGAIN on the read; the channel usually returns within
# seconds, so the slurp loop rides it out (one contiguous capture with a logged
# gap) instead of dying. A channel that stays dead longer than this ceiling exits.
# EINTR is deliberately NOT here: as InterruptedError it's caught by the existing
# break clause (signal-driven shutdown), and the transport's read() already
# restarts EINTR at the syscall level (#N).
_ERESTARTSYS = 512
_TRANSIENT_READ_ERRNOS = frozenset((_ERESTARTSYS, errno.EAGAIN, errno.EWOULDBLOCK))
RESET_RETRY_BACKOFF = 0.1          # seconds between read retries during a reset
MAX_RESET_SECONDS = 180.0          # give up if the channel stays dead this long
# #N re-open gap: riding out a reset on the SAME fd recovers a transient
# blip, but NOT a hard channel teardown (e.g. T99W640 SDX72 radio-revert) where
# the fd stays valid yet delivers nothing — the channel needs open()+re-arm.
# If a reset persists this long on the same fd, slurp() asks its reconnect_fn
# (when supplied) to rebuild the client (re-open device + re-arm log/F3 masks).
REOPEN_AFTER_SECONDS = 6.0


def _parse_size(s: str) -> int:
    """Parse a human-friendly size like 100M, 2G, 4096K → bytes."""
    s = s.strip().upper()
    if not s:
        raise ValueError("empty size")
    multiplier = 1
    if s[-1] in "KMGT":
        multiplier = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[s[-1]]
        s = s[:-1]
    return int(float(s) * multiplier)


def _resolve_output_arg(path: Optional[str]) -> Optional[str]:
    """Normalize the ``-o`` argument so ``-`` means stdout (#N).

    ``-`` is the universal CLI convention for "write to stdout". The main
    path already treats a falsy ``args.output`` as stdout
    (``sys.stdout.buffer.fileno()``), so map ``-`` (and the empty string) to
    ``None`` and let every ``if args.output:`` branch route there. A real path
    that merely *contains* a dash (``cap-2026.bin``, ``./-foo``) is preserved.

    Without this, ``diaggulp ... -o -`` ran ``os.open("-", …)`` and created a
    regular file literally named ``-`` while the downstream pipe
    (``| diag_tail.py --tee``) saw zero bytes — the exact failure caught on the
    bench LV55 during #N/#N hardware validation.
    """
    if path == "-" or path == "":
        return None
    return path


def _open_output(path: str) -> tuple[int, str]:
    """Open the output path with %s timestamp expansion.

    Returns ``(fd, resolved_path)`` so callers can locate sidecars
    (e.g. ``<resolved_path>.anchors.json`` for #N anchor frames).

    If %s is present in the path, the placeholder expands to the current
    Unix timestamp. To handle rapid rotations within the same wall-clock
    second, the function uses O_EXCL and falls back to appending a
    monotonic counter suffix when the timestamped path already exists.
    """
    if "%s" in path:
        ts = str(int(time.time()))
        candidate = path.replace("%s", ts)
        try:
            fd = os.open(
                candidate,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o644,
            )
            return fd, candidate
        except FileExistsError:
            # Same-second collision — append a counter suffix
            for suffix in range(1, 10000):
                alt = path.replace("%s", f"{ts}_{suffix}")
                try:
                    fd = os.open(
                        alt,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o644,
                    )
                    return fd, alt
                except FileExistsError:
                    continue
            raise RuntimeError(f"Could not find unique rotation path for {path}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    return fd, path


def _all_logs_mask_bytes(bitsize: int) -> bytes:
    """Pure: the all-bits-set SET_MASK payload for a log type of ``bitsize``
    items — ``ceil(bitsize / 8)`` bytes with every advertised item bit set and
    no out-of-range bits in the final byte.

    Shared by the default (:func:`_build_all_logs_mask`) and telit-quirk
    (:func:`_build_all_logs_mask_telit`) all-logs handshakes so both emit the
    identical wire bytes; isolating it also makes the bit-trim unit-testable.
    """
    mask = bytes([0xFF] * ((bitsize + 7) // 8))
    if bitsize % 8 != 0:
        # Clear the high (8 - bitsize%8) bits of the final byte.
        mask = mask[:-1] + bytes([0xFF >> (8 - (bitsize % 8))])
    return mask


# Vendor SPC bodies to try, in order, when --spc auto is requested. The EG25/EC25
# MDM9607 family gates LOG_CONFIG (0x73) behind an SPC unlock (opcode 0x46) and
# rejects the mask handshake with DIAG_BAD_CMD_F until unlocked (#N). Mirrors
# the list in tools/capture_dlf_from_diag.py: Quectel reference 000000, then the
# Telit-form 0000.
_SPC_AUTO = ["000000", "0000"]


def _try_spc_unlock(client: DiagClient, spc_arg: str) -> bool:
    """Send a DIAG SPC unlock (opcode 0x46) before the LOG_CONFIG handshake (#N).

    ``spc_arg == "auto"`` tries the known vendor codes in :data:`_SPC_AUTO` in
    order, stopping at the first accepted (``status==1``); any other value is
    tried as a literal 6-char code. Returns True iff an unlock was accepted.
    Pure orchestration over :meth:`DiagClient.unlock_spc` so it is unit-testable
    with a fake client. Mirrors tools/capture_dlf_from_diag.py.
    """
    spcs = _SPC_AUTO if spc_arg.lower() == "auto" else [spc_arg]
    return any(client.unlock_spc(s) for s in spcs)


def _build_all_logs_mask(client: DiagClient) -> None:
    """Send a log mask that subscribes to EVERY log code in EVERY group.

    QCSuper does this by default in its ``_fill_log_mask`` with
    ``bit_value=1``. We replicate it here so the captured stream
    contains the full DIAG surface (LTE + NR5G + GNSS + everything
    else the modem can emit).

    Uses the existing DiagClient subscribe_logs() with a pre-computed
    "every possible code" list — diaggrok's registered_codes() only
    has the 33 codes we have parsers for, which is much smaller than
    "everything the modem will emit".
    """
    from struct import pack, unpack_from, calcsize

    # These constants are private to the ``diagmunge`` transport core —
    # re-define here to avoid coupling.
    DIAG_LOG_CONFIG_F = 115
    LOG_CFG_RETRIEVE_RANGES = 1
    LOG_CFG_SET_MASK = 3
    LOG_CFG_HDR_FMT = "<3xII"
    LOG_CFG_SUCCESS = 0

    result = client._send_recv(
        DIAG_LOG_CONFIG_F,
        pack("<3xI", LOG_CFG_RETRIEVE_RANGES),
        timeout=10.0,
    )
    if result is None:
        raise RuntimeError("Timed out querying log type ranges")
    _, resp = result
    operation, status = unpack_from(LOG_CFG_HDR_FMT, resp)
    assert operation == LOG_CFG_RETRIEVE_RANGES
    if status != LOG_CFG_SUCCESS:
        raise RuntimeError(f"RETRIEVE_RANGES failed (status={status})")

    bitsizes = unpack_from("<16I", resp, calcsize(LOG_CFG_HDR_FMT))

    enabled_groups = 0
    total_codes = 0
    for log_type, bitsize in enumerate(bitsizes):
        if not bitsize:
            continue
        mask = _all_logs_mask_bytes(bitsize)

        result = client._send_recv(
            DIAG_LOG_CONFIG_F,
            pack("<3xIII", LOG_CFG_SET_MASK, log_type, bitsize) + mask,
            timeout=10.0,
        )
        if result is None:
            raise RuntimeError(f"Timed out setting mask for log type 0x{log_type:x}")
        _, resp = result
        operation, status = unpack_from(LOG_CFG_HDR_FMT, resp)
        if operation != LOG_CFG_SET_MASK:
            raise RuntimeError(f"Unexpected SET_MASK response opcode {operation}")
        if status != LOG_CFG_SUCCESS:
            raise RuntimeError(
                f"SET_MASK failed for log type 0x{log_type:x} (status={status})"
            )

        enabled_groups += 1
        total_codes += bitsize

    print(
        f"diaggulp: subscribed to all {total_codes} log codes across "
        f"{enabled_groups} log groups",
        file=sys.stderr,
    )


def _narrow_mask_bytes(
    bitsizes: "tuple[int, ...]", log_codes: "list[int]"
) -> "dict[int, bytes]":
    """Pure: build per-log-type SET_MASK payloads subscribing to EXACTLY
    ``log_codes`` and nothing else (the #N narrow-mask validation capture).

    A DIAG log code is ``(equipment_id << 12) | item``: the top 4 bits select
    the log type (0..15, the index into ``bitsizes`` from RETRIEVE_RANGES) and
    the low 12 bits are the item index within that type. Within a type's mask,
    item ``i`` is bit ``i % 8`` of byte ``i // 8``, LSB-first — the QCSuper
    ``_fill_log_mask`` convention (same bit layout :func:`_build_all_logs_mask`
    sets to all-ones).

    Returns ``{log_type: mask_bytes}`` for only the types that have a requested
    code; ``mask_bytes`` is ``ceil(bitsize / 8)`` bytes. Raises ``ValueError``
    (before any I/O) for a code whose equipment id or item is outside the
    modem's advertised range — so a typo'd code fails loudly instead of
    silently capturing nothing.
    """
    by_type: "dict[int, bytearray]" = {}
    for code in sorted(set(log_codes)):
        log_type = code >> 12
        item = code & 0xFFF
        if log_type >= len(bitsizes):
            raise ValueError(
                f"log code 0x{code:04X}: equipment id 0x{log_type:X} is outside "
                f"the modem's {len(bitsizes)} log types"
            )
        bitsize = bitsizes[log_type]
        if bitsize == 0 or item >= bitsize:
            raise ValueError(
                f"log code 0x{code:04X}: item 0x{item:X} is out of range for log "
                f"type 0x{log_type:X} (modem advertises {bitsize} codes there)"
            )
        mask = by_type.setdefault(log_type, bytearray((bitsize + 7) // 8))
        mask[item // 8] |= 1 << (item % 8)
    return {lt: bytes(m) for lt, m in by_type.items()}


def _build_narrow_mask(client: DiagClient, log_codes: "list[int]") -> None:
    """Send a log mask subscribing to ONLY ``log_codes`` (+ nothing else).

    The all-logs mask (:func:`_build_all_logs_mask`) subscribes to every code in
    every group (~11.8k codes), which floods a validation capture: a recipe
    under test is a handful of codes, so a GNSS spike alone produced ~107k
    records (#N). This narrows the SET_MASK to just the requested codes —
    the code under test plus any liveness canary — so the capture is lean and
    the code-under-test's records aren't buried.

    Same RETRIEVE_RANGES → per-type SET_MASK handshake as the all-logs path; the
    only difference is the mask bytes (computed by :func:`_narrow_mask_bytes`).
    """
    from struct import pack, unpack_from, calcsize

    DIAG_LOG_CONFIG_F = 115
    LOG_CFG_RETRIEVE_RANGES = 1
    LOG_CFG_SET_MASK = 3
    LOG_CFG_HDR_FMT = "<3xII"
    LOG_CFG_SUCCESS = 0

    result = client._send_recv(
        DIAG_LOG_CONFIG_F,
        pack("<3xI", LOG_CFG_RETRIEVE_RANGES),
        timeout=10.0,
    )
    if result is None:
        raise RuntimeError("Timed out querying log type ranges")
    _, resp = result
    operation, status = unpack_from(LOG_CFG_HDR_FMT, resp)
    assert operation == LOG_CFG_RETRIEVE_RANGES
    if status != LOG_CFG_SUCCESS:
        raise RuntimeError(f"RETRIEVE_RANGES failed (status={status})")

    bitsizes = unpack_from("<16I", resp, calcsize(LOG_CFG_HDR_FMT))

    # Compute every mask BEFORE sending any — an out-of-range code raises here,
    # so we never half-apply a mask and leave the modem in a partial state.
    masks = _narrow_mask_bytes(bitsizes, log_codes)

    for log_type, mask in sorted(masks.items()):
        bitsize = bitsizes[log_type]
        result = client._send_recv(
            DIAG_LOG_CONFIG_F,
            pack("<3xIII", LOG_CFG_SET_MASK, log_type, bitsize) + mask,
            timeout=10.0,
        )
        if result is None:
            raise RuntimeError(f"Timed out setting mask for log type 0x{log_type:x}")
        _, resp = result
        operation, status = unpack_from(LOG_CFG_HDR_FMT, resp)
        if operation != LOG_CFG_SET_MASK:
            raise RuntimeError(f"Unexpected SET_MASK response opcode {operation}")
        if status != LOG_CFG_SUCCESS:
            raise RuntimeError(
                f"SET_MASK failed for log type 0x{log_type:x} (status={status})"
            )

    codes_str = ", ".join(f"0x{c:04X}" for c in sorted(set(log_codes)))
    print(
        f"diaggulp: narrow mask — subscribed to {len(set(log_codes))} log "
        f"code(s) across {len(masks)} group(s): {codes_str}",
        file=sys.stderr,
    )


def _parse_int_arg(s: str) -> int:
    """argparse ``type=`` for a hex (``0x...``) or decimal integer.

    Mirrors the ``int(c, 0)`` parse the ``--log-code`` path uses, but as a
    proper ``type=`` callable so argparse reports a clean error on a bad value.
    """
    import argparse as _argparse

    try:
        return int(s, 0)
    except ValueError:
        raise _argparse.ArgumentTypeError(
            f"expected a hex (0x...) or decimal integer, got {s!r}"
        )


def _enable_ext_msg_f3(client: DiagClient) -> None:
    """Enable the modem's F3 debug-message (DIAG_EXT_MSG_F) runtime stream.

    The log mask handshake (:func:`_build_all_logs_mask`) only subscribes to
    *log* codes — the structured 0x10 LOG_F records diaggrok/qcsuper parse.
    It does **not** turn on the firmware's free-text F3 debug messages
    (``DIAG_EXT_MSG_F`` 0x79 plaintext + ``DIAG_QSR4_EXT_MSG_TERSE_F`` 0x99
    hashed). Those carry the human-readable subsystem trace — e.g. the
    ``AT+CFUN=1`` rejection reason — and are silent on a modem whose radio
    is off, which is exactly the state where the log stream is empty too.

    This sends ``DIAG_EXT_MSG_CONFIG_F`` subcommand ``SET_ALL_RT_MASKS``
    (set every SSID's runtime level to 0xFFFFFFFF), so the modem emits its
    full F3 surface for the capture window. Decode the resulting HDLC with
    ``tools/diag_f3_decode.py`` (0x79 plaintext, no DB) or
    ``tools/blackbox/qsr4_decode.py`` (0x79 + 0x99 QSR4-terse, needs the
    build-matched ``qdsp6m.qdb``). See #N.
    """
    from struct import pack

    DIAG_EXT_MSG_CONFIG_F = 0x7D
    EXT_MSG_SET_ALL_RT_MASKS = 5
    ALL_LEVELS = 0xFFFFFFFF

    result = client._send_recv(
        DIAG_EXT_MSG_CONFIG_F,
        pack("<BxxI", EXT_MSG_SET_ALL_RT_MASKS, ALL_LEVELS),
        timeout=10.0,
    )
    if result is None:
        raise RuntimeError("Timed out enabling F3 ext-msg runtime masks")
    print(
        "diaggulp: enabled all F3 ext-msg runtime levels "
        "(DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS)",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Bounded F3 arming — per-subsystem SET_RT_MASK (#N)
#
# ``_enable_ext_msg_f3`` (above) arms the firmware's *entire* F3 surface with
# DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS (sub_cmd 5): one level word applied
# to every SSID. That's verbose — the RM500Q-AE pilot saw ~660k 0x99 frames in
# 30s, and on a chatty SDX72 the F3 stream can dominate capture size. The only
# escape was the all-or-nothing ``--no-ext-msg-f3``.
#
# This block adds the *bounded* primitive: DIAG_EXT_MSG_CONFIG_F sub_cmd 4
# (SET_RT_MASK), which arms F3 for a single SSID (or a contiguous SSID range)
# at a chosen severity, leaving every other subsystem dark. An operator who
# only wants LTE/NR ML1 + search trace can arm just those SSIDs instead of the
# whole device.
#
# Wire format (derived from the proven SET_ALL_RT_MASKS payload ``<BxxI`` —
# sub_cmd + 2-byte rsvd + u32 level — where SET_RT_MASK replaces that rsvd slot
# with the (ss_id_first, ss_id_last) range):
#
#     cmd_code     u8   = DIAG_EXT_MSG_CONFIG_F (0x7D, prepended by _send_recv)
#     sub_cmd      u8   = 4  (SET_RT_MASK)
#     ss_id_first  u16  first SSID in the range
#     ss_id_last   u16  last SSID in the range, inclusive
#     rt_mask      u32  runtime severity bitmask applied across [first, last]
#
# i.e. ``pack("<BHHI", 4, first, last, rt_mask)``. We always send one request
# per SSID (first == last) — the unambiguous single-subsystem form — so we
# never have to guess whether the firmware expects one mask-per-range or a
# mask *array* of (last-first+1) words for a multi-SSID range.
#
# ⚠️ HARDWARE-UNVERIFIED: the byte layout above is the canonical Qualcomm
# DIAG_EXT_MSG_CONFIG_F structure and is byte-for-byte consistent with the
# SET_ALL form this tool already ships, but SET_RT_MASK itself has NOT yet been
# armed against a live modem in this repo. ``_enable_ext_msg_f3_bounded`` checks
# for a DIAG_BAD_CMD_F rejection and surfaces it loudly so a wrong layout fails
# visibly rather than silently arming nothing. The ≥2-chipset live validation is
# tracked as the open item on #N.

# Qualcomm msg.h MSG_LVL_* runtime severity bits. Lower bit == less severe ==
# more verbose; FATAL is the most severe. ``_f3_level_mask`` ORs the chosen
# level with every more-severe level ("arm this severity and above").
_F3_MSG_LEVELS = {
    "low": 0x01,
    "med": 0x02,
    "high": 0x04,
    "error": 0x08,
    "fatal": 0x10,
}
# Ordered least→most severe, for the cumulative "and above" mask.
_F3_LEVEL_ORDER = ("low", "med", "high", "error", "fatal")

# Named F3 SSID presets (#N) — curated, GROUNDED ss_id sets for
# --ext-msg-f3-preset, so a capture can arm just a topic's subsystems without
# hand-listing ss_ids. The ss_ids are the firmware's own MSG_SSID values, read
# directly from the qdb (each QShrink record carries its ss_id); verified STABLE
# across SDX55 (RM500Q-AE + SIMCom SIM8202) and SDX62 (RM520N-GL) — the
# MSG_SSID space is a stable Qualcomm enum, so these
# transfer across builds/vendors (an ss_id absent on a given build is a no-op).
# Provenance per ss_id (dominant qdb source file):
#   1007 → srchtc_sm / srch_rx / srch_sect           (search)
#   3001 → srchcr / l1cmmeas / srchinterf            (LTE L1 measurement + search)
#   9509 → nr5g_ml1_rfmgr_trm_if / nr5g_ml1_common   (NR5G ML1)
#   9520 → nr5g_ml1_common_triage                    (NR5G ML1)
# ⚠️ SET_RT_MASK itself is still hardware-unverified in-repo (#N) — the
# arming wire format is canonical but unconfirmed against a live modem.
_F3_PRESETS: dict[str, tuple[int, ...]] = {
    "ml1": (1007, 3001, 9509, 9520),   # LTE/NR ML1 + search trace
}


def _f3_level_mask(level: str) -> int:
    """Runtime mask for an F3 severity floor — the level plus all above it.

    ``"all"`` returns 0xFFFFFFFF (the SET_ALL_RT_MASKS value, every level on).
    ``"high"`` returns HIGH|ERROR|FATAL (0x1C) — high-severity and worse only,
    a quiet capture. ``"low"`` returns the full 5-bit surface (0x1F).
    """
    level = level.lower()
    if level == "all":
        return 0xFFFFFFFF
    if level not in _F3_MSG_LEVELS:
        raise ValueError(
            f"unknown F3 level {level!r}; choose from "
            f"{', '.join(_F3_LEVEL_ORDER)}, all"
        )
    floor = _F3_LEVEL_ORDER.index(level)
    mask = 0
    for name in _F3_LEVEL_ORDER[floor:]:
        mask |= _F3_MSG_LEVELS[name]
    return mask


def _build_ext_msg_set_rt_mask(ss_id_first: int, ss_id_last: int, rt_mask: int) -> bytes:
    """DIAG_EXT_MSG_CONFIG_F / SET_RT_MASK (sub_cmd 4) request payload.

    Returns the bytes *after* the 0x7D command code (``_send_recv`` prepends
    that). See the module block above for the wire format and the
    hardware-unverified caveat.
    """
    from struct import pack

    EXT_MSG_SET_RT_MASK = 4
    if not (0 <= ss_id_first <= 0xFFFF and 0 <= ss_id_last <= 0xFFFF):
        raise ValueError(f"ss_id out of u16 range: {ss_id_first}..{ss_id_last}")
    if ss_id_last < ss_id_first:
        raise ValueError(f"ss_id_last {ss_id_last} < ss_id_first {ss_id_first}")
    return pack("<BHHI", EXT_MSG_SET_RT_MASK, ss_id_first, ss_id_last, rt_mask & 0xFFFFFFFF)


def _build_ext_msg_query_ss_ranges() -> bytes:
    """DIAG_EXT_MSG_CONFIG_F / QUERY_SSID_RANGES (sub_cmd 1) request payload.

    The RETRIEVE-equivalent that enumerates the firmware's valid SSID ranges —
    the only reliable way to discover which ss_ids ``--ext-msg-f3-ss`` may
    target on a given build (the SSID set is firmware-dependent). ``b"\\x01"``
    matches the request already sent by ``tools/diag_probe_log_gen.py``.
    """
    return b"\x01"


def _parse_ext_msg_ss_ranges(body: bytes) -> list[tuple[int, int]]:
    """Parse a QUERY_SSID_RANGES response body into (first, last) SSID pairs.

    ``body`` is the ``_send_recv`` response payload (everything after 0x7D),
    i.e. starts with the echoed sub_cmd byte. Canonical layout::

        sub_cmd     u8   (== 1)
        num_ranges  u16
        ranges[]    num_ranges × { ss_id_first u16, ss_id_last u16 }

    Defensive: returns as many well-formed pairs as the buffer holds; never
    raises on a short/garbled tail (this response shape is hardware-unverified
    in-repo, so we degrade rather than crash a live capture).
    """
    from struct import unpack_from

    if len(body) < 3:
        return []
    num = unpack_from("<H", body, 1)[0]
    ranges: list[tuple[int, int]] = []
    off = 3
    for _ in range(num):
        if off + 4 > len(body):
            break
        first, last = unpack_from("<HH", body, off)
        ranges.append((first, last))
        off += 4
    return ranges


def _query_ext_msg_ss_ranges(client: DiagClient) -> list[tuple[int, int]]:
    """Send QUERY_SSID_RANGES and return the parsed (first, last) SSID pairs.

    Returns ``[]`` on timeout or an empty/garbled response.
    """
    result = client._send_recv(
        0x7D, _build_ext_msg_query_ss_ranges(), timeout=5.0
    )
    if result is None:
        return []
    op, body = result
    if op != 0x7D:
        return []
    return _parse_ext_msg_ss_ranges(body)


def _enable_ext_msg_f3_bounded(
    client: DiagClient, ss_ids: "list[int]", rt_mask: int
) -> None:
    """Arm F3 for only ``ss_ids`` at runtime mask ``rt_mask`` (one SET_RT_MASK each).

    Bounded counterpart to :func:`_enable_ext_msg_f3` — leaves every SSID not in
    ``ss_ids`` dark, so a capture can carry e.g. just LTE/NR ML1 + search F3
    instead of the whole device's surface (#N). Raises ``RuntimeError`` on a
    timeout or an explicit DIAG_BAD_CMD_F rejection (a wrong wire layout fails
    loudly here rather than silently arming nothing).
    """
    DIAG_EXT_MSG_CONFIG_F = 0x7D
    armed = []
    for ss_id in ss_ids:
        result = client._send_recv(
            DIAG_EXT_MSG_CONFIG_F,
            _build_ext_msg_set_rt_mask(ss_id, ss_id, rt_mask),
            timeout=10.0,
        )
        if result is None:
            raise RuntimeError(
                f"Timed out arming F3 SET_RT_MASK for ss_id 0x{ss_id:04x}"
            )
        op, _body = result
        if op == DIAG_BAD_CMD_F:
            raise RuntimeError(
                f"Modem rejected F3 SET_RT_MASK for ss_id 0x{ss_id:04x} "
                "(DIAG_BAD_CMD_F) — wire layout or ss_id may be wrong for this "
                "firmware; enumerate valid ranges with --ext-msg-f3-list-ss"
            )
        armed.append(ss_id)
    print(
        "diaggulp: armed bounded F3 ext-msg for "
        f"{len(armed)} subsystem(s) "
        f"({', '.join(f'0x{s:04x}' for s in armed)}) at rt_mask 0x{rt_mask:08x} "
        "(DIAG_EXT_MSG_CONFIG_F / SET_RT_MASK)",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Telit / SDX20 DIAG quirk path (#N)
#
# The LM960A18 (SDX20) DIAG-over-USB-serial interface is half-duplex-hostile in
# two coupled ways, proven by instrumented probing against a live unit:
#
#   1. flush-on-OUT / one-behind delivery — the modem flushes its USB IN
#      endpoint lazily, roughly one command behind. A passive reader that
#      writes nothing sees 0 bytes; a request's reply arrives only when the
#      *next* OUT (command) is written. So buffered LOG_F records never reach
#      the host during a normal passive capture.
#   2. full-duplex deadlock — the modem will not accept a large OUT transfer (a
#      multi-hundred-byte SET_MASK mask) while its IN buffer holds undrained
#      data; serial.write() then blocks forever. Small writes fit the RX FIFO
#      and slip through, which is why the first (tiny) log type acked but the
#      first large one wedged in prior sessions.
#
# These break the normal path two ways: the shared _send_recv correlates only
# on the 1-byte opcode, so a late reply for one DIAG_LOG_CONFIG_F sub-operation
# (RETRIEVE_RANGES vs SET_MASK — same opcode 0x73) aliases onto the next
# request (garbage bitsizes -> a ~512 MB mask alloc, the observed "hang"); and
# the passive slurp() loop never flushes the buffered log stream.
#
# This opt-in (--telit-quirk) path adds: a bounded backlog drain on open,
# pumped (chunked + IN-drained) writes to dodge the deadlock, operation-field
# reply correlation, and periodic keep-alive kicks during capture. It touches
# only diaggulp; the shared DiagClient defaults other modems rely on are
# unchanged. See #N.

_DIAG_LOG_CONFIG_F = 115  # opcode 0x73 — log subscription command/response
_LOG_CFG_RETRIEVE_RANGES = 1
_LOG_CFG_SET_MASK = 3


# --- VID/PID auto-detection of flush-on-OUT modems (#N) ---
#
# --telit-quirk (above) had to be passed by hand; a user who forgets it gets
# the old 0-byte capture with no hint why. So auto-enable the quirk when the
# serial DIAG port belongs to a known flush-on-OUT device.
#
# Keyed on a curated (vid, pid) allow-list, NOT VID-only: the quirk path adds
# real overhead (backlog drain on open, pumped/IN-drained writes, periodic
# keep-alive kicks), so enabling it on a Telit modem that does NOT need it
# would be a pointless regression. The list is seeded with the single unit the
# quirk is live-validated against (#N) and grows only as siblings are
# confirmed flush-on-OUT on real hardware. Inline rather than module.yaml-
# sourced: the capture tool is transport-agnostic and shouldn't depend on the
# per-module metadata tree just to flip one bool (revisit if the list grows).
_FLUSH_ON_OUT_ALLOWLIST = {
    (0x1BC7, 0x1041): "Telit LM960A18",  # SDX20, live-validated #N / #N
}


def _match_flush_on_out_quirk(vid: Optional[int], pid: Optional[int]) -> Optional[str]:
    """Pure lookup: human label for a known flush-on-OUT ``(vid, pid)``, else None.

    Kept side-effect-free so the allow-list policy is unit-testable without any
    sysfs/USB access (mirrors the ``_telit_logconfig_reply_matches`` pattern)."""
    if vid is None or pid is None:
        return None
    label = _FLUSH_ON_OUT_ALLOWLIST.get((vid, pid))
    if label is None:
        return None
    return f"{label} ({vid:04x}:{pid:04x})"


def _usb_ids_for_tty(device_path: str) -> Optional[tuple[int, int]]:
    """Resolve the USB ``(vid, pid)`` for a ``/dev/tty*`` serial device via sysfs.

    Walks ``/sys/class/tty/<name>/device`` up the USB device tree to the first
    parent exposing ``idVendor``/``idProduct``. Returns the ids as ints, or
    None when the path is not a USB tty (virtual port, socat pty, a container
    without ``/sys``, or a non-USB DIAG transport)."""
    if not device_path:
        return None
    try:
        name = os.path.basename(os.path.realpath(device_path))
        node = os.path.realpath(os.path.join("/sys/class/tty", name, "device"))
    except OSError:
        return None
    cur = node
    for _ in range(10):  # bounded; the USB device tree is shallow
        vpath = os.path.join(cur, "idVendor")
        ppath = os.path.join(cur, "idProduct")
        if os.path.isfile(vpath) and os.path.isfile(ppath):
            try:
                with open(vpath) as fv:
                    vid = int(fv.read().strip(), 16)
                with open(ppath) as fp:
                    pid = int(fp.read().strip(), 16)
            except (OSError, ValueError):
                return None
            return (vid, pid)
        parent = os.path.dirname(cur)
        if parent == cur:  # reached filesystem root without a USB ancestor
            break
        cur = parent
    return None


def _detect_flush_on_out_quirk(device_path: str) -> Optional[str]:
    """Human label if ``device_path`` is a known flush-on-OUT modem, else None.

    Composes the sysfs id lookup with the pure allow-list match; the sysfs walk
    is the only I/O surface, so the policy half stays unit-testable."""
    ids = _usb_ids_for_tty(device_path)
    if ids is None:
        return None
    return _match_flush_on_out_quirk(ids[0], ids[1])


def _telit_kick_payload() -> bytes:
    """A tiny, read-only DIAG_LOG_CONFIG_F RETRIEVE_RANGES payload used purely
    as a flush-kick: an OUT that provokes the modem to deliver a buffered IN
    reply, without mutating modem state (re-querying ranges is idempotent)."""
    from struct import pack
    return pack("<3xI", _LOG_CFG_RETRIEVE_RANGES)


def _telit_logconfig_reply_matches(opcode: int, body: bytes, operation: int) -> bool:
    """Pure predicate: is ``(opcode, body)`` a DIAG_LOG_CONFIG_F reply for
    ``operation``? Discriminates by the body ``operation`` u32 (offset 4, after
    3 pad bytes) so a one-behind aliased reply for a *different* sub-operation
    is rejected instead of bound (the #N correlation bug)."""
    from struct import unpack_from
    if opcode != _DIAG_LOG_CONFIG_F or len(body) < 8:
        return False
    return unpack_from("<3xI", body)[0] == operation


def _telit_drain_bounded(
    client: DiagClient,
    *,
    quiet: float = 0.6,
    max_total: float = 6.0,
    max_frames: int = 8000,
) -> int:
    """Read and discard frames until ``quiet`` seconds of silence, or a cap is
    hit. Clears the cross-session IN backlog (stale frames that survive
    tcflush) so the first handshake transaction is not mis-correlated. Bounded
    by ``max_total`` / ``max_frames`` so an already-streaming modem can't trap
    us indefinitely. Returns the number of frames discarded."""
    deadline = time.monotonic() + max_total
    n = 0
    while n < max_frames and time.monotonic() < deadline:
        try:
            client.recv(timeout=quiet)
            n += 1
        except TimeoutError:
            break
    return n


def _telit_write_pumped(
    client: DiagClient,
    opcode: int,
    payload: bytes,
    *,
    chunk: int = 48,
    drain_each: float = 0.03,
) -> None:
    """Write one HDLC frame in ``chunk``-byte slices, draining IN between
    slices, so a large OUT never wedges behind a full modem IN buffer (the
    #N duplex deadlock). Frames drained here are discarded; the caller's
    kick loop re-provokes the real reply. Serial transport only."""
    frame = client._hdlc_encapsulate(bytes([opcode]) + payload)
    transport = client._transport
    for i in range(0, len(frame), chunk):
        piece = frame[i:i + chunk]
        # Each <=48-byte piece fits one USB bulk packet, so write() either
        # delivers it whole or (when the modem's IN buffer is full) raises
        # SerialTimeoutException having sent nothing — no partial-frame
        # corruption, so retry-after-drain is safe. A write timeout means
        # "IN is full"; the cure is to drain (read), then retry the piece.
        for _ in range(6):
            try:
                transport.write(piece)
                break
            except OSError:
                _telit_drain_bounded(client, quiet=0.1, max_total=0.5, max_frames=4000)
        else:
            raise RuntimeError(
                "modem refused OUT (IN buffer wedged) — log mask write timed out"
            )
        end = time.monotonic() + drain_each
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            try:
                client.recv(timeout=remaining)
            except TimeoutError:
                break


def _telit_log_config_xact(
    client: DiagClient,
    operation: int,
    payload: bytes,
    *,
    timeout: float = 4.0,
    kick_every: float = 0.4,
) -> "Optional[bytes]":
    """One DIAG_LOG_CONFIG_F transaction over the flush-on-OUT modem.

    Pumped-write the command, then send tiny RETRIEVE_RANGES flush-kicks every
    ``kick_every`` seconds until a reply whose body operation matches
    ``operation`` arrives (operation-field correlation discards the kicks' own
    RETRIEVE_RANGES replies and any aliased prior-operation reply). Returns the
    matching reply body, or ``None`` on timeout."""
    _telit_write_pumped(client, _DIAG_LOG_CONFIG_F, payload)
    kick = _telit_kick_payload()
    deadline = time.monotonic() + timeout
    next_kick = time.monotonic() + kick_every
    while True:
        now = time.monotonic()
        if now >= deadline:
            return None
        if now >= next_kick:
            try:
                client.send(_DIAG_LOG_CONFIG_F, kick)
            except OSError:
                # IN buffer full -> can't write now; the recv() below drains
                # it, which frees the modem to accept the next kick. A skipped
                # flush-kick is harmless. (#N)
                pass
            next_kick = now + kick_every
        try:
            opcode, body = client.recv(timeout=min(kick_every, max(0.01, deadline - now)))
        except TimeoutError:
            continue
        if _telit_logconfig_reply_matches(opcode, body, operation):
            return body


def _telit_retrieve_ranges(client: DiagClient) -> "tuple[int, ...]":
    """RETRIEVE_RANGES over the telit-quirk transaction. Returns the 16
    per-log-type bitsizes. Raises RuntimeError on timeout or implausible sizes
    (a guard against any residual mis-correlation reaching the SET_MASK loop —
    a bogus bitsize would otherwise drive a multi-hundred-MB mask alloc)."""
    from struct import pack, unpack_from, calcsize
    body = _telit_log_config_xact(
        client, _LOG_CFG_RETRIEVE_RANGES,
        pack("<3xI", _LOG_CFG_RETRIEVE_RANGES), timeout=8.0,
    )
    if body is None:
        raise RuntimeError("Timed out querying log type ranges")
    _, status = unpack_from("<3xII", body)
    if status != 0:
        raise RuntimeError(f"RETRIEVE_RANGES failed (status={status})")
    bitsizes = unpack_from("<16I", body, calcsize("<3xII"))
    if any(b > (1 << 20) for b in bitsizes):
        raise RuntimeError(
            f"RETRIEVE_RANGES returned implausible bitsizes {bitsizes} "
            "(stale-frame mis-correlation); aborting before mask alloc"
        )
    return bitsizes


def _telit_set_mask(client: DiagClient, log_type: int, bitsize: int, mask: bytes) -> None:
    """SET_MASK for one log type over the telit-quirk transaction.

    Fire-and-forget tolerant (#N follow-up, observed 2026-06-12 on LM960
    32.01.110 / SDX20): some flush-on-OUT Telit firmwares APPLY the SET_MASK
    but never emit a LOG_CONFIG SET_MASK reply the operation-correlator can
    match — the mask still takes effect (proven by the subscribed codes then
    flowing: a type-0x7-only write yielded 1074 0x7001 records, and an
    all-logs type-0x1 write re-armed the GNSS 0x1xxx firehose). The prior
    code raised on the missing ack and ABORTED the per-log-type loop, so only
    the first group ever got written. Treat a missing/non-correlated ack as a
    best-effort fire-and-forget success (warn, continue) so EVERY log type in
    the all-logs / multi-group narrow handshake gets its SET_MASK write. A
    non-zero status in a real ack is still a hard error."""
    from struct import pack, unpack_from
    body = _telit_log_config_xact(
        client, _LOG_CFG_SET_MASK,
        pack("<3xIII", _LOG_CFG_SET_MASK, log_type, bitsize) + mask,
    )
    if body is None:
        print(
            f"diaggulp: [telit-quirk] no SET_MASK ack for log type 0x{log_type:x} "
            f"— assuming fire-and-forget applied, continuing",
            file=sys.stderr,
        )
        return
    _, status = unpack_from("<3xII", body)
    if status != 0:
        raise RuntimeError(f"SET_MASK failed for log type 0x{log_type:x} (status={status})")


def _build_all_logs_mask_telit(client: DiagClient) -> None:
    """All-logs handshake for the flush-on-OUT Telit/SDX20 path (#N).

    Same RETRIEVE_RANGES -> per-type SET_MASK shape as :func:`_build_all_logs_mask`,
    but every transaction goes through the pumped/operation-correlated path.
    Assumes the caller already ran :func:`_telit_drain_bounded`."""
    bitsizes = _telit_retrieve_ranges(client)
    enabled_groups = 0
    total_codes = 0
    for log_type, bitsize in enumerate(bitsizes):
        if not bitsize:
            continue
        _telit_set_mask(client, log_type, bitsize, _all_logs_mask_bytes(bitsize))
        enabled_groups += 1
        total_codes += bitsize
    print(
        f"diaggulp: [telit-quirk] subscribed to all {total_codes} log codes "
        f"across {enabled_groups} log groups",
        file=sys.stderr,
    )


def _build_narrow_mask_telit(client: DiagClient, log_codes: "list[int]") -> None:
    """Narrow handshake (#N) for the flush-on-OUT Telit/SDX20 path (#N).

    Reuses the pure :func:`_narrow_mask_bytes` builder; only the transport
    transaction differs from :func:`_build_narrow_mask`."""
    bitsizes = _telit_retrieve_ranges(client)
    masks = _narrow_mask_bytes(bitsizes, log_codes)  # raises before any I/O on bad code
    for log_type, mask in sorted(masks.items()):
        _telit_set_mask(client, log_type, bitsizes[log_type], mask)
    codes_str = ", ".join(f"0x{c:04X}" for c in sorted(set(log_codes)))
    print(
        f"diaggulp: [telit-quirk] narrow mask — subscribed to "
        f"{len(set(log_codes))} log code(s) across {len(masks)} group(s): {codes_str}",
        file=sys.stderr,
    )


class _RotatingWriter:
    """Writer that rotates output by file size or wall-clock time.

    The output path may contain ``%s`` which expands to the current
    Unix timestamp at file open. Rotation closes the current file and
    opens a fresh one with a new timestamp.
    """

    def __init__(
        self,
        path: str,
        rotate_size: Optional[int] = None,
        rotate_interval: Optional[int] = None,
    ):
        self._path = path
        self._rotate_size = rotate_size
        self._rotate_interval = rotate_interval
        self._fd = -1
        self._current_path = ""
        self._written = 0
        self._opened_at = 0.0
        self._open_new()

    def _open_new(self) -> None:
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
        self._fd, self._current_path = _open_output(self._path)
        self._written = 0
        self._opened_at = time.monotonic()

    def write(self, data: bytes) -> None:
        os.write(self._fd, data)
        self._written += len(data)
        # Rotation check after each write
        if self._rotate_size and self._written >= self._rotate_size:
            self._open_new()
        elif (
            self._rotate_interval
            and (time.monotonic() - self._opened_at) >= self._rotate_interval
        ):
            self._open_new()

    def close(self) -> None:
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1


def slurp(
    client: DiagClient,
    out_fd: int,
    chunk_size: int = READ_CHUNK,
    kick_fn: "Optional[callable]" = None,
    kick_interval: float = 0.3,
    reconnect_fn: "Optional[callable]" = None,
    tee_fn: "Optional[callable]" = None,
) -> tuple[int, float]:
    """Run the read-and-write loop. Returns (bytes_written, elapsed_seconds).

    The loop is intentionally as bare as possible — select() blocks
    until data is available, then read() pulls a chunk and write()
    pushes it to the output. No HDLC parsing, no CRC validation,
    no per-frame Python work. The whole point is that the read+write
    pair has nothing between them.

    ``kick_fn`` (the #N telit-quirk keep-alive): when provided, it is called
    roughly every ``kick_interval`` seconds to write a tiny OUT to the modem.
    Flush-on-OUT modems (LM960/SDX20) only deliver buffered LOG_F records in
    response to host writes, so a purely passive loop captures nothing. The
    select() timeout is bounded to the kick interval so a kick still fires when
    no data is arriving. ``kick_fn=None`` (default) keeps the loop fully
    passive — unchanged for every other transport."""
    transport = client._transport
    fileno = transport.fileno()
    bytes_written = 0
    start = time.monotonic()
    select_timeout = min(1.0, kick_interval) if kick_fn else 1.0
    next_kick = start + kick_interval if kick_fn else None
    reset_since = None   # monotonic time the current reset window began (#N)
    last_reopen = None   # monotonic time of the last re-open attempt (#N)
    while True:
        # Adaptive keep-alive: kick only after kick_interval of NO data. While
        # the modem floods (next_kick deferred on every read below), no kick
        # fires — a kick then is both unnecessary (stream already flowing) and
        # unwriteable (IN-full modem won't accept the OUT). See #N.
        if next_kick is not None and time.monotonic() >= next_kick:
            try:
                kick_fn()
            except (BrokenPipeError, KeyboardInterrupt):
                break
            except OSError:
                # Write timeout / busy modem (SerialTimeoutException is an
                # OSError): the modem is clearly emitting, so dropping this
                # keep-alive kick is harmless. Keep capturing.
                pass
            next_kick = time.monotonic() + kick_interval
        try:
            ready, _, _ = select.select([fileno], [], [], select_timeout)
        except (KeyboardInterrupt, InterruptedError):
            break
        if not ready:
            continue
        try:
            data = transport.read(chunk_size)
        except (KeyboardInterrupt, InterruptedError):
            break
        except OSError as exc:
            # Transient MHI DIAG channel reset (#N): EINTR/ERESTARTSYS(512)/
            # EAGAIN. The channel usually returns within seconds, so ride it out
            # instead of dying mid-capture — one contiguous output file with a
            # logged gap. A channel dead longer than MAX_RESET_SECONDS exits.
            if exc.errno not in _TRANSIENT_READ_ERRNOS:
                raise
            now = time.monotonic()
            if reset_since is None:
                reset_since = now
                last_reopen = now
                print(f"diaggulp: DIAG channel reset (errno {exc.errno}); "
                      f"riding it out (≤{MAX_RESET_SECONDS:.0f}s)", file=sys.stderr)
            elif now - reset_since > MAX_RESET_SECONDS:
                print(f"diaggulp: DIAG channel dead {now - reset_since:.0f}s "
                      f"(errno {exc.errno}); exiting", file=sys.stderr)
                raise
            elif reconnect_fn is not None and now - last_reopen >= REOPEN_AFTER_SECONDS:
                # Same-fd ride-out hasn't recovered — the channel was torn down
                # (not a transient blip). Re-open it and re-arm the masks (#N).
                last_reopen = now
                try:
                    client = reconnect_fn()
                    transport = client._transport
                    fileno = transport.fileno()
                    print("diaggulp: DIAG channel re-opened + re-armed "
                          f"after {now - reset_since:.0f}s of reset", file=sys.stderr)
                except Exception as rexc:   # noqa: BLE001 — best-effort, keep trying
                    print(f"diaggulp: DIAG re-open failed ({rexc}); will retry",
                          file=sys.stderr)
            time.sleep(RESET_RETRY_BACKOFF)
            continue
        if reset_since is not None:
            print(f"diaggulp: DIAG channel recovered after "
                  f"{time.monotonic() - reset_since:.1f}s", file=sys.stderr)
            reset_since = None
        if not data:
            print("diaggulp: transport closed (EOF)", file=sys.stderr)
            break
        # The hot path is exactly two function calls: read() and write().
        try:
            os.write(out_fd, data)
        except (BrokenPipeError, KeyboardInterrupt):
            break
        bytes_written += len(data)
        # #N live decode: tee a COPY to the side-thread decoder AFTER the raw
        # write. tee_fn is a non-blocking put_nowait that drops on a full queue,
        # so it can never stall the read→write pair or risk a raw byte.
        if tee_fn is not None:
            tee_fn(data)
        if next_kick is not None:
            next_kick = time.monotonic() + kick_interval  # defer: data flowing
    elapsed = time.monotonic() - start
    return bytes_written, elapsed


# ---------------------------------------------------------------------------
# Live / streaming DIAG decode (#N) — decode a SELECTED set of log codes
# inline as frames arrive, on a side thread, so an operator can watch records
# (cells appearing/disappearing, a SIB1 landing) WITHOUT the capture →
# stop → hdlc_to_dlf → offline-decode round-trip.
#
# Design contract (from #N): NEVER block the capture hot path. diaggulp's
# whole value is lossless low-CPU capture (#N); the raw .bin stays the
# canonical complete artifact. So live decode runs on a separate thread fed by
# a BOUNDED queue: the hot path's tee is a single non-blocking put_nowait, and
# if the decoder can't keep up we drop the *decode copy* (with a counter),
# never raw bytes. Decode is observability, not ground truth — the authoritative
# record is still the raw capture re-decoded offline with a pinned diaggrok SHA.
# ---------------------------------------------------------------------------
class LiveDecoder:
    """Side-thread streaming decoder for a selected set of DIAG log codes.

    Feed it the same raw HDLC byte chunks the capture hot path writes (via
    :meth:`feed`); it reassembles frames across chunk boundaries with the
    shared ``diaggrok.hdlc.iter_log_records_stream`` primitive, filters to the
    selected codes, runs ``diaggrok.registry.parse`` inline, and emits one
    JSONL record per decoded frame to ``out`` (default stderr). A code with no
    registered parser triggers a one-time live novelty alert (#N hook).

    ``codes=None`` decodes every LOG code seen (the ``--decode-live`` form);
    a set restricts to those codes (the repeatable ``--decode 0xXXXX`` form).
    """

    # Bounded so a slow decoder can never balloon memory. Each item is one
    # os.read() chunk (~64 KiB); 256 chunks ≈ 16 MiB worst case before we start
    # dropping the DECODE copy (raw bytes are already safely written).
    _MAXSIZE = 256

    def __init__(self, codes: "Optional[set[int]]", out=None,
                 verify_crc: bool = True, pcap_sink=None,
                 emit_jsonl: bool = True):
        self.codes = codes
        self.out = out if out is not None else sys.stderr
        self.verify_crc = verify_crc
        self.pcap_sink = pcap_sink      # diagmunge PcapSink or None
        self.emit_jsonl = emit_jsonl    # False when only --pcap-out is active
        self._q: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=self._MAXSIZE)
        self._thread: "Optional[threading.Thread]" = None
        self._sentinel = object()
        # Counters (read after stop()): decode output dropped under overload —
        # NEVER raw bytes. Plus decode volume + per-code tallies for the summary.
        self.dropped_chunks = 0
        self.dropped_bytes = 0
        self.decoded = 0
        self.parse_errors = 0
        self.code_counts: "dict[int, int]" = {}
        self._novel_seen: "set[int]" = set()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="diaggulp-live-decode", daemon=True)
        self._thread.start()

    def feed(self, data: bytes) -> None:
        """Tee one hot-path chunk to the decoder — non-blocking, drop on full.

        Called from the capture hot loop right after the raw write. On a full
        queue we drop the decode copy (the raw .bin already has these bytes)
        and count it, so the decoder can NEVER stall the read→write pair."""
        try:
            self._q.put_nowait(data)
        except queue.Full:
            self.dropped_chunks += 1
            self.dropped_bytes += len(data)

    def _chunks(self):
        """Yield queued chunks until the sentinel — the stream iterable."""
        while True:
            item = self._q.get()
            if item is self._sentinel:
                return
            yield item

    def _run(self) -> None:
        # Lazy imports: only pay the diaggrok import cost when live decode is on.
        from diaggrok.hdlc import iter_log_records_stream
        from diaggrok import registry
        for code, ts, payload in iter_log_records_stream(
                self._chunks(), verify_crc=self.verify_crc, flush_tail=True):
            if self.codes is not None and code not in self.codes:
                continue
            self.decoded += 1
            self.code_counts[code] = self.code_counts.get(code, 0) + 1
            decoded = None
            rec = None
            try:
                rec = registry.parse(code, ts, payload)
                if rec is not None:
                    decoded = (rec.to_dict() if hasattr(rec, "to_dict")
                               and callable(rec.to_dict) else _asdict_safe(rec))
                elif code not in self._novel_seen:
                    # Unparsed code in the live stream → novelty alert (#N).
                    self._novel_seen.add(code)
                    print(f"diaggulp[live]: NEW unparsed log code 0x{code:04X} "
                          f"(no diaggrok parser)", file=sys.stderr, flush=True)
            except Exception as exc:  # a parser bug must not kill the thread
                self.parse_errors += 1
                decoded = {"_parse_error": str(exc)}
            if self.pcap_sink is not None and rec is not None:
                import time
                try:
                    self.pcap_sink.write_record(code, time.time(), rec)
                except Exception:
                    pass  # a pcap-encode bug must not kill the capture thread
            if not self.emit_jsonl:
                continue
            line = json.dumps({"code": f"0x{code:04X}", "ts": ts,
                               "decoded": decoded}, default=str)
            try:
                self.out.write(line + "\n")
                self.out.flush()
            except (BrokenPipeError, ValueError):
                # Output closed (e.g. operator redirected to a closed pipe) —
                # keep draining the queue so feed() never blocks the hot path.
                pass

    def stop(self, timeout: float = 5.0) -> None:
        """Signal shutdown, drain, and print a one-line summary to stderr."""
        if self._thread is None:
            return
        try:
            self._q.put_nowait(self._sentinel)
        except queue.Full:
            # Queue saturated; block briefly to deliver the sentinel.
            self._q.put(self._sentinel)
        self._thread.join(timeout=timeout)
        top = sorted(self.code_counts.items(), key=lambda kv: -kv[1])[:8]
        top_str = ", ".join(f"0x{c:04X}×{n}" for c, n in top) or "(none)"
        drop_str = ""
        if self.dropped_chunks:
            drop_str = (f"; DROPPED {self.dropped_chunks} decode chunk(s) "
                        f"/ {self.dropped_bytes:,} B under load (raw .bin "
                        f"unaffected)")
        print(f"diaggulp[live]: decoded {self.decoded:,} record(s) across "
              f"{len(self.code_counts)} code(s) [{top_str}]"
              f"{'; ' + str(self.parse_errors) + ' parse error(s)' if self.parse_errors else ''}"
              f"{drop_str}", file=sys.stderr, flush=True)


def _asdict_safe(rec) -> "dict | str":
    """Best-effort serialize a parser result that lacks ``to_dict``."""
    try:
        from dataclasses import asdict, is_dataclass
        if is_dataclass(rec):
            return asdict(rec)
    except Exception:
        pass
    return str(rec)


# ---------------------------------------------------------------------------
# Offline pcap replay (#N) — read DGE1 datagrams from a pcap capture of the
# diagbarf UDP broadcast and reassemble the same raw HDLC the udp-listen path
# produces. Uses the shared DGE1 deframer (parse_dge1_header + Dge1SeqTracker)
# so live and offline paths report identical gap statistics.
# ---------------------------------------------------------------------------

# Classic-pcap global-header magics (per-file byte order; ns vs us timestamp
# resolution is irrelevant here — we never read the packet timestamps).
_PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"   # little-endian, microsecond
_PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"   # big-endian, microsecond
_PCAP_MAGIC_LE_NS = b"\x4d\x3c\xb2\xa1"  # little-endian, nanosecond
_PCAP_MAGIC_BE_NS = b"\xa1\xb2\x3c\x4d"  # big-endian, nanosecond

# Link-layer header types we know how to strip down to the IP packet.
_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW = 101          # raw IP (no link layer)
_LINKTYPE_LINUX_SLL = 113
_LINKTYPE_LINUX_SLL2 = 276


def _udp_payload_from_ip(ip: bytes, port: Optional[int]) -> Optional[bytes]:
    """Return the UDP payload of an IPv4/IPv6 packet, or None if it is not a
    UDP datagram (or does not match ``port`` when a filter is given)."""
    if len(ip) < 1:
        return None
    version = ip[0] >> 4
    if version == 4:
        if len(ip) < 20:
            return None
        ihl = (ip[0] & 0x0F) * 4
        if ip[9] != 17 or len(ip) < ihl + 8:   # protocol 17 == UDP
            return None
        udp = ip[ihl:]
    elif version == 6:
        if len(ip) < 40 or ip[6] != 17:         # next-header 17 == UDP (no ext hdrs)
            return None
        udp = ip[40:]
    else:
        return None
    if len(udp) < 8:
        return None
    src_port = int.from_bytes(udp[0:2], "big")
    dst_port = int.from_bytes(udp[2:4], "big")
    if port is not None and port not in (src_port, dst_port):
        return None
    return udp[8:]


def _udp_payload_from_link(linktype: int, frame: bytes, port: Optional[int]) -> Optional[bytes]:
    """Strip the link layer down to the IP packet, then extract the UDP
    payload. Returns None for non-IP / non-UDP / non-matching frames."""
    if linktype == _LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        off = 12
        ethertype = int.from_bytes(frame[off:off + 2], "big")
        # Skip 802.1Q / 802.1ad VLAN tags (possibly stacked).
        while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 6:
            off += 4
            ethertype = int.from_bytes(frame[off:off + 2], "big")
        ip = frame[off + 2:]
        if ethertype not in (0x0800, 0x86DD):
            return None
        return _udp_payload_from_ip(ip, port)
    if linktype == _LINKTYPE_LINUX_SLL:
        return _udp_payload_from_ip(frame[16:], port) if len(frame) >= 16 else None
    if linktype == _LINKTYPE_LINUX_SLL2:
        return _udp_payload_from_ip(frame[20:], port) if len(frame) >= 20 else None
    if linktype == _LINKTYPE_RAW:
        return _udp_payload_from_ip(frame, port)
    return None


def iter_pcap_udp_payloads(path: str, port: Optional[int] = None):
    """Yield the UDP payload of every UDP datagram in a classic-pcap file
    (optionally filtered to ``port`` on either src or dst).

    Supports the four classic-pcap global-header magics (LE/BE × us/ns) and
    the Ethernet / Linux-SLL / Linux-SLL2 / raw-IP link types. pcapng is not
    supported (tcpdump ``-w`` writes classic pcap by default); a pcapng file
    raises ValueError so the caller can surface a clear message.
    """
    with open(path, "rb") as fh:
        gh = fh.read(24)
        if len(gh) < 24:
            raise ValueError(f"{path}: too short to be a pcap (got {len(gh)} bytes)")
        magic = gh[:4]
        if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_LE_NS):
            endian = "little"
        elif magic in (_PCAP_MAGIC_BE, _PCAP_MAGIC_BE_NS):
            endian = "big"
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError(f"{path}: pcapng is not supported — re-save as "
                             "classic pcap (tcpdump -w writes classic by default)")
        else:
            raise ValueError(f"{path}: not a pcap file (bad magic {magic.hex()})")
        linktype = int.from_bytes(gh[20:24], endian)
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                break
            incl_len = int.from_bytes(ph[8:12], endian)
            frame = fh.read(incl_len)
            if len(frame) < incl_len:
                break  # truncated final record
            payload = _udp_payload_from_link(linktype, frame, port)
            if payload is not None:
                yield payload


def replay_pcap_dge1(path: str, port: Optional[int], out_fd: int) -> "tuple[int, dict]":
    """Deframe the DGE1 datagrams in ``path`` and write the reassembled raw
    HDLC byte stream to ``out_fd``. Returns ``(bytes_written, gap_report)`` —
    the gap report has the same shape the live udp-listen sidecar carries."""
    tracker = Dge1SeqTracker()
    bytes_written = 0
    for datagram in iter_pcap_udp_payloads(path, port):
        parsed = parse_dge1_header(datagram)
        if parsed is None:
            tracker.note_malformed()
            continue
        payload, seq, restart = parsed
        if not tracker.track(seq, restart):
            continue  # late/duplicate — dropped, matches udp-listen behavior
        os.write(out_fd, payload)
        bytes_written += len(payload)
    return bytes_written, tracker.gap_report()


def _run_pcap_transport(args, explicit_port: bool) -> int:
    """Handle ``--transport pcap`` end to end: read DGE1 datagrams from a pcap,
    reassemble the DLF, and write the .udpgaps.json gap sidecar."""
    if not args.pcap:
        print("error: --transport pcap requires --pcap FILE", file=sys.stderr)
        return 2
    if not os.path.exists(args.pcap):
        print(f"error: pcap file not found: {args.pcap}", file=sys.stderr)
        return 2
    # The diagbarf broadcast lands on UDP 12399; default the filter to that
    # unless the user explicitly set --port (which globally defaults to 2500).
    port = args.port if explicit_port else 12399

    out_fd, resolved_output_path = _open_output(args.output) if args.output \
        else (sys.stdout.buffer.fileno(), None)
    try:
        bytes_written, gap_report = replay_pcap_dge1(args.pcap, port, out_fd)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        if args.output:
            try:
                os.close(out_fd)
            except OSError:
                pass
        return 2
    if args.output:
        try:
            os.close(out_fd)
        except OSError:
            pass

    if resolved_output_path is not None:
        gaps_path = resolved_output_path + ".udpgaps.json"
        try:
            with open(gaps_path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "version": 1,
                        "tool": "diaggulp.py",
                        "transport": "pcap",
                        "framing": "DGE1",
                        "pcap": args.pcap,
                        "port": port,
                        **gap_report,
                    },
                    fh,
                    indent=2,
                )
                fh.write("\n")
        except OSError as exc:
            print(f"warning: could not write gap sidecar {gaps_path}: {exc}",
                  file=sys.stderr)

    if not args.quiet:
        print(
            f"diaggulp: pcap replay complete — wrote {bytes_written} bytes"
            + (f" to {resolved_output_path}" if resolved_output_path else " to stdout")
            + f" (datagrams received={gap_report['received']} "
            f"missing={gap_report['missing']} "
            f"malformed={gap_report['malformed']} "
            f"loss={gap_report['loss_pct']:.2f}%)",
            file=sys.stderr,
        )
    return 0


# ===========================================================================
# NMEA side-capture
# ---------------------------------------------------------------------------
# Whenever diaggulp captures DIAG on a serial transport, it also captures the
# modem's NMEA stream from the dedicated NMEA port (operator decision
# 2026-06-19: "make it the norm whenever we're using diaggulp"; `--no-nmea`
# opts out). This runs in its own daemon thread on its own serial fd writing
# its own `<output-stem>.nmea` file, so it touches none of diaggulp's DIAG hot
# path and the #N throughput guarantee is unaffected. Line format matches
# tools/gnss_capture_nmea.py: "<UTC ISO8601> <NMEA line>".
# ===========================================================================

# Best-effort vendor -> NMEA USB interface number. Conservative: only the
# compositions where the NMEA interface is unambiguous get an auto-guess;
# everything else returns None and the caller must pass --nmea-port (which the
# survey/wardrive orchestration does from its own modem_discover run). The
# explicit flag always wins over this map.
_VENDOR_NMEA_INTF = {
    "2c7c": 1,   # Quectel (EG25/RM5xx DM+NMEA+AT+modem)
    "1e0e": 1,   # SIMCom (SIM7600/SIM8202)
    "1bc7": 3,   # Telit (LM960/FN980 1040 composition)
}


def nmea_output_path(diag_output_path):
    """Derive the sibling .nmea path from a diaggulp -o output path.

    `diag_capture.bin` -> `diag_capture.nmea`; any other extension (or none)
    gets `.nmea` appended after stripping a trailing `.bin`/`.hdlc`.
    """
    if diag_output_path is None:
        return None
    base = diag_output_path
    for ext in (".bin", ".hdlc"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return base + ".nmea"


def _read_sysfs(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


def resolve_sibling_nmea_port(diag_device, sysfs_root="/sys"):
    """Best-effort: find the NMEA tty that is a USB sibling of `diag_device`.

    Walks /sys/class/tty/<tty>/device to the USB interface dir, climbs to the
    parent USB device, reads idVendor, looks up the conventional NMEA interface
    number, and returns the /dev path of the ttyUSB* on that interface. Returns
    None on any unknown/ambiguous layout (PCIe/MHI, unmapped vendor, missing
    sibling) — auto-resolve is a convenience, not a guarantee.

    `sysfs_root` is injectable for testing against a fixture tree.
    """
    if not diag_device or not diag_device.startswith("/dev/"):
        return None
    tty = os.path.basename(diag_device)
    dev_link = os.path.join(sysfs_root, "class", "tty", tty, "device")
    try:
        intf_dir = os.path.realpath(dev_link)
    except OSError:
        return None
    if not os.path.isdir(intf_dir):
        return None

    # Interface dir name: "<bus>-<port>[.<port>]:<config>.<intf>"
    intf_name = os.path.basename(intf_dir)
    if ":" not in intf_name:
        return None
    usb_dev_dir = os.path.dirname(intf_dir)  # parent = the USB device
    prefix = intf_name.rsplit(":", 1)[0]     # "<bus>-<port...>"
    config = intf_name.rsplit(":", 1)[1].split(".")[0]

    vendor = (_read_sysfs(os.path.join(usb_dev_dir, "idVendor")) or "").lower()
    nmea_intf = _VENDOR_NMEA_INTF.get(vendor)
    if nmea_intf is None:
        return None

    sib_name = f"{prefix}:{config}.{nmea_intf}"
    sib_dir = os.path.join(usb_dev_dir, sib_name)
    if not os.path.isdir(sib_dir):
        return None
    # The sibling interface dir contains a ttyUSBN/ child (or tty/ttyUSBN/).
    for cand in (sib_dir, os.path.join(sib_dir, "tty")):
        try:
            entries = os.listdir(cand)
        except OSError:
            continue
        for e in entries:
            if e.startswith("ttyUSB") or e.startswith("ttyACM"):
                return os.path.join("/dev", e)
    return None


def format_nmea_line(raw_line, ts=None):
    """Prefix a decoded NMEA line with a UTC ISO-8601 timestamp."""
    if ts is None:
        ts = datetime.now(timezone.utc)
    return f"{ts.isoformat()} {raw_line}"


class NmeaSidecar:
    """Background NMEA capture thread. Fully isolated from the DIAG path."""

    def __init__(self, port, out_path, baud=115200, quiet=False):
        self.port = port
        self.out_path = out_path
        self.baud = baud
        self.quiet = quiet
        self._stop = threading.Event()
        self._thread = None
        self.lines = 0
        self.error = None

    def start(self):
        try:
            import serial  # lazy: only the live capture needs pyserial
        except ImportError as e:           # pragma: no cover - env-dependent
            self.error = f"pyserial unavailable: {e}"
            self._warn(self.error)
            return False
        try:
            self._ser = serial.Serial(self.port, self.baud, timeout=1)
        except Exception as e:             # noqa: BLE001 - any open failure is non-fatal
            self.error = f"could not open NMEA port {self.port}: {e}"
            self._warn(self.error)
            return False
        self._thread = threading.Thread(target=self._run, name="nmea-sidecar", daemon=True)
        self._thread.start()
        if not self.quiet:
            self._warn(f"NMEA side-capture started on {self.port} -> {self.out_path}")
        return True

    def _run(self):
        try:
            with open(self.out_path, "w", encoding="utf-8") as fh:
                while not self._stop.is_set():
                    try:
                        raw = self._ser.readline()
                    except Exception:      # noqa: BLE001 - serial hiccup; keep going
                        continue
                    if not raw:
                        continue
                    line = raw.decode("ascii", errors="replace").strip()
                    if not line:
                        continue
                    fh.write(format_nmea_line(line) + "\n")
                    fh.flush()
                    self.lines += 1
        except OSError as e:
            self.error = f"NMEA writer failed: {e}"
            self._warn(self.error)
        finally:
            try:
                self._ser.close()
            except Exception:              # noqa: BLE001
                pass

    def stop(self):
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=3)
        if not self.quiet:
            self._warn(f"NMEA side-capture stopped ({self.lines} lines)")

    def _warn(self, msg):
        print(f"diaggulp[nmea]: {msg}", file=sys.stderr)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="diaggulp.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "device",
        nargs="?",
        help="Serial device path (for --transport=serial, default)",
    )
    parser.add_argument(
        "--transport",
        choices=["serial", "tcp", "udp", "tcp-connect", "udp-listen", "pcap"],
        default="serial",
        help="DIAG transport (default: serial). 'tcp-connect' dials a device "
             "that LISTENS (the #N diagbarf TCP sink); 'udp-listen' "
             "passively reassembles the #N DGE1-framed UDP stream. Both are "
             "passive consumers (the on-device daemon already armed the mask), "
             "so --no-mask is forced and anchor frames are disabled. 'pcap' "
             "(#N) is fully offline: it reads DGE1 datagrams from a "
             "pcap/tcpdump capture of the diagbarf broadcast (--pcap FILE) and "
             "reassembles the same raw-HDLC -> DLF the live udp-listen path "
             "produces, plus a .udpgaps.json gap sidecar.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host for tcp/udp transport")
    parser.add_argument("--port", type=int, default=2500, help="Port for tcp/udp")
    parser.add_argument(
        "--udp-reorder-window", type=int, default=0, metavar="N",
        help="udp-listen only (#N): enable a bounded reorder buffer of N "
             "DGE1 seqs. On reordering host paths (e.g. CFW-3212 eno1.45, where "
             "the on-wire stream is in order but the live socket reorders — "
             "#N), this resequences early-arrived datagrams instead of "
             "dropping them, recovering records that --transport pcap already "
             "sees. 0 (default) = no buffering (flat-LAN behavior). Try ~2048 "
             "on a heavy-reorder path; the window bounds both memory and "
             "delivery latency.",
    )
    parser.add_argument(
        "--pcap",
        help="Path to a pcap/pcapng capture of the diagbarf DGE1 UDP stream "
             "(for --transport pcap, #N). Capture e.g. with "
             "`tcpdump -i <iface> -w diagbarf.pcap 'udp port 12399'`.",
    )
    parser.add_argument(
        "-b", "--baud", type=int, default=115200,
        help="Serial baud rate (default 115200)",
    )
    parser.add_argument(
        "-o", "--output",
        help='Output file path (use "%%s" for Unix timestamp; default stdout)',
    )
    parser.add_argument(
        "--rotate-size", type=_parse_size,
        help="Rotate output file every N bytes (e.g. 100M, 1G)",
    )
    parser.add_argument(
        "--rotate-interval", type=int,
        help="Rotate output file every N seconds",
    )
    parser.add_argument(
        "--no-mask", action="store_true",
        help="Skip the log mask handshake (just dump whatever's already flowing)",
    )
    parser.add_argument(
        "--log-code", action="append", default=None, metavar="0xXXXX",
        help="Subscribe to ONLY this DIAG log code instead of the default "
             "all-logs mask (repeatable). The #N narrow-mask validation "
             "capture: pass the code under test plus any liveness canary, e.g. "
             "--log-code 0xB8D1 --log-code 0x1875. Hex (0x...) or decimal. "
             "Ignored under --no-mask.",
    )
    parser.add_argument(
        "--decode", action="append", default=None, type=_parse_int_arg,
        metavar="0xXXXX",
        help="#N LIVE DECODE: decode this log code inline as frames arrive "
             "(repeatable) and emit one JSONL record per decoded frame to "
             "--decode-out (default stderr), instead of only post-capture "
             "offline decode. Runs on a side thread fed by a bounded queue — "
             "the raw .bin stays canonical and is never affected; under load "
             "the DECODE copy is dropped (counted), never raw bytes. Pair with "
             "a narrow --log-code mask (mandatory on shared DIAG/AT-task parts "
             "like the EM7455). Hex (0x...) or decimal.",
    )
    parser.add_argument(
        "--decode-live", action="store_true", default=False,
        help="#N LIVE DECODE for EVERY LOG code seen (no per-code filter) — "
             "the broad form of --decode. Best paired with a narrow --log-code "
             "mask so it decodes a handful of codes, not 13k.",
    )
    parser.add_argument(
        "--decode-out", default=None, metavar="PATH",
        help="#N: write the live-decode JSONL here instead of stderr "
             "(one decoded record per line). The capture's own raw/DLF outputs "
             "are unaffected.",
    )
    parser.add_argument(
        "--pcap-out", default=None, metavar="PATH",
        help="ONE-SHOT LIVE PCAP: while capturing, also write a "
             "Wireshark-readable GSMTAP pcap here (LTE RRC/NAS on UDP/4729) "
             "plus a sibling .nr.pcap for NR signalling (Exported-PDU). Runs "
             "on the live-decode side thread; the raw capture (-o) is "
             "unaffected. Frame timestamps are arrival wall-clock. Requires "
             "the diaggrok decode extra (imported lazily).",
    )
    parser.add_argument(
        "--ext-msg-f3", action=argparse.BooleanOptionalAction, default=True,
        help="Arm the modem's F3 debug-message stream (DIAG_EXT_MSG_CONFIG_F / "
             "SET_ALL_RT_MASKS) so the capture carries free-text 0x79 / hashed "
             "0x99 QSR4 subsystem trace, not just structured log codes. "
             "DEFAULT: ON (#N) — every capture should carry resolvable F3 so "
             "it can be F3-ground-truthed later (#N). Pass --no-ext-msg-f3 to "
             "skip arming (e.g. to bound capture size on a chatty SDX72, where "
             "SET_ALL_RT_MASKS can emit ~660k 0x99 frames in 30s — a per-subsystem "
             "severity preset is the #N follow-up). The F3 mask is orthogonal "
             "to the binary log mask; both are raised. Decode with "
             "tools/diag_f3_extract.py (#N) / tools/diag_f3_decode.py (#N).",
    )
    parser.add_argument(
        "--ext-msg-f3-ss", action="append", default=None, metavar="SSID", type=_parse_int_arg,
        help="Arm F3 for ONLY this subsystem id (repeatable) via the bounded "
             "DIAG_EXT_MSG_CONFIG_F / SET_RT_MASK (sub_cmd 4), instead of the "
             "all-on SET_ALL_RT_MASKS. Bounds capture size on a chatty modem "
             "(#N) — e.g. arm just LTE/NR ML1 + search SSIDs. Hex (0x...) or "
             "decimal. Implies F3 arming and overrides --ext-msg-f3 / "
             "--no-ext-msg-f3. Severity floor set by --ext-msg-f3-level. "
             "Discover valid ss_ids on this firmware with --ext-msg-f3-list-ss. "
             "⚠️ SET_RT_MASK is hardware-unverified in-repo (#N).",
    )
    parser.add_argument(
        "--ext-msg-f3-preset", default=None, choices=sorted(_F3_PRESETS),
        help="Arm F3 for a curated, GROUNDED set of subsystem ids by name, "
             "instead of hand-listing --ext-msg-f3-ss. 'ml1' arms LTE/NR ML1 + "
             "search (ss_ids 1007/3001/9509/9520, read from the qdb and verified "
             "stable across SDX55/SDX62). Merges with any --ext-msg-f3-ss. Same "
             "bounded SET_RT_MASK path; severity via --ext-msg-f3-level. "
             "⚠️ SET_RT_MASK is hardware-unverified in-repo (#N).",
    )
    parser.add_argument(
        "--ext-msg-f3-level", default="all",
        choices=("low", "med", "high", "error", "fatal", "all"),
        help="Severity floor for --ext-msg-f3-ss: arm the chosen Qualcomm "
             "MSG_LVL_* level and every more-severe level. 'all' (default) = "
             "every level (0xFFFFFFFF, matching SET_ALL_RT_MASKS); 'high' = "
             "HIGH|ERROR|FATAL only (a quiet capture). Ignored unless "
             "--ext-msg-f3-ss is given.",
    )
    parser.add_argument(
        "--ext-msg-f3-list-ss", action="store_true",
        help="Query the firmware's valid F3 SSID ranges "
             "(DIAG_EXT_MSG_CONFIG_F / QUERY_SSID_RANGES, sub_cmd 1), print "
             "them, and exit. The RETRIEVE-equivalent for discovering which "
             "ss_ids --ext-msg-f3-ss may target (the SSID set is "
             "firmware-dependent). Requires a live modem.",
    )
    parser.add_argument(
        "--mask-retries", type=int, default=1,
        help="On mask handshake timeout, retry this many times (default 1) "
             "after sleeping --mask-retry-delay seconds. Each retry re-runs "
             "the full RETRIEVE_RANGES + SET_MASK sequence.",
    )
    parser.add_argument(
        "--mask-retry-delay", type=float, default=5.0,
        help="Seconds to sleep before each mask handshake retry (default 5.0). "
             "Tuned to let the modem settle after USB re-enumeration / cold boot.",
    )
    quirk_group = parser.add_mutually_exclusive_group()
    quirk_group.add_argument(
        "--telit-quirk", dest="telit_quirk", action="store_const",
        const=True, default=None,
        help="Force the flush-on-OUT DIAG capture path for Telit/SDX20 modems "
             "(LM960A18). These modems deliver buffered DIAG only in response "
             "to host writes and deadlock on large mask writes, so the normal "
             "passive handshake+capture returns 0 bytes (#N). This enables: "
             "a bounded backlog drain on open, pumped (chunked) mask writes, "
             "operation-field reply correlation, and periodic keep-alive kicks "
             "during capture. DEFAULT IS AUTO (#N): the path turns itself on "
             "when the serial DIAG port's USB VID/PID is a known flush-on-OUT "
             "device, so this flag is only needed to force it on for an "
             "unrecognized unit. Serial transport only; harmless but pointless "
             "on other modems. The capture stream interleaves small 0x73 "
             "kick-reply frames, which downstream decoders skip.",
    )
    quirk_group.add_argument(
        "--no-telit-quirk", dest="telit_quirk", action="store_const", const=False,
        help="Force the flush-on-OUT quirk path OFF, overriding the #N VID "
             "auto-detect. Use if the auto-enabled path ever misbehaves on a "
             "recognized Telit unit and you want the legacy passive capture.",
    )
    parser.add_argument(
        "--chunk-size", type=_parse_size, default=READ_CHUNK,
        help="Read chunk size (default 64K)",
    )
    parser.add_argument(
        "--anchor-frame", choices=["none", "boundary"], default="boundary",
        help="Anchor-frame strategy for DLF↔host timestamp calibration (#N). "
             "'boundary' (default) sends a DIAG_VERNO_F request immediately "
             "before and after the capture and writes a "
             "<output>.anchors.json sidecar consumed by "
             "diaggrok_at_correlate.py --auto-align. 'none' disables "
             "anchor emission (original behavior).",
    )
    parser.add_argument(
        "--anchor-timeout", type=float, default=2.0,
        help="Timeout in seconds for each anchor-frame DIAG_VERNO_F "
             "round trip (default 2.0). On timeout the capture proceeds "
             "without that anchor and the sidecar records the partial "
             "result; correlate's fallback handles missing anchors.",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--enable-oemdre", action="store_true",
        help="Before the log-mask handshake, enable Qualcomm OEM DRE in the "
             "SAME DiagClient session (NV item 7165=1 + GPS PDAPI DRE-ON "
             "session command) so 0x14DE OemdreMeasurementReport packets flow. "
             "Use for SDX-family modems whose GNSS measurements are otherwise "
             "emitted under chipset-specific log codes gnss_compare.py can't "
             "parse. Doing it in-session avoids the second-channel-open wedge "
             "seen on MHI char devices (EM160R-GL /dev/wwan0qcdm0).",
    )
    parser.add_argument(
        "--spc", default=None,
        help="Before the log-mask handshake, send a DIAG SPC unlock (opcode "
             "0x46) in the SAME session. Use a literal 6-char code (e.g. "
             "000000) or 'auto' to try known vendor SPCs (000000 then 0000). "
             "Needed on EG25/EC25-class (MDM9607) modems that reject "
             "LOG_CONFIG with DIAG_BAD_CMD_F until unlocked (#N). Reachable "
             "from a wardrive via diag_engine slurp_args. Skipped on the "
             "passive tcp-connect/udp-listen transports (no command path).",
    )
    parser.add_argument(
        "--min-free-pct", type=float, default=5.0,
        help="Disk-space floor (percent free) for the capture filesystem. "
             "diaggulp REFUSES to start a capture when the output dir's "
             "filesystem has less than this fraction free (default 5.0%%). A "
             "full disk silently wedges both the capture AND syncthing's corpus "
             "folder (its 1%%-min-free guard stalls all sync). Use 0 to disable.",
    )
    parser.add_argument(
        "--no-disk-check", action="store_true",
        help="Skip the --min-free-pct preflight entirely (operator override).",
    )
    parser.add_argument(
        "--nmea-port", default=None, metavar="PATH",
        help="Capture the modem's NMEA stream from this serial port alongside "
             "the DIAG capture, writing a UTC-timestamped <output-stem>.nmea "
             "sidecar. Runs in an isolated thread on its own fd (no effect on "
             "the DIAG hot path). If omitted (and not --no-nmea), diaggulp "
             "best-effort auto-resolves the sibling NMEA tty from the DIAG "
             "device's USB topology. Serial transport only.",
    )
    parser.add_argument(
        "--no-nmea", action="store_true",
        help="Disable NMEA side-capture. NMEA capture is ON by default on the "
             "serial transport (operator decision 2026-06-19) so every capture "
             "that has a reachable NMEA port also yields a GNSS transcript; pass "
             "this to opt out.",
    )
    parser.add_argument(
        "--nmea-baud", type=int, default=115200,
        help="Baud for the NMEA side-capture port (default 115200; correct for "
             "all known Telit/Quectel/Sierra/SIMCom USB NMEA interfaces).",
    )
    args = parser.parse_args(argv)

    # ``-o -`` means stdout, not a file named ``-`` (#N). Normalize before
    # any ``if args.output:`` branch (disk preflight, output open, sidecars).
    args.output = _resolve_output_arg(args.output)

    # --- Disk-space preflight: a full disk wedges both the capture and the
    # syncthing corpus folder (the 1%-min-free guard stalls ALL sync, both
    # directions, fleet-wide — observed 2026-06-13, lv55 captures not
    # propagating). Refuse to START a capture below the floor so the operator
    # frees space first. Skipped for stdout (no -o) and offline pcap replay. ---
    if args.output and not args.no_disk_check and args.min_free_pct > 0:
        import shutil
        out_dir = os.path.dirname(os.path.abspath(args.output)) or "."
        try:
            _u = shutil.disk_usage(out_dir)
            free_gb = _u.free / 1e9
            pct_free = 100.0 * _u.free / _u.total if _u.total else 100.0
        except OSError:
            free_gb = pct_free = None
        if pct_free is not None and pct_free < args.min_free_pct:
            print(
                f"error: only {pct_free:.1f}% ({free_gb:.1f} GB) free on the "
                f"capture filesystem ({out_dir}) — below the "
                f"{args.min_free_pct:.0f}% floor. A full disk wedges both this "
                f"capture and syncthing's corpus folder (its 1%-min-free guard "
                f"stalls all sync fleet-wide). Free space first (e.g. "
                f"`rm -rf <redacted-capture-path> or pass --min-free-pct / "
                f"--no-disk-check to override.",
                file=sys.stderr,
            )
            return 2
        if (pct_free is not None and pct_free < 2 * args.min_free_pct
                and not args.quiet):
            print(
                f"warning: {pct_free:.1f}% ({free_gb:.1f} GB) free on {out_dir} "
                f"— a long all-F3 capture can be hundreds of MB; watch headroom.",
                file=sys.stderr,
            )

    # --- Offline pcap replay (#N): fully self-contained, no live device,
    # no mask handshake, no select loop. Handle it before any live transport
    # machinery and return. ---
    if args.transport == "pcap":
        _raw_argv = argv if argv is not None else sys.argv[1:]
        explicit_port = any(a == "--port" or a.startswith("--port=") for a in _raw_argv)
        return _run_pcap_transport(args, explicit_port)

    # --- Open the transport ---
    if args.transport == "serial":
        if not args.device:
            print("error: --transport=serial requires a device path", file=sys.stderr)
            return 2
        client = DiagClient.from_serial(args.device, args.baud)
    elif args.transport == "tcp":
        client = DiagClient.from_tcp_server(args.host, args.port)
    elif args.transport == "udp":
        client = DiagClient.from_udp_broadcast(args.host, args.port)
    elif args.transport == "tcp-connect":
        # #N: dial a device that LISTENS (diagbarf TCP-listen sink).
        client = DiagClient.from_tcp_client(args.host, args.port)
    elif args.transport == "udp-listen":
        # #N: passively reassemble the DGE1-framed UDP stream.
        # #N: optional bounded reorder buffer for reordering host paths.
        client = DiagClient.from_udp_listen(
            args.host, args.port, reorder_window=args.udp_reorder_window)
    else:
        print(f"error: unknown transport {args.transport}", file=sys.stderr)
        return 2

    # The #N passive transports consume a stream the on-device daemon
    # already armed; we cannot (and must not) run the mask handshake, and
    # anchor frames need a writable command path the daemon ignores. Force
    # both off so the common defaults don't stall waiting for responses.
    if args.transport in ("tcp-connect", "udp-listen"):
        if not args.no_mask:
            print(
                "diaggulp: --transport "
                f"{args.transport} is a passive consumer of the #N "
                "diagbarf stream; forcing --no-mask (daemon owns the mask)",
                file=sys.stderr,
            )
            args.no_mask = True
        # Passive diagbarf consumer: the daemon owns all mask state, so we never
        # arm F3 here either (overrides the #N default-on + the #N bounded
        # preset).
        args.ext_msg_f3 = False
        args.ext_msg_f3_ss = None
        args.ext_msg_f3_preset = None
        if args.anchor_frame != "none":
            args.anchor_frame = "none"

    # --- RETRIEVE-equivalent: enumerate the firmware's F3 SSID ranges and exit
    #     (#N). A simple query (no mask handshake / unlock needed, per
    #     tools/diag_probe_log_gen.py), so we run it as early as the transport
    #     is open and bail before opening any output. ---
    if args.ext_msg_f3_list_ss:
        ranges = _query_ext_msg_ss_ranges(client)
        client.close()
        if not ranges:
            print(
                "diaggulp: no F3 SSID ranges returned (timeout or empty/garbled "
                "response — this firmware may not support QUERY_SSID_RANGES)",
                file=sys.stderr,
            )
            return 1
        print(f"diaggulp: {len(ranges)} F3 SSID range(s):", file=sys.stderr)
        for first, last in ranges:
            count = last - first + 1
            print(f"  0x{first:04x}..0x{last:04x}  ({count} ssid(s))")
        return 0

    # --- Resolve the tri-state quirk switch by USB VID/PID auto-detect (#N) ---
    # args.telit_quirk is True (forced on), False (forced off via
    # --no-telit-quirk), or None (auto). On the serial path, auto sniffs the
    # device's USB ids and flips the quirk on for a known flush-on-OUT modem;
    # everywhere else auto resolves to off (no writable USB-serial port to
    # quirk). After this block args.telit_quirk is a plain bool again, so every
    # downstream `if args.telit_quirk:` is unchanged.
    if args.telit_quirk is None:
        detected = (
            _detect_flush_on_out_quirk(args.device)
            if args.transport == "serial" else None
        )
        if detected:
            print(
                f"diaggulp: detected {detected} -> enabling flush-on-OUT quirk "
                "(#N; pass --no-telit-quirk to disable)",
                file=sys.stderr,
            )
        args.telit_quirk = bool(detected)

    # --- Telit/SDX20 flush-on-OUT setup (#N) ---
    if args.telit_quirk:
        if args.transport != "serial":
            print(
                "error: --telit-quirk is a serial-transport quirk path; it "
                "needs the writable USB-serial DIAG port",
                file=sys.stderr,
            )
            return 2
        # Pumped mask writes must never block forever if the modem stops
        # draining its OUT endpoint; a finite write timeout turns a wedge into
        # a recoverable handshake failure. Best-effort (raw-fd MHI path has no
        # ._ser).
        ser = getattr(client._transport, "_ser", None)
        if ser is not None:
            try:
                ser.write_timeout = 3.0
            except Exception as exc:
                print(f"warning: could not set serial write_timeout ({exc})", file=sys.stderr)
        # This firmware does not answer DIAG_VERNO_F (the prior anchor probe),
        # so a boundary anchor only emits a spurious timeout warning. Drop it.
        if args.anchor_frame != "none":
            args.anchor_frame = "none"

    # --- SPC unlock (#N): EG25/EC25 (MDM9607) gate LOG_CONFIG behind an SPC
    # unlock (opcode 0x46) and reject the mask handshake with DIAG_BAD_CMD_F
    # until unlocked. Must run before the handshake, on a writable command path
    # — so skip the #N passive consumers (tcp-connect/udp-listen own no
    # command channel). Mirrors tools/capture_dlf_from_diag.py's --spc.
    if args.spc:
        if args.transport in ("tcp-connect", "udp-listen"):
            print(
                f"diaggulp: --spc ignored on passive transport {args.transport} "
                "(no writable command path)",
                file=sys.stderr,
            )
        elif _try_spc_unlock(client, args.spc):
            if not args.quiet:
                print("diaggulp: SPC unlock accepted (#N)", file=sys.stderr)
        else:
            print(
                "diaggulp: WARNING: no SPC accepted; continuing (modem may not "
                "gate LOG_CONFIG behind SPC)",
                file=sys.stderr,
            )

    # --- Optionally enable OEM DRE in this same session (#GNSS-SDX) ---
    # Must run on the same channel-open as the capture: on MHI char devices
    # (EM160R-GL /dev/wwan0qcdm0) a second DIAG tool opening the port wedges
    # the baseband DIAG task, so diag_setup.py-then-diaggulp is not viable.
    if args.enable_oemdre:
        nv_ok = client.enable_oemdre_nv()
        sess_ok = client.enable_oemdre_session()
        print(
            f"diaggulp: OEM DRE enable — nv_ack={nv_ok} session_ack={sess_ok}",
            file=sys.stderr,
        )

    # --- Send log mask config to enable all log codes ---
    # The handshake commonly times out on cold-boot / USB re-enumeration
    # while the modem is still settling (#N). Retry once after a short
    # sleep before falling back to the no-mask path — without retries, an
    # empty 0-byte capture is the most likely outcome of those scenarios.
    if not args.no_mask:
        # Narrow-mask (#N) when --log-code is given, else the all-logs mask.
        # Parse the codes once up front so a bad literal fails before the modem
        # handshake rather than mid-retry.
        narrow_codes: Optional[list[int]] = None
        if args.log_code:
            try:
                narrow_codes = [int(c, 0) for c in args.log_code]
            except ValueError as exc:
                print(f"error: invalid --log-code value ({exc})", file=sys.stderr)
                return 2
        attempts = max(1, 1 + args.mask_retries)
        last_exc: Optional[RuntimeError] = None
        for attempt in range(1, attempts + 1):
            try:
                if args.telit_quirk:
                    # Clear the cross-session IN backlog so the first
                    # transaction isn't mis-correlated (#N), then run the
                    # pumped/operation-correlated handshake.
                    discarded = _telit_drain_bounded(client)
                    if not args.quiet:
                        print(
                            f"diaggulp: [telit-quirk] drained {discarded} "
                            "stale frame(s) before handshake",
                            file=sys.stderr,
                        )
                    if narrow_codes:
                        _build_narrow_mask_telit(client, narrow_codes)
                    else:
                        _build_all_logs_mask_telit(client)
                elif narrow_codes:
                    _build_narrow_mask(client, narrow_codes)
                else:
                    _build_all_logs_mask(client)
                last_exc = None
                break
            except RuntimeError as exc:
                last_exc = exc
                print(
                    f"warning: log mask handshake failed "
                    f"(attempt {attempt}/{attempts}): {exc}",
                    file=sys.stderr,
                )
                if attempt < attempts:
                    print(
                        f"warning: retrying after {args.mask_retry_delay:.1f}s",
                        file=sys.stderr,
                    )
                    time.sleep(args.mask_retry_delay)
        if last_exc is not None:
            print(
                "warning: continuing without mask config — captured stream "
                "may be empty if modem isn't already configured",
                file=sys.stderr,
            )

    # --- Optionally enable the F3 ext-msg debug stream (#N) ---
    # Independent of the log mask: F3 messages are the firmware's free-text
    # subsystem trace, useful when the radio is off and the log stream is
    # silent. Non-fatal on failure — the log capture still proceeds.
    #
    # Three mutually-exclusive arming modes:
    #   --ext-msg-f3-ss <id>... / --ext-msg-f3-preset <name>
    #                            → bounded SET_RT_MASK, only those SSIDs (#N)
    #   --ext-msg-f3 (default)   → all-on SET_ALL_RT_MASKS, whole device (#N)
    #   --no-ext-msg-f3          → don't arm
    # A bounded ss list takes precedence over the all-on default/flag.
    # A named preset expands to its grounded ss_ids and merges with any -ss list.
    bounded_ss = list(args.ext_msg_f3_ss or ())
    if args.ext_msg_f3_preset:
        bounded_ss = sorted(set(bounded_ss) | set(_F3_PRESETS[args.ext_msg_f3_preset]))
    if bounded_ss:
        rt_mask = _f3_level_mask(args.ext_msg_f3_level)
        try:
            _enable_ext_msg_f3_bounded(client, bounded_ss, rt_mask)
        except RuntimeError as exc:
            print(
                f"warning: could not arm bounded F3 ext-msg stream ({exc}); "
                "continuing with log capture only",
                file=sys.stderr,
            )
    elif args.ext_msg_f3:
        try:
            _enable_ext_msg_f3(client)
        except RuntimeError as exc:
            print(
                f"warning: could not enable F3 ext-msg stream ({exc}); "
                "continuing with log capture only",
                file=sys.stderr,
            )

    # --- Open output ---
    writer: Optional[_RotatingWriter] = None
    resolved_output_path: Optional[str] = None
    if args.output:
        if args.rotate_size or args.rotate_interval:
            writer = _RotatingWriter(
                args.output,
                rotate_size=args.rotate_size,
                rotate_interval=args.rotate_interval,
            )
            out_fd = writer._fd  # writer manages the fd
            resolved_output_path = writer._current_path
        else:
            out_fd, resolved_output_path = _open_output(args.output)
    else:
        out_fd = sys.stdout.buffer.fileno()

    # SIGINT/SIGTERM handlers — let the main loop's KeyboardInterrupt path
    # do the cleanup so we get a final stats line. Both signals are wired to
    # the same handler so an interactive Ctrl-C (SIGINT) drains exactly like a
    # `kill -TERM` (#N): the select() loop bounds its block to <=1s and
    # catches KeyboardInterrupt, so the stop lands on the clean-exit path.
    def _sig_handler(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    # --- Anchor-frame eligibility check (#N) ---
    # We only emit anchors for non-rotating, non-stdout captures. Rotating
    # captures span multiple files with their own time bases, and stdout
    # capture has no place to put the sidecar; both are deferred to a
    # follow-up if the need arises.
    anchor_enabled = (
        args.anchor_frame == "boundary"
        and resolved_output_path is not None
        and writer is None
    )
    if args.anchor_frame == "boundary" and not anchor_enabled:
        if resolved_output_path is None:
            print(
                "warning: --anchor-frame=boundary requires --output (stdout "
                "capture has no sidecar location); skipping anchor emission",
                file=sys.stderr,
            )
        elif writer is not None:
            print(
                "warning: --anchor-frame=boundary not yet supported with "
                "--rotate-size / --rotate-interval; skipping anchor emission",
                file=sys.stderr,
            )

    # --- Pre-capture anchor (#N) ---
    pre_anchor: Optional[dict] = None
    if anchor_enabled:
        try:
            pre_anchor = client.emit_version_anchor(timeout=args.anchor_timeout)
        except Exception as exc:
            print(f"warning: pre-anchor emission failed: {exc}", file=sys.stderr)
        if pre_anchor is None:
            print(
                "warning: pre-anchor DIAG_VERNO_F timed out — sidecar will "
                "contain only the post-anchor (if it succeeds)",
                file=sys.stderr,
            )
        elif not args.quiet:
            print(
                f"diaggulp: pre-anchor host_mono_ns={pre_anchor['host_mono_ns']} "
                f"rtt_ns={pre_anchor['rtt_ns']}",
                file=sys.stderr,
            )

    # --- Keep-alive kick (#N) ---
    # Flush-on-OUT modems only deliver buffered LOG_F in response to host
    # writes; a tiny periodic RETRIEVE_RANGES OUT keeps the stream flowing.
    # None for every other modem -> the loops stay fully passive.
    kick_fn = None
    kick_interval = 0.3
    if args.telit_quirk:
        _kick_payload = _telit_kick_payload()
        kick_fn = lambda: client.send(_DIAG_LOG_CONFIG_F, _kick_payload)  # noqa: E731

    # --- Re-open on hard channel teardown (#N) ---
    # For the raw-fd / serial path (e.g. the MHI DIAG chardev), a radio-revert
    # can tear the channel down so the fd stays valid but delivers nothing. The
    # same-fd ride-out in slurp() can't recover that; reconnect_fn rebuilds the
    # client (re-open device + re-arm log/F3 masks) so capture resumes once the
    # modem comes back. Only meaningful for serial; None for tcp/udp/pcap.
    reconnect_fn = None
    if args.transport == "serial":
        def reconnect_fn():
            nonlocal client
            try:
                client._transport.close()
            except Exception:    # noqa: BLE001 — best-effort close of a dead fd
                pass
            newc = DiagClient.from_serial(args.device, args.baud)
            # re-arm the log mask (may raise if the modem is still settling —
            # slurp() catches and retries the re-open on the next threshold)
            if narrow_codes:
                (_build_narrow_mask_telit if args.telit_quirk
                 else _build_narrow_mask)(newc, narrow_codes)
            else:
                (_build_all_logs_mask_telit if args.telit_quirk
                 else _build_all_logs_mask)(newc)
            # re-arm F3 (same precedence as the initial arm above)
            if bounded_ss:
                _enable_ext_msg_f3_bounded(
                    newc, bounded_ss, _f3_level_mask(args.ext_msg_f3_level))
            elif args.ext_msg_f3:
                _enable_ext_msg_f3(newc)
            client = newc
            return newc

    # --- NMEA side-capture (default-on, serial only, isolated, non-fatal) ---
    # Operator decision 2026-06-19: capture NMEA whenever diaggulp captures, so
    # every DIAG capture that has a reachable NMEA port also yields a GNSS
    # transcript. Fully isolated (own thread/fd/file); --no-nmea opts out.
    nmea_sidecar = None
    if args.transport == "serial" and not args.no_nmea and args.output:
        nmea_port = args.nmea_port or resolve_sibling_nmea_port(args.device)
        if nmea_port:
            nmea_out = nmea_output_path(resolved_output_path or args.output)
            nmea_sidecar = NmeaSidecar(
                nmea_port, nmea_out, baud=args.nmea_baud, quiet=args.quiet)
            nmea_sidecar.start()   # logs + returns False on failure; never raises
        elif not args.quiet:
            print(
                "diaggulp[nmea]: no NMEA port given and none auto-resolved from "
                f"{args.device}; pass --nmea-port to capture NMEA (or --no-nmea "
                "to silence this).",
                file=sys.stderr,
            )

    # --- Live decode side-thread (#N) ---
    # Enabled by --decode <code>... or --decode-live. Decodes a SELECTED set of
    # log codes inline as frames arrive, on a separate thread fed by a bounded
    # queue, so the raw-capture hot path is untouched (the .bin stays canonical).
    live_decoder = None
    _decode_out_fh = None
    _pcap_files = None
    _pcap_nr_path = None
    _pcap_sink = None
    if args.decode or args.decode_live or args.pcap_out:
        decode_codes = set(args.decode) if args.decode else None
        if args.pcap_out:
            # Lazy: pull the diaggrok-backed pcap core only when --pcap-out is
            # set, preserving diaggulp's decoder-free base package.
            from diagmunge.munge.dlf_to_pcap import PcapSink, _open_outputs
            from diaggrok.gsmtap import pcap_eligible_codes
            _pcap_out = Path(args.pcap_out)
            writer, nr_writer, _pcap_files, _pcap_nr_path = _open_outputs(_pcap_out)
            _pcap_sink = PcapSink(writer, nr_writer=nr_writer)
            # Broaden the decode filter to include pcap-eligible codes so they
            # reach the sink; a code with no encoder is simply skip-tallied.
            pe = set(pcap_eligible_codes())
            if decode_codes is not None:
                decode_codes = decode_codes | pe
            elif not args.decode_live:
                decode_codes = pe   # pcap-only: parse just the eligible codes
        if args.decode_out:
            _decode_out_fh = open(args.decode_out, "w", encoding="utf-8")
        emit_jsonl = bool(args.decode or args.decode_live)
        live_decoder = LiveDecoder(
            decode_codes, out=_decode_out_fh, pcap_sink=_pcap_sink,
            emit_jsonl=emit_jsonl)
        live_decoder.start()
        if emit_jsonl:
            scope = (", ".join(f"0x{c:04X}" for c in sorted(decode_codes))
                     if decode_codes else "ALL log codes in the mask")
            print(f"diaggulp[live]: decoding {scope} → "
                  f"{args.decode_out or 'stderr'} (raw .bin unaffected)",
                  file=sys.stderr)
        if args.pcap_out:
            print(f"diaggulp[pcap]: live GSMTAP/NR pcap → {args.pcap_out} "
                  f"(raw .bin unaffected)", file=sys.stderr)
    tee_fn = live_decoder.feed if live_decoder is not None else None

    # --- The hot loop ---
    try:
        if writer is not None:
            # When rotating, we need to use writer.write() (not raw os.write)
            # so the rotation check fires. Inline a tiny version of slurp().
            transport = client._transport
            fileno = transport.fileno()
            bytes_written = 0
            start = time.monotonic()
            select_timeout = min(1.0, kick_interval) if kick_fn else 1.0
            next_kick = start + kick_interval if kick_fn else None
            try:
                while True:
                    # Adaptive keep-alive (#N); see slurp() for rationale.
                    if next_kick is not None and time.monotonic() >= next_kick:
                        try:
                            kick_fn()
                        except OSError:
                            pass  # busy modem; stream already flowing
                        next_kick = time.monotonic() + kick_interval
                    ready, _, _ = select.select([fileno], [], [], select_timeout)
                    if not ready:
                        continue
                    data = transport.read(args.chunk_size)
                    if not data:
                        break
                    writer.write(data)
                    bytes_written += len(data)
                    if tee_fn is not None:
                        tee_fn(data)   # #N: non-blocking tee to live decoder
                    if next_kick is not None:
                        next_kick = time.monotonic() + kick_interval  # data flowing
            except KeyboardInterrupt:
                pass
            elapsed = time.monotonic() - start
        else:
            bytes_written, elapsed = slurp(
                client, out_fd, args.chunk_size,
                kick_fn=kick_fn, kick_interval=kick_interval,
                reconnect_fn=reconnect_fn, tee_fn=tee_fn,
            )
    finally:
        # --- Stop live decode side-thread + close its sink (#N) ---
        if live_decoder is not None:
            live_decoder.stop()
            if _decode_out_fh is not None:
                _decode_out_fh.close()
            if _pcap_files is not None:
                from diagmunge.munge.dlf_to_pcap import _finalize_outputs
                _finalize_outputs(_pcap_files, _pcap_nr_path,
                                  _pcap_sink.nr_written)
                print(f"diaggulp[pcap]: {_pcap_sink.written} GSMTAP + "
                      f"{_pcap_sink.nr_written} NR frame(s) -> {args.pcap_out}",
                      file=sys.stderr, flush=True)

        # --- Stop NMEA side-capture (isolated; never blocks DIAG teardown) ---
        if nmea_sidecar is not None:
            nmea_sidecar.stop()

        # --- Post-capture anchor (#N) ---
        # Sent while the client is still open. Any log bytes consumed by
        # _send_recv during the response handshake are not written to the
        # output file — that's an acceptable few-ms loss at the tail of an
        # already-aborted capture.
        post_anchor: Optional[dict] = None
        if anchor_enabled:
            try:
                post_anchor = client.emit_version_anchor(timeout=args.anchor_timeout)
            except Exception as exc:
                print(
                    f"warning: post-anchor emission failed: {exc}",
                    file=sys.stderr,
                )
            if post_anchor is None and pre_anchor is not None:
                print(
                    "warning: post-anchor DIAG_VERNO_F timed out — sidecar "
                    "will contain only the pre-anchor (single-anchor "
                    "fallback in correlate)",
                    file=sys.stderr,
                )

        if writer is not None:
            writer.close()
        elif args.output:
            try:
                os.close(out_fd)
            except OSError:
                pass
        # --- Write UDP gap sidecar (#N, udp-listen) ---
        # Grab the report BEFORE close() — counters survive, but read it here
        # so a transport without gap_report() (any non-udp-listen path) is a
        # clean no-op.
        gap_report = None
        report_fn = getattr(client._transport, "gap_report", None)
        if callable(report_fn):
            try:
                gap_report = report_fn()
            except Exception:
                gap_report = None

        try:
            client.close()
        except Exception:
            pass

        if gap_report is not None and resolved_output_path is not None:
            gaps_path = resolved_output_path + ".udpgaps.json"
            try:
                with open(gaps_path, "w", encoding="utf-8") as fh:
                    json.dump(
                        {
                            "version": 1,
                            "tool": "diaggulp.py",
                            "transport": args.transport,
                            "framing": "DGE1",
                            **gap_report,
                        },
                        fh,
                        indent=2,
                    )
                    fh.write("\n")
                if not args.quiet:
                    print(
                        f"diaggulp: wrote UDP gap sidecar {gaps_path} "
                        f"(received={gap_report['received']} "
                        f"missing={gap_report['missing']} "
                        f"loss={gap_report['loss_pct']:.2f}%)",
                        file=sys.stderr,
                    )
            except OSError as exc:
                print(
                    f"warning: failed to write UDP gap sidecar "
                    f"{gaps_path}: {exc}",
                    file=sys.stderr,
                )

        # --- Write anchor sidecar (#N) ---
        if anchor_enabled and resolved_output_path is not None and (
            pre_anchor is not None or post_anchor is not None
        ):
            anchors_list: list[dict] = []
            if pre_anchor is not None:
                anchors_list.append({"kind": "start", **pre_anchor})
            if post_anchor is not None:
                anchors_list.append({"kind": "end", **post_anchor})
            sidecar_path = resolved_output_path + ".anchors.json"
            sidecar = {
                "version": 1,
                "method": "diag_verno_response",
                "tool": "diaggulp.py",
                "anchors": anchors_list,
            }
            try:
                with open(sidecar_path, "w", encoding="utf-8") as fh:
                    json.dump(sidecar, fh, indent=2)
                    fh.write("\n")
                if not args.quiet:
                    print(
                        f"diaggulp: wrote anchor sidecar {sidecar_path} "
                        f"({len(anchors_list)} anchor(s))",
                        file=sys.stderr,
                    )
            except OSError as exc:
                print(
                    f"warning: failed to write anchor sidecar "
                    f"{sidecar_path}: {exc}",
                    file=sys.stderr,
                )

    if not args.quiet:
        rate = bytes_written / elapsed if elapsed > 0 else 0.0
        print(
            f"diaggulp: {bytes_written} bytes in {elapsed:.2f}s "
            f"({rate / 1024 / 1024:.2f} MB/s)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

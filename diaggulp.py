#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Luke Jenkins
"""
diaggulp.py — low-CPU host-side DIAG capture for wardriving and bulk dumps.

Reads raw DIAG bytes from a connected modem (USB serial, raw libusb, TCP, or
UDP) and writes them to a file or stdout. The output is the same HDLC-framed byte
stream the modem emits — drop it into any downstream tool that consumes
DIAG (QCSuper's --dlf, SCAT, the diaggrok decoders, or your own parser).

Output format
-------------

**The output is raw HDLC, not the QCSuper DLF record format.** The default
``-o capture.dlf`` extension is historical; the file is a concatenation of
0x7E-delimited HDLC frames exactly as emitted by the modem, with no
per-record length headers, CRC envelope, or DLF metadata.

Downstream decoders must pick the matching input mode:

- **raw-HDLC / binary mode with CRC validation** — the correct path for
  diaggulp output (the consumer does the HDLC framing + CRC check itself)
- **DLF record mode** — for a true QCSuper DLF file, where per-record
  length/type headers carry the framing instead

Misusing the default QCSuper DLF mode on diaggulp output yields a near-zero
parse rate (the HDLC delimiter bytes are not a valid DLF record header).

Design
------

A modem with full LTE + GNSS + NR masks emits about 1 MB/s of DIAG, and a
reader that does per-byte or per-frame work in Python at that rate costs CPU
and drops frames when it falls behind. diaggulp does as little as possible on
the capture path:

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

Shutdown, and how to supervise it
-----------------------------------------

SIGINT and SIGTERM are wired to the same handler, which raises
``KeyboardInterrupt`` so the read loop breaks on its clean-exit path and
still prints a final stats line. The ``finally:`` teardown that follows is
**bounded at every step**, so an ordinary
``timeout N diaggulp.py ...`` normally exits within a second or two of the
signal. SIGHUP (a dropped controlling shell) is wired the same way unless the
run was started under ``nohup``. Once the teardown has started, further stop
signals are held and a closed stderr pipe is ignored, so an impatient
supervisor cannot cut the ``--disarm-*-on-exit`` / ``--restore-f3-mask-on-exit``
steps short. Only SIGKILL can. To clear a modem that was left armed,
run a brief quiesce: ``diaggulp ... -o /dev/null --disarm-logs-on-exit`` (add
the other ``-on-exit`` flags for whatever else was armed).

``--seconds N`` / ``--duration N`` is the *native* way to bound a
capture: the read loop stops on its own clock, takes that same clean-exit path,
and the process exits **0**. Prefer it over the wrapper for anything
programmatic — ``timeout`` reports **124** at the normal end of a timed sample,
so every caller otherwise has to special-case a successful capture as a failure.

⚠️ **``--seconds`` is not a substitute for ``timeout -k`` on an UNATTENDED run.**
It bounds the read loop, not the teardown — and the unreproduced stall below is
a *teardown* problem, so a capture that hits it stalls just the same. The two
compose: ``--seconds`` gives the clean exit-0 in the normal case, an outer
``timeout -k`` remains the backstop for the pathological one.

⚠️ **It has been observed not to.** Once (147 MB / 403 557 records /
170 s), the process outlived its ``timeout``
by nine minutes and needed ``kill -9``. The capture itself was intact —
this is a shutdown-path problem, not a data-loss one — and it has **not
been reproduced or root-caused**. Two consequences for anything scripting
this tool:

⛔ **Use ``timeout -k``, never bare ``timeout``.** Bare ``timeout`` sends
   TERM and then waits forever for a child that doesn't die, so an
   unattended capture that hits this stalls the whole run::

       timeout -k 10 170 python diaggulp.py ...
       #       ^^^^^ SIGKILL 10s after the SIGTERM if still alive

⛔ **Never clean up with ``pkill -f diaggulp.py``.** ``-f`` matches against
   full command lines — including the command line of the shell running
   the ``pkill`` itself, which contains that same string. The cleanup
   command kills itself (observed: exit 144 = 128+16/SIGSTKFLT-class
   self-signal) and may leave the actual capture running. The working
   form brackets the first character so the pattern cannot match its own
   invocation::

       pgrep -f "[d]iaggulp[.]py" | xargs -r kill

   This is a general ``pkill -f`` hazard, not a diaggulp one, but this is
   where the project hit it.
"""

from __future__ import annotations

import argparse
import importlib.util
import errno
import fcntl
import json
import os
import queue
import select
import signal
import stat
import struct
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple, Optional

# Reuse the existing DiagClient for transport abstraction + log mask handshake
from diagmunge import (
    DIAG_BAD_CMD_F,
    DIAG_VERNO_F,
    DiagClient,
    Dge1SeqTracker,
    parse_dge1_header,
    resync_frame_boundary,
)
from diagmunge.transport import BrokerError, log_config_reply_matches
from diagmunge.f3mask import (  # moved out for diaggpsd
    DIAG_EXT_MSG_CONFIG_F,
    EXT_MSG_ALL_LEVELS,
    EXT_MSG_GET_BUILD_MASK,
    EXT_MSG_GET_RT_MASK,
    EXT_MSG_MASK_TABLE_HDR_LEN,
    EXT_MSG_QUERY_SSID_RANGES,
    EXT_MSG_SET_ALL_RT_MASKS,
    EXT_MSG_SET_RT_MASK,
    EXT_MSG_SS_RANGE0_LAST,
    F3MaskSnapshot,
    _EXT_MSG_SS_RANGES_HDR_LEN,
    _build_ext_msg_query_ss_ranges,
    _parse_ext_msg_ss_ranges,
    _query_ext_msg_ss_ranges,
    _snapshot_set_all_value,
    build_ext_msg_config_get_mask_request,
    build_ext_msg_config_set_all_rt_masks_request,
    build_ext_msg_set_rt_mask_array,
    describe_ext_msg_rt_mask,
    describe_ext_msg_rt_snapshot,
    ext_msg_set_all_stored_mask,
    log_pre_arm_ext_msg_rt_mask,
    parse_ext_msg_mask_table_reply,
    parse_set_all_rt_masks_reply,
    read_ext_msg_rt_mask,
    read_ext_msg_rt_mask_snapshot,
    restore_ext_msg_rt_mask,
)
import zstandard as zstd
from diagmunge.diag_cmd import (
    DIAG_EVENT_MASK_GET_F,
    EventMask,
    build_event_mask_get,
    build_event_mask_set,
    build_event_report_enable,
    parse_event_mask_reply,
    build_subsys_command,
    build_qsh_metrics_enable,
    build_qsh_trace_maskset_set,
)
from diagmunge.qsh_maskset import (
    BUNDLED_DEFAULT_PROFILE,
    bundled_measured_on,
    bundled_profile_table,
    load_pairs_file,
    sweep_pairs,
)

# Where a QSH-trace (0x9001) maskset can come from, first match wins:
#   1. --qsh-pairs-file PATH  a {"pairs": [[ssid, level], ...]} file, e.g. one
#                             measured on the user's own modem
#   2. --qsh-sweep            every SSID 1..110 at every sub-stream bit
#   3. --qsh-profile NAME     a named profile (default below)
#
# The vendor-config-derived profiles are private: the public
# diagmunge does not ship ``qsh_golden``, so it is imported optionally. With
# it, ``golden`` stays the default arming. Without it, the default is
# the bundled ``measured-union``: the OR of the masksets measured on an
# RM500Q-AE, a T99W175, an RM520N-GL and a T99W640, shipped with NO WARRANTY.
# It replaced the T99W640-only maskset, no longer shipped, once three more
# modems were measured: off the T99W640 that maskset caught 4-5
# subsystems where a measured maskset caught 12-15. Only a missing *qsh_golden* is tolerated; any other import failure
# inside it is a real bug and raises.
try:
    from diagmunge.qsh_golden import (
        QSH_TRACE_DEFAULT_PROFILE as _GOLDEN_DEFAULT_PROFILE,
        QSH_TRACE_PROFILE_HELP as _GOLDEN_PROFILE_HELP,
        QSH_TRACE_PROFILES as _GOLDEN_PROFILES,
        qsh_trace_profile as _golden_profile,
    )
except ModuleNotFoundError as _exc:
    if _exc.name != "diagmunge.qsh_golden":
        raise
    _GOLDEN_DEFAULT_PROFILE = None
    _GOLDEN_PROFILE_HELP = ""
    _GOLDEN_PROFILES = {}
    _golden_profile = None

#: True when ``diagmunge.qsh_golden`` is installed, False in a public build.
QSH_GOLDEN_AVAILABLE: bool = bool(_GOLDEN_PROFILES)

#: The bundled, measured profiles (``diagmunge.qsh_maskset``), each
#: ``measured-<profile>``.
BUNDLED_QSH_PROFILES = bundled_profile_table()

#: Every ``--qsh-profile`` this build can arm.
QSH_TRACE_PROFILES: dict[str, tuple[tuple[int, int], ...]] = {
    **{name: _golden_profile(name) for name in _GOLDEN_PROFILES},
    **BUNDLED_QSH_PROFILES,
}
QSH_TRACE_DEFAULT_PROFILE: str = _GOLDEN_DEFAULT_PROFILE or BUNDLED_DEFAULT_PROFILE

#: SSIDs ``--qsh-sweep`` arms: one full SET (the per-SET cap is 110 pairs).
QSH_SWEEP_SSIDS = range(1, 111)


class QshTracePlan(NamedTuple):
    """The one maskset a run arms, resolved once from the CLI."""

    label: str      # what the log lines call it
    pairs: tuple    # ordering-legal (ssid, level) pairs
    source: str     # "profile" | "pairs-file" | "sweep"
    profile: Optional[str] = None   # the --qsh-profile name, when source is "profile"


def _plan_qsh_trace(args) -> QshTracePlan:
    """Resolve the QSH-trace maskset: pairs file > sweep > profile.

    Raises ``ValueError`` / ``OSError`` for an unreadable or invalid pairs
    file; ``main`` turns that into a usage error before any transport opens.
    """
    path = getattr(args, "qsh_pairs_file", None)
    if path:
        return QshTracePlan(f"pairs file {path}", load_pairs_file(path), "pairs-file")
    if getattr(args, "qsh_sweep", False):
        return QshTracePlan(
            f"sweep SSIDs {QSH_SWEEP_SSIDS.start}..{QSH_SWEEP_SSIDS.stop - 1}",
            sweep_pairs(QSH_SWEEP_SSIDS), "sweep")
    name = getattr(args, "qsh_profile", None) or QSH_TRACE_DEFAULT_PROFILE
    return QshTracePlan(f"profile {name!r}", QSH_TRACE_PROFILES[name], "profile", name)


def _qsh_plan_notice(plan: QshTracePlan) -> Optional[str]:
    """The one-line stderr notice a plan earns, or ``None``.

    A bundled profile was measured on one modem model and carries no warranty,
    so say so and point at the two sources that fit any modem. A pairs file or
    a sweep is named so the log records what was armed.
    """
    if plan.profile in BUNDLED_QSH_PROFILES:
        return (f"diaggulp: QSH-trace {plan.label} ({len(plan.pairs)} SSIDs) was "
                f"measured on {bundled_measured_on(plan.profile)} and is provided "
                "AS IS, with NO WARRANTY; a maskset measured on your own modem "
                "(--qsh-pairs-file) fits it best, and --qsh-sweep needs no "
                "measurement")
    if plan.source != "profile":
        return f"diaggulp: QSH-trace maskset from {plan.label} ({len(plan.pairs)} SSIDs)"
    return None

# How many bytes to ask the kernel for per read(). 64 KB matches DiagClient's
# default and is large enough that read syscall overhead is negligible at any
# realistic DIAG byte rate.
READ_CHUNK = 64 * 1024

# Transient MHI DIAG channel reset survival. A reset surfaces as
# ERESTARTSYS(512)/EAGAIN on the read; the channel usually returns within
# seconds, so the slurp loop rides it out (one contiguous capture with a logged
# gap) instead of dying. A channel that stays dead longer than this ceiling exits.
# EINTR is deliberately NOT here: as InterruptedError it's caught by the existing
# break clause (signal-driven shutdown), and the transport's read() already
# restarts EINTR at the syscall level.
_ERESTARTSYS = 512
_TRANSIENT_READ_ERRNOS = frozenset((_ERESTARTSYS, errno.EAGAIN, errno.EWOULDBLOCK))
RESET_RETRY_BACKOFF = 0.1          # seconds between read retries during a reset
MAX_RESET_SECONDS = 180.0          # give up if the channel stays dead this long
# Re-open gap: riding out a reset on the SAME fd recovers a transient
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
    """Normalize the ``-o`` argument so ``-`` means stdout.

    ``-`` is the universal CLI convention for "write to stdout". The main
    path already treats a falsy ``args.output`` as stdout
    (``sys.stdout.buffer.fileno()``), so map ``-`` (and the empty string) to
    ``None`` and let every ``if args.output:`` branch route there. A real path
    that merely *contains* a dash (``cap-2026.bin``, ``./-foo``) is preserved.

    Without this, ``diaggulp ... -o -`` ran ``os.open("-", …)`` and created a
    regular file literally named ``-`` while the downstream pipe
    (``| diag_tail.py --tee``) saw zero bytes — the exact failure caught on the
    bench LV55 during hardware validation.
    """
    if path == "-" or path == "":
        return None
    return path


def _path_filesystem_type(path: str) -> Optional[str]:
    """Return the filesystem type backing ``path`` (e.g. ``tmpfs``, ``ext4``),
    or ``None`` when it cannot be determined (non-Linux, unreadable /proc).

    Linux-only, by design: it reads ``/proc/self/mountinfo`` and picks the mount
    whose mount point is the longest prefix of the absolute path. macOS/BSD have
    no ``/proc/self/mountinfo`` and simply get ``None`` (the caller degrades to
    "unknown, no warning"), which is correct — the tmpfs-capture hazard this
    feeds is a Linux dev-host phenomenon.
    """
    try:
        target = os.path.abspath(path)
        best_mount = ""
        best_fstype = None
        with open("/proc/self/mountinfo", "r") as fh:
            for line in fh:
                # mountinfo: ... <mount_point> ... " - " <fstype> <source> <opts>
                fields = line.split()
                sep = fields.index("-") if "-" in fields else -1
                if sep < 0 or sep + 1 >= len(fields):
                    continue
                mount_point = fields[4]
                fstype = fields[sep + 1]
                # longest mount point that is a path-prefix of target wins
                if (target == mount_point or target.startswith(
                        mount_point.rstrip("/") + "/")) and len(mount_point) > len(best_mount):
                    best_mount = mount_point
                    best_fstype = fstype
        return best_fstype
    except (OSError, ValueError, IndexError):
        return None


def _claim_output_fd(fd: int, path: str) -> int:
    """Take an exclusive advisory lock on a capture output fd.

    Two diaggulp processes pointed at one path used to be a *silent* data loss:
    each held its own file offset from 0 and they mutually overwrote, so the
    file on disk ended up a byte-level mosaic of two modems' DIAG streams whose
    regions were each internally well-framed. CRC health, ``unknown_codes`` and
    the qdb bind all read clean on it — nothing downstream could tell. Two
    concurrent wardrive captures lost ~half of every byte captured that way.

    ``flock`` is the right primitive: it is per-open-file-description (so a
    second process genuinely fails), it is released automatically when the
    writer dies (no stale lockfile to garbage-collect), and unlike ``O_EXCL`` it
    does not break the legitimate re-run-overwrites-the-old-capture case.

    A filesystem that cannot lock (``EOPNOTSUPP``/``ENOLCK`` — some network
    mounts) downgrades to a warning: refusing to capture at all would be a worse
    failure than capturing unprotected, and the collision this guards is the
    second line of defence behind go_wardrive's unique output dirs.
    """
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in (errno.EOPNOTSUPP, errno.ENOLCK):
            print(f"WARN: {path}: filesystem does not support flock ({exc}); "
                  f"concurrent-writer protection unavailable",
                  file=sys.stderr)
            return fd
        os.close(fd)
        raise SystemExit(
            f"ERROR: another live process already holds the capture file "
            f"{path} (flock: {exc}) — refusing to share it.\n"
            f"  Two writers on one capture do NOT interleave; they overwrite, "
            f"and roughly half of each stream is destroyed unrecoverably.\n"
            f"  Give each modem its own -o path."
        )
    return fd


def _suggest_rotate_template(path: str) -> str:
    """Return ``path`` with a ``%s`` placeholder inserted before the extension,
    for use in the rotation fail-fast message (``rot.hdlc`` -> ``rot_%s.hdlc``,
    ``cap`` -> ``cap_%s``). Purely advisory; does not touch the filesystem."""
    root, ext = os.path.splitext(path)
    return f"{root}_%s{ext}"


def _open_output(path: str) -> tuple[int, str]:
    """Open the output path with %s timestamp expansion.

    Returns ``(fd, resolved_path)`` so callers can locate sidecars
    (e.g. ``<resolved_path>.anchors.json`` for anchor frames).

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
            return _claim_output_fd(fd, candidate), candidate
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
                    return _claim_output_fd(fd, alt), alt
                except FileExistsError:
                    continue
            raise RuntimeError(f"Could not find unique rotation path for {path}")
    # Open WITHOUT O_TRUNC, claim the lock, and only then truncate. With
    # O_TRUNC in the open flags the loser of the race has already destroyed the
    # winner's capture by the time flock tells it to back off.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
    # A non-regular sink (`-o /dev/null` for the quiesce recipe, a FIFO) has no
    # length to truncate (ftruncate raises EINVAL) and no capture to protect:
    # the flock would only make two concurrent quiesce runs refuse each other
    #.
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        return fd, path
    _claim_output_fd(fd, path)
    os.ftruncate(fd, 0)
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
# rejects the mask handshake with DIAG_BAD_CMD_F until unlocked. The
# Quectel reference 000000 first, then the Telit-form 0000.
_SPC_AUTO = ["000000", "0000"]


def _try_spc_unlock(client: DiagClient, spc_arg: str) -> bool:
    """Send a DIAG SPC unlock (opcode 0x46) before the LOG_CONFIG handshake.

    ``spc_arg == "auto"`` tries the known vendor codes in :data:`_SPC_AUTO` in
    order, stopping at the first accepted (``status==1``); any other value is
    tried as a literal 6-char code. Returns True iff an unlock was accepted.
    Pure orchestration over :meth:`DiagClient.unlock_spc` so it is unit-testable
    with a fake client.
    """
    spcs = _SPC_AUTO if spc_arg.lower() == "auto" else [spc_arg]
    return any(client.unlock_spc(s) for s in spcs)


# --- Pure request builders -----------------------------------------
# The DIAG constants and the exact `pack()` layouts used to live inline in the
# three senders below, which made them untestable without a modem: the only way
# to see the bytes was to open a device. Pulling them out as pure functions
# gives the framing-tier Kaitai layouts for 0x73 and 0x7D a real equivalence
# target — those layouts are checked against THIS builder's output, not against
# a copy of it, so a change here that the layout does not follow fails a test.
#
# Each returns the request PAYLOAD — everything after the opcode byte, which is
# what DiagClient.send()/_send_recv() take. The .ksy layouts model the frame
# from the opcode byte, so a test prepends it.

DIAG_LOG_CONFIG_F = 115                 # 0x73
LOG_CFG_RETRIEVE_RANGES = 1
LOG_CFG_SET_MASK = 3
LOG_CFG_HDR_FMT = "<3xII"               # response: 3 pad, operation, status
LOG_CFG_SUCCESS = 0



def build_log_config_retrieve_ranges_request() -> bytes:
    """0x73 RETRIEVE_ID_RANGES request payload: 3 pad bytes, then the op.

    Step 1 of the two-step arming handshake — ask how many log codes exist in
    each of the 16 log types before masking any of them.
    """
    from struct import pack

    return pack("<3xI", LOG_CFG_RETRIEVE_RANGES)


def build_log_config_set_mask_request(
    log_type: int, num_items: int, mask: bytes
) -> bytes:
    """0x73 SET_MASK request payload: 3 pad, op, log_type, num_items, mask.

    ``mask`` must be ``ceil(num_items / 8)`` bytes — the modem sizes its read
    off ``num_items``, so a short mask is a malformed request rather than a
    partially-applied one.
    """
    from struct import pack

    expected = (num_items + 7) // 8
    if len(mask) != expected:
        raise ValueError(
            f"mask for log type 0x{log_type:x} is {len(mask)} bytes, "
            f"expected {expected} for num_items={num_items}"
        )
    return pack("<3xIII", LOG_CFG_SET_MASK, log_type, num_items) + mask


def _require_nonzero_log_ranges(bitsizes: "tuple[int, ...]") -> None:
    """Fail the all-logs handshake on a success-with-all-zero RETRIEVE_RANGES.

    Seen on an SDX72 module: status 0 and all 16 bitsizes 0, so no mask gets
    set. The arm used to report ``subscribed to all 0 log codes across 0 log
    groups``, which reads like success, and the capture then had no ``0x10``
    plane. Raising lets the caller's retry loop try again and puts the reason on
    stderr. The cause is not known yet; the same units answered non-zero later.
    """
    if not any(bitsizes):
        raise RuntimeError(
            "RETRIEVE_RANGES returned success but all 16 log-type bitsizes are 0 "
            "— no log mask can be set, so the classic 0x10 log plane will be EMPTY "
            ""
        )


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
    from struct import unpack_from, calcsize

    result = client._send_recv(
        DIAG_LOG_CONFIG_F,
        build_log_config_retrieve_ranges_request(),
        timeout=10.0,
        match=lambda op, b: log_config_reply_matches(op, b, LOG_CFG_RETRIEVE_RANGES),
    )
    if result is None:
        raise RuntimeError("Timed out querying log type ranges")
    _, resp = result
    operation, status = unpack_from(LOG_CFG_HDR_FMT, resp)
    assert operation == LOG_CFG_RETRIEVE_RANGES
    if status != LOG_CFG_SUCCESS:
        raise RuntimeError(f"RETRIEVE_RANGES failed (status={status})")

    bitsizes = unpack_from("<16I", resp, calcsize(LOG_CFG_HDR_FMT))
    _require_nonzero_log_ranges(bitsizes)

    enabled_groups = 0
    total_codes = 0
    for log_type, bitsize in enumerate(bitsizes):
        if not bitsize:
            continue
        mask = _all_logs_mask_bytes(bitsize)

        result = client._send_recv(
            DIAG_LOG_CONFIG_F,
            build_log_config_set_mask_request(log_type, bitsize, mask),
            timeout=10.0,
            match=lambda op, b: log_config_reply_matches(op, b, LOG_CFG_SET_MASK),
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
    ``log_codes`` and nothing else (the narrow-mask validation capture).

    A DIAG log code is ``(equipment_id << 12) | item``: the top 4 bits select
    the log type (0..15, the index into ``bitsizes`` from RETRIEVE_RANGES) and
    the low 12 bits are the item index within that type. Within a type's mask,
    item ``i`` is bit ``i % 8`` of byte ``i // 8``, LSB-first — the QCSuper
    ``_fill_log_mask`` convention (same bit layout :func:`_build_all_logs_mask`
    sets to all-ones).

    Returns ``{log_type: mask_bytes}`` for EVERY log type the modem advertises
    (``bitsize > 0``), not just the requested ones: a type with no requested code
    gets an explicit ALL-ZERO mask. ``mask_bytes`` is ``ceil(bitsize / 8)`` bytes.
    Raises ``ValueError`` (before any I/O) for a code whose equipment id or item
    is outside the modem's advertised range — so a typo'd code fails loudly
    instead of silently capturing nothing.

    ⚠️ The zero masks are the ``--log-code`` **exclusivity** contract.
    Emitting entries only for requested types made the arming ADDITIVE against
    whatever the modem already held: the caller sends ``SET_MASK`` per returned
    type, so an omitted type kept the PREVIOUS run's mask. Measured on two
    vendors — a Quectel EG25-G run requesting 0x1476/0x14D8 (type 1) also
    captured 0x4116 (type 4) and 0xB0C0/0xB192/0xB193 (type 0xB), while a Telit
    LM960A18 run requesting type-0xB codes also captured 0x1476/0x14D8 (type 1).
    Each inherited the other's untouched type, which is why the two leaked in
    opposite directions. Clear-then-set makes ``--log-code`` mean what it reads
    as.

    Types advertising 0 codes stay omitted — nothing to clear, and a
    ``SET_MASK`` over 0 items is meaningless.
    """
    # Pre-seed a zero mask for every advertised type, so types with no requested
    # code are explicitly CLEARED rather than left holding a stale mask.
    by_type: "dict[int, bytearray]" = {
        lt: bytearray((bs + 7) // 8) for lt, bs in enumerate(bitsizes) if bs > 0
    }
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
        by_type[log_type][item // 8] |= 1 << (item % 8)
    return {lt: bytes(m) for lt, m in by_type.items()}


def _build_narrow_mask(client: DiagClient, log_codes: "list[int]") -> None:
    """Send a log mask subscribing to ONLY ``log_codes`` (+ nothing else).

    The all-logs mask (:func:`_build_all_logs_mask`) subscribes to every code in
    every group (~11.8k codes), which floods a validation capture: a recipe
    under test is a handful of codes, so a GNSS spike alone produced ~107k
    records. This narrows the SET_MASK to just the requested codes —
    the code under test plus any liveness canary — so the capture is lean and
    the code-under-test's records aren't buried.

    Same RETRIEVE_RANGES → per-type SET_MASK handshake as the all-logs path; the
    only difference is the mask bytes (computed by :func:`_narrow_mask_bytes`).
    """
    from struct import unpack_from, calcsize

    result = client._send_recv(
        DIAG_LOG_CONFIG_F,
        build_log_config_retrieve_ranges_request(),
        timeout=10.0,
        match=lambda op, b: log_config_reply_matches(op, b, LOG_CFG_RETRIEVE_RANGES),
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
            build_log_config_set_mask_request(log_type, bitsize, mask),
            timeout=10.0,
            match=lambda op, b: log_config_reply_matches(op, b, LOG_CFG_SET_MASK),
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
    subscribed = len({c >> 12 for c in set(log_codes)})
    print(
        f"diaggulp: narrow mask — subscribed to {len(set(log_codes))} log "
        f"code(s) across {subscribed} group(s): {codes_str} "
        f"(cleared {len(masks) - subscribed} other group(s))",
        file=sys.stderr,
    )


def _parse_broker_sub(s: str) -> dict:
    """``--broker-sub`` value: a diagbroker SUB declaration, a JSON object.

    ``name`` defaults to ``diaggulp`` so the broker's log names the client.
    """
    try:
        decl = json.loads(s)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"not JSON: {exc}") from None
    if not isinstance(decl, dict):
        raise argparse.ArgumentTypeError("must be a JSON object, e.g. '{\"floor\":\"max\"}'")
    decl.setdefault("name", "diaggulp")
    return dict(sorted(decl.items(), key=lambda kv: kv[0] != "name"))


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


def _parse_positive_seconds(s: str) -> float:
    """argparse ``type=`` for ``--seconds`` / ``--duration``.

    Zero and negatives are rejected rather than clamped: ``--seconds 0`` would
    otherwise mean "capture nothing and exit 0", which is indistinguishable from
    a successful sample in every artifact a caller reads afterwards.
    """
    import argparse as _argparse

    try:
        value = float(s)
    except ValueError:
        raise _argparse.ArgumentTypeError(
            f"expected a number of seconds, got {s!r}"
        )
    if value <= 0:
        raise _argparse.ArgumentTypeError(
            f"capture duration must be > 0 seconds, got {s!r}"
        )
    return value


def _enable_ext_msg_f3(
    client: DiagClient, level_mask: int = EXT_MSG_ALL_LEVELS
) -> None:
    """Enable the modem's F3 debug-message (DIAG_EXT_MSG_F) runtime stream.

    The log mask handshake (:func:`_build_all_logs_mask`) only subscribes to
    *log* codes — the structured 0x10 LOG_F records diaggrok/qcsuper parse.
    It does **not** turn on the firmware's free-text F3 debug messages
    (``DIAG_EXT_MSG_F`` 0x79 plaintext + ``DIAG_QSR4_EXT_MSG_TERSE_F`` 0x99
    hashed). Those carry the human-readable subsystem trace — e.g. the
    ``AT+CFUN=1`` rejection reason — and are silent on a modem whose radio
    is off, which is exactly the state where the log stream is empty too.

    This sends ``DIAG_EXT_MSG_CONFIG_F`` subcommand ``SET_ALL_RT_MASKS``
    (set every SSID's runtime level to ``level_mask``), so the modem emits its
    F3 surface for the capture window. Decode the resulting HDLC with an F3
    decoder: 0x79 plaintext needs no database; 0x99 QSR4-terse needs the
    build-matched ``qdsp6m.qdb``.

    ⛔ **The echo confirms the REQUEST was accepted — it does NOT confirm what
    the firmware STORED, as measured on a live EG25-G / MDM9607.** Reading the runtime table back with sub-command 3 shows this
    part storing the mask's **low byte replicated across all four bytes** of
    every SSID's u32, while the reply echoes the requested u32 verbatim:

    ======================  ==================  ==========================
    requested               echoed in reply     actually stored per SSID
    ======================  ==================  ==========================
    ``0x00000000``          ``0x00000000``      ``0x00000000``
    ``0x0000001F``          ``0x0000001F``      ``0x1F1F1F1F``
    ``0x000000AB``          ``0x000000AB``      ``0xABABABAB``
    ``0x000F041F``          ``0x000F041F``      ``0x1F1F1F1F``
    ``0xFFFFFFFF``          ``0xFFFFFFFF``      ``0xFFFFFFFF``
    ======================  ==================  ==========================

    So ``0xFFFFFFFF`` (the default) and ``0x00000000`` are exact, and every
    *reduced* mask silently arms **more** than asked: ``0x0000001F`` arms bits
    ``{0-4, 8-12, 16-20, 24-28}``, not ``{0-4}``. That is the whole of "the
    0x1F arm defies the AND gate" — the AND gate held; the stored mask
    was never the requested one. A mask whose four bytes are not all equal-or-zero
    stores a mixed pattern that is still unexplained; treat non-uniform masks as
    unpinned. The only trustworthy reading is a sub-command 3 readback.

    ``level_mask`` is the runtime severity mask applied to EVERY SSID
    (:func:`_f3_level_mask` maps a ``--ext-msg-f3-level`` name to it). The
    default ``EXT_MSG_ALL_LEVELS`` (0xFFFFFFFF) is "emit the whole surface";
    a reduced mask (e.g. ERROR|FATAL = 0xFFFFFFF8) floors the volume — the
    celldiag-verified working form. This path used to hardcode the
    default, so ``--ext-msg-f3-level`` was a **silent no-op** on the
    unbounded (F3-actually-flows) path — the floor was consumed only by the
    bounded SSID path, which is inert on SDX55.
    """
    result = client._send_recv(
        DIAG_EXT_MSG_CONFIG_F,
        build_ext_msg_config_set_all_rt_masks_request(level_mask),
        timeout=10.0,
    )
    if result is None:
        raise RuntimeError("Timed out enabling F3 ext-msg runtime masks")
    if level_mask == EXT_MSG_ALL_LEVELS:
        detail = "all F3 ext-msg runtime levels"
    else:
        detail = f"F3 ext-msg runtime levels floored to mask 0x{level_mask:08X}"

    # Inspect the reply instead of trusting non-None. The old
    # code printed "enabled" on ANY response, so a firmware that CLAMPED or
    # REJECTED the mask was indistinguishable from one that accepted it — the
    # capture then silently carries a different arm than the log claims.
    _op, body = result
    parsed = parse_set_all_rt_masks_reply(body)
    if parsed is None:
        print(
            f"diaggulp: WARNING — SET_ALL_RT_MASKS reply not a recognizable echo "
            f"(op=0x{_op:02X} body={bytes(body).hex()}); F3 mask 0x{level_mask:08X} "
            f"UNCONFIRMED — the reply may be truncated by F3 saturating the port",
            file=sys.stderr,
        )
    elif parsed[2] != level_mask:
        _sub, status, echoed = parsed
        print(
            f"diaggulp: WARNING — requested F3 mask 0x{level_mask:08X} but firmware "
            f"echoed 0x{echoed:08X} (status {status}) — CLAMPED or REJECTED; the "
            f"capture will NOT match the requested arm",
            file=sys.stderr,
        )
    else:
        _sub, status, echoed = parsed
        print(
            f"diaggulp: enabled {detail} "
            f"(DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS; echo 0x{echoed:08X} confirmed, "
            f"status {status})",
            file=sys.stderr,
        )


def _enable_qsh_metrics(client: DiagClient) -> None:
    """Globally enable QSH (Subsystem Health) metrics for the capture.

    Complements the log mask (:func:`_build_all_logs_mask`), F3 arming
    (:func:`_enable_ext_msg_f3`), and QSH-*trace* arming
    (:func:`_enable_qsh_trace`). This adds QSH-*metrics* by sending the
    global-enable form of the ``0x9002`` subsystem command
    (``build_qsh_metrics_enable``), so a capture banks as many QSH flavors as
    the part will emit — decode later, mirroring the F3 workflow.

    ⚠️ **QSH-metrics (0x9002) is NOT the ``0x9D`` enabler.** An earlier docstring
    here claimed the log + F3 masks "already bank QSH-trace (0x9D)"; a
    host-side bisection **disproved that** — a mask-armed FN980 (SDX55) banks
    ``0x9D``=0 until the ``0x9001`` maskset SET is sent (:func:`_enable_qsh_trace`).
    ``0x9002`` here only adds the QSH-*metrics* flavor, which SDX24 rejects.

    **Non-fatal by policy.** Only SDX-era+ parts implement the QSH LTE
    subsystem; a pre-SDX MDM9607 (EG25-G/EC25) returns ``0x13 BAD_CMD`` and any
    part may time out. None of that should abort a capture — QSH metrics are an
    additive bonus on top of the log + F3 streams — so every failure mode here
    is logged and swallowed.
    """
    inner = build_qsh_metrics_enable()
    try:
        res = client._send_recv(inner[0], inner[1:], timeout=5.0)
    except Exception as exc:  # transport hiccup — never fatal for QSH arming
        print(f"diaggulp: QSH-metrics enable skipped (transport: {exc})",
              file=sys.stderr)
        return
    if res is None:
        print("diaggulp: QSH-metrics enable timed out (part may not implement "
              "QSH); continuing", file=sys.stderr)
        return
    op, body = res
    if op == DIAG_BAD_CMD_F:
        print("diaggulp: QSH-metrics not supported on this part "
              "(0x13 BAD_CMD — pre-SDX); continuing", file=sys.stderr)
        return
    status = int.from_bytes(body[3:7], "little") if len(body) >= 7 else -1
    if status == 0:
        print("diaggulp: enabled QSH metrics (0x9002 global enable, status 0)",
              file=sys.stderr)
    else:
        print(f"diaggulp: QSH-metrics enable returned status {status} "
              "(non-zero); continuing", file=sys.stderr)


def _enable_qsh_trace(
    client: DiagClient, maskset: "QshTracePlan | str | None" = None,
) -> bool:
    """Arm the QSH-*trace* stream — the actual ``0x9D`` enabler.

    Sends the ``0x9001`` QSH-trace maskset SET (subsys ``0x44``) for
    ``maskset`` — the command that turns on ``0x9D DIAG_QSH_TRACE_PAYLOAD_F``.
    ``maskset`` is a :class:`QshTracePlan` (what ``main`` passes), a
    profile name, or ``None`` for :data:`QSH_TRACE_DEFAULT_PROFILE`.

    **Host-side validated:** on a tethered
    FN980 (SDX55, ``/dev/ttyUSB9``) a mask-armed baseline banks ``0x9D``=0; after
    this single ``0x9001`` frame ``0x9D`` floods (~1400/s), status 0. The 45× F3
    ``0x7D`` SET_RT_MASK block an on-device logger also sends is **not** required for
    ``0x9D`` — it only enriches the F3 ``0x99``/``0x79`` planes (:func:`_enable_ext_msg_f3`
    covers that). Empty-maskset ``0x9001`` (count 0) is the matching disarm.

    ⚠️ **The arm LATCHES in the modem — it is not scoped to the capture, and
    it SURVIVES REBOOTS.** These modems remember their last DIAG state **per
    subsystem** and keep emitting that log type until it is *explicitly
    disabled* — a power-cycle does NOT reset it (a field finding). So the arm can be inherited not just from a previous run this
    session but from a previous *boot*, by whatever tool last touched the modem.
    Measured on an RM520N-GL (SDX62, ``…_11.200.11.200``): after one armed run, a subsequent
    ``--no-qsh-trace`` capture 50 s later still banked **22,241 ``0x9D``
    frames**, and a run 1.7 h later was still flooding. Only the explicit
    empty-maskset disarm zeroes it (``postdisarm`` capture: ``0x9D``=0), after
    which a re-arm restores the flood. Consequence for experiment design: a
    ``--no-qsh-trace`` capture is a valid ``0x9D``-negative control **only after
    an explicit disarm** — ⛔ **NOT after a reboot.** (An earlier version of this
    note offered "or a modem reboot" as an alternative; that was an *unmeasured*
    assumption — only the disarm was ever measured to zero ``0x9D`` — and the
    per-subsystem-latch finding above refutes it.) Otherwise a capture silently
    inherits the previous run's *or a previous boot's* arm, and a "baseline"
    labelled no-QSH is not one.

    **Non-fatal by policy** (like :func:`_enable_qsh_metrics`). Older/pre-QSH
    parts vary: SDX20 (LM960) dispatches ``0x9001`` but returns **status 2** and
    emits **no ``0x9D``** (a real per-generation negative, not an error); a
    pre-SDX part may return ``0x13 BAD_CMD`` or time out. None aborts a capture —
    QSH-trace is additive on top of the log + F3 + metrics streams.

    Returns ``True`` only when the SET came back status 0. That is the gate for
    :func:`_disarm_qsh_trace`: a run disarms only what it armed itself.
    """
    plan = maskset if isinstance(maskset, QshTracePlan) else _plan_qsh_trace(
        argparse.Namespace(qsh_profile=maskset))
    inner = build_qsh_trace_maskset_set(plan.pairs)
    if plan.profile and plan.profile != QSH_TRACE_DEFAULT_PROFILE:
        # Announce a narrowed arm — a capture that silently armed fewer
        # subsystems than the operator assumed reads as a modem-side gap.
        default_n = len(QSH_TRACE_PROFILES[QSH_TRACE_DEFAULT_PROFILE])
        print(f"diaggulp: QSH-trace {plan.label} "
              f"({len(plan.pairs)} SSIDs, vs {default_n} in "
              f"{QSH_TRACE_DEFAULT_PROFILE!r})",
              file=sys.stderr)
    try:
        res = client._send_recv(inner[0], inner[1:], timeout=5.0)
    except Exception as exc:  # transport hiccup — never fatal for QSH arming
        print(f"diaggulp: QSH-trace arm skipped (transport: {exc})",
              file=sys.stderr)
        return False
    if res is None:
        print("diaggulp: QSH-trace arm timed out (part may not implement QSH "
              "trace); continuing", file=sys.stderr)
        return False
    op, body = res
    if op == DIAG_BAD_CMD_F:
        print("diaggulp: QSH-trace not supported on this part "
              "(0x13 BAD_CMD — pre-SDX); continuing", file=sys.stderr)
        return False
    status = _qsh_maskset_status(body)
    if status == 0:
        print("diaggulp: armed QSH trace (0x9001 maskset SET, status 0 — 0x9D "
              "should now flow)", file=sys.stderr)
        return True
    print(f"diaggulp: QSH-trace arm returned status {status} (non-zero; "
          "e.g. SDX20 returns 2 with no 0x9D); continuing", file=sys.stderr)
    return False


def _qsh_maskset_status(body: bytes) -> int:
    """u32 status word of a 0x9001 reply body: subsys echo (``44 0190``) first."""
    return int.from_bytes(body[3:7], "little") if len(body) >= 7 else -1


#: The DIAG_QSH_TRACE_PAYLOAD_F opcode.
QSH_TRACE_PAYLOAD_OPCODE = 0x9D


def _count_opcode_frames(
    client: DiagClient, seconds: float, opcodes: "tuple[int, ...]",
) -> "dict[int, int] | None":
    """Count frames per opcode in ``opcodes`` (bare or 0x98-wrapped) over ``seconds``.

    Peeks each frame's head with :mod:`diagmunge.framefilter` and never unescapes
    the body. Returns ``None`` when the transport closes mid-window. A frame cut
    at the window's end is not counted.
    """
    from diagmunge.framefilter import FrameSplitter, peek

    split = FrameSplitter()
    counts = dict.fromkeys(opcodes, 0)
    end = time.monotonic() + seconds
    while True:
        left = end - time.monotonic()
        if left <= 0:
            return counts
        try:
            chunk = client.read_raw(timeout=min(left, 0.25))
        except EOFError:
            return None
        for esc in split.feed(chunk):
            pk = peek(esc)
            if pk is None:
                continue
            for op in opcodes:
                if op in (pk.opcode, pk.inner_opcode):
                    counts[op] += 1
                    break


def _count_qsh_trace_frames(client: DiagClient, seconds: float) -> "int | None":
    """Count ``0x9D`` frames (bare or 0x98-wrapped) arriving over ``seconds``."""
    counts = _count_opcode_frames(client, seconds, (QSH_TRACE_PAYLOAD_OPCODE,))
    return None if counts is None else counts[QSH_TRACE_PAYLOAD_OPCODE]


def _disarm_qsh_trace(
    client: DiagClient, *, sample_s: float = 2.5, settle_s: float = 2.0,
) -> bool:
    """Disarm the QSH-trace maskset this run armed, and VERIFY on the stream.

    The 0x9001 maskset is modem-side sticky: it outlives the DIAG
    session, and a power-cycle does not clear it either. A one-shot capture
    that leaves it armed hands every later reader of the port a ``0x9D`` flood.
    On the RM500Q-AE that was 2,700 frames/s against 4 frames/s of ``0x1476``.

    There is no maskset GET, so unlike :func:`restore_ext_msg_rt_mask`
    nothing can be *written back*. The empty ``count=0`` SET is the only
    operation. So this runs only when *this* run's arm came back status 0.

    The proof is the stream, not the status word. ``0x9D`` is counted over a
    window **before** the disarm, then again after a settle that lets in-flight
    frames drain. ``True`` only when the before-window saw ``0x9D`` (the
    positive control: a gauge that never read positive proves nothing) and the
    after-window saw none.

    Both windows must outlast the port's delivery period. A Foxconn T99W175
    (SDX55) flushes DIAG every ~1.27 s, so frames generated just before the
    disarm still arrive up to one flush later. The former 0.5 s settle let that
    tail into the after-window and a working disarm read "STILL flowing"; the
    former 1.5 s sample caught a still-armed modem by a 0.23 s margin.
    An RM500Q-AE streams continuously and its tail ends within 20 ms.
    """
    pre = _count_qsh_trace_frames(client, sample_s)
    inner = build_qsh_trace_maskset_set(())
    try:
        res = client._send_recv(inner[0], inner[1:], timeout=5.0)
    except Exception as exc:  # teardown must never raise
        res, why = None, f"raised ({exc})"
    else:
        why = "timed out"
    if res is None or res[0] == DIAG_BAD_CMD_F:
        why = why if res is None else "was rejected (DIAG_BAD_CMD_F)"
        print(f"diaggulp: ⚠️ QSH-trace disarm {why}; the modem is LEFT ARMED "
              "and every later reader of this port gets the 0x9D flood",
              file=sys.stderr)
        return False
    status = _qsh_maskset_status(res[1])
    if status != 0:
        print(f"diaggulp: ⚠️ QSH-trace disarm returned status {status}; treat "
              "the maskset as still armed", file=sys.stderr)
        return False
    _count_qsh_trace_frames(client, settle_s)
    post = _count_qsh_trace_frames(client, sample_s)
    rates = (f"0x9D {pre if pre is not None else '?'} frames in {sample_s:g} s "
             f"before, {post if post is not None else '?'} after")
    if pre and post == 0:
        print(f"diaggulp: disarmed QSH trace (0x9001 count=0, status 0), "
              f"VERIFIED on the stream — {rates}", file=sys.stderr)
        return True
    if not pre:
        print(f"diaggulp: QSH-trace disarm sent (status 0) but NOT verified: no "
              f"0x9D was flowing before it, so the stream cannot show the "
              f"change — {rates}", file=sys.stderr)
        return False
    print(f"diaggulp: ⚠️ QSH-trace disarm sent (status 0) but 0x9D is STILL "
          f"flowing — {rates}; treat the maskset as armed",
          file=sys.stderr)
    return False


#: The two streams ``--disarm-logs-on-exit`` stops: DIAG_LOG_F records
#: (armed by the LOG_CONFIG mask) and DIAG_EVENT_REPORT_F packets.
LOG_F_OPCODE = 0x10
EVENT_REPORT_OPCODE = 0x60
#: LOG_CONFIG operation 0: disable every log code in every log type.
LOG_CFG_DISABLE = 0
#: An unanswered disarm is re-sent this many times in all. On a port still
#: streaming at full rate the reply can be lost in the flood.
DISARM_ATTEMPTS = 3


def _send_log_disable(client: DiagClient, *, telit_quirk: bool = False) -> str:
    """LOG_CONFIG op 0. Returns ``"ok"``, ``"rejected"`` or ``"no-reply"``."""
    from struct import pack

    payload = pack("<3xI", LOG_CFG_DISABLE)
    for _ in range(DISARM_ATTEMPTS):
        if telit_quirk:
            body = _telit_log_config_xact(client, LOG_CFG_DISABLE, payload)
            res = None if body is None else (_DIAG_LOG_CONFIG_F, body)
        else:
            res = client._send_recv(
                _DIAG_LOG_CONFIG_F, payload, timeout=5.0,
                match=lambda op, b: log_config_reply_matches(op, b, LOG_CFG_DISABLE),
            )
        if res is not None:
            return "rejected" if res[0] == DIAG_BAD_CMD_F else "ok"
    return "no-reply"


def _send_events_off(client: DiagClient) -> str:
    """EVENT_REPORT_F off. Returns ``"ok"``, ``"rejected"`` or ``"no-reply"``.

    The reply shares opcode 0x60 with the unsolicited event packets, so while
    events are flowing an event can be taken for the reply. The stream census in
    :func:`_disarm_logs_and_events` is the proof, not this return value.
    """
    inner = build_event_report_enable(False)
    for _ in range(DISARM_ATTEMPTS):
        res = client._send_recv(inner[0], inner[1:], timeout=5.0)
        if res is not None:
            return "rejected" if res[0] == DIAG_BAD_CMD_F else "ok"
    return "no-reply"


def _disarm_logs_and_events(
    client: DiagClient, *, telit_quirk: bool = False,
    sample_s: float = 2.5, settle_s: float = 2.0,
) -> dict:
    """Clear the log mask and event reporting, and VERIFY on the stream.

    Both are modem-side sticky: they outlive the DIAG session and are cleared
    only by a re-enumeration. A MiFi 6620L (MDM9625) kept streaming ~600 KB/s
    after a ``--seconds 60`` run until LOG_CONFIG op 0 and ``0x60 00`` were sent
    by hand. Neither mask can be read back, so like the QSH maskset
    they are cleared, not restored.

    ``0x10`` and ``0x60`` frames are counted over a window before the disarm and
    again after a settle (the same windows as :func:`_disarm_qsh_trace`, sized
    for the T99W175's ~1.27 s DIAG flush). A plane still flowing after
    the first disarm gets its command re-sent once and is counted again. Per
    plane, the verdict is ``verified`` (flowing before, 0 after), ``unverified``
    (nothing flowing before: the gauge never read positive), ``still-flowing``,
    or ``unknown`` (the transport closed). Never raises.
    """
    planes = (("log", LOG_F_OPCODE), ("events", EVENT_REPORT_OPCODE))
    ops = tuple(op for _, op in planes)
    senders = {
        "log": lambda: _send_log_disable(client, telit_quirk=telit_quirk),
        "events": lambda: _send_events_off(client),
    }
    report: dict = {}
    try:
        pre = _count_opcode_frames(client, sample_s, ops)
        sent = {name: senders[name]() for name, _ in planes}
        _count_opcode_frames(client, settle_s, ops)
        post = _count_opcode_frames(client, sample_s, ops)
        resent = []
        if post is not None:
            resent = [name for name, op in planes if post[op]]
            for name in resent:
                sent[name] = senders[name]()
            if resent:
                _count_opcode_frames(client, settle_s, ops)
                post = _count_opcode_frames(client, sample_s, ops)
    except Exception as exc:  # teardown must never raise
        print(f"diaggulp: ⚠️ log/event disarm raised ({exc}); treat the log mask "
              "and event reporting as still armed", file=sys.stderr)
        return {"error": str(exc)}
    for name, op in planes:
        before = None if pre is None else pre[op]
        after = None if post is None else post[op]
        if before is None or after is None:
            verdict = "unknown"
        elif after:
            verdict = "still-flowing"
        elif before:
            verdict = "verified"
        else:
            verdict = "unverified"
        report[name] = {"command": sent[name], "before": before, "after": after,
                        "resent": name in resent, "verdict": verdict}
    for name, label, cmd in (("log", "log mask", "LOG_CONFIG op 0"),
                             ("events", "event reporting", "0x60 00")):
        r = report[name]
        rates = (f"0x{dict(planes)[name]:02X} {r['before']} frames in "
                 f"{sample_s:g} s before, {r['after']} after")
        if r["verdict"] == "verified":
            print(f"diaggulp: disarmed {label} ({cmd}: {r['command']}), VERIFIED "
                  f"on the stream — {rates}", file=sys.stderr)
        elif r["verdict"] == "unverified":
            print(f"diaggulp: {label} disarm sent ({cmd}: {r['command']}) but NOT "
                  f"verified: nothing was flowing before it — {rates}",
                  file=sys.stderr)
        else:
            print(f"diaggulp: ⚠️ {label} disarm ({cmd}: {r['command']}) — the "
                  f"stream is {r['verdict'].upper()} — {rates}; the modem is "
                  "LEFT ARMED, so every later reader of this port gets it. "
                  "Reboot it (AT+CFUN=1,1) to clear", file=sys.stderr)
    return report


def _enable_events(client: DiagClient) -> None:
    """Enable the modem's DIAG event-report (0x60) stream for the capture.

    Events are a distinct log flavor from the log-code 0x10 records
    (:func:`_build_all_logs_mask`) and the F3 ext-msg text
    (:func:`_enable_ext_msg_f3`): discrete state-transition markers (call drop,
    RRC state change, RACH outcome, …). Arming them by default banks that
    surface too, mirroring the F3/QSH policy — decode later.

    **Non-fatal by policy** (like :func:`_enable_qsh_metrics`). The 0x60 event
    on-switch is stable across chipset generations, but a transport hiccup or a
    part that rejects it must never abort a capture — events are additive on top
    of the log + F3 + QSH streams — so every failure mode is logged and swallowed.
    """
    inner = build_event_report_enable(True)
    try:
        res = client._send_recv(inner[0], inner[1:], timeout=5.0)
    except Exception as exc:  # transport hiccup — never fatal for event arming
        print(f"diaggulp: event-report enable skipped (transport: {exc})",
              file=sys.stderr)
        return
    if res is None:
        print("diaggulp: event-report enable timed out; continuing",
              file=sys.stderr)
        return
    op, _body = res
    if op == DIAG_BAD_CMD_F:
        print("diaggulp: event reporting not supported on this part "
              "(0x13 BAD_CMD); continuing", file=sys.stderr)
        return
    print("diaggulp: enabled DIAG event reporting (0x60)", file=sys.stderr)


def _event_mask_get(client: DiagClient) -> "tuple[EventMask, bytes] | None":
    """Read the event mask (0x81). Returns ``(mask, request_bytes)`` or ``None``.

    Tries the 4-byte request first (the only form the EM9291, an SDX62, answers), then the bare
    opcode the older readbacks used. ``None`` on BAD_CMD, on a reply
    that does not parse, or when neither form is answered.
    """
    for req in (build_event_mask_get(), bytes([DIAG_EVENT_MASK_GET_F])):
        res = client._send_recv(req[0], req[1:], timeout=3.0)
        if res is None:
            continue
        op, body = res
        if op != DIAG_EVENT_MASK_GET_F:
            return None
        try:
            return parse_event_mask_reply(body), req
        except ValueError:
            return None
    return None


def _event_mask_summary(mask: EventMask) -> dict:
    ids = mask.set_ids()
    return {
        "num_bits": mask.num_bits,
        "enabled_count": len(ids),
        "highest_enabled_id": ids[-1] if ids else None,
        "mask_hex": mask.mask.hex(),
    }


def _arm_event_mask(
    client: DiagClient, event_ids: "list[int] | None", *, telit_quirk: bool = False,
) -> dict:
    """Record (and optionally narrow) the event mask after the 0x60 on-switch.

    ``0x60`` on REWRITES the whole mask to all-ones (measured live on an EM9291 SDX62 and
    on an EM160R-GL), so this must run AFTER it. On MDM9625 it is acked but leaves
    the mask EMPTY; without ``event_ids`` an empty readback is then filled
    with every id and verified. With ``event_ids`` the mask is
    set to EXACTLY those ids (width from the GET, never guessed) and verified by
    a second GET, never by the 0x82 reply: a refused SET still replies.

    Always returns a record for the ``anchors.json`` ``event_mask`` block, so a
    capture states what was armed. "Event X never appears" is then
    distinguishable from "event X was never armed". **Non-fatal by policy**,
    like :func:`_enable_events`.
    """
    rec: dict = {"version": 1}
    if event_ids:
        rec["requested_ids"] = sorted(set(event_ids))
    if telit_quirk:
        # _send_recv cannot complete a request/response on the flush-on-OUT path.
        rec["status"] = "skipped_telit_quirk"
        print("diaggulp: event-mask readback skipped (--telit-quirk path)",
              file=sys.stderr)
        return rec
    try:
        got = _event_mask_get(client)
        if got is None:
            rec["status"] = "get_unanswered"
            print("diaggulp: event-mask readback (0x81) unanswered; the armed "
                  "event set is UNRECORDED for this capture; continuing",
                  file=sys.stderr)
            return rec
        mask, req = got
        rec["get_request_hex"] = req.hex()
        if event_ids:
            bad = sorted(i for i in set(event_ids) if not 0 <= i < mask.num_bits)
            if bad:
                rec["status"] = "ids_out_of_range"
                rec["out_of_range_ids"] = bad
                rec["armed"] = _event_mask_summary(mask)
                print(f"diaggulp: ⚠️ --event-ids {bad} outside this build's "
                      f"{mask.num_bits}-id event mask; mask left as armed",
                      file=sys.stderr)
                return rec
            want = EventMask.empty(mask.num_bits).with_ids(event_ids)
            set_req = build_event_mask_set(want)
            res = client._send_recv(set_req[0], set_req[1:], timeout=5.0)
            rec["set_reply_op"] = None if res is None else res[0]
            post = _event_mask_get(client)
            if post is None:
                rec["status"] = "set_unverified"
                print("diaggulp: ⚠️ event-mask narrow sent but the readback "
                      "failed; armed set unknown", file=sys.stderr)
                return rec
            mask = post[0]
            rec["narrowed_verified"] = mask.set_ids() == tuple(rec["requested_ids"])
        elif mask.num_bits and not mask.set_ids():
            # On MDM9625 0x60 on is acked but leaves the mask EMPTY, so
            # an "events on" capture carries no events. Fill it explicitly.
            want = EventMask.empty(mask.num_bits).with_ids(range(mask.num_bits))
            set_req = build_event_mask_set(want)
            res = client._send_recv(set_req[0], set_req[1:], timeout=5.0)
            rec["auto_filled"] = True
            rec["set_reply_op"] = None if res is None else res[0]
            post = _event_mask_get(client)
            if post is None:
                rec["status"] = "set_unverified"
                print("diaggulp: ⚠️ event mask was empty after 0x60; fill sent "
                      "but the readback failed; armed set unknown",
                      file=sys.stderr)
                return rec
            mask = post[0]
            rec["fill_verified"] = len(mask.set_ids()) == mask.num_bits
            print("diaggulp: event mask was EMPTY after 0x60; filled "
                  f"all {mask.num_bits} id(s) via 0x82 — verified="
                  f"{rec['fill_verified']}", file=sys.stderr)
        rec["status"] = "ok"
        rec["armed"] = _event_mask_summary(mask)
    except Exception as exc:  # transport hiccup — never fatal
        rec["status"] = "transport_error"
        rec["error"] = str(exc)
        print(f"diaggulp: event-mask readback skipped (transport: {exc})",
              file=sys.stderr)
        return rec
    armed = rec["armed"]
    if event_ids and not rec["narrowed_verified"]:
        print(f"diaggulp: ⚠️ event-mask narrow NOT verified: wanted "
              f"{rec['requested_ids']}, readback has {armed['enabled_count']} "
              "id(s) armed", file=sys.stderr)
    else:
        print(f"diaggulp: event mask armed — {armed['enabled_count']} of "
              f"{armed['num_bits']} event id(s) (0x81 readback)",
              file=sys.stderr)
    return rec


# ---------------------------------------------------------------------------
# Bounded F3 arming — per-subsystem SET_RT_MASK
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
# Wire format — HARDWARE-VERIFIED on a live Quectel EG25-G (MDM9607,
# EG25GGBR07A08M2G):
#
#     cmd_code     u8   = DIAG_EXT_MSG_CONFIG_F (0x7D, prepended by _send_recv)
#     sub_cmd      u8   = 4  (SET_RT_MASK)
#     ss_id_first  u16  first SSID in the range
#     ss_id_last   u16  last SSID in the range, inclusive
#     status       u16  0 on a request  <-- WAS MISSING; see below
#     rt_mask[]    u32  ONE runtime mask per ss_id in [first, last]
#
# i.e. ``pack("<BHHH", 4, first, last, 0) + u32 per ss_id``. Note this is
# byte-for-byte the same header the sub_cmd 2/3 mask-table REPLY uses, which is
# the structural reason to believe it: request and reply share one struct.
#
# ⛔ The previous reading — ``pack("<BHHI", 4, first, last, rt_mask)`` — omitted
# the status u16 and so put the mask at offset 5 where the firmware reads it at
# 7. Every bounded arm therefore wrote the HIGH half of the requested mask plus
# two bytes of whatever followed the request buffer. Measured against an
# all-zero table: ss 7 <- 0x01020408 stored 0xA2CC0102 (old) vs 0x01020408
# (corrected). The old form ACKed every time; nothing about it looked wrong.
#
# ⚠️ It is a mask ARRAY, not a broadcast: a single u32 sent for the range 30..35
# set entry 30 correctly, entry 31 to out-of-buffer garbage, and left 32..35
# untouched. Six copies set all six. ``_build_ext_msg_set_rt_mask`` replicates
# accordingly; ``build_ext_msg_set_rt_mask_array`` takes an explicit per-ss_id
# list (used by the exit-time restore, which must reproduce a non-uniform
# table).
#
# ⚠️ Unlike SET_ALL_RT_MASKS — which stores a cumulative prefix-OR of its
# request bytes (``ext_msg_set_all_stored_mask``) — the bounded path stores the
# mask VERBATIM once correctly framed. Verified on ss_ids 3, 7, 10, 20 and the
# range 30..35 by reading the table back with sub_cmd 3.

# The chipset's msg.h MSG_LVL_* runtime severity bits. Lower bit == less severe ==
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

# Named F3 SSID presets — curated, GROUNDED ss_id sets for
# --ext-msg-f3-preset, so a capture can arm just a topic's subsystems without
# hand-listing ss_ids. The ss_ids are the firmware's own MSG_SSID values, read
# directly from the qdb (each QShrink record carries its ss_id); verified STABLE
# across SDX55 (RM500Q-AE + SIMCom SIM8202) and SDX62 (RM520N-GL) — the
# MSG_SSID space is a stable chipset enum, so these
# transfer across builds/vendors (an ss_id absent on a given build is a no-op).
# Provenance per ss_id (dominant qdb source file):
#   1007 → srchtc_sm / srch_rx / srch_sect           (search)
#   3001 → srchcr / l1cmmeas / srchinterf            (LTE L1 measurement + search)
#   9509 → nr5g_ml1_rfmgr_trm_if / nr5g_ml1_common   (NR5G ML1)
#   9520 → nr5g_ml1_common_triage                    (NR5G ML1)
# ⛔ SET_RT_MASK is now hardware-TESTED and came back INERT on SDX55, which
# supersedes the earlier "unverified" caveat. On the RM500Q-AE
# (RM500QAEAAR11A03M4G_01.200.01.200) the `ml1` preset — ss_ids 1007/3001/9509/
# 9520 (= 0x03ef/0x0bb9/0x2525/0x2530) — armed cleanly (every SET_RT_MASK acked,
# no DIAG_BAD_CMD_F) and produced ZERO F3 frames over a 330 MB capture, while
# bare `--ext-msg-f3 --ext-msg-f3-level all` (SET_ALL_RT_MASKS) on the same modem
# gave 8.3M 0x99 + 229k 0x79. So the arm ack does NOT imply F3 will flow, and the
# bounded path fails SILENTLY in the safe-looking direction.
# 🆕 The LEADING candidate root cause is now that the
# request itself was malformed — the wire form omitted a 2-byte status field, so
# every bounded arm on every part wrote a garbage mask that ACKed exactly like a
# good one (see the wire block above). Corrected and verified storing verbatim
# on MDM9607. ⚠️ NOT confirmed on SDX55 — no reachable RM500Q-AE on this host —
# so this stays open and this warning stays until a bounded arm is measured
# emitting F3 there. Prefer the unbounded arm on unmeasured parts.
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


def _f3_set_all_level_mask(level: str) -> int:
    """Runtime mask for SET_ALL_RT_MASKS floored at ``level`` — celldiag form.

    ⚠️ This is a DIFFERENT encoding from :func:`_f3_level_mask`, and the
    difference is load-bearing. ``_f3_level_mask`` sets *only* the
    defined level bits (e.g. error → ERROR|FATAL = 0x18) and feeds the bounded
    SET_RT_MASK path — which is documented inert on SDX55, i.e. never
    hardware-validated. The **SET_ALL_RT_MASKS** path uses the *"all bits on,
    clear the bits strictly below the floor"* form, ``0xFFFFFFFF & ~below``.
    That is the value the kp celldiag helper (``diag_config_enable_f3``) sends
    and which is hardware-verified to reduce modem-side F3 volume on the
    LM960A18/SDX20: ``all`` 0xFFFFFFFF → ``high`` 0xFFFFFFFC → ``error``
    0xFFFFFFF8. Threading the 0x18 form here would
    leave ``--ext-msg-f3-level`` an appearance-only fix — the flag would change
    the request bytes but not to the value the modem is known to honor.
    """
    level = level.lower()
    if level == "all":
        return EXT_MSG_ALL_LEVELS
    if level not in _F3_MSG_LEVELS:
        raise ValueError(
            f"unknown F3 level {level!r}; choose from "
            f"{', '.join(_F3_LEVEL_ORDER)}, all"
        )
    floor = _F3_LEVEL_ORDER.index(level)
    below = 0
    for name in _F3_LEVEL_ORDER[:floor]:
        below |= _F3_MSG_LEVELS[name]
    return EXT_MSG_ALL_LEVELS & ~below & 0xFFFFFFFF


def _resolve_set_all_mask(level: str, raw_mask: "int | None") -> int:
    """The F3 runtime mask to arm: an explicit ``raw_mask``, else ``level``.

    The named levels (:func:`_f3_set_all_level_mask`) only ever move bits 0-4 —
    the five chipset ``MSG_LVL_*`` bits. That is the whole severity vocabulary
    they can express, and on a legacy-QSR part it is the wrong vocabulary:
    measured on a live EG25-G (MDM9607) the dominant F3 plane is ``0x92``
    ``DIAG_QSR_EXT_MSG_TERSE_F`` at 86% of all frames, and its sites' masks sit
    on ``MSG_MASK_15/16/19/21/22`` — bit 19 alone carries 42.6%. So
    ``--ext-msg-f3-level error`` (0xFFFFFFF8) removes 98.7% of the frames whose
    mask lies entirely in bits 0-2 and 1.0% of everything else: **15% of total
    volume**, from a flag that reads as "quiet capture".

    A raw mask reaches the other 27 bits, which is what makes the plane
    bound-able (or silence-able) on the parts where it dominates.

    ⚠️ ``0`` is a real, meaningful value — commanded silence — and must not be
    confused with "no mask given". ``--ext-msg-f3-level-mask 0`` SENDS a
    SET_ALL_RT_MASKS carrying level 0, whereas ``--no-ext-msg-f3`` sends
    nothing and leaves whatever mask a previous run armed still in force. That
    is "omitting is not clearing" on the F3 mask rather than the log
    mask, so this takes ``None`` (not ``0``) as its absent sentinel.
    """
    if raw_mask is None:
        return _f3_set_all_level_mask(level)
    if not 0 <= raw_mask <= 0xFFFFFFFF:
        raise ValueError(
            f"F3 runtime mask out of u32 range: 0x{raw_mask:X}"
            if raw_mask >= 0 else f"F3 runtime mask is negative: {raw_mask}"
        )
    return raw_mask


def _should_arm_unbounded_f3(ext_msg_f3: bool, raw_mask: "int | None") -> bool:
    """Whether the unbounded SET_ALL_RT_MASKS arm should run.

    An explicit ``--ext-msg-f3-level-mask`` IMPLIES arming, exactly as
    ``--ext-msg-f3-ss`` does. Without that, ``--no-ext-msg-f3
    --ext-msg-f3-level-mask 0x80000`` would parse cleanly, print nothing, and
    arm nothing — a silent no-op of the same shape as the bug where
    ``--ext-msg-f3-level`` changed the request bytes on a path that never ran.
    """
    return bool(ext_msg_f3) or raw_mask is not None


class _F3ArmPlan(NamedTuple):
    """What to arm, decided once, applied at every (re)connect.

    ``mode`` is ``"bounded"`` (SET_RT_MASK over ``bounded_ss``), ``"unbounded"``
    (SET_ALL_RT_MASKS) or ``"none"``. ``rt_mask`` is already in the encoding the
    chosen path wants, so the applier never re-derives it — the initial arm and
    the reconnect re-arm consume the SAME value, which is what stops the two
    from drifting apart (they previously repeated the precedence by hand).
    """
    mode: str
    rt_mask: int
    bounded_ss: tuple


def _plan_f3_arming(args) -> _F3ArmPlan:
    """Resolve --ext-msg-f3* into a single arming plan.

    Precedence: a bounded ss list (``--ext-msg-f3-ss`` / ``--ext-msg-f3-preset``)
    beats the all-on default; ``--ext-msg-f3-level-mask`` supplies the mask
    literally on whichever path runs and implies arming; otherwise
    the named ``--ext-msg-f3-level`` decides, in each path's own encoding.
    """
    bounded_ss = list(args.ext_msg_f3_ss or ())
    if args.ext_msg_f3_preset:
        bounded_ss = sorted(set(bounded_ss) | set(_F3_PRESETS[args.ext_msg_f3_preset]))
    raw = args.ext_msg_f3_level_mask
    if bounded_ss:
        rt_mask = (_resolve_set_all_mask(args.ext_msg_f3_level, raw)
                   if raw is not None else _f3_level_mask(args.ext_msg_f3_level))
        return _F3ArmPlan("bounded", rt_mask, tuple(bounded_ss))
    if _should_arm_unbounded_f3(args.ext_msg_f3, raw):
        return _F3ArmPlan(
            "unbounded", _resolve_set_all_mask(args.ext_msg_f3_level, raw), ())
    return _F3ArmPlan("none", 0, ())


def _apply_f3_arming(
    client, plan: _F3ArmPlan, *, warn_only: bool = True
) -> "F3MaskSnapshot | None":
    """Execute an :class:`_F3ArmPlan` against ``client``; return the PRE-ARM snapshot.

    ``warn_only`` matches the initial arm's policy (a failed F3 arm degrades to
    log-only capture rather than aborting); the reconnect path passes False so
    ``slurp()`` sees the failure and retries the re-open.

    Every arm reads and logs the runtime mask it is about to destroy.
    That read is unconditional and its failure is non-fatal — it is a record,
    not a gate — and it happens here rather than inside the two arming functions
    so the reconnect path cannot quietly skip it. The returned table is the
    input to :func:`restore_ext_msg_rt_mask` for callers that opted in; a
    ``"none"`` plan changes nothing, so it reads nothing.
    """
    if plan.mode == "none":
        return None
    pre_arm = log_pre_arm_ext_msg_rt_mask(client)
    try:
        if plan.mode == "bounded":
            _enable_ext_msg_f3_bounded(client, list(plan.bounded_ss), plan.rt_mask)
        else:
            _enable_ext_msg_f3(client, plan.rt_mask)
    except RuntimeError as exc:
        if not warn_only:
            raise
        which = "bounded " if plan.mode == "bounded" else ""
        print(
            f"warning: could not arm {which}F3 ext-msg stream ({exc}); "
            "continuing with log capture only",
            file=sys.stderr,
        )
    return pre_arm


def _build_ext_msg_set_rt_mask(ss_id_first: int, ss_id_last: int, rt_mask: int) -> bytes:
    """DIAG_EXT_MSG_CONFIG_F / SET_RT_MASK (sub_cmd 4) request payload.

    Returns the bytes *after* the 0x7D command code (``_send_recv`` prepends
    that). Wire, hardware-verified on a live EG25-G (MDM9607) —
    identical in shape to the sub_cmd 2/3 *reply* this module also parses::

        [0]    u8    sub_cmd = 4
        [1:3]  u16   ss_id_first
        [3:5]  u16   ss_id_last
        [5:7]  u16   status / reserved  (0 on a request)
        [7:]   u32[] LE   ONE mask per ss_id in ``first..last`` inclusive

    ⛔ **This corrects a two-byte layout bug that made every bounded arm write
    garbage.** The previous form was ``<BHHI`` — sub_cmd, first,
    last, mask — which omits the ``status`` u16 and so places the mask at offset
    **5** where the firmware reads it at **7**. The modem therefore read the
    high half of our mask plus two bytes *past the end of the request buffer*.
    Measured, arming a single ss_id against an all-zero table:

    ==============  ==================  ===========================
    request         old wire stored     corrected wire stored
    ==============  ==================  ===========================
    ss 3  ← 0x55        ``0xBB7F0000``      ``0x00000055``
    ss 7  ← 0x01020408  ``0xA2CC0102``      ``0x01020408``
    ss 20 ← 0xAABBCCDD  ``0x9171AABB``      ``0xAABBCCDD``
    ==============  ==================  ===========================

    The tell is in the old column: ``0x...0102`` for a requested ``0x01020408``
    is bytes **7 and 8 of our own request** — the low half of what the firmware
    read — while the top two bytes differ run to run because they are whatever
    followed the buffer. The corrected form stores the mask **verbatim**, with
    no prefix-OR transform (that applies to SET_ALL_RT_MASKS only,
    :func:`ext_msg_set_all_stored_mask`).

    ⚠️ **This is the leading candidate explanation for "bounded
    SET_RT_MASK ACKs but emits zero F3 on SDX55"**. A request that arms a garbage
    mask ACKs exactly like a good one. Not yet confirmed on SDX55 (no reachable
    RM500Q-AE), so that question is not closed by this; but the bounded
    path was never sending what it claimed on *any* part.

    ⚠️ The array is **one mask per ss_id**, not one mask broadcast over the
    range: sending a single u32 for ``30..35`` set entry 30 correctly, entry 31
    to out-of-buffer garbage, and left 32..35 untouched. ``rt_mask`` is
    therefore replicated ``ss_id_last - ss_id_first + 1`` times here (verified:
    six copies for ``30..35`` set all six entries to the requested value).
    """
    from struct import pack

    if not (0 <= ss_id_first <= 0xFFFF and 0 <= ss_id_last <= 0xFFFF):
        raise ValueError(f"ss_id out of u16 range: {ss_id_first}..{ss_id_last}")
    if ss_id_last < ss_id_first:
        raise ValueError(f"ss_id_last {ss_id_last} < ss_id_first {ss_id_first}")
    count = ss_id_last - ss_id_first + 1
    return pack(
        "<BHHH", EXT_MSG_SET_RT_MASK, ss_id_first, ss_id_last, 0
    ) + pack("<I", rt_mask & 0xFFFFFFFF) * count


def _enable_ext_msg_f3_bounded(
    client: DiagClient, ss_ids: "list[int]", rt_mask: int
) -> None:
    """Arm F3 for only ``ss_ids`` at runtime mask ``rt_mask`` (one SET_RT_MASK each).

    Bounded counterpart to :func:`_enable_ext_msg_f3` — leaves every SSID not in
    ``ss_ids`` dark, so a capture can carry e.g. just LTE/NR ML1 + search F3
    instead of the whole device's surface. Raises ``RuntimeError`` on a
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
    # ⚠️ This arm ACKS (no DIAG_BAD_CMD_F) but that does NOT mean F3 will
    # flow. On the RM500Q-AE (SDX55, RM500QAEAAR11A03M4G_01.200.01.200) the ml1
    # preset armed cleanly here and produced ZERO F3 frames (qsr4_0x99: 0,
    # ext_msg_0x79: 0) over a 330 MB capture, while bare --ext-msg-f3
    # --ext-msg-f3-level all (SET_ALL_RT_MASKS) on the same modem, same session,
    # gave 8.3M 0x99 + 229k 0x79. The bounded SET_RT_MASK path is acked-but-inert
    # on that build — the failure is silent and in the safe-looking direction. So
    # warn every time the bounded path is used until it is confirmed working on
    # the target hardware.
    print(
        "diaggulp: ⚠️ bounded F3 (SET_RT_MASK) armed cleanly but is NOT confirmed "
        "to emit F3 on every build — on SDX55 (RM500Q-AE) it yielded ZERO frames "
        "while unbounded SET_ALL_RT_MASKS gave millions. VERIFY F3 is "
        "actually flowing (check the .scan.json `f3` block, or watch for 0x79/0x99 "
        "records); if it is zero, drop the preset/-ss and use bare "
        "`--ext-msg-f3 --ext-msg-f3-level all`.",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Telit / SDX20 DIAG quirk path
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
# unchanged.

_DIAG_LOG_CONFIG_F = 115  # opcode 0x73 — log subscription command/response
_LOG_CFG_RETRIEVE_RANGES = 1
_LOG_CFG_SET_MASK = 3


# --- VID/PID auto-detection of flush-on-OUT modems ---
#
# --telit-quirk (above) had to be passed by hand; a user who forgets it gets
# the old 0-byte capture with no hint why. So auto-enable the quirk when the
# serial DIAG port belongs to a known flush-on-OUT device.
#
# Keyed on a curated (vid, pid) allow-list, NOT VID-only: the quirk path adds
# real overhead (backlog drain on open, pumped/IN-drained writes, periodic
# keep-alive kicks), so enabling it on a Telit modem that does NOT need it
# would be a pointless regression. The list is seeded with the single unit the
# quirk is live-validated against and grows only as siblings are
# confirmed flush-on-OUT on real hardware. Inline rather than module.yaml-
# sourced: the capture tool is transport-agnostic and shouldn't depend on the
# per-module metadata tree just to flip one bool (revisit if the list grows).
_FLUSH_ON_OUT_ALLOWLIST = {
    (0x1BC7, 0x1041): "Telit LM960A18",  # SDX20, live-validated
    (0x1BC7, 0x1040): "Telit LM960A18",  # SDX20 alt USB comp (DIAG at if00); live-validated
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
    is rejected instead of bound."""
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


def _resync_frame_boundary(
    client: DiagClient,
    *,
    quiet: float = 0.25,
    max_total: float = 1.5,
    max_frames: int = 4000,
) -> int:
    """Terminate a stale partial frame before the first request.

    Delegates to ``diagmunge.resync_frame_boundary``, shared with
    ``qsh_maskset_discover`` (whose probe SET read a stale ``"ati\\r"`` as
    "QSH unsupported"). Returns frames discarded.
    """
    return resync_frame_boundary(client, quiet=quiet, max_total=max_total,
                                 max_frames=max_frames)


def _wait_diag_ready(
    open_client,
    wait_s: float,
    *,
    probe_timeout: float = 1.5,
    first_backoff: float = 0.5,
    max_backoff: float = 4.0,
    sleep=time.sleep,
    clock=time.monotonic,
) -> Optional[DiagClient]:
    """Reopen until the DIAG function answers a ``DIAG_VERNO_F`` probe.

    Right after a USB (re)enumeration the DIAG tty can exist before the
    function answers: the T99W640's gadget re-compose made the first write die
    with pyserial's ``SerialException`` ("device reports readiness to read but
    returned no data"). That is an ``OSError``, so it is caught here along with
    a node that is not there yet. A VERNO reply or a ``DIAG_BAD_CMD_F`` both
    mean the function is answering. Each failed attempt closes its client and
    backs off (doubling, capped) until ``wait_s`` runs out; returns None then.
    """
    deadline = clock() + wait_s
    backoff = first_backoff
    attempt = 0
    while True:
        attempt += 1
        client = None
        try:
            client = open_client()
            reply = client._send_recv(DIAG_VERNO_F, b"", timeout=probe_timeout)
            if reply is not None and reply[0] in (DIAG_VERNO_F, DIAG_BAD_CMD_F):
                if attempt > 1:
                    print(f"diaggulp: DIAG ready after {attempt} attempts",
                          file=sys.stderr)
                return client
            why = "no DIAG_VERNO_F reply" if reply is None else \
                f"opcode {reply[0]:#04x} instead of DIAG_VERNO_F"
        except OSError as exc:
            why = f"{type(exc).__name__}: {exc}"
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001 - closing a dead port is best-effort
                pass
        remaining = deadline - clock()
        if remaining <= 0:
            print(f"error: DIAG did not answer within --wait-ready {wait_s:.1f}s "
                  f"(attempt {attempt}: {why})", file=sys.stderr)
            return None
        delay = min(backoff, remaining)
        print(f"diaggulp: DIAG not ready (attempt {attempt}: {why}); reopening in "
              f"{delay:.1f}s", file=sys.stderr)
        sleep(delay)
        backoff = min(backoff * 2, max_backoff)


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
    duplex deadlock). Frames drained here are discarded; the caller's
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
                # flush-kick is harmless.
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

    Fire-and-forget tolerant — on LM960 32.01.110 / SDX20, some flush-on-OUT Telit firmwares APPLY the SET_MASK
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


def _telit_version_anchor(
    client: DiagClient, *, timeout: float = 2.0, kick_every: float = 0.4
) -> "Optional[dict]":
    """DIAG_VERNO_F clock anchor over the flush-on-OUT (telit-quirk) path.

    ``DiagClient.emit_version_anchor()`` issues a plain write + blocking read.
    On a flush-on-OUT modem that write can wedge behind a full IN buffer, and
    even when it lands the modem may only deliver the reply in response to a
    *subsequent* OUT — so the read times out and the anchor is lost. This is
    the anchor analogue of :func:`_telit_log_config_xact`: pumped write, then
    flush-kicks until the VERNO reply surfaces.

    Returns the same dict shape as ``emit_version_anchor`` (so the sidecar and
    ``diaggrok_at_correlate``'s ``_anchor_mono_ns`` consume it unchanged), or
    ``None`` if the firmware genuinely never answers — the caller then falls
    back to :func:`_host_bracket_anchor`.

    ⚠️ **Hardware verdict on the motivating part: the LM960A18 never answers,
    and the flush-on-OUT theory does NOT explain why**. Firmware
    32.01.1X0. A 50 s live capture ran both boundaries over this
    pumped path; both returned ``None`` and fell back to ``host_bracket``, and
    a scan of the resulting 45.8 MB / 1,020,536-frame stream found **zero**
    opcode-``0x00`` frames — the reply is not merely being missed by
    ``recv()``, it is never on the wire. The decisive control: in that same
    capture the QSH arms (``0x9002`` → status 0, ``0x9001`` → status 2) and
    event-report enable (``0x60``) all got real replies via
    ``DiagClient._send_recv``, which is a **plain** write + blocking read.
    So this firmware does answer commands on the unpumped path; it simply does
    not implement ``DIAG_VERNO_F``. The muteness is **opcode-specific**, not a
    property of the transport shape.

    Keep this function anyway: it is the fair test (an unpumped probe could
    not distinguish "not implemented" from "wedged"), it costs one bounded
    timeout at each boundary, and a different flush-on-OUT part may well
    answer over it. Do not "simplify" it back to a plain exchange on the
    strength of this one part's result.
    """
    host_mono_ns = time.monotonic_ns()
    try:
        _telit_write_pumped(client, DIAG_VERNO_F, b"")
    except (OSError, RuntimeError):
        return None
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
                # IN buffer full — the recv() below drains it.
                pass
            next_kick = now + kick_every
        try:
            opcode, body = client.recv(
                timeout=min(kick_every, max(0.01, deadline - now)))
        except TimeoutError:
            continue
        if opcode == DIAG_VERNO_F:
            host_mono_recv_ns = time.monotonic_ns()
            return {
                "opcode": DIAG_VERNO_F,
                "host_mono_ns": host_mono_ns,
                "host_mono_recv_ns": host_mono_recv_ns,
                "response_bytes_hex": body.hex(),
                "rtt_ns": host_mono_recv_ns - host_mono_ns,
            }


def _host_bracket_anchor() -> dict:
    """Best-effort host-side-only clock anchor.

    Used when the modem will not answer DIAG_VERNO_F at all (the LM960A18 /
    SDX20 fire-and-forget firmware is the motivating case). It records host
    time at the capture boundary rather than at a modem-acknowledged instant,
    so it is a **strictly coarser precision class**: the error is the modem's
    own buffering/queueing latency at that boundary, not half a round trip.

    That is still worth writing. The alternative shipped before this — no
    sidecar at all — drops ``diaggrok_at_correlate`` to rung 3
    (``record_boundary``), which makes the *same* first-record ↔ capture-start
    assumption with none of it written down. Consumers distinguish the classes
    via the sidecar's ``method`` field and each anchor's own ``method`` key.

    Deliberately omits ``host_mono_recv_ns``: there is no response, so
    ``_anchor_mono_ns`` must not average a fabricated pair — it falls through
    to ``host_mono_ns`` alone.
    """
    return {
        "method": "host_bracket",
        "host_mono_ns": time.monotonic_ns(),
        "host_unix_ns": time.time_ns(),
    }


def _emit_boundary_anchor(
    client: DiagClient,
    *,
    which: str,
    timeout: float,
    telit_quirk: bool,
    quiet: bool,
) -> dict:
    """Emit one boundary anchor — **never returns None**.

    Tries the real DIAG_VERNO_F exchange first (over the pumped telit path
    when that quirk is active), and degrades to a host-side bracket when the
    modem does not answer. Guaranteeing a dict is the point: the anchor
    sidecar's existence no longer depends on modem cooperation, so a capture
    can always be tied to host/UTC time with a stated precision class.
    """
    anchor: Optional[dict] = None
    try:
        if telit_quirk:
            anchor = _telit_version_anchor(client, timeout=timeout)
        else:
            anchor = client.emit_version_anchor(timeout=timeout)
    except Exception as exc:   # noqa: BLE001 — anchors are best-effort
        print(f"warning: {which}-anchor emission failed: {exc}", file=sys.stderr)
    if anchor is None:
        anchor = _host_bracket_anchor()
        print(
            f"warning: {which}-anchor DIAG_VERNO_F unanswered — falling back "
            f"to a host-side bracket (method=host_bracket, coarser: error is "
            f"the modem's boundary buffering latency, not half an RTT)",
            file=sys.stderr,
        )
    elif not quiet:
        print(
            f"diaggulp: {which}-anchor host_mono_ns={anchor['host_mono_ns']} "
            f"rtt_ns={anchor['rtt_ns']}",
            file=sys.stderr,
        )
    return anchor


# --- QSHRINK4 diag_id binding table request --------------------------
#
# DIAGNOSTIC_SERVICES_DIAGID_TABLE: 0x4B DIAG_SUBSYS_CMD_F / subsys 0x12
# (DIAG_SERV) / cmd 0x0222, payload = u8 table version. The response names the
# protection domains behind a capture's diag_id channels — the index that says
# WHICH qdsp6m.qdb could resolve a hashed 0x99 / 0x9D message. It had only ever
# been seen in on-device diag_mdlog captures (0 of 271 measured host-tool
# captures carried it) because it is the RESPONSE to a client's session-start
# request, and no host tool of ours asked. Measured live on EM9190 /
# T99W175 (SDX55) and two RM520N-GL builds (SDX62): the bare 4-byte request is
# silently DROPPED (timeout, not 0x13), and the 5-byte form below returns the
# table. SDX20 (LM960A18) and MDM9607 (EG25-G) answer 0x13 BAD_CMD.
#
# The record rides <output>.anchors.json, because a DLF cannot hold a command
# response and _send_recv consumes the reply before the writer sees it anyway.
# diag_scan reads it back into the `diag_id_binding` sidecar block when the
# stream carries no binding frame. Best-effort, like the anchors: never aborts
# a capture, and every outcome is recorded rather than swallowed.
DIAG_SERV_SUBSYS = 0x12
DIAGID_TABLE_CMD = 0x0222
DIAGID_TABLE_VERSION = 1
DIAG_SUBSYS_CMD_F = 0x4B


def _request_diag_id_binding(
    client: DiagClient, timeout: float, quiet: bool = False,
    telit_quirk: bool = False,
) -> dict:
    """Ask for the diag_id binding table; return a record for the sidecar.

    ``status`` is one of ``table`` (a 0x4B reply echoing subsys/cmd — the
    bytes are recorded verbatim and parsed later by diag_scan, which owns the
    walk), ``bad_cmd`` (0x13 — a measured negative: this part does not serve
    the table), ``timeout``, ``unexpected`` (a 0x4B reply that is not this
    command's echo), ``error`` (transport exception, message in ``detail``), or
    ``skipped`` (the flush-on-OUT Telit path, where a plain _send_recv cannot
    surface the reply and the one SDX20 part we hold answers 0x13 anyway).
    """
    payload = bytes([DIAG_SERV_SUBSYS]) + DIAGID_TABLE_CMD.to_bytes(2, "little") \
        + bytes([DIAGID_TABLE_VERSION])
    request = build_subsys_command(DIAG_SERV_SUBSYS, DIAGID_TABLE_CMD,
                                   bytes([DIAGID_TABLE_VERSION]))
    assert request == bytes([DIAG_SUBSYS_CMD_F]) + payload
    rec: dict = {
        "opcode": DIAG_SUBSYS_CMD_F,
        "request_hex": request.hex(),
        "status": None,
        "response_hex": None,
        "host_mono_ns": time.monotonic_ns(),
        "rtt_ns": None,
    }
    if telit_quirk:
        rec["status"] = "skipped"
        rec["detail"] = ("telit-quirk (flush-on-OUT) path: reply cannot be "
                         "read by a plain request; not attempted")
    else:
        try:
            result = client._send_recv(DIAG_SUBSYS_CMD_F, payload, timeout=timeout)
            rec["rtt_ns"] = time.monotonic_ns() - rec["host_mono_ns"]
            if result is None:
                rec["status"] = "timeout"
            else:
                opcode, body = result
                rec["response_hex"] = bytes([opcode]).hex() + body.hex()
                if opcode == DIAG_BAD_CMD_F:
                    rec["status"] = "bad_cmd"
                elif opcode == DIAG_SUBSYS_CMD_F and body[:3] == payload[:3]:
                    rec["status"] = "table"
                else:
                    rec["status"] = "unexpected"
        except Exception as exc:  # noqa: BLE001 — best-effort, like the anchors
            rec["status"] = "error"
            rec["detail"] = f"{type(exc).__name__}: {exc}"
    if not quiet:
        tail = rec["response_hex"] or rec.get("detail") or ""
        print(f"diaggulp: diag_id binding table request -> {rec['status']} {tail}",
              file=sys.stderr)
    return rec


def _anchor_sidecar_doc(
    pre_anchor: "Optional[dict]", post_anchor: "Optional[dict]",
    diag_id_binding: "Optional[dict]" = None,
    event_mask: "Optional[dict]" = None,
) -> dict:
    """Build the ``<output>.anchors.json`` document.

    Stamps each anchor with its own precision class — anchors that came back
    from a real DIAG_VERNO_F exchange carry no ``method`` of their own, so
    they default to ``diag_verno_response``; :func:`_host_bracket_anchor`
    self-labels. The top-level ``method`` summarises, and is ``"mixed"`` when
    the two boundaries disagree (a modem can answer VERNO at t0 and be wedged
    or unplugged by tN) rather than overclaiming in either direction.
    """
    anchors_list: list[dict] = []
    if pre_anchor is not None:
        anchors_list.append({"kind": "start", **pre_anchor})
    if post_anchor is not None:
        anchors_list.append({"kind": "end", **post_anchor})
    for anchor in anchors_list:
        anchor.setdefault("method", "diag_verno_response")
    methods = {a["method"] for a in anchors_list}
    doc = {
        "version": 1,
        "method": methods.pop() if len(methods) == 1 else "mixed",
        "tool": "diaggulp.py",
        "anchors": anchors_list,
    }
    if diag_id_binding is not None:
        # The DIAGID_TABLE exchange, recorded verbatim (see
        # _request_diag_id_binding). Absent when the request was not made.
        doc["diag_id_binding"] = diag_id_binding
    if event_mask is not None:
        # The post-arm 0x81 readback, and any --event-ids narrowing.
        doc["event_mask"] = event_mask
    return doc


def _rotation_boundary_anchor(host_mono_ns: int, host_unix_ns: int) -> dict:
    """The anchor at a rotation boundary: host time, no modem exchange.

    Same precision class as :func:`_host_bracket_anchor`, a host reading at a
    stream boundary whose error is the modem-to-host buffering latency, and
    like it no ``host_mono_recv_ns``. Unlike a VERNO pre-anchor it has no slack
    between the anchor and the first record: it sits at the exact byte where
    one segment ends and the next begins. A ``DIAG_VERNO_F`` mid-capture would
    lose bytes instead, because ``_send_recv`` drains every frame it is not
    waiting for.
    """
    return {"method": "rotation_boundary", "host_mono_ns": host_mono_ns,
            "host_unix_ns": host_unix_ns}


def _write_anchor_sidecar(capture_path: str, doc: dict, *, quiet: bool) -> None:
    """Write ``<capture_path>.anchors.json``. Warns, never raises."""
    sidecar_path = capture_path + ".anchors.json"
    try:
        with open(sidecar_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        if not quiet:
            print(
                f"diaggulp: wrote anchor sidecar {sidecar_path} "
                f"({len(doc['anchors'])} anchor(s))",
                file=sys.stderr,
            )
    except OSError as exc:
        print(
            f"warning: failed to write anchor sidecar "
            f"{sidecar_path}: {exc}",
            file=sys.stderr,
        )


def _build_all_logs_mask_telit(client: DiagClient) -> None:
    """All-logs handshake for the flush-on-OUT Telit/SDX20 path.

    Same RETRIEVE_RANGES -> per-type SET_MASK shape as :func:`_build_all_logs_mask`,
    but every transaction goes through the pumped/operation-correlated path.
    Assumes the caller already ran :func:`_telit_drain_bounded`."""
    bitsizes = _telit_retrieve_ranges(client)
    _require_nonzero_log_ranges(bitsizes)
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
    """Narrow handshake for the flush-on-OUT Telit/SDX20 path.

    Reuses the pure :func:`_narrow_mask_bytes` builder; only the transport
    transaction differs from :func:`_build_narrow_mask`."""
    bitsizes = _telit_retrieve_ranges(client)
    masks = _narrow_mask_bytes(bitsizes, log_codes)  # raises before any I/O on bad code
    for log_type, mask in sorted(masks.items()):
        _telit_set_mask(client, log_type, bitsizes[log_type], mask)
    codes_str = ", ".join(f"0x{c:04X}" for c in sorted(set(log_codes)))
    subscribed = len({c >> 12 for c in set(log_codes)})
    print(
        f"diaggulp: [telit-quirk] narrow mask — subscribed to "
        f"{len(set(log_codes))} log code(s) across {subscribed} group(s): "
        f"{codes_str} (cleared {len(masks) - subscribed} other group(s))",
        file=sys.stderr,
    )


class _RotatingWriter:
    """Writer that rotates output by file size or wall-clock time.

    The output path may contain ``%s`` which expands to the current
    Unix timestamp at file open. Rotation closes the current file and
    opens a fresh one with a new timestamp.

    ``on_rotate`` (optional), set after construction, is called as
    ``on_rotate(closed_path, new_path, host_mono_ns, host_unix_ns)`` once the
    new segment is open. The two clocks are read right after the write that
    crossed the threshold, so they mark the stream position where the closed
    segment ends and the new one begins. Nothing is sent to the modem
    and no byte is lost.
    """

    def __init__(
        self,
        path: str,
        rotate_size: Optional[int] = None,
        rotate_interval: Optional[int] = None,
    ):
        # Rotation with no ``%s`` template re-opens the SAME path on every
        # rotation and truncates it to zero, so only the final segment survives —
        # silently, with exit 0 and the full (captured, not retained) byte count.
        # There is no correct use of rotation without a unique-path template, so
        # refuse to construct rather than discard data. (Checked before any file
        # is opened, so a rejected writer leaves nothing on disk.)
        if (rotate_size or rotate_interval) and "%s" not in path:
            raise ValueError(
                f"--rotate-size / --rotate-interval require a '%s' timestamp "
                f"placeholder in the output path so each segment gets a unique "
                f"name; got {path!r}. Without it, every rotation overwrites the "
                f"previous segment and all but the last is lost."
            )
        self._path = path
        self._rotate_size = rotate_size
        self._rotate_interval = rotate_interval
        self._fd = -1
        self._current_path = ""
        self._written = 0
        self._opened_at = 0.0
        self.on_rotate: "Optional[callable]" = None
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
            self._rotate()
        elif (
            self._rotate_interval
            and (time.monotonic() - self._opened_at) >= self._rotate_interval
        ):
            self._rotate()

    def _rotate(self) -> None:
        closed = self._current_path
        mono_ns, unix_ns = time.monotonic_ns(), time.time_ns()
        self._open_new()
        if self.on_rotate is not None:
            self.on_rotate(closed, self._current_path, mono_ns, unix_ns)

    def close(self) -> None:
        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1


# An MHI UCI read() returns at most ONE transfer buffer (TRE). On a host
# whose OOT pcie_mhi posts 8 KiB DIAG TREs (stock DIAG_MAX_PCIE_PKT_SZ), every
# DIAG packet longer than one TRE arrives CORRUPTED: the first TRE carries its
# head, the next TRE REPLAYS that head instead of the tail, and the tail is lost
# for good. On the wire that is a read of exactly 8192 bytes followed by a read
# that starts with the same 24 bytes, which is O(1) to spot per read. 24, not
# the 16 the offline walker uses: on a 0x98-wrapped frame the timestamp only
# starts at byte 16, and without a CRC check to back it up a 16-byte probe
# would fire on two back-to-back same-code, same-length packets. The fix is on
# the host: raise the DIAG MTU with
# tools/oot-pcie-mhi-patches/0010-fix-sdx7x-diag-mtu-32k.patch.
MHI_REPLAY_SEAM = 8192
_REPLAY_PROBE = 24   # 8 B 0x98 wrapper + 16 B LOG header, timestamp included


class ReplaySeamWatch:
    """Count MHI replay seams across consecutive transport reads.

    Watching costs one length check and one 16-byte compare per read, so it
    stays in the capture hot loop at no measurable cost. It never alters the
    bytes: the raw capture is written unchanged, and the offline walkers still
    split the seam (``diaggrok.hdlc._replay_seam``). This only makes the LOSS
    visible at capture time instead of weeks later in a corpus sweep."""

    def __init__(self) -> None:
        self.seams = 0
        self.first_offset: "Optional[int]" = None
        self._prev_head: "Optional[bytes]" = None

    def observe(self, data: bytes, offset: int) -> None:
        """Feed one read(). ``offset`` = bytes written before this read."""
        if self._prev_head is not None and data[:_REPLAY_PROBE] == self._prev_head:
            self.seams += 1
            if self.first_offset is None:
                self.first_offset = offset
        head = data[:_REPLAY_PROBE]
        # A replayed head carries an opcode, length, code and timestamp, so it
        # is never one repeated byte. A stream transport (TCP behind diagbarf)
        # can start a full 8192-byte read inside a frame's zero padding, and two
        # such reads would otherwise "match" — a live false positive.
        self._prev_head = (head if len(data) == MHI_REPLAY_SEAM
                           and head.count(head[:1]) != len(head) else None)

    def report(self, stop_info: "Optional[dict]" = None) -> None:
        """Record the count in ``stop_info`` and print a loud banner if any."""
        if stop_info is not None:
            stop_info["replay_seams"] = self.seams
        if self.seams:
            print(f"diaggulp: ⛔ {self.seams} DIAG packet(s) LOST to the 8 KiB MHI "
                  f"replay seam (first at byte {self.first_offset}). Every "
                  "DIAG packet longer than one 8 KiB transfer buffer arrived "
                  "with its tail replaced by a replay of its head. The host's "
                  "OOT pcie_mhi DIAG MTU is too small: install "
                  "tools/oot-pcie-mhi-patches/0010-fix-sdx7x-diag-mtu-32k.patch "
                  "(dkms/install.sh) and reload the driver.",
                  file=sys.stderr, flush=True)


class _TolerantStream:
    """A stream whose writes cannot raise.

    When a harness stops a capture it often closes the pipe that held
    diaggulp's stderr. The next teardown ``print`` then raises
    ``BrokenPipeError`` and every disarm after it is skipped, leaving the log,
    event and QSH planes armed. The teardown's messages are worth losing; the
    disarms are not.
    """

    def __init__(self, stream) -> None:
        self._stream = stream

    def write(self, s):
        try:
            return self._stream.write(s)
        except (OSError, ValueError):
            return len(s)

    def flush(self) -> None:
        try:
            self._stream.flush()
        except (OSError, ValueError):
            pass

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _shield_teardown(deferred: list) -> dict:
    """Make the capture teardown run to the end.

    The first SIGTERM/SIGINT ends the read loop as ``KeyboardInterrupt``. A
    second one, which a supervisor sends when the process is slow to exit,
    used to raise again inside the ``finally:`` and abort whatever disarm was
    running: measured on an M3100, where the F3 restore printed but log, events
    and QSH were left armed (8.5 MB in 6 s to nobody). From here on, a stop
    signal is recorded in ``deferred`` and otherwise ignored, because the
    teardown is already the stop. SIGKILL cannot be caught; ``timeout -k``
    still has the last word. Returns the handlers it replaced, for the caller
    to put back once the teardown is over.
    """
    def _defer(signum, frame):
        deferred.append(signum)
    replaced = {}
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        if signal.getsignal(sig) is not signal.SIG_IGN:
            replaced[sig] = signal.signal(sig, _defer)
    if not isinstance(sys.stderr, _TolerantStream):
        sys.stderr = _TolerantStream(sys.stderr)
    return replaced


def slurp(
    client: DiagClient,
    out_fd: int,
    chunk_size: int = READ_CHUNK,
    kick_fn: "Optional[callable]" = None,
    kick_interval: float = 0.3,
    reconnect_fn: "Optional[callable]" = None,
    tee_fn: "Optional[callable]" = None,
    max_seconds: "Optional[float]" = None,
    stop_info: "Optional[dict]" = None,
) -> tuple[int, float]:
    """Run the read-and-write loop. Returns (bytes_written, elapsed_seconds).

    ``stop_info`` (optional out-dict): when provided, its ``"reason"`` key
    is set to WHY the loop stopped — ``"deadline"`` (``max_seconds`` reached, a
    clean stop), ``"signal"`` (SIGINT/SIGTERM, a clean operator stop),
    ``"broken_pipe"`` (a downstream sink closed), or ``"eof"`` (the transport
    closed on its own — an UNEXPECTED mid-capture death on a live modem). The
    caller uses this to distinguish a silent wardrive-killing EOF from a clean
    stop and exit loudly + non-zero on ``"eof"``. Omitting it changes nothing.

    The loop is intentionally as bare as possible — select() blocks
    until data is available, then read() pulls a chunk and write()
    pushes it to the output. No HDLC parsing, no CRC validation,
    no per-frame Python work. The whole point is that the read+write
    pair has nothing between them.

    ``kick_fn`` (the telit-quirk keep-alive): when provided, it is called
    roughly every ``kick_interval`` seconds to write a tiny OUT to the modem.
    Flush-on-OUT modems (LM960/SDX20) only deliver buffered LOG_F records in
    response to host writes, so a purely passive loop captures nothing. The
    select() timeout is bounded to the kick interval so a kick still fires when
    no data is arriving. ``kick_fn=None`` (default) keeps the loop fully
    passive — unchanged for every other transport.

    ``max_seconds`` (the ``--seconds`` flag) stops the loop on its own
    clock after roughly that many seconds and returns normally, so the caller
    exits **0** instead of inheriting ``timeout(1)``'s 124. ``None`` (default)
    is the historical behaviour: run until EOF or a signal."""
    transport = client._transport
    fileno = transport.fileno()
    bytes_written = 0
    start = time.monotonic()
    base_select_timeout = min(1.0, kick_interval) if kick_fn else 1.0
    select_timeout = base_select_timeout
    next_kick = start + kick_interval if kick_fn else None
    deadline = (start + max_seconds) if max_seconds else None
    reset_since = None   # monotonic time the current reset window began
    last_reopen = None   # monotonic time of the last re-open attempt
    seam_watch = ReplaySeamWatch()   # 8 KiB MHI replay seam, O(1)/read

    def _stop(reason):   # record WHY the loop ended, if the caller cares
        if stop_info is not None:
            stop_info["reason"] = reason

    while True:
        # Deadline. The select() timeout is clamped to whatever is LEFT on
        # the clock, not just polled between selects: a silent port blocks the
        # full quantum, so an unclamped check turns a 0.2 s sample into a 1.0 s
        # one. Short samples are the whole use case (a caller arms → samples →
        # disarms), so the overshoot would be the dominant term.
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _stop("deadline")
                break
            select_timeout = min(base_select_timeout, remaining)
        # Adaptive keep-alive: kick only after kick_interval of NO data. While
        # the modem floods (next_kick deferred on every read below), no kick
        # fires — a kick then is both unnecessary (stream already flowing) and
        # unwriteable (IN-full modem won't accept the OUT).
        if next_kick is not None and time.monotonic() >= next_kick:
            try:
                kick_fn()
            except BrokenPipeError:
                _stop("broken_pipe")
                break
            except KeyboardInterrupt:
                _stop("signal")
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
            _stop("signal")
            break
        if not ready:
            continue
        try:
            data = transport.read(chunk_size)
        except (KeyboardInterrupt, InterruptedError):
            _stop("signal")
            break
        except OSError as exc:
            # Transient MHI DIAG channel reset: EINTR/ERESTARTSYS(512)/
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
                # (not a transient blip). Re-open it and re-arm the masks.
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
            _stop("eof")
            break
        seam_watch.observe(data, bytes_written)   # O(1)
        # The hot path is exactly two function calls: read() and write().
        try:
            os.write(out_fd, data)
        except BrokenPipeError:
            _stop("broken_pipe")
            break
        except KeyboardInterrupt:
            _stop("signal")
            break
        bytes_written += len(data)
        # Live decode: tee a COPY to the side-thread decoder AFTER the raw
        # write. tee_fn is a non-blocking put_nowait that drops on a full queue,
        # so it can never stall the read→write pair or risk a raw byte.
        if tee_fn is not None:
            tee_fn(data)
        if next_kick is not None:
            next_kick = time.monotonic() + kick_interval  # defer: data flowing
    seam_watch.report(stop_info)
    elapsed = time.monotonic() - start
    return bytes_written, elapsed


def slurp_rotating(
    client: DiagClient,
    writer: "_RotatingWriter",
    chunk_size: int = READ_CHUNK,
    kick_fn: "Optional[callable]" = None,
    kick_interval: float = 0.3,
    tee_fn: "Optional[callable]" = None,
    max_seconds: "Optional[float]" = None,
    stop_info: "Optional[dict]" = None,
) -> tuple[int, float]:
    """:func:`slurp` for the rotating case. Returns (bytes_written, elapsed).

    ``stop_info`` (optional out-dict): same contract as :func:`slurp` —
    records the stop ``"reason"`` (``"deadline"`` / ``"signal"`` / ``"eof"``).

    Rotation is driven by ``_RotatingWriter.write()`` counting bytes and
    re-opening the output, so this loop must go through the writer rather than
    ``os.write(out_fd, …)`` — that one difference is why it cannot simply be
    :func:`slurp`.

    ⚠️ **It used to live inline in ``main()``**, described in its own
    comment as "a tiny version of slurp()". That is the shape where a new flag
    reaches one copy and silently not the other, and the failure is quiet: a
    ``--seconds`` the rotating loop ignored would not error, it would **hang
    until killed** — the pre-flag behaviour wearing the flag's name. It is a
    module-level function now so the deadline can be *observed* on this path,
    not just on ``slurp``'s.

    The channel-reset ride-out deliberately stays in :func:`slurp` alone;
    this loop keeps its original, simpler error surface."""
    transport = client._transport
    fileno = transport.fileno()
    bytes_written = 0
    start = time.monotonic()
    base_select_timeout = min(1.0, kick_interval) if kick_fn else 1.0
    select_timeout = base_select_timeout
    next_kick = start + kick_interval if kick_fn else None
    deadline = (start + max_seconds) if max_seconds else None
    seam_watch = ReplaySeamWatch()   # shared with slurp()

    def _stop(reason):   # record WHY the loop ended, if the caller cares
        if stop_info is not None:
            stop_info["reason"] = reason

    try:
        while True:
            # Deadline, clamped into the select() timeout — see slurp().
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _stop("deadline")
                    break
                select_timeout = min(base_select_timeout, remaining)
            # Adaptive keep-alive; see slurp() for rationale.
            if next_kick is not None and time.monotonic() >= next_kick:
                try:
                    kick_fn()
                except OSError:
                    pass  # busy modem; stream already flowing
                next_kick = time.monotonic() + kick_interval
            ready, _, _ = select.select([fileno], [], [], select_timeout)
            if not ready:
                continue
            data = transport.read(chunk_size)
            if not data:
                print("diaggulp: transport closed (EOF)", file=sys.stderr)
                _stop("eof")
                break
            seam_watch.observe(data, bytes_written)   # O(1)
            writer.write(data)
            bytes_written += len(data)
            if tee_fn is not None:
                tee_fn(data)   # non-blocking tee to live decoder
            if next_kick is not None:
                next_kick = time.monotonic() + kick_interval  # data flowing
    except KeyboardInterrupt:
        _stop("signal")
    seam_watch.report(stop_info)
    elapsed = time.monotonic() - start
    return bytes_written, elapsed


def _capture_exit(stop_info: "Optional[dict]", bytes_written: int) -> "tuple[int, Optional[str]]":
    """Map a capture-loop ``stop_info`` to an ``(exit_code, alarm_text)``.

    A live modem must never close its own DIAG stream, so an ``"eof"`` stop means
    the transport died mid-capture (USB drop / channel teardown — the CARCOM-G1
    session-7c92 wardrive, ``[Errno 5]`` then EOF ~9 min in). The old code broke
    the loop, wrote its sidecar, and returned 0, so a moving wardrive kept running
    while the tty had gone silent. Return a distinct **non-zero code 3** plus a
    loud banner so the operator — or a wrapper reconnect loop (e.g.
    ``cv2x-quickcapture.sh``) — sees it and re-opens + re-arms. Every clean stop
    (``"deadline"`` from ``--seconds``, ``"signal"``, ``"broken_pipe"`` from a
    closed downstream sink, or an unset reason) returns ``(0, None)``."""
    if (stop_info or {}).get("reason") == "eof":
        return 3, (
            "diaggulp: ⛔⛔ TRANSPORT EOF MID-CAPTURE — capture STOPPED and is "
            "NOT resuming. The DIAG interface closed on its own (USB drop / "
            "channel teardown), NOT an operator stop or a --seconds deadline. "
            f"Captured {bytes_written} bytes before the drop. If this was a live "
            "wardrive, the rest of the drive recorded NOTHING — re-open the port "
            "and re-arm the mask (exit code 3)."
        )
    return 0, None


# ---------------------------------------------------------------------------
# Live / streaming DIAG decode — decode a SELECTED set of log codes
# inline as frames arrive, on a side thread, so an operator can watch records
# (cells appearing/disappearing, a SIB1 landing) WITHOUT the capture →
# stop → hdlc_to_dlf → offline-decode round-trip.
#
# Design contract: NEVER block the capture hot path. diaggulp's
# whole value is lossless low-CPU capture; the raw .bin stays the
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
    registered parser triggers a one-time live novelty alert.

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
                    # Unparsed code in the live stream → novelty alert.
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
# Offline pcap replay — read DGE1 datagrams from a pcap capture of the
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


def _udp_ports_and_payload_from_ip(ip: bytes) -> "Optional[tuple[int, int, bytes]]":
    """Return ``(src_port, dst_port, payload)`` for an IPv4/IPv6 UDP datagram,
    else None.

    Split out of :func:`_udp_payload_from_ip` so a caller can learn
    WHICH port a datagram used without a second parse. The port-filtering
    wrapper below preserves the original contract for every existing caller;
    the port census is the only consumer that needs the ports themselves.
    """
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
    return src_port, dst_port, udp[8:]


def _udp_payload_from_ip(ip: bytes, port: Optional[int]) -> Optional[bytes]:
    """Return the UDP payload of an IPv4/IPv6 packet, or None if it is not a
    UDP datagram (or does not match ``port`` when a filter is given)."""
    got = _udp_ports_and_payload_from_ip(ip)
    if got is None:
        return None
    src_port, dst_port, payload = got
    if port is not None and port not in (src_port, dst_port):
        return None
    return payload


def _udp_ports_and_payload_from_link(linktype: int,
                                     frame: bytes) -> "Optional[tuple[int, int, bytes]]":
    """Strip the link layer down to the IP packet, then extract
    ``(src_port, dst_port, payload)``. None for non-IP / non-UDP frames."""
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
        return _udp_ports_and_payload_from_ip(ip)
    if linktype == _LINKTYPE_LINUX_SLL:
        return _udp_ports_and_payload_from_ip(frame[16:]) if len(frame) >= 16 else None
    if linktype == _LINKTYPE_LINUX_SLL2:
        return _udp_ports_and_payload_from_ip(frame[20:]) if len(frame) >= 20 else None
    if linktype == _LINKTYPE_RAW:
        return _udp_ports_and_payload_from_ip(frame)
    return None


def _udp_payload_from_link(linktype: int, frame: bytes, port: Optional[int]) -> Optional[bytes]:
    """Strip the link layer down to the IP packet, then extract the UDP
    payload. Returns None for non-IP / non-UDP / non-matching frames."""
    got = _udp_ports_and_payload_from_link(linktype, frame)
    if got is None:
        return None
    src_port, dst_port, payload = got
    if port is not None and port not in (src_port, dst_port):
        return None
    return payload


_PCAPNG_SHB = 0x0A0D0D0A
_PCAPNG_IDB = 0x00000001
_PCAPNG_EPB = 0x00000006


def _pcapng_tsresol_to_ns(raw: int) -> int:
    """Nanoseconds per timestamp unit for an if_tsresol option value."""
    if raw & 0x80:  # 2^-n seconds form — rare; refuse rather than mis-scale
        raise ValueError(f"pcapng if_tsresol 2^-n form (0x{raw:02x}) not supported")
    if raw > 9:  # sub-nanosecond decimal resolution — can't represent in integer ns
        raise ValueError(f"pcapng if_tsresol decimal form (0x{raw:02x}) finer than 1ns not supported")
    return 10 ** (9 - raw)  # decimal: raw=6 (us) -> 1000 ns/unit, raw=9 (ns) -> 1


def iter_pcapng_udp_payloads(path: str, port: Optional[int] = None, *,
                             with_ports: bool = False):
    """Yield ``(wire_ts_ns, udp_payload)`` for every UDP datagram in a pcapng file.

    Walks Section Header / Interface Description / Enhanced Packet blocks
    (the blocks tcpdump/dumpcap emit). Per-interface ``if_tsresol`` scales
    the EPB timestamp to integer nanoseconds. Non-EPB blocks are skipped.
    """
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head != b"\x0a\x0d\x0d\x0a":
            raise ValueError(f"{path}: not a pcapng file (bad first block {head.hex()})")
        fh.seek(0)
        ns_per_unit_by_if: list[int] = []
        linktype_by_if: list[int] = []
        while True:
            hdr = fh.read(8)
            if len(hdr) < 8:
                break
            btype = int.from_bytes(hdr[0:4], "little")
            total = int.from_bytes(hdr[4:8], "little")
            if total < 12:
                break
            body_and_trailer = fh.read(total - 8)
            if len(body_and_trailer) < total - 8:
                break
            body = body_and_trailer[:-4]  # everything except the trailing 4-byte total field
            if btype == _PCAPNG_IDB:
                linktype = int.from_bytes(body[0:2], "little")
                ns_per_unit = 1000  # default if_tsresol = 6 (microseconds)
                # options begin after linktype(2)+reserved(2)+snaplen(4) = 8
                opt = 8
                while opt + 4 <= len(body):
                    code = int.from_bytes(body[opt:opt + 2], "little")
                    olen = int.from_bytes(body[opt + 2:opt + 4], "little")
                    val = body[opt + 4:opt + 4 + olen]
                    if code == 0:  # opt_endofopt
                        break
                    if code == 9 and olen >= 1:  # if_tsresol
                        ns_per_unit = _pcapng_tsresol_to_ns(val[0])
                    opt += 4 + olen + ((-olen) % 4)
                linktype_by_if.append(linktype)
                ns_per_unit_by_if.append(ns_per_unit)
            elif btype == _PCAPNG_EPB:
                if_id = int.from_bytes(body[0:4], "little")
                ts_units = (int.from_bytes(body[4:8], "little") << 32) | int.from_bytes(body[8:12], "little")
                cap_len = int.from_bytes(body[12:16], "little")
                frame = body[20:20 + cap_len]
                ns_per_unit = ns_per_unit_by_if[if_id] if if_id < len(ns_per_unit_by_if) else 1000
                linktype = linktype_by_if[if_id] if if_id < len(linktype_by_if) else 101
                got = _udp_ports_and_payload_from_link(linktype, frame)
                if got is None:
                    continue
                src_port, dst_port, payload = got
                if port is not None and port not in (src_port, dst_port):
                    continue
                ts = ts_units * ns_per_unit
                yield (ts, src_port, dst_port, payload) if with_ports else (ts, payload)


def iter_pcap_udp_payloads(path: str, port: Optional[int] = None, *,
                           with_ports: bool = False):
    """Yield (wire_ts_ns, payload) tuples for every UDP datagram in a classic-pcap file
    (optionally filtered to ``port`` on either src or dst).

    wire_ts_ns is the per-packet timestamp in nanoseconds since the Unix epoch.
    For microsecond magics, it is calculated as ts_sec * 1_000_000_000 + ts_frac * 1000
    (ts_frac is scaled from microseconds to nanoseconds);
    for nanosecond magics, as ts_sec * 1_000_000_000 + ts_frac (ts_frac used as-is).

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
        ns_magic = magic in (_PCAP_MAGIC_LE_NS, _PCAP_MAGIC_BE_NS)
        while True:
            ph = fh.read(16)
            if len(ph) < 16:
                break
            ts_sec = int.from_bytes(ph[0:4], endian)
            ts_frac = int.from_bytes(ph[4:8], endian)
            wire_ts_ns = ts_sec * 1_000_000_000 + (ts_frac if ns_magic else ts_frac * 1000)
            incl_len = int.from_bytes(ph[8:12], endian)
            frame = fh.read(incl_len)
            if len(frame) < incl_len:
                break  # truncated final record
            got = _udp_ports_and_payload_from_link(linktype, frame)
            if got is None:
                continue
            src_port, dst_port, payload = got
            if port is not None and port not in (src_port, dst_port):
                continue
            yield ((wire_ts_ns, src_port, dst_port, payload) if with_ports
                   else (wire_ts_ns, payload))


_PCAPNG_MAGIC = struct.pack("<I", 0x0A0D0D0A)  # b"\x0a\x0d\x0d\x0a"


def _sniff_and_dispatch(real_path: str, port, with_ports: bool = False):
    """Sniff the container format by magic and dispatch to the appropriate reader."""
    with open(real_path, "rb") as fh:
        magic = fh.read(4)
    if magic == _PCAPNG_MAGIC:
        yield from iter_pcapng_udp_payloads(real_path, port, with_ports=with_ports)
    elif magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE, _PCAP_MAGIC_LE_NS, _PCAP_MAGIC_BE_NS):
        yield from iter_pcap_udp_payloads(real_path, port, with_ports=with_ports)
    else:
        raise ValueError(f"{real_path}: unrecognized container magic {magic.hex()}")


def iter_udp_payloads(path: str, port: Optional[int] = None, *,
                      scratch_dir: Optional[str] = None,
                      with_ports: bool = False):
    """Yield ``(wire_ts_ns, udp_payload)`` from a pcap/pcapng, optionally ``.zst``.

    Sniffs the container by magic (after any zstd layer), so the extension is
    advisory. This is the single container-I/O entry point the streaming DIAG
    source is built on.

    ``scratch_dir`` chooses where a ``.zst`` input is transiently decompressed.
    ``None`` (the default) keeps the historical behavior — the OS temp dir, which
    on several hosts is tmpfs and can OOM on a large decompress. The
    pcap-native streaming source (:func:`diagmunge.diag_source.open_diag_source`)
    passes the sanctioned repo scratch dir so parts decompress one-at-a-time onto
    real disk; each temp is deleted as soon as its part is streamed.

    ``path`` may be any :term:`path-like` — the ``--resume`` carve chain hands
    down :class:`pathlib.Path` parts (`resolve_pcap_parts`), so coerce to ``str``
    here at the single container-I/O boundary rather than at every caller.
    """
    path = os.fspath(path)
    if path.endswith(".zst"):
        with tempfile.NamedTemporaryFile(suffix=".cap", delete=True,
                                         dir=scratch_dir) as tmp:
            with open(path, "rb") as fh:
                zstd.ZstdDecompressor().copy_stream(fh, tmp)
            tmp.flush()
            yield from _sniff_and_dispatch(tmp.name, port, with_ports)
    else:
        yield from _sniff_and_dispatch(path, port, with_ports)


def pcap_replay_available() -> bool:
    """True when the pcap replay core (``diagmunge.diag_source``) is importable.

    It ships with diagmunge and needs diaggrok's HDLC framer, so an install
    that predates it, or that lacks diaggrok, has no ``--pcap`` replay.
    ``main`` checks this before opening any output.
    """
    try:
        # find_spec does not import the module, so check its diaggrok dep too.
        return (importlib.util.find_spec("diagmunge.diag_source") is not None
                and importlib.util.find_spec("diaggrok.hdlc") is not None)
    except ModuleNotFoundError:     # diagmunge or diaggrok itself is absent
        return False


def replay_pcap_dge1(source, port: Optional[int], out_fd: int) -> "tuple[int, dict]":
    """Deframe the DGE1 datagrams in ``source`` and write the reassembled raw
    HDLC byte stream to ``out_fd``. Returns ``(bytes_written, gap_report)`` —
    the gap report has the same shape the live udp-listen sidecar carries.

    ``source`` is a single capture path (legacy) **or** an ordered sequence of
    part paths (the multi-part pcap master). The parts are
    chained into ONE datagram stream so a single :class:`Dge1SeqTracker` spans
    the split between part N and N+1 — a record straddling the boundary
    reassembles and the gap report is contiguous across the seam. **No merged
    pcap** — the parts feed the carve directly.

    The deframe is the shared :func:`diagmunge.diag_source.iter_dge1_payloads`
    core (also driving the F3/scan pcap paths), so the carve's late/dup-drop and
    gap accounting cannot drift from those paths. That core sniffs the
    container by magic and decompresses ``.zst`` parts one-at-a-time into
    sanctioned scratch, so a ``.pcapng[.zst]`` master carves natively — the
    format this whole effort produces.
    """
    from diagmunge.diag_source import iter_dge1_payloads  # lazy: avoids import cycle

    bytes_written = 0
    gen = iter_dge1_payloads(source, port=port)
    while True:
        try:
            _wire_ts, payload = next(gen)
        except StopIteration as stop:
            gap_report = stop.value
            break
        os.write(out_fd, payload)
        bytes_written += len(payload)
    return bytes_written, gap_report


def _run_pcap_transport(args, explicit_port: bool) -> int:
    """Handle ``--transport pcap`` end to end: read DGE1 datagrams from a pcap,
    reassemble the DLF, and write the .udpgaps.json gap sidecar."""
    if not args.pcap:
        print("error: --transport pcap requires --pcap FILE", file=sys.stderr)
        return 2
    # ``--pcap`` is ``nargs='+'`` so this is always a list; a single part is a
    # one-element list (backward-compatible). Every ordered part must exist —
    # the master is carved as one stream, so a missing part is a hard error, not
    # a silent skip.
    missing = [p for p in args.pcap if not os.path.exists(p)]
    if missing:
        print(f"error: pcap file(s) not found: {', '.join(missing)}",
              file=sys.stderr)
        return 2
    if not pcap_replay_available():
        print("error: --pcap replay needs diagmunge.diag_source (diagmunge "
              "with the decode extra, i.e. diaggrok installed); upgrade "
              "diagmunge or capture live with --transport udp-listen instead",
              file=sys.stderr)
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
                        # A single part records a scalar (legacy sidecar shape,
                        # byte-for-byte unchanged); a genuine multi-part master
                        # records the ordered part list.
                        "pcap": args.pcap[0] if len(args.pcap) == 1 else args.pcap,
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
# modem's NMEA stream from the dedicated NMEA port (`--no-nmea` opts out). This runs in its own daemon thread on its own serial fd writing
# its own `<output-stem>.nmea` file, so it touches none of diaggulp's DIAG hot
# path and the throughput guarantee is unaffected. Line format is
# "<UTC ISO8601> <NMEA line>", the same as the standalone NMEA capture.
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


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the CLI parser. Split out of main() so tests can pin flag defaults."""
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
        choices=["serial", "tcp", "udp", "tcp-connect", "udp-listen", "pcap",
                 "libusb"],
        default="serial",
        help="DIAG transport (default: serial). 'tcp-connect' dials a device "
             "that LISTENS (the diagbarf TCP sink); 'udp-listen' "
             "passively reassembles the DGE1-framed UDP stream. Both are "
             "passive consumers (the on-device daemon already armed the mask), "
             "so --no-mask is forced and anchor frames are disabled — unless "
             "--client-arms-mask (tcp-connect only) says the listener "
             "is a stock diag_socket_log that arms nothing. 'pcap' "
             "is fully offline: it reads DGE1 datagrams from a "
             "pcap/tcpdump capture of the diagbarf broadcast (--pcap FILE) and "
             "reassembles the same raw-HDLC -> DLF the live udp-listen path "
             "produces, plus a .udpgaps.json gap sidecar. 'libusb' "
             "captures from a raw-USB-only DIAG modem that exposes no ttyUSB / "
             "cdc-wdm node (Inseego M3100 SDX65, Foxconn/T99W MHI variants): "
             "give --usb-vid/--usb-pid (the DIAG interface is auto-detected by "
             "probing each candidate vendor interface with DIAG_VERNO_F "
             "; or override with --usb-iface/--usb-ep-in/--usb-ep-out). "
             "The full mask handshake, "
             "--log-code narrow mask, F3 arm, and rotation all work over it.",
    )
    parser.add_argument(
        "--usb-vid", type=_parse_int_arg, metavar="VID",
        help="libusb transport: USB idVendor (e.g. 0x05c6). Required "
             "for --transport libusb.",
    )
    parser.add_argument(
        "--usb-pid", type=_parse_int_arg, metavar="PID",
        help="libusb transport: USB idProduct (e.g. 0x90b6). Required "
             "for --transport libusb.",
    )
    parser.add_argument(
        "--usb-iface", type=_parse_int_arg, default=None, metavar="N",
        help="libusb transport: DIAG interface number. Default: "
             "auto-detect by probing candidate vendor interfaces with "
             "DIAG_VERNO_F, best-ranked first (M3100 = 3, WNC 81UMV91M21 = 4).",
    )
    parser.add_argument(
        "--usb-no-probe", action="store_true",
        help="libusb transport: skip the DIAG_VERNO_F probe and pick "
             "the interface from descriptor bits alone (the older behaviour). "
             "The probe costs one short round-trip per candidate; without it, "
             "protocol 0x30 is assumed to be DIAG — which is TRUE on the "
             "M3100/Foxconn shape and FALSE on chipset-vendor LE gadget "
             "compositions, where 0x30 is 'ipc' and DIAG is ff/ff/0xff. "
             "Prefer pinning --usb-iface/--usb-ep-in/--usb-ep-out over this.",
    )
    parser.add_argument(
        "--usb-ep-in", type=_parse_int_arg, default=None, metavar="EP",
        help="libusb transport: bulk IN endpoint address. Default: "
             "auto-detect from the DIAG interface (M3100 = 0x84).",
    )
    parser.add_argument(
        "--usb-ep-out", type=_parse_int_arg, default=None, metavar="EP",
        help="libusb transport: bulk OUT endpoint address. Default: "
             "auto-detect from the DIAG interface (M3100 = 0x02).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host for tcp/udp transport")
    parser.add_argument("--port", type=int, default=2500, help="Port for tcp/udp")
    parser.add_argument(
        "--udp-reorder-window", type=int, default=0, metavar="N",
        help="udp-listen only: enable a bounded reorder buffer of N "
             "DGE1 seqs. On reordering host paths (e.g. CFW-3212 eno1.45, where "
             "the on-wire stream is in order but the live socket reorders) "
             ", this resequences early-arrived datagrams instead of "
             "dropping them, recovering records that --transport pcap already "
             "sees. 0 (default) = no buffering (flat-LAN behavior). Try ~2048 "
             "on a heavy-reorder path; the window bounds both memory and "
             "delivery latency.",
    )
    parser.add_argument(
        "--pcap",
        nargs="+",
        metavar="PART",
        help="Path(s) to a pcap/pcapng capture of the diagbarf DGE1 UDP stream "
             "(for --transport pcap). Capture e.g. with "
             "`tcpdump -i <iface> -w diagbarf.pcap 'udp port 12399'`. Pass "
             "MULTIPLE ordered parts (the `<stem>.<NN>.pcapng[.zst]` master) "
             "to carve them into one .dlf streamed in order — one seq "
             "tracker spans the part boundaries, no merged pcap.",
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
        help="Rotate output file every N bytes (e.g. 100M, 1G). REQUIRES a '%%s' "
             "placeholder in -o (e.g. -o cap_%%s.hdlc) so each segment gets a "
             "unique name; without it every rotation overwrites the previous "
             "segment and diaggulp exits non-zero at startup. Rotation cuts "
             "at a chunk boundary, NOT an HDLC frame boundary, so the frame "
             "straddling each rotation is split across two segments — concatenate "
             "segments in timestamp order for offline decode (a per-segment read "
             "drops ~1 frame per boundary). Verified: raw output is complete "
             "(raw >= decode-live, which drops under load); no whole records are lost.",
    )
    parser.add_argument(
        "--rotate-interval", type=int,
        help="Rotate output file every N seconds. REQUIRES a '%%s' placeholder "
             "in -o (e.g. -o cap_%%s.hdlc) so each segment gets a unique name; "
             "without it every rotation overwrites the previous segment and "
             "diaggulp exits non-zero at startup.",
    )
    parser.add_argument(
        "--seconds", "--duration", type=_parse_positive_seconds,
        default=None, metavar="N",
        help="STOP the capture after ~N seconds and exit 0. This is a "
             "stop, not a rotation: --rotate-interval keeps rotating WITHIN "
             "the window. Replaces the 'timeout N python "
             "diaggulp.py …' idiom, whose exit 124 on the normal end of "
             "a timed sample makes every caller special-case a successful "
             "capture as a failure. Takes the same clean-exit path SIGTERM "
             "does, so --restore-f3-mask-on-exit and the post-capture anchor "
             "still fire. The timeout(1) wrapper keeps working unchanged.",
    )
    parser.add_argument(
        "--no-mask", action="store_true",
        help="Skip the LOG mask handshake only. F3, QSH trace/metrics and event "
             "arming still run (each is default-ON with its own --no-* flag); "
             "use --passive to arm nothing",
    )
    parser.add_argument(
        "--passive", action="store_true",
        help="Arm NOTHING: implies --no-mask and switches off F3, QSH trace + "
             "metrics and event arming, so the capture records what is already "
             "flowing (an as-found probe, or a read of another tool's arm). "
             "Read-only requests (VERNO anchors, DIAGID table) still run. An "
             "explicit arming flag alongside it is a usage error",
    )
    parser.add_argument(
        "--client-arms-mask", action="store_true",
        help="tcp-connect only: the listener we dial is a stock "
             "vendor diag_socket_log (e.g. `diag_socket_log -l -a <ip> -p "
             "<port>`; Netgear AirCard 791L DMoTCP on 192.168.1.1:5511), which "
             "is a bidirectional /dev/diag relay that arms NOTHING. Run the "
             "normal active session over it (log-mask handshake honoring "
             "--log-code, F3/event/QSH arming, anchor frames) instead of the "
             "default passive diagbarf-consumer mode, which captures 0 bytes "
             "against such a listener.",
    )
    parser.add_argument(
        "--broker-sub", type=_parse_broker_sub, default=None, metavar="JSON",
        help="tcp-connect only: the listener we dial is a diagbroker "
             "(apps/diagbroker). Send this SUB declaration, strip the "
             "broker's OK line, then capture its stream. The broker owns the "
             "mask, so --no-mask is forced. An archival capture usually wants "
             "'{\"floor\":\"max\",\"markers\":true}': every code armed while it "
             "runs, plus a marker frame (opcode 0xFB) at each mask change.",
    )
    parser.add_argument(
        "--log-code", action="append", default=None, metavar="0xXXXX",
        help="Subscribe to ONLY this DIAG log code instead of the default "
             "all-logs mask (repeatable). For a narrow-mask validation "
             "capture, pass the code under test plus any liveness canary, e.g. "
             "--log-code 0xB8D1 --log-code 0x1875. Hex (0x...) or decimal. "
             "Ignored under --no-mask.",
    )
    parser.add_argument(
        "--decode", action="append", default=None, type=_parse_int_arg,
        metavar="0xXXXX",
        help="LIVE DECODE: decode this log code inline as frames arrive "
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
        help="LIVE DECODE for EVERY LOG code seen (no per-code filter) — "
             "the broad form of --decode. Best paired with a narrow --log-code "
             "mask so it decodes a handful of codes, not 13k.",
    )
    parser.add_argument(
        "--decode-out", default=None, metavar="PATH",
        help="Write the live-decode JSONL here instead of stderr "
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
             "DEFAULT: ON — every capture should carry resolvable F3 so "
             "it can be F3-ground-truthed later. Pass --no-ext-msg-f3 to "
             "skip arming (e.g. to bound capture size on a chatty SDX72, where "
             "SET_ALL_RT_MASKS can emit ~660k 0x99 frames in 30s — a per-subsystem "
             "severity preset is a follow-up). The F3 mask is orthogonal "
             "to the binary log mask; both are raised. Decode with an F3 "
             "extractor / decoder.",
    )
    parser.add_argument(
        "--qsh-enable", action=argparse.BooleanOptionalAction, default=True,
        help="Globally enable QSH (Subsystem Health) metrics for the "
             "capture (0x9002 global enable). Adds the QSH-*metrics* "
             "flavor; NOTE this is NOT the 0x9D enabler (see --qsh-trace). "
             "DEFAULT: ON. Non-fatal: pre-SDX parts (MDM9607) return 0x13 BAD_CMD "
             "and are skipped cleanly. Pass --no-qsh-enable to skip (targeted "
             "captures / saturation control).",
    )
    parser.add_argument(
        "--qsh-trace", action=argparse.BooleanOptionalAction, default=True,
        help="Arm the QSH-*trace* stream — the actual 0x9D "
             "(DIAG_QSH_TRACE_PAYLOAD_F) enabler. Sends the 0x9001 "
             "maskset SET from --qsh-pairs-file, else --qsh-sweep, else "
             "--qsh-profile. Host-side validated on FN980/SDX55 "
             "(0x9D goes 0 -> ~1400/s). Distinct from --qsh-enable (0x9002 "
             "metrics). DEFAULT: ON. Non-fatal: "
             "SDX20 dispatches it but returns status 2 with no 0x9D; pre-QSH "
             "parts 0x13 BAD_CMD — both skipped cleanly. Pass --no-qsh-trace "
             "to skip (targeted captures / saturation).",
    )
    parser.add_argument(
        "--qsh-profile", default=QSH_TRACE_DEFAULT_PROFILE,
        choices=sorted(QSH_TRACE_PROFILES),
        help="Which named 0x9001 maskset to arm. DEFAULT: "
             f"{QSH_TRACE_DEFAULT_PROFILE!r}. "
             # argparse %-formats help; the prose may carry a literal '%'
             + _GOLDEN_PROFILE_HELP.replace("%", "%%")
             + "The measured-* profiles were measured on real modems and come "
             "with NO WARRANTY. 'measured-union' ORs every one of them "
             "(RM500Q-AE, T99W175, RM520N-GL, T99W640; SDX55/62/72) "
             "and reaches SSIDs above 110 that --qsh-sweep cannot; a maskset "
             "measured on your own modem (--qsh-pairs-file) fits it best. "
             "There is no 'gnss' profile: 0x9D carries no GNSS-engine "
             "trace, only GNSS on/off and RF power state on MPOWER bit 4 / RF "
             "bit 2, which golden lacks; arm those with qsh_trace_arm.py "
             "--gnss-state. WARNING the "
             "modem-side maskset is STICKY across DIAG session teardown, so a "
             "--no-qsh-trace run inherits the last arm. A new SET REPLACES the "
             "armed maskset rather than adding to it (measured on SDX55, "
             "SDX62 and SDX72). "
             "Ignored when --no-qsh-trace or with --qsh-pairs-file / --qsh-sweep.",
    )
    qsh_src = parser.add_mutually_exclusive_group()
    qsh_src.add_argument(
        "--qsh-pairs-file", metavar="PATH",
        help="Arm the 0x9001 maskset in PATH, a JSON {\"pairs\": [[ssid, level], "
             "...]} file (the format qsh_maskset_discover -o writes, measured "
             "on your own modem). Checked before any port opens: at most 110 "
             "pairs, ssid >= 1, strictly ascending ssid. Overrides "
             "--qsh-profile.",
    )
    qsh_src.add_argument(
        "--qsh-sweep", action="store_true",
        help="Arm every SSID 1..110 at every sub-stream bit. Vendor-free and "
             "model-independent: the modem ignores SSIDs it does not implement. "
             "Expect a higher 0x9D rate than a measured maskset (373/s on a "
             "T99W640). It cannot reach SSIDs above 110 (113 on an RM520N-GL, "
             "115/119 on a T99W640), which 'measured-union' arms. Overrides "
             "--qsh-profile.",
    )
    parser.add_argument(
        "--events-enable", action=argparse.BooleanOptionalAction, default=True,
        help="Enable the DIAG event-report (0x60) stream for the capture. "
             "Events are a distinct log flavor from log-code 0x10 records and F3 "
             "text — discrete state-transition markers (call drop, RRC state "
             "change, RACH outcome). DEFAULT: ON, mirroring the log/F3/QSH "
             "policy. Non-fatal: a part that rejects 0x60 is skipped cleanly. "
             "Pass --no-events-enable to skip (targeted captures / saturation).",
    )
    parser.add_argument(
        "--event-ids", default=None, metavar="ID[,ID...]",
        type=lambda s: [_parse_int_arg(x) for x in s.split(",") if x.strip()],
        help="Narrow the event stream to EXACTLY these event ids (hex or "
             "decimal, comma-separated) with DIAG_EVENT_MASK_SET_F 0x82 after "
             "the 0x60 on-switch. The mask width comes from this "
             "modem's 0x81 readback, and the result is verified by a second "
             "readback. Without this flag 0x60 arms every event id on most parts; "
             "where it leaves the mask EMPTY (MDM9625) every id is filled "
             "via 0x82 and verified. The readback is recorded in "
             "<output>.anchors.json (event_mask). "
             "Requires event reporting (incompatible with --no-events-enable). "
             "The narrowed mask is left armed until the next 0x60.",
    )
    parser.add_argument(
        "--ext-msg-f3-ss", action="append", default=None, metavar="SSID", type=_parse_int_arg,
        help="Arm F3 for ONLY this subsystem id (repeatable) via the bounded "
             "DIAG_EXT_MSG_CONFIG_F / SET_RT_MASK (sub_cmd 4), instead of the "
             "all-on SET_ALL_RT_MASKS. Bounds capture size on a chatty modem "
             "— e.g. arm just LTE/NR ML1 + search SSIDs. Hex (0x...) or "
             "decimal. Implies F3 arming and overrides --ext-msg-f3 / "
             "--no-ext-msg-f3. Severity floor set by --ext-msg-f3-level. "
             "Discover valid ss_ids on this firmware with --ext-msg-f3-list-ss. "
             "⚠️ SET_RT_MASK's wire form was CORRECTED: a missing "
             "2-byte field meant every bounded arm wrote garbage; it is "
             "now verified storing verbatim on MDM9607, but NOT yet confirmed to "
             "make F3 flow on SDX55.",
    )
    parser.add_argument(
        "--ext-msg-f3-preset", default=None, choices=sorted(_F3_PRESETS),
        help="Arm F3 for a curated, GROUNDED set of subsystem ids by name, "
             "instead of hand-listing --ext-msg-f3-ss. 'ml1' arms LTE/NR ML1 + "
             "search (ss_ids 1007/3001/9509/9520, read from the qdb and verified "
             "stable across SDX55/SDX62). Merges with any --ext-msg-f3-ss. Same "
             "bounded SET_RT_MASK path; severity via --ext-msg-f3-level. "
             "⚠️ SET_RT_MASK's wire form was CORRECTED: a missing "
             "2-byte field meant every bounded arm wrote garbage; it is "
             "now verified storing verbatim on MDM9607, but NOT yet confirmed to "
             "make F3 flow on SDX55.",
    )
    parser.add_argument(
        "--ext-msg-f3-level", default="all",
        choices=("low", "med", "high", "error", "fatal", "all"),
        help="Severity floor for F3 arming: arm the chosen chipset "
             "MSG_LVL_* level and every more-severe level. 'all' (default) = "
             "every level (0xFFFFFFFF, matching SET_ALL_RT_MASKS); 'high' = "
             "HIGH|ERROR|FATAL only (a quiet capture). Applies to BOTH the "
             "bounded --ext-msg-f3-ss path and the unbounded --ext-msg-f3 "
             "whole-device path; on the unbounded path it floors the "
             "SET_ALL_RT_MASKS level directly.",
    )
    parser.add_argument(
        "--ext-msg-f3-level-mask", default=None, metavar="MASK",
        type=_parse_int_arg,
        help="Arm an ARBITRARY 32-bit F3 runtime mask, overriding "
             "--ext-msg-f3-level. The named levels only move "
             "bits 0-4 (the chipset's MSG_LVL_*); on legacy-QSR parts the dominant "
             "plane does not live there. Measured on a live EG25-G/MDM9607: "
             "0x92 DIAG_QSR_EXT_MSG_TERSE_F is 86%% of frames and its masks "
             "sit on MSG_MASK_15/16/19/21/22 (bit 19 = 42.6%% alone), so "
             "'--ext-msg-f3-level error' cuts only 15%% of volume. Use e.g. "
             "0x00080000 to arm just that bit, 0x1F for the five named levels "
             "only, or 0 for commanded SILENCE. ⚠️ 0 is not the same as "
             "--no-ext-msg-f3: this SENDS a mask-0 SET_ALL_RT_MASKS, while "
             "--no-ext-msg-f3 sends nothing and leaves a previous run's mask "
             "armed. Hex (0x...) or decimal.",
    )
    parser.add_argument(
        "--disarm-logs-on-exit", action="store_true",
        help="On exit, clear the binary log mask (LOG_CONFIG op 0) and event "
             "reporting (0x60 00), then verify on the stream that 0x10 and 0x60 "
             "stopped. Both are modem-side sticky and have no GET, so "
             "they are cleared, not restored. Left armed, the port keeps "
             "streaming to nobody (~600 KB/s on a MiFi 6620L) and floods every "
             "later reader. Opt-in, like the two flags below; for a one-shot "
             "capture use all three.",
    )
    parser.add_argument(
        "--disarm-qsh-on-exit", action="store_true",
        help="On exit, disarm the QSH-trace 0x9001 maskset (empty count=0 SET) "
             "if THIS run armed it, then verify on the stream that 0x9D stopped "
             ". The maskset is modem-side sticky and has no GET, "
             "so it cannot be restored to a prior value, only cleared. Left "
             "armed, it floods every later reader of the port (2,700 0x9D "
             "frames/s on an RM500Q-AE). Opt-in, like --restore-f3-mask-on-exit: "
             "a capture meant to leave QSH armed for a following tap needs it "
             "left alone. Use the two together for a one-shot capture.",
    )
    parser.add_argument(
        "--restore-f3-mask-on-exit", action="store_true",
        help="On exit, put the modem's F3 runtime mask back to the value that "
             "was there BEFORE this run armed it, and verify by reading it back "
             ". The F3 runtime mask is a modem-side state change that "
             "OUTLIVES the DIAG session — it is sticky until the part "
             "re-enumerates — so a run that narrows it (or silences it with "
             "--ext-msg-f3-level-mask 0) leaves the next session looking at an "
             "empty F3 plane with no indication why. ⛔ Deliberately opt-in: a "
             "capture MEANT to leave the modem armed for a following passive tap "
             "would be broken by an automatic restore, silently. The pre-arm "
             "value is LOGGED on every arm regardless, which is the half that "
             "makes a later 'this build emits no F3 for subsystem X' "
             "distinguishable from an inherited narrow mask.",
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
    parser.add_argument(
        "--wait-ready", type=float, default=0.0, metavar="SECONDS",
        help="Serial only: open the port and probe DIAG_VERNO_F, reopening with "
             "backoff on a transport error or no reply, for up to SECONDS before "
             "the first real request (default 0 = off). For a capture started "
             "right after a modem (re)enumerates, where the tty exists before "
             "the DIAG function answers. A modem that never answers "
             "VERNO (LM960A18, telit-quirk path) cannot use it.",
    )
    quirk_group = parser.add_mutually_exclusive_group()
    quirk_group.add_argument(
        "--telit-quirk", dest="telit_quirk", action="store_const",
        const=True, default=None,
        help="Force the flush-on-OUT DIAG capture path for Telit/SDX20 modems "
             "(LM960A18). These modems deliver buffered DIAG only in response "
             "to host writes and deadlock on large mask writes, so the normal "
             "passive handshake+capture returns 0 bytes. This enables: "
             "a bounded backlog drain on open, pumped (chunked) mask writes, "
             "operation-field reply correlation, and periodic keep-alive kicks "
             "during capture. DEFAULT IS AUTO: the path turns itself on "
             "when the serial DIAG port's USB VID/PID is a known flush-on-OUT "
             "device, so this flag is only needed to force it on for an "
             "unrecognized unit. Serial transport only; harmless but pointless "
             "on other modems. The capture stream interleaves small 0x73 "
             "kick-reply frames, which downstream decoders skip.",
    )
    quirk_group.add_argument(
        "--no-telit-quirk", dest="telit_quirk", action="store_const", const=False,
        help="Force the flush-on-OUT quirk path OFF, overriding the VID "
             "auto-detect. Use if the auto-enabled path ever misbehaves on a "
             "recognized Telit unit and you want the legacy passive capture.",
    )
    parser.add_argument(
        "--chunk-size", type=_parse_size, default=READ_CHUNK,
        help="Read chunk size (default 64K)",
    )
    parser.add_argument(
        "--anchor-frame", choices=["none", "boundary"], default="boundary",
        help="Anchor-frame strategy for DLF↔host timestamp calibration. "
             "'boundary' (default) sends a DIAG_VERNO_F request immediately "
             "before and after the capture and writes a "
             "<output>.anchors.json sidecar consumed by "
             "diaggrok_at_correlate.py --auto-align. A modem that never "
             "answers DIAG_VERNO_F (e.g. the LM960A18 telit-quirk path) "
             "still gets a sidecar, with method=host_bracket — a coarser "
             "host-side boundary timestamp. 'none' disables anchor "
             "emission (original behavior) and leaves the capture with no "
             "DIAG↔host clock mapping at all.",
    )
    parser.add_argument(
        "--diag-id-binding", action=argparse.BooleanOptionalAction, default=True,
        help="Ask the modem for its QSHRINK4 diag_id binding table "
             "(0x4B/0x12/0x0222 DIAGNOSTIC_SERVICES_DIAGID_TABLE) right "
             "after the start anchor and record the raw reply in "
             "<output>.anchors.json, where diag_scan reads it into the "
             "diag_id_binding sidecar block. Default on. The table names the "
             "protection domains behind the diag_id channels (which qdb resolves "
             "which hashed F3/QSH messages); it is only ever emitted in answer "
             "to this request, so without it a host-tool capture never carries "
             "one. Parts below SDX55 answer 0x13 and that is recorded as a "
             "measured negative. Uses --anchor-timeout; disabled on passive "
             "transports and, like the anchors, needs --output.",
    )
    parser.add_argument(
        "--anchor-timeout", type=float, default=2.0,
        help="Timeout in seconds for each anchor-frame DIAG_VERNO_F "
             "round trip (default 2.0). On timeout that boundary degrades "
             "to a host-side bracket (method=host_bracket) rather than "
             "being dropped.",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress output",
    )
    parser.add_argument(
        "--enable-oemdre", action="store_true",
        help="Before the log-mask handshake, enable the vendor OEM DRE in the "
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
             "LOG_CONFIG with DIAG_BAD_CMD_F until unlocked. Reachable "
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
             "serial transport so every capture "
             "that has a reachable NMEA port also yields a GNSS transcript; pass "
             "this to opt out.",
    )
    parser.add_argument(
        "--nmea-baud", type=int, default=115200,
        help="Baud for the NMEA side-capture port (default 115200; correct for "
             "all known Telit/Quectel/Sierra/SIMCom USB NMEA interfaces).",
    )
    registry = _modem_registry()  # --operator-approved
    if registry is not None:
        registry.add_operator_approved_arg(parser)
    return parser


def _modem_registry():
    """The peer-modem guard module, or ``None`` where it does not ship.

    The guard lives beside this file in . The public diaggulp has no
    ``modem_registry`` and no notion of a peer host, so there it is skipped
    . Fail closed: if the file IS here but will not import, raise
    rather than run unguarded.
    """
    try:
        import modem_registry
    except ModuleNotFoundError as exc:
        if exc.name != "modem_registry" or \
                Path(__file__).with_name("modem_registry.py").exists():
            raise
        return None
    return modem_registry


_PASSIVE_TRANSPORTS = ("tcp-connect", "udp-listen")


def _clear_default_arms(args) -> None:
    """Switch off every arm that is NOT the log mask.

    F3 (the default-on arm and the bounded preset), QSH
    metrics (0x9002) and trace (0x9001), and event reporting (0x60 plus the
    event mask) are each default-ON and independent of ``--no-mask``. Shared by
    the passive transports and ``--passive`` so the two "arm nothing" paths
    clear the same list.
    """
    args.ext_msg_f3 = False
    args.ext_msg_f3_ss = None
    args.ext_msg_f3_preset = None
    args.ext_msg_f3_level_mask = None
    args.qsh_enable = False
    args.qsh_trace = False
    args.events_enable = False
    args.event_ids = None


#: Flags that ask for an arm, so they contradict ``--passive``.
_PASSIVE_CONFLICTS = (
    ("log_code", "--log-code"), ("ext_msg_f3_ss", "--ext-msg-f3-ss"),
    ("ext_msg_f3_preset", "--ext-msg-f3-preset"),
    ("ext_msg_f3_level_mask", "--ext-msg-f3-level-mask"),
    ("enable_oemdre", "--enable-oemdre"), ("client_arms_mask", "--client-arms-mask"),
)


def _apply_passive_flag(args) -> Optional[str]:
    """``--passive``: arm NOTHING, on any transport.

    ``--no-mask`` skips only the log mask; diaggulp still arms F3 all-levels,
    the QSH trace maskset, QSH metrics and the full event mask. Measured on an
    RM520N-GL (SDX62): a ``--no-mask`` read of a qlc-armed modem replaced
    qlc's arm, so 0x79 rose from 4 to 125 frames/s and 0x9D fell from 1,189 to
    345/s. A bare reader that sends nothing matched qlc. Read-only requests
    (VERNO anchors, the DIAGID table query) still run.

    Returns an error message when an arming flag contradicts it, else None.
    """
    if not getattr(args, "passive", False):
        return None
    clash = [flag for attr, flag in _PASSIVE_CONFLICTS if getattr(args, attr, None)]
    if clash:
        return f"--passive arms nothing, so it cannot be combined with {', '.join(clash)}"
    args.no_mask = True
    _clear_default_arms(args)
    return None


def _apply_passive_transport_policy(args) -> bool:
    """Force the passive-consumer settings when the transport owns no mask.

    The passive transports consume a stream the on-device daemon already
    armed; we cannot (and must not) run the mask handshake, and anchor frames
    need a writable command path the daemon ignores. Force both off so the
    common defaults don't stall waiting for responses.

    ``--client-arms-mask`` opts tcp-connect OUT of this: a stock
    vendor ``diag_socket_log -l`` (Netgear AirCard 791L DMoTCP, port 5511)
    is a bidirectional ``/dev/diag`` relay that arms NOTHING, so a passive
    consumer of it captures 0 bytes. With the flag the dial is an ordinary
    active session (mask handshake, F3, events, QSH, anchor) like serial.

    Returns True when the transport is being treated as passive.
    """
    if args.transport not in _PASSIVE_TRANSPORTS:
        return False
    if getattr(args, "client_arms_mask", False):
        return False
    if not args.no_mask and getattr(args, "broker_sub", None) is not None:
        # The peer is a diagbroker, not diagbarf, and --client-arms-mask
        # is a usage error with --broker-sub, so don't suggest it.
        print(
            "diaggulp: --broker-sub: the diagbroker owns the mask; "
            "forcing --no-mask",
            file=sys.stderr,
        )
        args.no_mask = True
    elif not args.no_mask:
        print(
            "diaggulp: --transport "
            f"{args.transport} is a passive consumer of the "
            "diagbarf stream; forcing --no-mask (daemon owns the mask). "
            "Dialing a stock vendor diag_socket_log (e.g. AirCard 791L "
            "port 5511), which arms nothing? Pass --client-arms-mask "
            "",
            file=sys.stderr,
        )
        args.no_mask = True
    # Passive diagbarf consumer: the daemon owns all mask state, so we arm
    # nothing (F3, QSH, events) either.
    _clear_default_arms(args)
    if args.anchor_frame != "none":
        args.anchor_frame = "none"
    # The DIAGID table is a request too; a passive consumer has no
    # command channel to send it on.
    args.diag_id_binding = False
    return True


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    # --passive is decided before any transport opens: a usage error must not
    # touch the device.
    passive_err = _apply_passive_flag(args)
    if passive_err:
        print(f"error: {passive_err}", file=sys.stderr)
        return 2
    # ⛔ In tcp-connect mode --host is the device we DIAL. If that is
    # ANOTHER host it is the `peer` tier: refuse it without an
    # operator grant, before anything touches the network.
    registry = _modem_registry()
    if args.transport == "tcp-connect" and registry is not None:
        registry.guard_peer_target(args.host, tool="diaggulp", grant=args.operator_approved)
    # (tcp / udp: --host is a local bind address, not a remote modem.)

    # ``-o -`` means stdout, not a file named ``-``. Normalize before
    # any ``if args.output:`` branch (disk preflight, output open, sidecars).
    args.output = _resolve_output_arg(args.output)
    if args.client_arms_mask and args.transport != "tcp-connect":
        parser.error("--client-arms-mask applies only to --transport "
                     "tcp-connect")
    if args.broker_sub is not None and args.transport != "tcp-connect":
        parser.error("--broker-sub applies only to --transport tcp-connect")
    if args.broker_sub is not None and args.client_arms_mask:
        parser.error("--broker-sub with --client-arms-mask: the broker owns the "
                     "mask, so a broker client never arms one")
    if args.event_ids and not args.events_enable:
        parser.error("--event-ids narrows the 0x60 event stream; it cannot be "
                     "combined with --no-events-enable")
    # A passive transport arms nothing (_apply_passive_transport_policy runs
    # after the transport opens); decide it here so an explicit maskset source
    # is refused, not silently dropped, and no arm notice prints for it.
    passive_transport = (args.transport in _PASSIVE_TRANSPORTS
                         and not getattr(args, "client_arms_mask", False))
    if (args.qsh_pairs_file or args.qsh_sweep) and (
            not args.qsh_trace or passive_transport):
        parser.error("--qsh-pairs-file / --qsh-sweep choose what --qsh-trace "
                     "arms, so they cannot be combined with --no-qsh-trace, "
                     "--passive, or a passive --transport without "
                     "--client-arms-mask")
    qsh_plan: Optional[QshTracePlan] = None
    if args.qsh_trace and not passive_transport:
        try:
            qsh_plan = _plan_qsh_trace(args)
        except (OSError, ValueError) as exc:
            parser.error(f"--qsh-pairs-file: {exc}")
        notice = _qsh_plan_notice(qsh_plan)
        if notice:
            print(notice, file=sys.stderr)

    # Fail fast — rotation writes one file per segment, so the output path
    # MUST carry a ``%s`` placeholder or every rotation overwrites the previous
    # segment (silently, with exit 0). Checked before the disk preflight and any
    # transport open, so a rejected invocation touches nothing.
    if (args.rotate_size or args.rotate_interval) and args.output \
            and "%s" not in args.output:
        print(
            f"error: --rotate-size / --rotate-interval need a '%s' timestamp "
            f"placeholder in -o so each rotated segment gets a unique name "
            f"(e.g. -o {args.output!r} -> "
            f"-o '{_suggest_rotate_template(args.output)}'). Without it every "
            f"rotation overwrites the previous segment and all but the last is "
            f"lost.",
            file=sys.stderr,
        )
        return 2

    # --- Disk-space preflight: a full disk wedges both the capture and the
    # syncthing corpus folder (the 1%-min-free guard stalls ALL sync, both
    # directions, fleet-wide). Refuse to START a capture below the floor so the operator
    # frees space first. Skipped for stdout (no -o) and offline pcap replay.
    #
    # The pcap exemption is load-bearing: a replay writes an output bounded by an input pcap that already fits
    # on the disk, so it cannot wedge anything — unlike a live capture, whose
    # length is bounded only by when the operator stops it. Enforcing the floor on
    # replay also made two unit tests of pcap parsing fail on any host under 5 %
    # free (they write to $TMPDIR), which reads as a code regression, not host
    # state. ---
    if (args.output and not args.no_disk_check and args.min_free_pct > 0
            and args.transport != "pcap"):
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
                f"stalls all sync fleet-wide). Free space first (e.g. prune "
                f"syncthing's .stversions history), or pass --min-free-pct / "
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

    # --- tmpfs capture-path guard: a RAM-backed output filesystem eats
    # the ~15 GiB OOM budget the host's memory-safety rule exists to protect, and
    # does it INVISIBLY — --min-free-pct passes (df reports a tmpfs as a normal
    # filesystem with free space) while every byte written sits in RAM. The agent
    # scratchpad is a tmpfs on some dev hosts, and it is exactly
    # where a capture "temporary file" naturally lands. This is a memory hazard,
    # not a disk one, so it fires independently of --no-disk-check/--min-free-pct;
    # a warning (not a refusal) keeps a deliberate small tmpfs capture possible.
    # Skipped for stdout (no -o). ---
    if args.output and not args.quiet:
        _fstype = _path_filesystem_type(
            os.path.dirname(os.path.abspath(args.output)) or ".")
        if _fstype in ("tmpfs", "ramfs"):
            _captures_root = os.environ.get("CHP_CAPTURES_ROOT")
            _write_to = (f"CAPTURES_ROOT ({_captures_root})" if _captures_root
                         else "a disk-backed directory")
            print(
                f"warning: capture output resolves onto a {_fstype} "
                f"(RAM-backed) filesystem at "
                f"{os.path.dirname(os.path.abspath(args.output)) or '.'} — every "
                f"byte written consumes RAM, not disk, against the host OOM "
                f"budget. --min-free-pct cannot see this (df reports a tmpfs as "
                f"free space). A long all-F3 capture is 1-4 MB/s and can reach "
                f"gigabytes. Write to {_write_to} instead, or "
                f"pass --quiet to silence this if the tmpfs capture is deliberate.",
                file=sys.stderr,
            )

    # --- Offline pcap replay: fully self-contained, no live device,
    # no mask handshake, no select loop. Handle it before any live transport
    # machinery and return. ---
    if args.transport == "pcap":
        _raw_argv = argv if argv is not None else sys.argv[1:]
        explicit_port = any(a == "--port" or a.startswith("--port=") for a in _raw_argv)
        return _run_pcap_transport(args, explicit_port)

    # --- Open the transport ---
    if args.transport == "serial":
        if not args.device:
            # macOS: auto-use a running qcseriald-darwin daemon's DIAG PTY when
            # no device was given. On Linux there is no such default, so
            # this only fires on darwin and only when a daemon is actually
            # bridging a modem — otherwise the original error stands.
            _qc = None
            try:
                from qcserial_darwin_ports import discover_on_macos
                _ports = discover_on_macos()
                _qc = _ports.diag_port() if _ports is not None else None
            except Exception:
                _qc = None
            if _qc:
                print(f"info: no device given; using qcseriald DIAG port {_qc} "
                      "(macOS qcseriald-darwin)", file=sys.stderr)
                args.device = _qc
            else:
                print("error: --transport=serial requires a device path "
                      "(no running qcseriald-darwin DIAG port found on macOS)",
                      file=sys.stderr)
                return 2
        if args.wait_ready > 0:
            client = _wait_diag_ready(
                lambda: DiagClient.from_serial(args.device, args.baud),
                args.wait_ready)
            if client is None:
                return 1
        else:
            client = DiagClient.from_serial(args.device, args.baud)
    elif args.transport == "tcp":
        client = DiagClient.from_tcp_server(args.host, args.port)
    elif args.transport == "udp":
        client = DiagClient.from_udp_broadcast(args.host, args.port)
    elif args.transport == "tcp-connect":
        # Dial a device that LISTENS (diagbarf TCP-listen sink).
        # With --broker-sub the far end is a diagbroker; subscribe first.
        try:
            if args.broker_sub is not None:
                client = DiagClient.from_tcp_client(args.host, args.port,
                                                    broker_sub=args.broker_sub)
            else:
                client = DiagClient.from_tcp_client(args.host, args.port)
        except BrokerError as exc:
            print(f"error: diagbroker {args.host}:{args.port}: {exc}", file=sys.stderr)
            return 2
    elif args.transport == "udp-listen":
        # Passively reassemble the DGE1-framed UDP stream.
        # Optional bounded reorder buffer for reordering host paths.
        client = DiagClient.from_udp_listen(
            args.host, args.port, reorder_window=args.udp_reorder_window)
    elif args.transport == "libusb":
        # Raw-USB-only DIAG (no ttyUSB/cdc-wdm node). Same active
        # command path as serial — the full mask handshake and F3 arm run
        # over the claimed bulk endpoints.
        if args.usb_vid is None or args.usb_pid is None:
            print("error: --transport=libusb requires --usb-vid and --usb-pid",
                  file=sys.stderr)
            return 2
        client = DiagClient.from_libusb(
            args.usb_vid, args.usb_pid,
            iface=args.usb_iface, ep_in=args.usb_ep_in, ep_out=args.usb_ep_out,
            probe=not args.usb_no_probe)
    else:
        print(f"error: unknown transport {args.transport}", file=sys.stderr)
        return 2

    passive = _apply_passive_transport_policy(args)

    # Terminate any stale partial frame in the modem's RX buffer before
    # the first request, on the transports that write straight to the device.
    if args.transport in ("serial", "libusb"):
        stale = _resync_frame_boundary(client)
        if stale:
            print(f"diaggulp: discarded {stale} stale frame(s) at open",
                  file=sys.stderr)

    # --- RETRIEVE-equivalent: enumerate the firmware's F3 SSID ranges and exit
    #. A simple query (no mask handshake / unlock needed), so we
    #     run it as early as the transport
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

    # --- Resolve the tri-state quirk switch by USB VID/PID auto-detect ---
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
                "(pass --no-telit-quirk to disable)",
                file=sys.stderr,
            )
        args.telit_quirk = bool(detected)

    # --- Telit/SDX20 flush-on-OUT setup ---
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
        # This firmware does not answer DIAG_VERNO_F, and the anchor used to
        # be simply dropped here — which is how the 1.87 GB LM960A18
        # wardrive capture ended up with no clock anchor at all. The boundary
        # anchor now stays enabled: it is retried over the pumped/kicked path
        # (_telit_version_anchor), and if the firmware still will not answer it
        # degrades to a host-side bracket rather than to nothing. See
        # _emit_boundary_anchor.
        #
        # Hardware-verified: on the LM960A18 / 32.01.1X0 the
        # pumped retry also comes back empty — zero opcode-0x00 frames in a
        # 1.02 M-frame capture — so this part always lands on host_bracket.
        # That is the expected steady state here, NOT a regression. Note the
        # muteness is opcode-specific, not transport-shaped: 0x9001 / 0x9002 /
        # 0x60 all answer a *plain* write+read on this same firmware.

    # --- SPC unlock: EG25/EC25 (MDM9607) gate LOG_CONFIG behind an SPC
    # unlock (opcode 0x46) and reject the mask handshake with DIAG_BAD_CMD_F
    # until unlocked. Must run before the handshake, on a writable command path
    # — so skip the passive consumers (tcp-connect/udp-listen own no
    # command channel).
    if args.spc:
        if passive:
            print(
                f"diaggulp: --spc ignored on passive transport {args.transport} "
                "(no writable command path)",
                file=sys.stderr,
            )
        elif _try_spc_unlock(client, args.spc):
            if not args.quiet:
                print("diaggulp: SPC unlock accepted", file=sys.stderr)
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
    # while the modem is still settling. Retry once after a short
    # sleep before falling back to the no-mask path — without retries, an
    # empty 0-byte capture is the most likely outcome of those scenarios.
    if not args.no_mask:
        # Narrow-mask when --log-code is given, else the all-logs mask.
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
                    # transaction isn't mis-correlated, then run the
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

    # --- Optionally enable the F3 ext-msg debug stream ---
    # Independent of the log mask: F3 messages are the firmware's free-text
    # subsystem trace, useful when the radio is off and the log stream is
    # silent. Non-fatal on failure — the log capture still proceeds.
    #
    # Three mutually-exclusive arming modes:
    #   --ext-msg-f3-ss <id>... / --ext-msg-f3-preset <name>
    #                            → bounded SET_RT_MASK, only those SSIDs
    #   --ext-msg-f3 (default)   → all-on SET_ALL_RT_MASKS, whole device
    #   --no-ext-msg-f3          → don't arm
    # A bounded ss list takes precedence over the all-on default/flag.
    # A named preset expands to its grounded ss_ids and merges with any -ss list.
    # --ext-msg-f3-level-mask supplies the mask directly, overriding the named
    # level on either path, and IMPLIES arming — so it can never combine with
    # --no-ext-msg-f3 into a silent no-op, the way --ext-msg-f3-ss
    # already implies arming.
    #
    # Decided ONCE into a plan, applied here and again on reconnect below. The
    # reconnect re-arm previously repeated this precedence by hand under a
    # "same precedence as above" comment — a shared plan makes the two the same
    # code, so a third arming variant cannot drift in.
    f3_plan = _plan_f3_arming(args)
    # The FIRST arm's pre-arm reading is the one worth restoring — a reconnect
    # re-arm would only ever read back this session's own mask.
    f3_pre_arm_mask = _apply_f3_arming(client, f3_plan)

    # Arm QSH last (additive; self-tolerant of unsupported parts).
    # Like the F3 pre-arm reading, only the FIRST arm decides the exit disarm.
    qsh_armed_here = False
    if args.qsh_trace:
        qsh_armed_here = _enable_qsh_trace(client, qsh_plan)  # 0x9D enabler
    if args.qsh_enable:
        _enable_qsh_metrics(client)    # the 0x9002 QSH-metrics flavor
    event_mask_record: Optional[dict] = None
    if args.events_enable:
        _enable_events(client)
        # After the LAST 0x60: the on-switch rewrites the whole mask.
        event_mask_record = _arm_event_mask(
            client, args.event_ids, telit_quirk=bool(args.telit_quirk))

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
    # `kill -TERM`: the select() loop bounds its block to <=1s and
    # catches KeyboardInterrupt, so the stop lands on the clean-exit path.
    def _sig_handler(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)
    # A dropped controlling shell (harness TaskStop) is a stop too, so it must
    # reach the disarming teardown rather than kill outright. A run
    # under nohup has SIGHUP ignored on purpose; leave that alone.
    if signal.getsignal(signal.SIGHUP) is not signal.SIG_IGN:
        signal.signal(signal.SIGHUP, _sig_handler)

    # --- Anchor-frame eligibility check ---
    # Anchors need a sidecar location, so stdout capture has none. A rotating
    # capture anchors every segment: VERNO at the run's two ends, and a
    # rotation_boundary anchor at each cut, which ends one segment and starts
    # the next. All segments share the modem's one DIAG time base.
    anchor_enabled = (
        args.anchor_frame == "boundary"
        and resolved_output_path is not None
    )
    if args.anchor_frame == "boundary" and not anchor_enabled:
        print(
            "warning: --anchor-frame=boundary requires --output (stdout "
            "capture has no sidecar location); skipping anchor emission",
            file=sys.stderr,
        )
    # Say it once, plainly, BEFORE a byte is banked. The three
    # branches above each explain their own cause, and --anchor-frame=none
    # explains nothing at all; none of them state the consequence. An operator
    # about to run a multi-GB wardrive leg should learn here — not at analysis
    # time — that this capture will have no DIAG↔host clock mapping.
    if not anchor_enabled:
        print(
            "warning: NO anchor sidecar will be written for this capture — "
            "there will be no DIAG↔host/UTC clock mapping, so downstream "
            "correlation (gpsd fixes, AT polls, other modems on the same "
            "drive) must infer the offset instead of reading it.",
            file=sys.stderr,
        )

    # --- Pre-capture anchor ---
    pre_anchor: Optional[dict] = None
    if anchor_enabled:
        pre_anchor = _emit_boundary_anchor(
            client, which="pre", timeout=args.anchor_timeout,
            telit_quirk=bool(args.telit_quirk), quiet=args.quiet,
        )

    # --- QSHRINK4 diag_id binding table request ---
    # Same eligibility as the anchors (a sidecar location is the only place
    # the reply can live — _send_recv consumes it before the writer sees it),
    # but independent of --anchor-frame: an operator who wants no clock anchor
    # still gets the PD table unless they say --no-diag-id-binding.
    binding_record: Optional[dict] = None
    if args.diag_id_binding and resolved_output_path is not None:
        binding_record = _request_diag_id_binding(
            client, timeout=args.anchor_timeout, quiet=args.quiet,
            telit_quirk=bool(args.telit_quirk),
        )

    # --- Keep-alive kick ---
    # Flush-on-OUT modems only deliver buffered LOG_F in response to host
    # writes; a tiny periodic RETRIEVE_RANGES OUT keeps the stream flowing.
    # None for every other modem -> the loops stay fully passive.
    kick_fn = None
    kick_interval = 0.3
    if args.telit_quirk:
        _kick_payload = _telit_kick_payload()
        kick_fn = lambda: client.send(_DIAG_LOG_CONFIG_F, _kick_payload)  # noqa: E731

    # --- Re-open on hard channel teardown ---
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
            # re-arm F3 from the SAME plan the initial arm used — shared code,
            # not a re-derivation, so the two can never diverge. warn_only=False
            # so a failed re-arm reaches slurp()'s re-open retry instead of
            # silently leaving the reconnected client unarmed.
            _apply_f3_arming(newc, f3_plan, warn_only=False)
            # re-arm QSH after reconnect (same additive policy)
            if args.qsh_trace:
                _enable_qsh_trace(newc, qsh_plan)  # the 0x9D enabler
            if args.qsh_enable:
                _enable_qsh_metrics(newc)
            if args.events_enable:
                _enable_events(newc)
                # The re-arm's 0x60 resets the mask to all-on, so re-apply any
                # narrowing and keep the first arm's record as the primary one.
                rearm = _arm_event_mask(
                    newc, args.event_ids, telit_quirk=bool(args.telit_quirk))
                if event_mask_record is not None:
                    event_mask_record.setdefault("rearms", []).append(rearm)
            client = newc
            return newc

    # --- NMEA side-capture (default-on, serial only, isolated, non-fatal) ---
    # Capture NMEA whenever diaggulp captures, so
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

    # --- Live decode side-thread ---
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
            from diagmunge.gsmtap import pcap_eligible_codes
            _pcap_out = Path(args.pcap_out)
            # Distinct names: ``writer`` is the rotating-capture writer.
            pcap_writer, nr_writer, _pcap_files, _pcap_nr_path = _open_outputs(_pcap_out)
            _pcap_sink = PcapSink(pcap_writer, nr_writer=nr_writer)
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

    # --- Per-segment anchor sidecars for a rotating capture ---
    # One {"path", "start"} per segment. A closed segment's sidecar is written
    # at the rotation, so a later kill -9 still leaves every closed segment
    # anchored; the open one is written at teardown with the post-anchor. The
    # run-level records (QSHRINK4 binding, event mask) go to segment 0 only.
    segments: list[dict] = []

    def _segment_sidecar_doc(index: int, start, end) -> "Optional[dict]":
        binding = binding_record if index == 0 else None
        events = event_mask_record if index == 0 else None
        if not ((anchor_enabled and (start is not None or end is not None))
                or binding is not None or events is not None):
            return None
        doc = _anchor_sidecar_doc(start if anchor_enabled else None,
                                  end if anchor_enabled else None,
                                  diag_id_binding=binding, event_mask=events)
        if writer is not None:
            seg = segments[index]
            doc["segment"] = {"index": index, "prev": seg.get("prev"),
                              "next": seg.get("next")}
        return doc

    if writer is not None:
        segments.append({"path": resolved_output_path, "start": pre_anchor})

        def _on_rotate(closed_path, new_path, mono_ns, unix_ns):
            boundary = _rotation_boundary_anchor(mono_ns, unix_ns)
            index = len(segments) - 1
            segments[index]["next"] = os.path.basename(new_path)
            doc = _segment_sidecar_doc(index, segments[index]["start"], boundary)
            if doc is not None:
                _write_anchor_sidecar(closed_path, doc, quiet=args.quiet)
            segments.append({"path": new_path, "start": boundary,
                             "prev": os.path.basename(closed_path)})

        writer.on_rotate = _on_rotate

    # --- The hot loop ---
    stop_info: dict = {}   # records WHY the capture loop stopped
    _deferred_signals: list[int] = []   # signals that arrived during teardown
    try:
        if writer is not None:
            # Rotating: must go through writer.write() so the rotation check
            # fires. A tested module-level function.
            bytes_written, elapsed = slurp_rotating(
                client, writer, args.chunk_size,
                kick_fn=kick_fn, kick_interval=kick_interval,
                tee_fn=tee_fn, max_seconds=args.seconds,
                stop_info=stop_info,
            )
        else:
            bytes_written, elapsed = slurp(
                client, out_fd, args.chunk_size,
                kick_fn=kick_fn, kick_interval=kick_interval,
                reconnect_fn=reconnect_fn, tee_fn=tee_fn,
                max_seconds=args.seconds,
                stop_info=stop_info,
            )
    finally:
        # The disarms below are the only thing standing between the modem and
        # a port streaming to nobody, so nothing may cut them short.
        _stderr_before_teardown = sys.stderr
        _handlers_before_teardown = _shield_teardown(_deferred_signals)
        # --- Stop live decode side-thread + close its sink ---
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

        # --- Post-capture anchor ---
        # Sent while the client is still open. Any log bytes consumed by
        # _send_recv during the response handshake are not written to the
        # output file — that's an acceptable few-ms loss at the tail of an
        # already-aborted capture.
        post_anchor: Optional[dict] = None
        if anchor_enabled:
            post_anchor = _emit_boundary_anchor(
                client, which="post", timeout=args.anchor_timeout,
                telit_quirk=bool(args.telit_quirk), quiet=args.quiet,
            )

        # --- Opt-in F3 runtime-mask restore ---
        # Sent while the client is still open, and deliberately NOT the default:
        # a capture meant to leave the modem armed for a following passive tap
        # would be broken by an automatic restore, silently. The pre-arm value
        # was logged unconditionally at arm time either way.
        if getattr(args, "restore_f3_mask_on_exit", False):
            if f3_pre_arm_mask is None:
                print(
                    "diaggulp: --restore-f3-mask-on-exit was requested but the "
                    "pre-arm F3 runtime mask was never read (no arm happened, or "
                    "the readback failed) — nothing to restore",
                    file=sys.stderr,
                )
            else:
                try:
                    restore_ext_msg_rt_mask(client, f3_pre_arm_mask)
                except Exception as exc:      # teardown must never raise
                    print(
                        f"diaggulp: ⚠️ F3 runtime-mask restore raised ({exc}); "
                        "the modem is left at the armed mask",
                        file=sys.stderr,
                    )

        # --- Opt-in QSH-trace disarm ---
        # Opt-in for the same reason as the F3 restore: a run meant to leave the
        # modem armed for a following passive tap must not be disarmed silently.
        if getattr(args, "disarm_qsh_on_exit", False):
            if not qsh_armed_here:
                print(
                    "diaggulp: --disarm-qsh-on-exit was requested but this run "
                    "did not arm QSH trace (--no-qsh-trace, a passive transport, "
                    "or a non-zero arm status) — leaving the maskset alone",
                    file=sys.stderr,
                )
            else:
                try:
                    _disarm_qsh_trace(client)
                except Exception as exc:      # teardown must never raise
                    print(
                        f"diaggulp: ⚠️ QSH-trace disarm raised ({exc}); the "
                        "maskset is left armed",
                        file=sys.stderr,
                    )

        # --- Opt-in log-mask + event-reporting disarm ---
        # Last, so the F3 / QSH windows above still see whatever they measure.
        # Opt-in for the same reason as both of those.
        if getattr(args, "disarm_logs_on_exit", False):
            if passive:
                print(
                    "diaggulp: --disarm-logs-on-exit ignored on passive transport "
                    f"{args.transport} (no writable command path)",
                    file=sys.stderr,
                )
            else:
                _disarm_logs_and_events(client, telit_quirk=bool(args.telit_quirk))

        if writer is not None:
            writer.close()
        elif args.output:
            try:
                os.close(out_fd)
            except OSError:
                pass
        # --- Write UDP gap sidecar (udp-listen) ---
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

        # --- Write anchor sidecar, one per segment ---
        # A rotating capture's closed segments were written at each rotation;
        # this writes the open (last) one, which ends at the post-anchor.
        if resolved_output_path is not None:
            if segments:
                last = len(segments) - 1
                final_path = segments[last]["path"]
                sidecar = _segment_sidecar_doc(last, segments[last]["start"], post_anchor)
            else:
                final_path = resolved_output_path
                sidecar = _segment_sidecar_doc(0, pre_anchor, post_anchor)
            if sidecar is not None:
                _write_anchor_sidecar(final_path, sidecar, quiet=args.quiet)

        if _deferred_signals:
            print(f"diaggulp: {len(_deferred_signals)} stop signal(s) arrived "
                  f"during teardown and were held until the disarms finished "
                  f"", file=sys.stderr)
        sys.stderr = _stderr_before_teardown
        for _sig, _handler in _handlers_before_teardown.items():
            signal.signal(_sig, _handler)

    if not args.quiet:
        rate = bytes_written / elapsed if elapsed > 0 else 0.0
        print(
            f"diaggulp: {bytes_written} bytes in {elapsed:.2f}s "
            f"({rate / 1024 / 1024:.2f} MB/s)",
            file=sys.stderr,
        )

    # --- Unexpected mid-capture transport EOF is NOT a clean stop ---
    code, alarm = _capture_exit(stop_info, bytes_written)
    if alarm:
        print(alarm, file=sys.stderr, flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())

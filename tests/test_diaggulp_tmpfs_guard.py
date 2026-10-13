"""diaggulp must warn when its capture output lands on a tmpfs.

A RAM-backed output filesystem eats the host's OOM budget, and does it
INVISIBLY: ``--min-free-pct`` passes (``df`` reports a tmpfs as an ordinary
filesystem with free space) while every captured byte sits in RAM. A scratch
directory is a tmpfs on many dev hosts (a tmpfs ``/tmp`` is common), and a
capture "temporary file" naturally lands there. A 1.48 GB capture was written
to one before anyone noticed.

``_path_filesystem_type`` is the detection primitive; these pin that it reads
the real mount table (so a genuinely tmpfs path is flagged and a disk path is
not) and degrades to ``None`` — not a crash, not a false positive — where the
mount table is unavailable.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


def _have_mountinfo() -> bool:
    return os.path.exists("/proc/self/mountinfo")


@pytest.mark.skipif(not _have_mountinfo(), reason="Linux /proc/self/mountinfo required")
def test_tmpfs_path_is_detected_as_tmpfs():
    # /dev/shm is a tmpfs on every mainstream Linux; /tmp often is but not
    # guaranteed, so anchor on /dev/shm when present.
    if os.path.isdir("/dev/shm"):
        assert d._path_filesystem_type("/dev/shm") in ("tmpfs", "ramfs")


@pytest.mark.skipif(not _have_mountinfo(), reason="Linux /proc/self/mountinfo required")
def test_disk_path_is_not_flagged_as_tmpfs():
    # The repo checkout lives on a real disk filesystem, never a tmpfs — so the
    # guard must not fire for a capture written next to the source tree.
    fstype = d._path_filesystem_type(str(Path(__file__).resolve().parent))
    assert fstype is not None
    assert fstype not in ("tmpfs", "ramfs")


@pytest.mark.skipif(not _have_mountinfo(), reason="Linux /proc/self/mountinfo required")
def test_longest_prefix_mount_wins():
    # A nested mount point must win over its parent: whatever backs /dev/shm is
    # resolved from the /dev/shm mount, not the / mount above it.
    if os.path.isdir("/dev/shm"):
        assert d._path_filesystem_type(os.path.join("/dev/shm", "some", "capture.bin")) in ("tmpfs", "ramfs")


def test_unresolvable_path_returns_none_not_crash(monkeypatch):
    # Where the mount table cannot be read (non-Linux, sandbox), the helper must
    # degrade to "unknown" so the guard silently no-ops rather than crashing a
    # capture at startup.
    def _boom(*a, **k):
        raise OSError("no /proc here")

    monkeypatch.setattr("builtins.open", _boom)
    assert d._path_filesystem_type("/anything") is None

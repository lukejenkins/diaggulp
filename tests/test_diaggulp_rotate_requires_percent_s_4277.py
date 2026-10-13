"""diaggulp rotation must not silently discard every segment but the last.

`diaggulp --rotate-size` / `--rotate-interval` with an `-o` path that
contains no `%s` re-opened the *same* path on every rotation and truncated it to
zero (``_open_output`` calls ``os.ftruncate(fd, 0)`` on the fixed-path branch), so
only the final segment survived on disk. The capture reported its full byte count
and exited 0 — the one number a caller would check to detect the loss (reported
bytes) is the one number that hid it.

There is no correct use of rotation without a unique-path template, so this is a
hard error, not a default (issue's preferred Option 1): the writer refuses to
construct, and the CLI fails fast at startup with a clear message.

Positive control: with `%s` in the path, every rotated segment is retained and
the summed segment bytes equal the bytes written (the invariant actually violated
by the bug).
"""
from __future__ import annotations

import glob
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


# --- the bug: rotation with no %s must be refused, not silently truncated ------
@pytest.mark.parametrize("kwargs", [
    {"rotate_size": 1000},
    {"rotate_interval": 5},
    {"rotate_size": 1000, "rotate_interval": 5},
])
def test_rotating_writer_without_percent_s_raises(tmp_path, kwargs):
    path = str(tmp_path / "rot.hdlc")  # no %s
    with pytest.raises(ValueError) as exc:
        d._RotatingWriter(path, **kwargs)
    assert "%s" in str(exc.value)
    # It must not have created (and later truncated) the fixed file.
    assert not os.path.exists(path)


def test_rotating_writer_with_percent_s_is_accepted(tmp_path):
    path = str(tmp_path / "rot_%s.hdlc")
    w = d._RotatingWriter(path, rotate_size=1000)
    try:
        assert w._fd >= 0
    finally:
        w.close()


def test_non_rotating_fixed_path_is_still_allowed(tmp_path):
    """A writer with NO rotation mode never rotates, so a fixed path is fine —
    the guard is scoped to rotation-enabled writers only."""
    path = str(tmp_path / "plain.hdlc")
    w = d._RotatingWriter(path)
    try:
        w.write(b"hello")
    finally:
        w.close()
    assert os.path.getsize(path) == 5


# --- positive control: %s rotation retains every byte -------------------------
def test_percent_s_rotation_retains_all_bytes(tmp_path):
    path = str(tmp_path / "rot_%s.hdlc")
    w = d._RotatingWriter(path, rotate_size=1000)
    written = 0
    chunk = b"x" * 100
    for _ in range(50):          # 5000 bytes => several size rotations
        w.write(chunk)
        written += len(chunk)
    w.close()
    segments = glob.glob(str(tmp_path / "rot_*.hdlc"))
    retained = sum(os.path.getsize(s) for s in segments)
    assert len(segments) >= 2, "size rotation should have produced multiple segments"
    assert retained == written, (
        f"retained {retained} != written {written} — segments were overwritten"
    )


# --- the CLI fails fast at startup (issue's Option 1 + acceptance) -------------
def test_cli_rejects_rotate_without_percent_s(tmp_path, capsys):
    out = str(tmp_path / "cap.hdlc")  # no %s
    rc = d.main(["/dev/null", "-o", out, "--rotate-interval", "5"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "%s" in err and "rotate" in err.lower()
    # fail BEFORE opening any transport / creating the output
    assert not os.path.exists(out)

"""Concurrent-writer protection on diaggulp capture files.

Before this, `_open_output` opened its capture `O_WRONLY|O_CREAT|O_TRUNC` with no
lock. Two diaggulp processes given the same `-o` path each held their own file
offset starting at 0, so they did not interleave — they mutually OVERWROTE. The
byte at any offset belonged to whichever writer wrote it last, the file size was
the max offset either reached rather than the sum written, and ~half of each
stream was destroyed. Two wardrives lost 45-49% this way.

`flock` is the fix rather than `O_EXCL` because it must not break the legitimate
re-run-overwrites-the-old-capture case, and because it is released automatically
when a writer dies — no stale lockfile to garbage-collect after a killed drive.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import pytest  # noqa: E402

from diaggulp import _open_output  # noqa: E402


def test_second_writer_on_the_same_path_is_refused(tmp_path):
    path = str(tmp_path / "quectel_rm520ngl_diag.hdlc")
    fd, resolved = _open_output(path)
    try:
        assert resolved == path
        with pytest.raises(SystemExit) as exc:
            _open_output(path)
        assert "refusing to share it" in str(exc.value)
    finally:
        os.close(fd)


def test_the_loser_does_not_truncate_the_winners_capture(tmp_path):
    """The ordering that matters: open WITHOUT O_TRUNC, claim the lock, and only
    then truncate. With O_TRUNC in the open flags the loser has already destroyed
    the winner's capture by the time flock tells it to back off — the refusal
    would be correct and the data still gone."""
    path = str(tmp_path / "capture.hdlc")
    fd, _ = _open_output(path)
    try:
        os.write(fd, b"\x7e" * 4096)
        os.fsync(fd)
        with pytest.raises(SystemExit):
            _open_output(path)
        assert os.path.getsize(path) == 4096
    finally:
        os.close(fd)


def test_lock_is_released_when_the_writer_closes(tmp_path):
    """A re-run must be able to overwrite a finished capture — that is why this
    is flock and not O_EXCL."""
    path = str(tmp_path / "capture.hdlc")
    fd, _ = _open_output(path)
    os.write(fd, b"stale-capture-bytes")
    os.close(fd)

    fd2, _ = _open_output(path)          # same path, previous writer gone
    try:
        assert os.path.getsize(path) == 0   # O_TRUNC semantics preserved
    finally:
        os.close(fd2)


def test_distinct_paths_are_both_writable(tmp_path):
    """The normal multi-modem drive: one capture file per unit, all concurrent."""
    fds = []
    try:
        for tag in ("quectel_rm520ngl_111111", "quectel_rm520ngl_222222",
                    "telit_lm960a18_333333"):
            fd, _ = _open_output(str(tmp_path / f"{tag}_diag.hdlc"))
            fds.append(fd)
        assert len(fds) == 3
    finally:
        for fd in fds:
            os.close(fd)


def test_timestamp_rotation_paths_are_also_locked(tmp_path):
    """The `%s` rotation branch already avoided same-name collisions via O_EXCL;
    it takes the lock too so every returned fd carries the same guarantee."""
    fd1, p1 = _open_output(str(tmp_path / "cap_%s.hdlc"))
    fd2, p2 = _open_output(str(tmp_path / "cap_%s.hdlc"))
    try:
        assert p1 != p2          # same wall-clock second, counter suffix applied
        with pytest.raises(SystemExit):
            _open_output(p1)     # ask for the exact rotated path back
    finally:
        os.close(fd1)
        os.close(fd2)

"""diaggulp grows a native ``--seconds`` / ``--duration`` stop.

Before this, the only way to time-bound a capture was
``timeout N diaggulp …`` — which exits **124** on the
*normal* end of a timed sample, so every programmatic caller had to special-case
"non-zero is fine here". A phase-2 planner emitted a ``--seconds`` command
that did not exist and it passed offline "verification" because only the JSON
*shape* was checked, never the command *string*; the modem rejected it the first
time it was actually executed.

⚠️ **Why both loops are exercised here.** ``diaggulp`` runs two structurally
different read loops: :func:`slurp` for the ordinary case, and — when
``--rotate-size`` / ``--rotate-interval`` is in play — a second loop that must go
through ``writer.write()`` so the rotation check fires. That second loop lived
inline in ``main()`` as a hand-copied "tiny version of slurp()", i.e. exactly the
shape where a new flag gets wired into one copy and silently not the other. A
``--seconds`` that the rotating path ignores does not fail loudly: it **hangs
until killed**, which is the old no-deadline behaviour wearing the new flag's name. So
the deadline is pinned as observed behaviour on *each* loop, and a source-reading
ratchet pins that ``main()`` still routes the rotating case through the tested
function rather than growing a third copy.

The transports below are real OS pipes, not mocks: ``slurp`` selects on a real
fd and calls a real ``read()``. A pipe whose write end is held open and never
written to is the honest stand-in for a **silent** modem — the case where the
deadline has to come from the loop's own clock, because no data will ever arrive
to carry it there.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from pathlib import Path

import pytest

# The test dir's parent holds diaggulp.py in-tree (tools/) and in the carve (root).
TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))

_SPEC = importlib.util.spec_from_file_location(
    "diaggulp_4270", str(TOOLS / "diaggulp.py")
)
diaggulp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diaggulp)


# ---------------------------------------------------------------------------
# Real-pipe transport doubles
# ---------------------------------------------------------------------------


class _PipeTransport:
    """The two methods ``slurp`` uses: ``fileno()`` and ``read(n)``."""

    def __init__(self, read_fd: int) -> None:
        self._fd = read_fd

    def fileno(self) -> int:
        return self._fd

    def read(self, n: int) -> bytes:
        return os.read(self._fd, n)


class _FakeClient:
    def __init__(self, read_fd: int) -> None:
        self._transport = _PipeTransport(read_fd)


class _RecordingWriter:
    """Stands in for the rotating writer: only ``write()`` is on the hot path."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def write(self, data: bytes) -> None:
        self.chunks.append(data)


def _run_bounded(fn, *, wall_limit: float):
    """Run ``fn`` on a thread and fail — rather than hang — if it overruns.

    A capture loop that ignores its deadline does not raise; it blocks forever.
    A test that simply calls it would hang the whole suite instead of reporting
    a failure, so the deadline is asserted from *outside* the loop as well.
    """
    box: dict = {}

    def _target():
        try:
            box["result"] = fn()
        except BaseException as exc:      # noqa: BLE001 — reported below
            box["error"] = exc

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(wall_limit)
    return t, box


# ---------------------------------------------------------------------------
# The flag itself
# ---------------------------------------------------------------------------


def test_the_parser_accepts_seconds():
    args = diaggulp.build_arg_parser().parse_args(
        ["/dev/ttyUSB0", "-o", "cap.bin", "--seconds", "30"]
    )
    assert args.seconds == pytest.approx(30.0)


def test_duration_is_an_alias_for_the_same_option():
    """``--duration`` and ``--seconds`` must land on ONE dest.

    Two dests would make ``--duration 30`` parse cleanly and then be ignored by
    a loop that only reads ``args.seconds`` — a silent no-op flag, which is the
    original failure mode with a different spelling.
    """
    args = diaggulp.build_arg_parser().parse_args(
        ["/dev/ttyUSB0", "-o", "cap.bin", "--duration", "30"]
    )
    assert args.seconds == pytest.approx(30.0)


def test_no_duration_leaves_the_capture_unbounded():
    args = diaggulp.build_arg_parser().parse_args(["/dev/ttyUSB0", "-o", "cap.bin"])
    assert args.seconds is None


@pytest.mark.parametrize("bad", ["0", "-5", "notanumber"])
def test_a_nonpositive_or_unparseable_duration_is_rejected_at_parse_time(bad, capsys):
    """``--seconds 0`` must not mean "capture nothing, exit 0" by accident.

    ⚠️ The message is asserted, not just the ``SystemExit``. An *unrecognised*
    option also raises ``SystemExit`` — so a bare ``pytest.raises`` here passes
    on a build that has no ``--seconds`` at all, which is the "test passes
    immediately, proving nothing" trap.
    """
    with pytest.raises(SystemExit):
        diaggulp.build_arg_parser().parse_args(
            ["/dev/ttyUSB0", "-o", "cap.bin", "--seconds", bad]
        )
    err = capsys.readouterr().err
    assert "unrecognized arguments" not in err, (
        "--seconds is not a known option — this test would pass on any build"
    )
    assert "--seconds" in err


def test_help_documents_the_flag_next_to_rotate_interval():
    """Discoverability IS the issue: ``--help`` showed rotation but no stop."""
    text = diaggulp.build_arg_parser().format_help()
    assert "--seconds" in text
    assert "--duration" in text


# ---------------------------------------------------------------------------
# Loop 1 — slurp(), the ordinary capture path
# ---------------------------------------------------------------------------


def test_slurp_stops_at_the_deadline_on_a_silent_transport(tmp_path):
    r, w = os.pipe()
    out_fd = os.open(tmp_path / "cap.bin", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        client = _FakeClient(r)
        t, box = _run_bounded(
            lambda: diaggulp.slurp(client, out_fd, max_seconds=0.4),
            wall_limit=5.0,
        )
        assert not t.is_alive(), (
            "slurp() ignored max_seconds and blocked on a silent transport"
        )
        assert "error" not in box, box.get("error")
        _bytes_written, elapsed = box["result"]
        assert elapsed == pytest.approx(0.4, abs=0.35)
    finally:
        os.close(w)
        os.close(r)
        os.close(out_fd)


def test_slurp_deadline_bounds_the_select_timeout(tmp_path):
    """A silent modem must not overshoot by a whole select() quantum.

    ``slurp`` blocks in ``select()`` for up to 1.0 s at a time. If the deadline
    is only checked *between* selects, a 0.2 s capture on a silent port runs
    ~1.0 s — five times what was asked for. Short samples are the entire use
    case (a planner arms, samples, disarms), so the timeout has to be clamped to
    whatever is left on the clock.
    """
    r, w = os.pipe()
    out_fd = os.open(tmp_path / "cap.bin", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        client = _FakeClient(r)
        started = time.monotonic()
        t, box = _run_bounded(
            lambda: diaggulp.slurp(client, out_fd, max_seconds=0.2),
            wall_limit=5.0,
        )
        assert not t.is_alive(), "slurp() overran its 0.2 s deadline"
        wall = time.monotonic() - started
        assert "error" not in box, box.get("error")
        assert wall < 0.9, f"deadline checked only between selects (wall={wall:.2f}s)"
    finally:
        os.close(w)
        os.close(r)
        os.close(out_fd)


def test_slurp_writes_the_bytes_that_arrived_before_the_deadline(tmp_path):
    """The stop is a stop, not a discard — a timed sample must keep its data."""
    r, w = os.pipe()
    cap = tmp_path / "cap.bin"
    out_fd = os.open(cap, os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.write(w, b"\x10\x00DIAGBYTES")
        client = _FakeClient(r)
        t, box = _run_bounded(
            lambda: diaggulp.slurp(client, out_fd, max_seconds=0.3),
            wall_limit=5.0,
        )
        assert not t.is_alive()
        assert "error" not in box, box.get("error")
        bytes_written, _elapsed = box["result"]
        assert bytes_written == len(b"\x10\x00DIAGBYTES")
    finally:
        os.close(w)
        os.close(r)
        os.close(out_fd)
    assert cap.read_bytes() == b"\x10\x00DIAGBYTES"


def test_slurp_without_a_deadline_still_stops_on_eof(tmp_path):
    """Default behaviour is untouched: no deadline ⇒ run until the port closes."""
    r, w = os.pipe()
    out_fd = os.open(tmp_path / "cap.bin", os.O_WRONLY | os.O_CREAT, 0o644)
    try:
        os.write(w, b"abc")
        os.close(w)
        client = _FakeClient(r)
        t, box = _run_bounded(
            lambda: diaggulp.slurp(client, out_fd), wall_limit=5.0
        )
        assert not t.is_alive()
        assert "error" not in box, box.get("error")
        bytes_written, _elapsed = box["result"]
        assert bytes_written == 3
    finally:
        os.close(r)
        os.close(out_fd)


# ---------------------------------------------------------------------------
# Loop 2 — the rotating path
# ---------------------------------------------------------------------------


def test_slurp_rotating_stops_at_the_deadline_on_a_silent_transport():
    r, w = os.pipe()
    try:
        client = _FakeClient(r)
        writer = _RecordingWriter()
        t, box = _run_bounded(
            lambda: diaggulp.slurp_rotating(client, writer, max_seconds=0.4),
            wall_limit=5.0,
        )
        assert not t.is_alive(), (
            "the rotating loop ignored max_seconds — a --seconds capture under "
            "--rotate-interval would hang until killed"
        )
        assert "error" not in box, box.get("error")
        _bytes_written, elapsed = box["result"]
        assert elapsed == pytest.approx(0.4, abs=0.35)
    finally:
        os.close(w)
        os.close(r)


def test_slurp_rotating_keeps_writing_through_the_writer_so_rotation_still_fires():
    """The deadline must not bypass ``writer.write()``.

    Rotation is driven by the writer counting bytes, so a deadline implemented
    by writing around the writer would silently disable ``--rotate-size`` /
    ``--rotate-interval`` for every timed capture.
    """
    r, w = os.pipe()
    try:
        os.write(w, b"ROTATE-ME")
        client = _FakeClient(r)
        writer = _RecordingWriter()
        t, box = _run_bounded(
            lambda: diaggulp.slurp_rotating(client, writer, max_seconds=0.3),
            wall_limit=5.0,
        )
        assert not t.is_alive()
        assert "error" not in box, box.get("error")
        bytes_written, _elapsed = box["result"]
        assert bytes_written == len(b"ROTATE-ME")
        assert b"".join(writer.chunks) == b"ROTATE-ME"
    finally:
        os.close(w)
        os.close(r)


def test_slurp_rotating_without_a_deadline_still_stops_on_eof():
    r, w = os.pipe()
    try:
        os.write(w, b"abc")
        os.close(w)
        client = _FakeClient(r)
        writer = _RecordingWriter()
        t, box = _run_bounded(
            lambda: diaggulp.slurp_rotating(client, writer), wall_limit=5.0
        )
        assert not t.is_alive()
        assert "error" not in box, box.get("error")
        bytes_written, _elapsed = box["result"]
        assert bytes_written == 3
    finally:
        os.close(r)


# ---------------------------------------------------------------------------
# Ratchet — main() must route both loops through the tested functions
# ---------------------------------------------------------------------------


def _main_capture_calls():
    """Every ``slurp`` / ``slurp_rotating`` call in ``main()``, as AST nodes."""
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(diaggulp.main)))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("slurp", "slurp_rotating")
    ]


def test_main_routes_the_rotating_capture_through_slurp_rotating():
    """A third hand-copied loop in ``main()`` would be untested by construction.

    This is the ratchet the bug asks for: the rotating branch existed only
    as inline source, so nothing could observe whether a new flag reached it.
    """
    called = {node.func.id for node in _main_capture_calls()}
    assert called == {"slurp", "slurp_rotating"}, (
        f"main() must drive both capture paths through the tested functions; "
        f"found calls to {sorted(called)}"
    )


def test_every_capture_call_in_main_is_handed_the_requested_duration():
    """BOTH call sites, checked individually — not "the string appears somewhere".

    ⚠️ Written because a mutation survived the earlier version of this test. That
    version asserted ``"max_seconds=args.seconds" in <source of main>``, so
    breaking *one* of the two call sites left the other one's occurrence to
    satisfy the check. Since the two loops are exactly what a ``--seconds``
    regression hides between, a whole-function substring search is the one shape
    of assertion that cannot see the bug it was written for.
    """
    import ast

    calls = _main_capture_calls()
    assert len(calls) == 2, f"expected 2 capture calls in main(), found {len(calls)}"
    for node in calls:
        kw = {k.arg: k.value for k in node.keywords}
        assert "max_seconds" in kw, (
            f"{node.func.id}() in main() is not given --seconds at all"
        )
        value = kw["max_seconds"]
        assert (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and value.value.id == "args"
            and value.attr == "seconds"
        ), (
            f"{node.func.id}() in main() must receive args.seconds, not "
            f"{ast.dump(value)} — a capture path that drops the duration hangs "
            f"until killed rather than failing"
        )

"""Tests for tools/diaggulp.py."""

import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Make tools/ importable + stub pyserial (imported lazily by the serial reader)
TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

# Mock pyserial so the import doesn't fail on hosts without it
sys.modules.setdefault("serial", MagicMock())

# Now import the module
import diaggulp  # noqa: E402


class _FakeSpcClient:
    """Records the SPC codes passed to unlock_spc and replies per `accept`."""

    def __init__(self, accept):
        self.calls = []
        self._accept = accept  # a code string that is accepted, or a callable

    def unlock_spc(self, spc):
        self.calls.append(spc)
        if callable(self._accept):
            return self._accept(spc)
        return spc == self._accept


class TestSpcUnlock:
    """#N — _try_spc_unlock orchestration over DiagClient.unlock_spc."""

    def test_auto_tries_vendor_list_in_order_until_accepted(self):
        # The Telit-form 0000 is accepted; auto must try 000000 first.
        client = _FakeSpcClient(accept="0000")
        assert diaggulp._try_spc_unlock(client, "auto") is True
        assert client.calls == ["000000", "0000"]

    def test_auto_first_code_accepted_short_circuits(self):
        client = _FakeSpcClient(accept="000000")
        assert diaggulp._try_spc_unlock(client, "auto") is True
        assert client.calls == ["000000"]  # any() stops at first True

    def test_auto_none_accepted_returns_false_and_tries_all(self):
        client = _FakeSpcClient(accept="deadbeef")  # nothing in the list matches
        assert diaggulp._try_spc_unlock(client, "auto") is False
        assert client.calls == ["000000", "0000"]

    def test_literal_code_is_tried_verbatim(self):
        client = _FakeSpcClient(accept="123456")
        assert diaggulp._try_spc_unlock(client, "123456") is True
        assert client.calls == ["123456"]

    def test_literal_code_rejected_returns_false(self):
        client = _FakeSpcClient(accept=lambda s: False)
        assert diaggulp._try_spc_unlock(client, "654321") is False
        assert client.calls == ["654321"]

    def test_spc_auto_list_matches_capture_tool(self):
        # Keep the vendor SPC list in sync with capture_dlf_from_diag.py.
        assert diaggulp._SPC_AUTO == ["000000", "0000"]


class TestParseSize:
    @pytest.mark.parametrize(
        "text,expected",
        [
            ("1024", 1024),
            ("1K", 1024),
            ("4K", 4096),
            ("1M", 1024 ** 2),
            ("100M", 100 * 1024 ** 2),
            ("1G", 1024 ** 3),
            ("2.5M", int(2.5 * 1024 ** 2)),
        ],
    )
    def test_valid_sizes(self, text, expected):
        assert diaggulp._parse_size(text) == expected

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            diaggulp._parse_size("")

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            diaggulp._parse_size("garbage")


class TestOpenOutput:
    def test_plain_path(self, tmp_path):
        path = str(tmp_path / "out.dlf")
        fd, resolved = diaggulp._open_output(path)
        try:
            assert os.path.isfile(path)
            assert resolved == path
        finally:
            os.close(fd)

    def test_timestamp_expansion(self, tmp_path):
        path_template = str(tmp_path / "out_%s.dlf")
        fd, _ = diaggulp._open_output(path_template)
        try:
            files = list(tmp_path.glob("out_*.dlf"))
            assert len(files) == 1
            # Filename should be out_<timestamp>.dlf with a 10-digit unix time
            name = files[0].name
            assert name.startswith("out_")
            assert name.endswith(".dlf")
            ts_part = name[4:-4]
            assert ts_part.isdigit()
            assert int(ts_part) > 1_700_000_000  # > Nov 2023
        finally:
            os.close(fd)


class TestRotatingWriter:
    def test_size_rotation(self, tmp_path):
        path = str(tmp_path / "rot_%s.dlf")
        # Tiny rotation threshold to force multiple rotations.
        # Writers with %s timestamp expansion at second granularity will
        # collide on rapid rotations within the same wall-clock second —
        # the LAST file written under a given timestamp wins. Sleep 1.1s
        # between writes so each rotation gets a unique filename.
        writer = diaggulp._RotatingWriter(path, rotate_size=100)
        try:
            writer.write(b"x" * 150)  # exceeds 100 → triggers rotation after this write
            time.sleep(1.1)
            writer.write(b"y" * 150)  # second rotation, second file
            time.sleep(1.1)
            writer.write(b"z" * 50)   # below threshold, fits in third file
        finally:
            writer.close()

        files = sorted(tmp_path.glob("rot_*.dlf"))
        # Expect at least 2 distinct files (the 1.1s sleep ensures unique
        # second-resolution timestamps)
        assert len(files) >= 2, f"expected ≥2 rotated files, got {[f.name for f in files]}"
        total = sum(f.stat().st_size for f in files)
        assert total == 350

    def test_no_rotation(self, tmp_path):
        path = str(tmp_path / "rot_norotate.dlf")
        writer = diaggulp._RotatingWriter(path)
        try:
            writer.write(b"a" * 1000)
        finally:
            writer.close()
        # Single file with all 1000 bytes
        assert (tmp_path / "rot_norotate.dlf").stat().st_size == 1000


class TestSlurpLoop:
    def test_slurp_writes_through(self, tmp_path):
        """Verify the slurp() function writes raw bytes to the output fd
        with NO transformation."""
        # Build a fake DiagClient with a fake transport
        fake_data = [b"abcd" * 100, b"efgh" * 50, b""]  # b"" → EOF
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = fake_data

        client = MagicMock()
        client._transport = fake_transport

        out_path = tmp_path / "out.bin"
        out_fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT, 0o644)

        # Mock select.select to immediately mark fd ready
        with patch("diaggulp.select.select", return_value=([-999], [], [])):
            try:
                bytes_written, elapsed = diaggulp.slurp(client, out_fd)
            finally:
                os.close(out_fd)

        # Sum of the non-empty fake_data entries
        assert bytes_written == 400 + 200
        assert out_path.read_bytes() == b"abcd" * 100 + b"efgh" * 50

    def test_slurp_handles_keyboard_interrupt(self, tmp_path):
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = KeyboardInterrupt
        client = MagicMock()
        client._transport = fake_transport

        out_path = tmp_path / "out2.bin"
        out_fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            with patch("diaggulp.select.select", return_value=([-999], [], [])):
                bytes_written, _ = diaggulp.slurp(client, out_fd)
        finally:
            os.close(out_fd)
        assert bytes_written == 0  # interrupted before any data

    def test_slurp_survives_transient_mhi_reset(self, tmp_path):
        """#N — a transient ERESTARTSYS(512)/EAGAIN reset mid-capture must be
        ridden out: the post-reset data still lands in one contiguous file."""
        import errno as _errno
        reset = OSError(512, "ERESTARTSYS")          # errno auto-set from arg0
        again = OSError(_errno.EAGAIN, "try again")
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        # two resets, then real data, then EOF
        fake_transport.read.side_effect = [reset, again, b"after-reset", b""]
        client = MagicMock()
        client._transport = fake_transport

        out_path = tmp_path / "reset.bin"
        out_fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT, 0o644)
        with patch("diaggulp.select.select", return_value=([-999], [], [])), \
                patch("diaggulp.time.sleep"):
            try:
                bytes_written, _ = diaggulp.slurp(client, out_fd)
            finally:
                os.close(out_fd)
        assert bytes_written == len(b"after-reset")
        assert out_path.read_bytes() == b"after-reset"

    def test_slurp_propagates_nontransient_oserror(self, tmp_path):
        """A genuinely broken fd (EBADF) is NOT a transient reset — must propagate."""
        import errno as _errno
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = OSError(_errno.EBADF, "bad fd")
        client = MagicMock()
        client._transport = fake_transport

        out_fd = os.open(str(tmp_path / "bad.bin"), os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            with patch("diaggulp.select.select", return_value=([-999], [], [])):
                with pytest.raises(OSError):
                    diaggulp.slurp(client, out_fd)
        finally:
            os.close(out_fd)

    def test_slurp_exits_when_reset_outlasts_ceiling(self, tmp_path):
        """A channel that stays in reset past MAX_RESET_SECONDS exits non-zero
        (raises) rather than spinning forever."""
        import itertools
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = OSError(512, "ERESTARTSYS")  # never recovers
        client = MagicMock()
        client._transport = fake_transport
        # clock advances 100 s per call → exceeds the 180 s ceiling within a few loops
        clock = itertools.count(0.0, 100.0)
        out_fd = os.open(str(tmp_path / "dead.bin"), os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            with patch("diaggulp.select.select", return_value=([-999], [], [])), \
                    patch("diaggulp.time.sleep"), \
                    patch("diaggulp.time.monotonic", side_effect=lambda: next(clock)):
                with pytest.raises(OSError):
                    diaggulp.slurp(client, out_fd)
        finally:
            os.close(out_fd)

    def test_slurp_reopens_channel_on_persistent_reset(self, tmp_path):
        """#N re-open gap: when a reset outlasts the same-fd ride-out
        (REOPEN_AFTER_SECONDS) and a reconnect_fn is supplied, slurp re-opens the
        channel (open()+re-arm) and capture resumes on the FRESH fd. Models the
        T99W640 hard MHI DIAG teardown where retrying the stale fd never recovers."""
        import itertools
        old_t = MagicMock()
        old_t.fileno.return_value = -999
        old_t.read.side_effect = OSError(512, "ERESTARTSYS")  # stale fd never recovers
        old_client = MagicMock()
        old_client._transport = old_t
        new_t = MagicMock()
        new_t.fileno.return_value = -888
        new_t.read.side_effect = [b"post-reopen", b""]
        new_client = MagicMock()
        new_client._transport = new_t
        reconnect_fn = MagicMock(return_value=new_client)
        # +2 s/call → crosses REOPEN_AFTER_SECONDS but not MAX_RESET_SECONDS
        clock = itertools.count(0.0, 2.0)
        out_path = tmp_path / "reopen.bin"
        out_fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT, 0o644)
        try:
            with patch("diaggulp.select.select", return_value=([1], [], [])), \
                    patch("diaggulp.time.sleep"), \
                    patch("diaggulp.time.monotonic", side_effect=lambda: next(clock)):
                bytes_written, _ = diaggulp.slurp(
                    old_client, out_fd, reconnect_fn=reconnect_fn)
        finally:
            os.close(out_fd)
        assert reconnect_fn.called, "reconnect_fn should fire on a persistent reset"
        assert out_path.read_bytes() == b"post-reopen"
        assert bytes_written == len(b"post-reopen")


class TestNarrowMaskBytes:
    """Pure narrow-mask builder for #N validation captures.

    16 log types; give the type under test a generous bitsize so item indices
    fit, and exercise the (equipment_id<<12 | item) decomposition + bit layout.
    """

    # bitsizes from a RETRIEVE_RANGES: type 0x1 and 0xB sized 0x1000 (4096),
    # type 0x0 empty, rest small. Index = log type.
    BITSIZES = (0, 0x1000, 256, 0, 0, 0, 0, 0, 0, 0, 0, 0x1000, 0, 0, 0, 0)

    def test_single_code_sets_exactly_one_bit(self):
        # 0xB8D1 -> type 0xB, item 0x8D1 = 2257; byte 2257//8=282, bit 2257%8=1.
        masks = diaggulp._narrow_mask_bytes(self.BITSIZES, [0xB8D1])
        assert set(masks) == {0xB}
        mask = masks[0xB]
        assert len(mask) == (0x1000 + 7) // 8  # full type width
        assert mask[282] == 0b10  # bit 1 set
        assert sum(bin(b).count("1") for b in mask) == 1  # exactly one bit total

    def test_multiple_codes_same_type_share_one_mask(self):
        # 0xB8D1 and 0xB885 both in type 0xB -> one mask, two bits set.
        masks = diaggulp._narrow_mask_bytes(self.BITSIZES, [0xB8D1, 0xB885])
        assert set(masks) == {0xB}
        assert sum(bin(b).count("1") for b in masks[0xB]) == 2

    def test_codes_in_different_types_split(self):
        # 0x1875 -> type 0x1, 0xB8D1 -> type 0xB: two separate masks.
        masks = diaggulp._narrow_mask_bytes(self.BITSIZES, [0x1875, 0xB8D1])
        assert set(masks) == {0x1, 0xB}
        for lt, mask in masks.items():
            assert sum(bin(b).count("1") for b in mask) == 1

    def test_dedups_repeated_codes(self):
        masks = diaggulp._narrow_mask_bytes(self.BITSIZES, [0xB8D1, 0xB8D1])
        assert sum(bin(b).count("1") for b in masks[0xB]) == 1

    def test_item_out_of_range_raises(self):
        # type 0x2 only advertises 256 items; item 0x900 is past the end.
        with pytest.raises(ValueError, match="out of range for log type 0x2"):
            diaggulp._narrow_mask_bytes(self.BITSIZES, [0x2900])

    def test_empty_log_type_raises(self):
        # type 0x0 has bitsize 0 -> no subscribable codes.
        with pytest.raises(ValueError, match="out of range for log type 0x0"):
            diaggulp._narrow_mask_bytes(self.BITSIZES, [0x0001])

    def test_equipment_id_beyond_16_types_raises(self):
        with pytest.raises(ValueError, match="outside the modem's"):
            diaggulp._narrow_mask_bytes(self.BITSIZES, [0x10000])


class TestAllLogsMaskBytes:
    """Pure all-bits-set mask builder shared by the default and telit-quirk
    all-logs handshakes (#N). A SET_MASK for a log type must carry a
    ceil(bitsize/8)-byte mask with every advertised item bit set and no
    out-of-range bits in the final byte."""

    def test_byte_aligned_bitsize_all_ones(self):
        mask = diaggulp._all_logs_mask_bytes(16)
        assert mask == b"\xff\xff"

    def test_single_bit(self):
        # bitsize 1 -> 1 byte, only bit 0 set.
        assert diaggulp._all_logs_mask_bytes(1) == b"\x01"

    def test_non_aligned_trims_final_byte(self):
        # bitsize 10 -> 2 bytes; last byte holds 2 valid bits (0b11).
        mask = diaggulp._all_logs_mask_bytes(10)
        assert len(mask) == 2
        assert mask[0] == 0xFF
        assert mask[1] == 0b11
        assert sum(bin(b).count("1") for b in mask) == 10

    def test_matches_legacy_inline_computation(self):
        # Byte-for-byte identical to the pre-refactor inline computation for
        # every real LM960 bitsize, so the refactor changes no wire bytes.
        for bitsize in (1, 511, 906, 1056, 1279, 2320, 2559, 3178):
            expected = bytes([0xFF] * ((bitsize + 7) // 8))
            if bitsize % 8 != 0:
                expected = expected[:-1] + bytes([0xFF >> (8 - (bitsize % 8))])
            assert diaggulp._all_logs_mask_bytes(bitsize) == expected


class TestTelitLogConfigReplyMatches:
    """Operation-field correlation for the telit-quirk handshake (#N).

    The shared _send_recv correlates only on the 1-byte opcode, but every
    DIAG_LOG_CONFIG_F sub-operation (RETRIEVE_RANGES=1, SET_MASK=3) shares
    opcode 0x73. On a flush-on-OUT modem a late reply for the *previous*
    operation aliases onto the current request. This predicate discriminates
    by the body operation u32 so the wrong reply is discarded, not bound."""

    from struct import pack as _pack
    RANGES_BODY = _pack("<3xII", 1, 0) + _pack("<16I", *([0] * 16))
    SETMASK_BODY = _pack("<3xII", 3, 0)

    def test_matches_correct_operation(self):
        assert diaggulp._telit_logconfig_reply_matches(115, self.RANGES_BODY, 1)
        assert diaggulp._telit_logconfig_reply_matches(115, self.SETMASK_BODY, 3)

    def test_rejects_aliased_operation(self):
        # A SET_MASK reply must NOT satisfy a RETRIEVE_RANGES wait, and vice versa.
        assert not diaggulp._telit_logconfig_reply_matches(115, self.SETMASK_BODY, 1)
        assert not diaggulp._telit_logconfig_reply_matches(115, self.RANGES_BODY, 3)

    def test_rejects_non_logconfig_opcode(self):
        # A LOG_F (0x10) push or any non-0x73 frame never matches.
        assert not diaggulp._telit_logconfig_reply_matches(0x10, self.SETMASK_BODY, 3)

    def test_rejects_truncated_body(self):
        assert not diaggulp._telit_logconfig_reply_matches(115, b"\x00\x00\x00", 1)


class TestSlurpKeepAlive:
    """slurp() keep-alive kicks (#N). On a flush-on-OUT modem the passive
    read loop must periodically write a tiny OUT or the modem never flushes
    buffered LOG_F records. The kick callback fires on the kick interval even
    when no data arrives, and data is still written through untouched."""

    def test_kick_fires_when_idle_then_data_flows(self, tmp_path):
        # Two ready cycles deliver data, then EOF. select always ready.
        fake_data = [b"\x7e\x10aa\x7e", b"\x7ebb\x7e", b""]
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = fake_data
        client = MagicMock()
        client._transport = fake_transport

        kicks = []
        out_path = tmp_path / "ka.bin"
        out_fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT, 0o644)
        # kick_interval 0 -> a kick is due on every loop iteration.
        with patch("diaggulp.select.select", return_value=([-999], [], [])):
            try:
                written, _ = diaggulp.slurp(
                    client, out_fd,
                    kick_fn=lambda: kicks.append(1), kick_interval=0.0,
                )
            finally:
                os.close(out_fd)

        assert written == len(fake_data[0]) + len(fake_data[1])
        assert out_path.read_bytes() == fake_data[0] + fake_data[1]
        assert len(kicks) >= 1  # at least one keep-alive kick was sent

    def test_kick_suppressed_while_data_flows(self, tmp_path):
        # Adaptive keep-alive: with a large interval and data arriving every
        # cycle, no kick should fire — the stream is already flowing, and
        # kicking a flooding (IN-full) modem would block its OUT endpoint.
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = [b"d" * 8, b"d" * 8, b"d" * 8, b""]
        client = MagicMock()
        client._transport = fake_transport
        kicks = []
        out_fd = os.open(str(tmp_path / "flow.bin"), os.O_WRONLY | os.O_CREAT, 0o644)
        with patch("diaggulp.select.select", return_value=([-999], [], [])):
            try:
                diaggulp.slurp(
                    client, out_fd,
                    kick_fn=lambda: kicks.append(1), kick_interval=10.0,
                )
            finally:
                os.close(out_fd)
        assert kicks == []  # data kept arriving -> next_kick perpetually deferred

    def test_kick_write_failure_is_tolerated(self, tmp_path):
        # A kick that raises OSError (SerialTimeoutException subclasses it when
        # the flooding modem won't accept the OUT) must NOT crash the capture.
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = [b"x" * 4, b""]
        client = MagicMock()
        client._transport = fake_transport

        def boom():
            raise OSError("Write timeout")

        out_path = tmp_path / "tol.bin"
        out_fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT, 0o644)
        with patch("diaggulp.select.select", return_value=([-999], [], [])):
            try:
                written, _ = diaggulp.slurp(
                    client, out_fd, kick_fn=boom, kick_interval=0.0,
                )
            finally:
                os.close(out_fd)
        assert written == 4  # data still captured despite kick failures
        assert out_path.read_bytes() == b"x" * 4

    def test_no_kick_fn_is_passive(self, tmp_path):
        # Default (no kick_fn) must not attempt any write — unchanged behavior.
        fake_transport = MagicMock()
        fake_transport.fileno.return_value = -999
        fake_transport.read.side_effect = [b"x" * 10, b""]
        client = MagicMock()
        client._transport = fake_transport
        out_fd = os.open(str(tmp_path / "p.bin"), os.O_WRONLY | os.O_CREAT, 0o644)
        with patch("diaggulp.select.select", return_value=([-999], [], [])):
            try:
                written, _ = diaggulp.slurp(client, out_fd)
            finally:
                os.close(out_fd)
        assert written == 10
        client.send.assert_not_called()


class TestFlushOnOutQuirkMatch:
    """Pure (vid, pid) allow-list match for the #N VID auto-detect."""

    def test_known_telit_lm960_matches(self):
        # The one unit the quirk is live-validated against (#N).
        label = diaggulp._match_flush_on_out_quirk(0x1BC7, 0x1041)
        assert label == "Telit LM960A18 (1bc7:1041)"

    def test_unknown_pid_same_vid_does_not_match(self):
        # A curated (vid,pid) list — NOT VID-only. A different Telit PID must
        # not inherit the quirk's overhead just because the vendor matches.
        assert diaggulp._match_flush_on_out_quirk(0x1BC7, 0x9999) is None

    def test_unknown_vendor_does_not_match(self):
        # Quectel RM520N (2c7c:0801) is not flush-on-OUT.
        assert diaggulp._match_flush_on_out_quirk(0x2C7C, 0x0801) is None

    def test_none_ids_return_none(self):
        assert diaggulp._match_flush_on_out_quirk(None, None) is None
        assert diaggulp._match_flush_on_out_quirk(0x1BC7, None) is None
        assert diaggulp._match_flush_on_out_quirk(None, 0x1041) is None


class TestDetectFlushOnOutQuirk:
    """_detect_flush_on_out_quirk composes the sysfs id lookup with the match.

    The sysfs walk itself (_usb_ids_for_tty) is I/O against /sys and is
    live-validated on the connected LM960; here we mock it to test the
    composition + label propagation in isolation.
    """

    def test_detect_returns_label_for_known_ids(self, monkeypatch):
        monkeypatch.setattr(diaggulp, "_usb_ids_for_tty", lambda p: (0x1BC7, 0x1041))
        assert (
            diaggulp._detect_flush_on_out_quirk("/dev/ttyUSB0")
            == "Telit LM960A18 (1bc7:1041)"
        )

    def test_detect_returns_none_for_unknown_ids(self, monkeypatch):
        monkeypatch.setattr(diaggulp, "_usb_ids_for_tty", lambda p: (0x2C7C, 0x0801))
        assert diaggulp._detect_flush_on_out_quirk("/dev/ttyUSB0") is None

    def test_detect_returns_none_when_ids_unresolvable(self, monkeypatch):
        # Virtual port / no /sys / non-USB tty -> no ids -> no quirk.
        monkeypatch.setattr(diaggulp, "_usb_ids_for_tty", lambda p: None)
        assert diaggulp._detect_flush_on_out_quirk("/dev/ttyUSB0") is None

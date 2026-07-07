"""Tests for diaggulp's NMEA side-capture (the NMEA section of tools/diaggulp.py).

Pure-logic + mocked-sysfs only; no hardware, no pyserial required.
"""
import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
# diaggulp's serial reader imports pyserial lazily — stub it so the import
# succeeds headless (mirrors tests/test_diaggulp.py).
sys.modules.setdefault("serial", MagicMock())

import pytest
from diaggulp import (
    NmeaSidecar,
    format_nmea_line,
    nmea_output_path,
    resolve_sibling_nmea_port,
)


# --- output path derivation ---------------------------------------------


# NB: fixtures deliberately avoid a `<dir>/<name>.bin|.hdlc` literal — that path
# shape is what a leaked capture artifact looks like, so the public-carve PII
# scanner rejects it in source. Coverage is preserved without it: the
# extensionless `/x/capture` case proves directory passthrough, and the
# basename cases prove `.bin` / `.hdlc` stripping — the function treats the
# directory prefix and the suffix independently.
@pytest.mark.parametrize("inp,expected", [
    ("diag_capture.bin", "diag_capture.nmea"),   # .bin stripped
    ("cap.hdlc", "cap.nmea"),                     # .hdlc stripped
    ("/x/capture", "/x/capture.nmea"),            # directory prefix preserved
    (None, None),
])
def test_nmea_output_path(inp, expected):
    assert nmea_output_path(inp) == expected


# --- line timestamp format ----------------------------------------------


def test_format_nmea_line_prefixes_utc():
    ts = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    line = format_nmea_line("$GPGGA,...", ts=ts)
    assert line == "2026-06-19T12:00:00+00:00 $GPGGA,..."


def test_format_nmea_line_default_ts_is_utc():
    line = format_nmea_line("$GPRMC,x")
    assert line.endswith("$GPRMC,x")
    assert "+00:00" in line  # tz-aware UTC


# --- sibling NMEA port resolution (mocked sysfs) ------------------------


def _build_sysfs(root, tty, vendor, diag_intf, sibling_intfs):
    """Create a fake /sys tree: a USB device with several interface dirs,
    each holding a ttyUSBN child. Returns nothing; mutates `root`.
    """
    usb_dev = os.path.join(root, "devices", "usb1", "1-1")
    os.makedirs(usb_dev, exist_ok=True)
    with open(os.path.join(usb_dev, "idVendor"), "w") as fh:
        fh.write(vendor + "\n")
    # interface dirs: "1-1:1.<intf>" each with a ttyUSB child
    all_intfs = {diag_intf: tty, **sibling_intfs}
    intf_dirs = {}
    for intf, ttyname in all_intfs.items():
        d = os.path.join(usb_dev, f"1-1:1.{intf}")
        os.makedirs(os.path.join(d, ttyname), exist_ok=True)
        intf_dirs[intf] = d
    # /sys/class/tty/<tty>/device -> the diag interface dir
    tty_class = os.path.join(root, "class", "tty", tty)
    os.makedirs(tty_class, exist_ok=True)
    os.symlink(intf_dirs[diag_intf], os.path.join(tty_class, "device"))


def test_resolve_quectel_sibling(tmp_path):
    root = str(tmp_path)
    # Quectel: diag=if0, nmea=if1, at=if2
    _build_sysfs(root, "ttyUSB0", "2c7c", diag_intf=0,
                 sibling_intfs={1: "ttyUSB1", 2: "ttyUSB2"})
    got = resolve_sibling_nmea_port("/dev/ttyUSB0", sysfs_root=root)
    assert got == "/dev/ttyUSB1"


def test_resolve_unknown_vendor_returns_none(tmp_path):
    root = str(tmp_path)
    _build_sysfs(root, "ttyUSB0", "dead", diag_intf=0,
                 sibling_intfs={1: "ttyUSB1"})
    assert resolve_sibling_nmea_port("/dev/ttyUSB0", sysfs_root=root) is None


def test_resolve_missing_sibling_returns_none(tmp_path):
    root = str(tmp_path)
    # Quectel vendor but no interface 1 present
    _build_sysfs(root, "ttyUSB0", "2c7c", diag_intf=0,
                 sibling_intfs={2: "ttyUSB2"})
    assert resolve_sibling_nmea_port("/dev/ttyUSB0", sysfs_root=root) is None


def test_resolve_non_dev_path_returns_none():
    assert resolve_sibling_nmea_port("tcp://host:2500") is None
    assert resolve_sibling_nmea_port(None) is None


# --- sidecar non-fatal open failure -------------------------------------


def test_sidecar_open_failure_is_non_fatal(tmp_path, monkeypatch):
    # Inject a `serial` module whose Serial() raises, so the test is hermetic
    # regardless of whether real pyserial (or another test's MagicMock stub) is
    # present in sys.modules. The point under test: an open failure is caught,
    # start() returns False, and no thread is launched — never a raise.
    import types
    fake = types.ModuleType("serial")

    def _boom(*a, **k):
        raise OSError("no such device")

    fake.Serial = _boom
    monkeypatch.setitem(sys.modules, "serial", fake)

    sc = NmeaSidecar("/dev/whatever", str(tmp_path / "x.nmea"), quiet=True)
    ok = sc.start()
    assert ok is False
    assert sc.error is not None
    assert sc._thread is None

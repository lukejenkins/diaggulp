"""diaggulp ``-o -`` must mean stdout, not a file literally named ``-`` (#N).

The #N LV55 runbook and #N's own usage document the pipe path
``diaggulp ... -o - | diag_tail.py --tee ...``. But ``_open_output`` ran
``os.open("-", O_CREAT|O_TRUNC)``, creating a 1.2 MB regular file named ``-``
in the cwd while the downstream pipe saw zero bytes (EOF immediately). Caught
live on the bench LV55 (cfw-3212) during #N/#N hardware validation — the
offline tee tests fed ``diag_tail`` from files, so they never exercised the
real ``diaggulp -o -`` producer.

``-`` is the universal CLI convention for stdout; normalize it (and the
empty/None no-``-o`` case) to the stdout sentinel so every ``if args.output:``
branch routes to ``sys.stdout.buffer`` instead of a file.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402


def test_dash_resolves_to_stdout_sentinel():
    # "-" is stdout, represented by the None sentinel the main path already
    # uses for "no -o given".
    assert d._resolve_output_arg("-") is None


def test_empty_and_none_resolve_to_stdout_sentinel():
    assert d._resolve_output_arg(None) is None
    assert d._resolve_output_arg("") is None


def test_real_path_passes_through_unchanged():
    assert d._resolve_output_arg("/<redacted-pii>") == "/<redacted-pii>"
    # A path that merely contains a dash is NOT stdout.
    assert d._resolve_output_arg("cap-2026.bin") == "cap-2026.bin"
    assert d._resolve_output_arg("./-foo") == "./-foo"

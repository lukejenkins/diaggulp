"""diaggulp's vendor-free QSH-trace maskset sources.

``--qsh-pairs-file`` arms a user's own ``{"pairs": [...]}`` file, ``--qsh-sweep``
arms every SSID 1..110, and a build without ``diagmunge.qsh_golden`` (the
public carve) defaults to the bundled T99W640 ``retail`` maskset. Synthetic
pairs only: no vendor-derived values appear here, so this file ships public.
"""

import importlib.util
import json
import os
import subprocess
import sys

import pytest

TOOLS = os.path.join(os.path.dirname(__file__), "..")
REPO = os.path.join(TOOLS, "..")
sys.path.insert(0, REPO)
sys.path.insert(0, TOOLS)

from diagmunge.diag_cmd import build_qsh_trace_maskset_set  # noqa: E402
from diagmunge.qsh_maskset import bundled_maskset, sweep_pairs  # noqa: E402

_SPEC = importlib.util.spec_from_file_location(
    "diaggulp_5608", os.path.join(TOOLS, "diaggulp.py"))
diaggulp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(diaggulp)

PAIRS = [[6, 0x0110], [61, 1], [119, 2]]


class _Client:
    def __init__(self):
        self.sent = []

    def _send_recv(self, op, payload, timeout=5.0):
        self.sent.append(bytes([op]) + payload)
        return (0x4B, bytes.fromhex("440190") + (0).to_bytes(4, "little"))


def _pairs_file(tmp_path, doc):
    f = tmp_path / "mine.json"
    f.write_text(doc if isinstance(doc, str) else json.dumps(doc))
    return str(f)


def _plan(*argv):
    return diaggulp._plan_qsh_trace(diaggulp.build_arg_parser().parse_args(list(argv)))


def test_pairs_file_arm_round_trips_through_the_encoder(tmp_path):
    plan = _plan("--qsh-pairs-file", _pairs_file(tmp_path, {"pairs": PAIRS}))
    assert plan.source == "pairs-file" and plan.pairs == tuple(map(tuple, PAIRS))
    c = _Client()
    assert diaggulp._enable_qsh_trace(c, plan) is True
    assert c.sent == [build_qsh_trace_maskset_set(tuple(map(tuple, PAIRS)))]


def test_pairs_file_overrides_qsh_profile(tmp_path):
    f = _pairs_file(tmp_path, {"pairs": PAIRS})
    plan = _plan("--qsh-profile", diaggulp.QSH_TRACE_DEFAULT_PROFILE, "--qsh-pairs-file", f)
    assert plan.source == "pairs-file"


def test_sweep_arms_every_ssid_1_to_110_at_every_bit():
    plan = _plan("--qsh-sweep")
    assert plan.pairs == sweep_pairs(range(1, 111))
    assert plan.pairs[0] == (1, 0xFFFF) and plan.pairs[-1] == (110, 0xFFFF)
    c = _Client()
    assert diaggulp._enable_qsh_trace(c, plan) is True
    assert c.sent == [build_qsh_trace_maskset_set(plan.pairs)]


def test_bundled_profiles_are_armable_in_every_build():
    plan = _plan("--qsh-profile", "measured-t99w640-retail")
    assert plan.pairs == bundled_maskset("t99w640-retail")
    assert _plan("--qsh-profile", "measured-t99w640-engineering-sample").pairs == \
        bundled_maskset("t99w640-engineering-sample")
    notice = diaggulp._qsh_plan_notice(plan)
    assert "T99W640" in notice and "NO WARRANTY" in notice
    assert "--qsh-pairs-file" in notice and "--qsh-sweep" in notice


def test_pairs_file_and_sweep_are_mutually_exclusive(tmp_path):
    f = _pairs_file(tmp_path, {"pairs": PAIRS})
    with pytest.raises(SystemExit) as e:
        diaggulp.build_arg_parser().parse_args(["--qsh-pairs-file", f, "--qsh-sweep"])
    assert e.value.code == 2


@pytest.mark.parametrize("doc, why", [
    ({"pairs": [[61, 1], [6, 272]]}, "strictly ascending"),
    ({"pairs": [[0, 1]]}, "ssid"),
    ({"pairs": []}, "disarm"),
    ("not json", "not JSON"),
])
def test_bad_pairs_file_is_a_usage_error_before_any_port_opens(tmp_path, capsys, doc, why):
    f = _pairs_file(tmp_path, doc)
    with pytest.raises(SystemExit) as e:
        diaggulp.main(["--qsh-pairs-file", f, "/dev/null-no-such-port"])
    assert e.value.code == 2
    assert why in capsys.readouterr().err


def test_missing_pairs_file_is_a_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        diaggulp.main(["--qsh-pairs-file", str(tmp_path / "absent.json")])
    assert e.value.code == 2
    assert "--qsh-pairs-file" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--qsh-sweep", "--qsh-pairs-file"])
def test_a_maskset_source_contradicts_no_qsh_trace(tmp_path, capsys, flag):
    argv = [flag] + ([_pairs_file(tmp_path, {"pairs": PAIRS})] if flag.endswith("file") else [])
    with pytest.raises(SystemExit) as e:
        diaggulp.main(argv + ["--no-qsh-trace"])
    assert e.value.code == 2
    assert "--no-qsh-trace" in capsys.readouterr().err


# A build without qsh_golden: block the module so `import` raises
# ModuleNotFoundError(name="diagmunge.qsh_golden"), exactly as the public
# diagmunge would.
_PUBLIC = """
import sys, importlib.util
sys.modules["diagmunge.qsh_golden"] = None
sys.path[:0] = [{tools!r}, {repo!r}]
spec = importlib.util.spec_from_file_location("dg", {path!r})
dg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dg)
from diagmunge.diag_cmd import build_qsh_trace_maskset_set
from diagmunge.qsh_maskset import union_maskset
{body}
"""


def _run_public(body):
    code = _PUBLIC.format(tools=TOOLS, repo=REPO,
                          path=os.path.join(TOOLS, "diaggulp.py"), body=body)
    return subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True, timeout=120)


def test_public_build_defaults_qsh_trace_on_with_the_measured_union():
    r = _run_public(
        "assert dg.QSH_GOLDEN_AVAILABLE is False\n"
        "a = dg.build_arg_parser().parse_args([])\n"
        "assert a.qsh_trace is True, a.qsh_trace\n"
        "assert a.qsh_profile == 'measured-union', a.qsh_profile\n"
        "assert sorted(dg.QSH_TRACE_PROFILES) == ['measured-rm500q-ae', "
        "'measured-rm520n-gl', 'measured-t99w175', "
        "'measured-t99w640-engineering-sample', 'measured-t99w640-retail', "
        "'measured-union'], "
        "sorted(dg.QSH_TRACE_PROFILES)\n"
        "print('OK')")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "OK"


def test_public_build_default_arm_is_exactly_the_union_maskset():
    r = _run_public(
        "class C:\n"
        "    sent = []\n"
        "    def _send_recv(self, op, payload, timeout=5.0):\n"
        "        self.sent.append(bytes([op]) + payload)\n"
        "        return (0x4B, bytes.fromhex('440190') + bytes(4))\n"
        "c = C()\n"
        "plan = dg._plan_qsh_trace(dg.build_arg_parser().parse_args([]))\n"
        "assert plan.pairs == union_maskset(), plan\n"
        "assert dg._enable_qsh_trace(c, plan) is True\n"
        "assert c.sent == [build_qsh_trace_maskset_set(union_maskset())], c.sent\n"
        "c.sent.clear()\n"
        "assert dg._enable_qsh_trace(c) is True\n"
        "assert c.sent == [build_qsh_trace_maskset_set(union_maskset())], c.sent\n"
        "n = dg._qsh_plan_notice(plan)\n"
        "assert 'NO WARRANTY' in n and 'RM520N-GL' in n and 'T99W640' in n, n\n"
        "print('OK')")
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "OK"


# The peer-modem guard (modem_registry) is not shipped with the public
# diaggulp. A copy of diaggulp.py with no modem_registry.py beside it must
# still build its parser; one WITH the guard file beside it must fail closed.
_NO_REGISTRY = """
import sys, importlib.util
sys.modules["modem_registry"] = None
sys.path[:0] = [{repo!r}]
spec = importlib.util.spec_from_file_location("dg", {path!r})
dg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dg)
a = dg.build_arg_parser().parse_args(["--qsh-sweep"])
print("PARSED", a.qsh_sweep)
"""


def test_diaggulp_runs_without_the_peer_guard_when_it_is_not_shipped(tmp_path):
    lone = tmp_path / "diaggulp.py"
    lone.write_bytes(open(os.path.join(TOOLS, "diaggulp.py"), "rb").read())
    r = subprocess.run(
        [sys.executable, "-c", _NO_REGISTRY.format(repo=REPO, path=str(lone))],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "PARSED True"


def test_a_shipped_but_unimportable_peer_guard_fails_closed():
    if not os.path.exists(os.path.join(TOOLS, "modem_registry.py")):
        pytest.skip("this tree does not ship the peer guard")
    r = subprocess.run(
        [sys.executable, "-c", _NO_REGISTRY.format(
            repo=REPO, path=os.path.join(TOOLS, "diaggulp.py"))],
        capture_output=True, text=True, timeout=120)
    assert r.returncode != 0
    assert "modem_registry" in r.stderr


@pytest.mark.parametrize("extra", [["--passive"], ["--transport", "udp-listen"]])
def test_a_maskset_source_on_a_run_that_arms_nothing_is_refused(capsys, extra):
    with pytest.raises(SystemExit) as e:
        diaggulp.main(["--qsh-sweep"] + extra)
    assert e.value.code == 2
    assert "--qsh-sweep" in capsys.readouterr().err

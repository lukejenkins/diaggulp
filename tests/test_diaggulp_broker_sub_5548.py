"""diaggulp ``--broker-sub``: a diagbroker client over tcp-connect.

diagbroker wants ``SUB {json}`` within 2 s and replies ``OK {json}``
before the raw HDLC. ``--broker-sub`` sends the declaration through
``DiagClient.from_tcp_client(broker_sub=...)``; the broker owns the mask, so the
passive tcp-connect policy (``--no-mask``) applies unchanged.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import diaggulp as d  # noqa: E402
from diagmunge.transport import BrokerError  # noqa: E402


def _args(*argv: str):
    return d.build_arg_parser().parse_args(list(argv))


def test_declaration_is_parsed_and_named():
    a = _args("--transport", "tcp-connect", "--host", "127.0.0.1",
              "--broker-sub", '{"floor":"max","markers":true}')
    assert a.broker_sub == {"name": "diaggulp", "floor": "max", "markers": True}


def test_an_explicit_name_is_kept():
    a = _args("--transport", "tcp-connect", "--broker-sub", '{"name":"arch","floor":"max"}')
    assert a.broker_sub["name"] == "arch"


@pytest.mark.parametrize("bad", ["not json", "[1,2]", '"max"'])
def test_a_non_object_declaration_is_a_usage_error(bad, capsys):
    with pytest.raises(SystemExit) as exc:
        _args("--transport", "tcp-connect", "--broker-sub", bad)
    assert exc.value.code == 2
    assert "--broker-sub" in capsys.readouterr().err


def test_the_passive_policy_still_forces_no_mask():
    a = _args("--transport", "tcp-connect", "--host", "127.0.0.1",
              "--broker-sub", '{"floor":"max"}')
    assert d._apply_passive_transport_policy(a) is True
    assert a.no_mask is True and a.ext_msg_f3 is False and a.events_enable is False


def test_the_passive_notice_names_the_broker_not_diagbarf(capsys):
    """Under --broker-sub the notice must not call the peer diagbarf or
    suggest --client-arms-mask, which is a usage error with --broker-sub."""
    a = _args("--transport", "tcp-connect", "--host", "127.0.0.1",
              "--broker-sub", '{"floor":"max"}')
    d._apply_passive_transport_policy(a)
    err = capsys.readouterr().err
    assert "diagbroker" in err
    assert "--client-arms-mask" not in err
    assert "diagbarf" not in err


class _Opened(Exception):
    pass


@pytest.mark.parametrize("transport", ["serial", "udp-listen", "tcp"])
def test_rejected_off_tcp_connect(transport, capsys, monkeypatch):
    def _boom(*a, **kw):
        raise _Opened(transport)
    for factory in ("from_serial", "from_udp_listen", "from_tcp_server", "from_tcp_client"):
        monkeypatch.setattr(d.DiagClient, factory, _boom)
    argv = ["--transport", transport, "--broker-sub", '{"floor":"max"}']
    if transport == "serial":
        argv.insert(0, "/dev/null")
    with pytest.raises(SystemExit) as exc:
        d.main(argv)
    assert exc.value.code == 2
    assert "--broker-sub applies only to --transport tcp-connect" in capsys.readouterr().err


def test_rejected_with_client_arms_mask(capsys, monkeypatch):
    monkeypatch.setattr(d.DiagClient, "from_tcp_client",
                        lambda *a, **kw: (_ for _ in ()).throw(_Opened()))
    with pytest.raises(SystemExit) as exc:
        d.main(["--transport", "tcp-connect", "--host", "127.0.0.1",
                "--client-arms-mask", "--broker-sub", '{"floor":"max"}'])
    assert exc.value.code == 2
    assert "the broker owns the mask" in capsys.readouterr().err


def test_main_hands_the_declaration_to_the_transport(monkeypatch, tmp_path):
    seen = {}

    def fake(host, port, broker_sub=None):
        seen.update(host=host, port=port, broker_sub=broker_sub)
        raise _Opened()
    monkeypatch.setattr(d.DiagClient, "from_tcp_client", fake)
    with pytest.raises(_Opened):
        d.main(["--transport", "tcp-connect", "--host", "127.0.0.1", "--port", "2700",
                "--broker-sub", '{"floor":"max"}', "-o", str(tmp_path / "x.bin"),
                "--no-disk-check"])
    assert seen == {"host": "127.0.0.1", "port": 2700,
                    "broker_sub": {"name": "diaggulp", "floor": "max"}}


def test_a_refused_subscription_exits_2_with_the_reason(monkeypatch, capsys, tmp_path):
    def fake(host, port, broker_sub=None):
        raise BrokerError("broker refused the subscription: unknown preset 'x'")
    monkeypatch.setattr(d.DiagClient, "from_tcp_client", fake)
    rc = d.main(["--transport", "tcp-connect", "--host", "127.0.0.1", "--port", "2700",
                 "--broker-sub", '{"floor":"x"}', "-o", str(tmp_path / "x.bin"),
                 "--no-disk-check"])
    assert rc == 2
    assert "unknown preset" in capsys.readouterr().err

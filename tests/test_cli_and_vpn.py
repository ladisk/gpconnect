"""Tests for argument parsing and the openconnect command construction."""

from __future__ import annotations

import subprocess

import pytest

from gpconnect.cli import parse_args
from gpconnect.tls import Tls
from gpconnect.vpn import check_cookie, elevation_prefix, run_openconnect, status_message

AUTH = {"username": "u@example.org", "prelogin_cookie": "COOKIE", "portal_userauthcookie": ""}
TLS = Tls("deadbeef", "/tmp/ca.pem")


def test_shared_flags_work_after_the_subcommand():
    args = parse_args(["connect", "vpn.example.org", "--webview"])
    assert args.portal == "vpn.example.org"
    assert args.webview is True


def test_shared_flags_work_before_the_subcommand():
    args = parse_args(["--webview", "connect", "vpn.example.org"])
    assert args.webview is True


def test_extra_openconnect_args_are_passed_through():
    args = parse_args(["connect", "vpn.example.org", "--", "-v"])
    assert args.openconnect_args == ["-v"]


def test_defaults_are_applied_when_flags_are_absent():
    args = parse_args(["connect", "vpn.example.org"])
    assert (args.webview, args.timeout, args.elevate) == (False, 300.0, "auto")
    assert args.insecure is False and args.servercert is None


def test_unknown_subcommand_is_rejected():
    with pytest.raises(SystemExit):
        parse_args(["nope"])


def test_elevation_none_is_empty():
    assert elevation_prefix("none") == []


def test_elevation_explicit_pkexec():
    assert elevation_prefix("pkexec") == ["pkexec"]


@pytest.fixture
def spawn(monkeypatch):
    """Run run_openconnect without spawning anything; capture argv and stdin."""
    recorded: dict = {}

    class FakeStdin:
        def write(self, data):
            recorded["stdin"] = data

        def close(self):
            pass

    class FakeProc:
        stdin = FakeStdin()
        stdout = iter(["ESP session established with server\n"])

        def wait(self):
            return 0

    def fake_popen(argv, **_kwargs):
        recorded["argv"] = argv
        return FakeProc()

    monkeypatch.setattr("gpconnect.vpn.find_openconnect", lambda: "/usr/sbin/openconnect")
    monkeypatch.setattr("gpconnect.vpn.subprocess.Popen", fake_popen)

    def run(auth=AUTH, gateway=None, extra=None):
        run_openconnect("vpn.example.org", auth, TLS, gateway, extra or [], elevate="none")
        return recorded

    return run


def test_portal_scope_and_pinned_certificate(spawn):
    rec = spawn()
    assert rec["argv"][-1] == "vpn.example.org"
    assert "--usergroup=portal:prelogin-cookie" in rec["argv"]
    assert "--servercert=sha256:deadbeef" in rec["argv"]
    assert "--cafile=/tmp/ca.pem" in rec["argv"]
    # the cookie is fed through stdin, never as an argument
    assert rec["stdin"] == "COOKIE\n"
    assert not any("COOKIE" in arg for arg in rec["argv"])


def test_gateway_scope(spawn):
    rec = spawn(gateway="gw.example.org")
    assert rec["argv"][-1] == "gw.example.org"
    assert "--usergroup=gateway:prelogin-cookie" in rec["argv"]


def test_portal_userauthcookie_enters_at_the_gateway(spawn):
    """The portal refuses this cookie with HTTP 512; only the gateway takes it."""
    auth = {"username": "u", "prelogin_cookie": "", "portal_userauthcookie": "PORTAL"}
    rec = spawn(auth=auth)
    assert "--usergroup=gateway:portal-userauthcookie" in rec["argv"]
    assert "--usergroup=portal:portal-userauthcookie" not in rec["argv"]
    assert rec["stdin"] == "PORTAL\n"


def test_prelogin_cookie_still_enters_at_the_portal(spawn):
    rec = spawn()
    assert "--usergroup=portal:prelogin-cookie" in rec["argv"]


def test_extra_arguments_precede_the_host(spawn):
    rec = spawn(extra=["-v"])
    assert rec["argv"][-2:] == ["-v", "vpn.example.org"]


@pytest.fixture
def authenticate_only(monkeypatch):
    """Stand in for `openconnect --authenticate` with a given exit code and output."""
    recorded: dict = {}

    def install(returncode=0, output=""):
        def fake_run(argv, **kwargs):
            recorded["argv"], recorded["input"] = argv, kwargs.get("input")
            return subprocess.CompletedProcess(argv, returncode, "", output)

        monkeypatch.setattr("gpconnect.vpn.find_openconnect", lambda: "/usr/sbin/openconnect")
        monkeypatch.setattr("gpconnect.vpn.subprocess.run", fake_run)
        return recorded

    return install


SAVED = {"username": "u@example.org", "prelogin_cookie": "",
         "portal_userauthcookie": "SAVED"}


def test_cookie_check_needs_no_root_and_no_tunnel(authenticate_only):
    recorded = authenticate_only(returncode=0)
    assert check_cookie("vpn.example.org", SAVED, TLS, None) is True
    assert recorded["argv"][0] == "/usr/sbin/openconnect"   # no sudo/pkexec in front
    assert "--authenticate" in recorded["argv"]
    assert "--usergroup=gateway:portal-userauthcookie" in recorded["argv"]
    assert recorded["input"] == "SAVED\n"


def test_cookie_check_recognises_a_refusal(authenticate_only):
    authenticate_only(returncode=1, output="User input required in non-interactive mode\n"
                                           "Failed to complete authentication\n")
    assert check_cookie("vpn.example.org", SAVED, TLS, None) is False


def test_cookie_check_is_undecided_without_network(authenticate_only):
    authenticate_only(returncode=1, output="Failed to connect to host vpn.example.org\n"
                                           "Failed to complete authentication\n")
    assert check_cookie("vpn.example.org", SAVED, TLS, None) is None


def test_esp_ready_is_reported_with_the_wait():
    msg = status_message("ESP session established with server", 3.4)
    assert msg == "tunnel ready over ESP after 3 s"


def test_https_fallback_is_reported_in_minutes():
    msg = status_message("Failed to connect ESP tunnel; using HTTPS instead.", 135)
    assert msg.startswith("tunnel ready over HTTPS after 2 min 15 s")


def test_ordinary_lines_are_not_reported():
    assert status_message("Got CONNECT response: HTTP/1.1 200 OK", 1) is None


def run_with_output(monkeypatch, lines):
    """Feed openconnect output lines through run_openconnect; return the status lines logged."""
    class FakeProc:
        class stdin:
            write = close = staticmethod(lambda *_: None)
        stdout = iter(line + "\n" for line in lines)
        wait = staticmethod(lambda: 0)

    logged: list[str] = []
    monkeypatch.setattr("gpconnect.vpn.find_openconnect", lambda: "/usr/sbin/openconnect")
    monkeypatch.setattr("gpconnect.vpn.subprocess.Popen", lambda *_a, **_k: FakeProc())
    monkeypatch.setattr("gpconnect.vpn.log", logged.append)
    run_openconnect("vpn.example.org", AUTH, TLS, None, [], elevate="none")
    return [m for m in logged if m.startswith(("connected to", "tunnel ready", "link lost"))]


HTTPS_UP = "Connected to HTTPS on vpn.example.org with ciphersuite (TLS1.2)-(ECDHE)"


def test_hip_check_after_ready_does_not_report_waiting(monkeypatch):
    status = run_with_output(monkeypatch, [
        HTTPS_UP,
        "ESP session established with server",
        "GlobalProtect HIP check due",
        "SSL negotiation with vpn.example.org",
        HTTPS_UP,
    ])
    assert status == ["connected to the gateway; waiting for the data tunnel (ESP over UDP)",
                      "tunnel ready over ESP after 0 s"]


def test_reconnect_after_link_loss_reports_waiting_then_ready(monkeypatch):
    status = run_with_output(monkeypatch, [
        HTTPS_UP,
        "ESP session established with server",
        "ESP detected dead peer",
        HTTPS_UP,
        "ESP session established with server",
    ])
    assert [m.split(";")[0].split(" after")[0] for m in status] == [
        "connected to the gateway", "tunnel ready over ESP",
        "link lost", "connected to the gateway", "tunnel ready over ESP"]

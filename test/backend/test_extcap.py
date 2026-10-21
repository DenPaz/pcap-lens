"""Extcap helpers: listing, options, and capturing through tshark."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import extcap
from pcap_backend.cancellation import CancelledError, CancelToken
from pcap_backend.capture import CaptureOptions, capture_command
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext
from pcap_backend.tshark import ToolError, run

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

CONFIG = """\
arg {number=0}{call=--remote-host}{display=Remote SSH server address}{type=string}{tooltip=Host {or IP}}{required=true}{group=Server}
arg {number=1}{call=--remote-port}{display=Port}{type=unsigned}{default=22}{range=1,65535}{group=Server}
arg {number=2}{call=--remote-priv}{display=Privilege}{type=radio}
value {arg=2}{value=none}{display=none}{default=true}
value {arg=2}{value=doas -n}{display=doas}
arg {number=3}{call=--sshkey}{display=Key}{type=fileselect}{mustexist=true}
arg {number=4}{call=bad}{display=Not an option}
value {arg=9}{value=orphan}
"""  # noqa: E501 - extcap lines are long


def test_settings_key_is_wiresharks() -> None:
    assert extcap.settings_key("sshdump", "--remote-host") == "extcap.sshdump.remotehost"
    assert extcap.settings_key("Android-wifi:5554", "--adb_port") == (
        "extcap.android_wifi_5554.adb_port"
    )


def test_interfaces_and_config_are_parsed() -> None:
    helper = extcap.parse_interfaces(
        Path("/x/sshdump"),
        "extcap {version=1.2.0}{help=file:///sshdump.html}\n"
        "interface {value=sshdump}{display=SSH remote capture}\r\n"
        "interface {value=}{display=no name}\n"
        "noise\n",
    )
    assert (helper.version, helper.interfaces) == ("1.2.0", [("sshdump", "SSH remote capture")])
    args = extcap.parse_config(CONFIG)
    assert [a["call"] for a in args] == [
        "--remote-host",
        "--remote-port",
        "--remote-priv",
        "--sshkey",
    ]
    host, port, priv, key = args
    assert host["tooltip"] == "Host {or IP}" and host["required"] and host["group"] == "Server"
    assert (port["type"], port["default"], port["range"], port["required"]) == (
        "unsigned", "22", "1,65535", False,
    )  # fmt: skip
    assert priv["values"] == [
        {"value": "none", "display": "none", "default": True},
        {"value": "doas -n", "display": "doas", "default": False},
    ]
    assert key["mustexist"]


def test_folders_and_helper_files(tmp_path: Path) -> None:
    folders = (
        "Personal configuration:\t/home/u/.config/wireshark\n"
        "Personal Extcap path:\t/home/u/.local/lib/wireshark/extcap\n"
        "Global Extcap path:  \t/usr/lib/wireshark/extcap\n"
    )
    personal, system = (
        Path("/home/u/.local/lib/wireshark/extcap"),
        Path("/usr/lib/wireshark/extcap"),
    )
    assert extcap.extcap_folders(folders, as_root=False) == [personal, system]
    assert extcap.extcap_folders(folders, as_root=True) == [system]
    (tmp_path / "sub").mkdir()
    for name, mode in (("sshdump", 0o755), ("README", 0o644), ("tool.exe", 0o644)):
        (tmp_path / name).write_text("")
        (tmp_path / name).chmod(mode)
    if sys.platform != "win32":
        assert [p.name for p in extcap.helper_files([tmp_path, tmp_path / "gone"], "linux")] == [
            "sshdump"
        ]
    assert [p.name for p in extcap.helper_files([tmp_path], "win32")] == ["tool.exe"]


def test_find_helpers_leaves_out_the_ones_that_fail() -> None:
    def runner(argv: list[str], _token: CancelToken, _timeout: float) -> str:
        name = Path(argv[0]).name
        if name == "hangs":
            raise CancelledError("timed out")  # (the helper's own token)
        if name == "broken":
            raise OSError("exec format error")
        if name == "quiet":
            return ""
        return f"interface {{value={name}-1}}{{display={name}}}\n"

    paths = [Path(n) for n in ("ok", "hangs", "broken", "quiet")]
    found = extcap.find_helpers(paths, CancelToken(), runner=runner)
    assert [(h.path.name, h.interfaces) for h in found] == [("ok", [("ok-1", "ok")])]
    cancelled = CancelToken()
    cancelled.cancel()
    with pytest.raises(CancelledError):
        extcap.find_helpers(paths, cancelled, runner=runner)


def test_extcap_interfaces_capture_through_tshark() -> None:
    options = CaptureOptions(
        interfaces=("lo", "sshdump"),
        capture_filter="udp",
        packets=10,
        extcap={"sshdump": {"--remote-host": "box", "--remote-noprom": "true"}},
    )
    assert options.dumpcap_args() == [
        "-q",
        "-i", "lo", "-f", "udp",
        "-i", "sshdump",
        "-o", "extcap.sshdump.remotehost:box",
        "-o", "extcap.sshdump.remotenoprom:true",
        "-c", "10",
        "-w", "-",
    ]  # fmt: skip
    tshark = Path("/bin/tshark")
    assert capture_command(tshark, options) == [str(tshark)]


@pytest.mark.parametrize(
    ("extcap_param", "message"),
    [
        ([], "must be an object"),
        ({"other": {}}, "isn't one of the interfaces"),
        ({"fake": {"remote-host": "x"}}, "isn't an option"),
        ({"fake": {"--host": ["x"]}}, "must be a string"),
        ({"fake": {"--host": "a\nb"}}, "one line"),
    ],
)
def test_bad_extcap_options_are_refused(
    service: PcapService, tmp_path: Path, extcap_param: Any, message: str
) -> None:
    with pytest.raises(InvalidParamsError, match=message):
        service.capture_start(
            {"dest": str(tmp_path / "x.pcapng"), "interfaces": ["fake"], "extcap": extcap_param},
            RequestContext(),
        )


def _wait(check: Callable[[], bool], timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() > deadline:
            raise AssertionError("timed out")
        time.sleep(0.05)


def _events(service: PcapService) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    service.notify = lambda method, payload: events.append((method, payload))
    return events


def _done(events: list[tuple[str, dict[str, Any]]]) -> bool:
    return any(m == "index" and p.get("event") == "done" for m, p in events)


@pytest.fixture
def fake_extcap(service: PcapService) -> Iterator[str]:
    """fake_extcap.py in tshark's personal extcap folder (removed afterwards:
    every capture-listing tshark runs every helper)."""
    if sys.platform == "win32":
        pytest.skip("extcap helpers are .exe files on Windows")
    if AS_ROOT:
        pytest.skip("Wireshark ignores the personal extcap folder as root")
    folders = service._require_tshark().folders()
    line = next((ln for ln in folders.split("\n") if ln.startswith("Personal Extcap path")), "")
    if not line.partition(":")[2].strip():
        pytest.skip("tshark has no personal extcap folder")
    personal = Path(line.partition(":")[2].strip())
    personal.mkdir(parents=True, exist_ok=True)
    helper = personal / "fake_extcap"
    # (A shell script answers tshark's interface query at once; Python does the rest.)
    helper.write_text(
        "#!/bin/sh\n"
        'case " $* " in *" --extcap-interfaces "*)\n'
        "  echo 'extcap {version=1.0}{help=https://example.invalid/fake}'\n"
        "  echo 'interface {value=fake-remote}{display=Fake remote capture}'\n"
        "  exit 0;;\n"
        "esac\n"
        f'exec "{sys.executable}" "{FIXTURES / "fake_extcap.py"}" "$@"\n'
    )
    helper.chmod(0o755)
    try:
        tshark = service._require_tshark().path
        listed = run([str(tshark), "-D"])
        if "fake-remote" not in listed.stdout.decode("utf-8", "replace"):
            answer = run([str(helper), "--extcap-interfaces"])
            pytest.fail(
                f"tshark doesn't list the fake extcap helper {helper}\n"
                f"tshark -D:\n{listed.stdout.decode()}\n{listed.stderr}\n"
                f"tshark -G folders:\n{folders}\n"
                f"the helper's answer: {answer.returncode} {answer.stdout.decode()} {answer.stderr}"
            )
        yield "fake-remote"
    finally:
        helper.unlink()


@pytest.mark.tshark
def test_capture_on_a_fake_extcap(service: PcapService, fake_extcap: str, tmp_path: Path) -> None:
    listed = service.list_interfaces({}, RequestContext())["interfaces"]
    fake = next(i for i in listed if i["name"] == fake_extcap)
    assert fake["extcap"] and fake["helper"] == "fake_extcap"
    assert fake["description"] == "Fake remote capture"
    config = service.extcap_config({"interface": fake_extcap}, RequestContext())
    assert [a["call"] for a in config["args"]] == ["--marker", "--packets", "--speed", "--fast"]

    events = _events(service)
    res = service.capture_start(
        {
            "dest": str(tmp_path / "remote.pcapng"),
            "interfaces": [fake_extcap],
            "extcap": {fake_extcap: {"--marker": "from-the-helper", "--packets": "4"}},
        },
        RequestContext(),
    )
    assert res["capture"]["interfaces"] == [fake_extcap]
    _wait(lambda: _done(events))  # the helper ends after 4 packets, and so does the capture
    assert (
        service.set_filter({"expr": 'udp contains "from-the-helper"'}, RequestContext())[
            "matchCount"
        ]
        == 4
    )
    stopped = next(p for m, p in events if m == "capture" and p["event"] == "stopped")
    assert "error" not in stopped, stopped


@pytest.mark.tshark
def test_stopping_an_extcap_capture(service: PcapService, fake_extcap: str, tmp_path: Path) -> None:
    events = _events(service)
    service.capture_start(
        {
            "dest": str(tmp_path / "remote.pcapng"),
            "interfaces": [fake_extcap],
            "extcap": {fake_extcap: {"--marker": "slow", "--packets": "0"}},
        },
        RequestContext(),
    )
    _wait(lambda: service.list_packets({"limit": 5}, RequestContext())["total"] >= 2)
    assert service.capture_stop({}, RequestContext())["stopped"]
    _wait(lambda: _done(events))
    stopped = next(p for m, p in events if m == "capture" and p["event"] == "stopped")
    assert "error" not in stopped, stopped
    assert service.capture_info({}, RequestContext())["frames"] >= 2


@pytest.mark.tshark
def test_a_failing_extcap_reports_its_error(
    service: PcapService, fake_extcap: str, tmp_path: Path
) -> None:
    with pytest.raises(ToolError, match="marker is required"):
        service.capture_start(
            {
                "dest": str(tmp_path / "x.pcapng"),
                "interfaces": [fake_extcap],
                "extcap": {fake_extcap: {}},
            },
            RequestContext(),
        )
    with pytest.raises(InvalidParamsError, match="no extcap helper"):
        service.extcap_config({"interface": "nothing-like-it"}, RequestContext())


@pytest.mark.tshark
def test_capture_with_randpkt(service: PcapService, tmp_path: Path) -> None:
    """Wireshark's own random packet generator, where it is installed."""
    listed = service.list_interfaces({}, RequestContext())["interfaces"]
    if not any(i["name"] == "randpkt" and i.get("extcap") for i in listed):
        pytest.skip("no randpktdump")
    events = _events(service)
    service.capture_start(
        {
            "dest": str(tmp_path / "random.pcapng"),
            "interfaces": ["randpkt"],
            "extcap": {"randpkt": {"--count": "5", "--type": "dns"}},
        },
        RequestContext(),
    )
    _wait(lambda: _done(events))
    assert service.capture_info({}, RequestContext())["frames"] == 5

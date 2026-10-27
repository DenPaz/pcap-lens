"""Statistics whatever the user's locale: Wireshark's tools run with C number
formatting on macOS and Linux (tool_env); on Windows, where they take the
regional settings, a decimal comma is detected and read in number cells."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from pcap_backend import stats
from pcap_backend import tshark as tshark_module
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.tshark import IS_WINDOWS, Tshark, find_tool, tool_env

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# Locales whose decimal separator is a comma (macOS has them all; Linux CI
# generates pt_BR.UTF-8).
COMMA_LOCALES = ("pt_BR.UTF-8", "pt_BR.utf8", "de_DE.UTF-8", "de_DE.utf8")

# tshark 4.6 on Windows with the pt-BR regional format (CI's Set-Culture).
WINDOWS_CONV = """\
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.1.10:50000         <-> 93.184.216.34:80                 5 761 bytes       6 414 bytes      11 1175 bytes     0,000000000         0,0100
"""  # noqa: E501 - tshark's line
WINDOWS_TREE = """\
IPv4 Statistics / IP Protocol Types:
Topic / Item                       Count         Average       Min Val       Max Val       Rate (ms)     Percent       Burst Rate    Burst Start
--------------------------------------------------------------------------------------------------------------------------------------------------
IPv4 Statistics/IP Protocol Types  103                                                     0,0606        100%          0,6000        0,000
 UDP                               91                                                      0,0535        88,35%        0,6000        0,000
 1,5                               12                                                      0,0071        11,65%        0,1000        1,000
"""  # noqa: E501 - tshark's line (the last topic made up: a name is text)


def _comma_locale() -> str | None:
    probe = (
        "import locale, sys\n"
        "locale.setlocale(locale.LC_ALL, sys.argv[1])\n"
        "print(locale.localeconv()['decimal_point'])\n"
    )
    for name in COMMA_LOCALES:
        res = subprocess.run(
            [sys.executable, "-c", probe, name], capture_output=True, text=True, check=False
        )
        if res.returncode == 0 and res.stdout.strip() == ",":
            return name
    return None


def test_tool_env_sets_c_numbers() -> None:
    env = tool_env({"PATH": "/bin", "LANG": "pt_BR.UTF-8", "LC_TIME": "pt_BR.UTF-8"})
    assert env == {
        "PATH": "/bin",
        "LANG": "pt_BR.UTF-8",
        "LC_TIME": "pt_BR.UTF-8",
        "LC_NUMERIC": "C",
    }
    # LC_ALL would override LC_NUMERIC: its value becomes LANG, and the LC_*
    # variables it overrode go.
    env = tool_env({"LC_ALL": "pt_BR.UTF-8", "LC_CTYPE": "en_US.UTF-8", "LANG": "en_US.UTF-8"})
    assert env == {"LANG": "pt_BR.UTF-8", "LC_NUMERIC": "C"}


def test_number_cells_with_decimal_commas() -> None:
    [conv] = stats.parse_conversations(WINDOWS_CONV, "tcp").rows
    assert conv["cells"][3] == 1175 and conv["cells"][-2:] == [0, 0.01]
    rows = stats.parse_stats_tree(WINDOWS_TREE, "ipv4_ptype").rows
    assert [r["cells"] for r in rows[1:]] == [
        ["UDP", 91, 0.0535, 88.35, 0.6, 0.0],
        ["1,5", 12, 0.0071, 11.65, 0.1, 1.0],
    ]


def _service_results(ctx: RequestContext) -> list[object]:
    """Statistics with decimals but no number over 999 (Linux's pt_BR, unlike
    Windows, groups thousands: "1.175 bytes")."""
    results: list[object] = []
    for name, requests in (
        (
            "mixed.pcapng",
            [{"kind": "io", "interval": 0.005}, {"kind": "conversations", "type": "udp"}],
        ),
        ("network.pcap", [{"kind": "ipv4", "type": "ptype"}]),
        ("services.pcap", [{"kind": "srt", "type": "icmp"}]),
    ):
        service = PcapService()
        try:
            service.initialize({}, ctx)
            service.open({"path": str(FIXTURES / name), "names": {}}, ctx)
            results += [service.stats(r, ctx) for r in requests]
        finally:
            service.shutdown()
    return results


@pytest.fixture
def comma_locale(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    """Sets a comma locale for the rest of the test (skips without one)."""
    name = _comma_locale()
    if name is None:
        pytest.skip("no locale with a decimal comma is installed")
    return lambda: monkeypatch.setenv("LC_ALL", name)


@pytest.mark.tshark
@pytest.mark.skipif(IS_WINDOWS, reason="Windows tools take the regional settings, not LC_*")
def test_statistics_in_a_comma_locale(
    comma_locale: Callable[[], None], ctx: RequestContext
) -> None:
    # In pt_BR tshark refused `-z io,stat,0.5` and wrote "1.175 bytes" and
    # "0,000000" into the conversation tables, which then had no rows.
    expected = _service_results(ctx)
    comma_locale()
    assert _service_results(ctx) == expected
    conv = expected[1]
    assert isinstance(conv, dict) and len(conv["rows"]) == 4


@pytest.mark.tshark
@pytest.mark.skipif(IS_WINDOWS, reason="LC_* can't give Windows' tshark a comma locale")
def test_statistics_from_a_tshark_with_decimal_commas(
    comma_locale: Callable[[], None], monkeypatch: pytest.MonkeyPatch, ctx: RequestContext
) -> None:
    # Windows' tshark in pt-BR, played by Linux's or macOS's without tool_env.
    expected = _service_results(ctx)
    monkeypatch.setattr(tshark_module, "_DECIMAL_COMMA", {})
    monkeypatch.setattr(
        tshark_module, "tool_env", lambda env=None: dict(os.environ if env is None else env)
    )
    comma_locale()
    tshark = Tshark.locate()
    assert tshark.decimal_comma() and tshark.decimal(0.005) == "0,005"
    assert _service_results(ctx) == expected


@pytest.fixture
def commented(tmp_path: Path) -> Path:
    """http.pcap with a packet comment holding a number with a decimal comma."""
    dest = tmp_path / "commented.pcapng"
    editcap = find_tool("editcap", sibling_of=Tshark.locate().path)
    argv = [str(editcap), "-F", "pcapng", "-a", "1:Measured 1,5 ms", str(FIXTURES / "http.pcap")]
    subprocess.run([*argv, str(dest)], check=True, capture_output=True)
    return dest


@pytest.mark.tshark
@pytest.mark.skipif(IS_WINDOWS, reason="LC_* can't give Windows' tshark a comma locale")
def test_packet_text_keeps_its_commas(
    comma_locale: Callable[[], None],
    monkeypatch: pytest.MonkeyPatch,
    commented: Path,
    ctx: RequestContext,
) -> None:
    # Codex review: converting the whole expert report made the comment
    # "Measured 1,5 ms" read "1.5" there but not in the pass that links
    # messages to packets, so its row lost its packets.
    monkeypatch.setattr(tshark_module, "_DECIMAL_COMMA", {})
    monkeypatch.setattr(
        tshark_module, "tool_env", lambda env=None: dict(os.environ if env is None else env)
    )
    comma_locale()
    service = PcapService()
    try:
        service.initialize({}, ctx)
        service.open({"path": str(commented), "names": {}}, ctx)
        rows = service.stats({"kind": "expert"}, ctx)["rows"]
    finally:
        service.shutdown()
    [comment] = [r for r in rows if r["cells"][0] == "Comment"]
    assert comment["cells"][1] == "Measured 1,5 ms" and comment["frames"] == [1]


@pytest.mark.tshark
def test_this_tshark_reads_its_decimals(ctx: RequestContext) -> None:
    # Whatever the platform and regional settings (CI runs this on Windows
    # in pt-BR too): an IO graph with a fractional interval and conversations
    # with their times.
    [io, conv, *_] = _service_results(ctx)
    assert isinstance(io, dict) and isinstance(conv, dict)
    assert [r["cells"][:2] for r in io["rows"]][:2] == [[0, 0.005], [0.005, 0.01]]
    assert {r["cells"][-1] for r in conv["rows"]} == {0.01, 0.002}

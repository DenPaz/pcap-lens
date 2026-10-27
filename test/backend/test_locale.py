"""Wireshark tools run with C number formatting, whatever the user's locale."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.tshark import IS_WINDOWS, tool_env

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# Locales whose decimal separator is a comma (macOS has them all; Linux CI
# generates pt_BR.UTF-8).
COMMA_LOCALES = ("pt_BR.UTF-8", "pt_BR.utf8", "de_DE.UTF-8", "de_DE.utf8")


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


@pytest.mark.tshark
@pytest.mark.skipif(IS_WINDOWS, reason="Windows tools take the regional settings, not LC_*")
def test_statistics_in_a_comma_locale(monkeypatch: pytest.MonkeyPatch, ctx: RequestContext) -> None:
    # In pt_BR tshark refused `-z io,stat,0.5` and wrote "1.175 bytes" and
    # "0,000000" into the conversation tables, which then had no rows.
    name = _comma_locale()
    if name is None:
        pytest.skip("no locale with a decimal comma is installed")

    def results() -> list[object]:
        service = PcapService()
        try:
            service.initialize({}, ctx)
            service.open({"path": str(FIXTURES / "http.pcap"), "names": {}}, ctx)
            return [
                service.stats({"kind": "io", "interval": 0.5}, ctx),
                service.stats({"kind": "conversations", "type": "tcp"}, ctx),
                service.stats({"kind": "endpoints", "type": "ip"}, ctx),
            ]
        finally:
            service.shutdown()

    expected = results()
    monkeypatch.setenv("LC_ALL", name)
    assert results() == expected
    conv = expected[1]
    assert isinstance(conv, dict) and len(conv["rows"]) == 1

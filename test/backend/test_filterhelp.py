"""Display filter help: hints for a filter matching nothing, field values, and
the field search of the filter builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_backend import filterhelp
from pcap_backend.fields import FieldCatalog
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import FilterError, InvalidParamsError, RequestContext

KNOWN = {"ip.addr", "ip.src", "tcp.port", "http", "http.host", "dns", "frame.len", "eth.addr"}


def test_filter_fields() -> None:
    known = KNOWN.__contains__
    assert filterhelp.filter_fields("ip.addr == 10.0.0.1 && tcp.port == 80", known) == [
        "ip.addr",
        "tcp.port",
    ]
    # Strings, functions, keywords, numbers and addresses are not fields; a
    # value word (`http` as a port name) is kept only because it is a field too.
    assert filterhelp.filter_fields(
        'http.host contains "ip.src and dns" or len(http.host) > 3 and not tcp.port in {80, 443}',
        known,
    ) == ["http.host", "tcp.port"]
    assert filterhelp.filter_fields(
        "eth.addr == aa:bb:cc:dd:ee:ff or ip.src[0:2] == 0a:00", known
    ) == [
        "eth.addr",
        "ip.src",
    ]
    assert filterhelp.filter_fields("tcp.port == http || dns || dns", known) == [
        "tcp.port",
        "http",
        "dns",
    ]
    assert filterhelp.filter_fields("frame.len > 0x10", known) == ["frame.len"]
    assert filterhelp.filter_fields("unknown.field == 1", known) == []


def test_always_present() -> None:
    assert filterhelp.always_present("frame")
    assert filterhelp.always_present("frame.len")
    assert filterhelp.always_present("_ws.expert")
    assert not filterhelp.always_present("framed")
    assert not filterhelp.always_present("ip.addr")


def test_case_hints() -> None:
    types = {"http.host": "FT_STRING", "http.request.method": "FT_STRING", "tcp.port": "FT_UINT16"}
    hints = filterhelp.case_hints(
        'http.host == "Example.com" && http.request.method eq "get" && tcp.port == "80"'
        ' && http.host == "123" && dns.qry.name == "X"',
        types.get,
    )
    assert hints == [
        {
            "field": "http.host",
            "value": "Example.com",
            "filter": 'lower(http.host) == "example.com"',
        },
        {
            "field": "http.request.method",
            "value": "get",
            "filter": 'lower(http.request.method) == "get"',
        },
    ]
    # Quotes and backslashes in the literal stay escaped in the suggestion.
    (hint,) = filterhelp.case_hints(r'http.host == "A\"B\\C"', types.get)
    assert hint["value"] == 'A"B\\C'
    assert hint["filter"] == r'lower(http.host) == "a\"b\\c"'


def test_count_values() -> None:
    counted = filterhelp.count_values(["a", "b\x1ea\x1ea", "", "c", "a"])
    assert dict(counted["counts"]) == {"a": 3, "b": 1, "c": 1}
    assert counted["packets"] == 4
    assert counted["more"] == 0


def test_count_values_caps_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(filterhelp, "MAX_DISTINCT", 2)
    counted = filterhelp.count_values(["a", "b", "c", "a", "d\x1eb"])
    assert dict(counted["counts"]) == {"a": 2, "b": 2}
    assert counted["more"] == 2  # c and d


def test_catalog_find() -> None:
    catalog = FieldCatalog.parse(
        "P\tInternet Protocol Version 4\tip\n"
        "P\tNETTL\tnettl\n"
        "F\tTime to Live\tip.ttl\tFT_UINT8\tip\tBASE_DEC\t0x0\t\n"
        "F\tSource Address\tip.src\tFT_IPv4\tip\tBASE_NONE\t0x0\t\n"
        "F\tTTL\tcdp.ttl\tFT_UINT8\tcdp\tBASE_DEC\t0x0\t\n"
        "F\tTime to live\tnbns.ttl\tFT_UINT32\tnbns\tBASE_DEC\t0x0\t\n"
    )
    assert [e["name"] for e in catalog.find("ttl", 10)] == [
        "ip.ttl",
        "cdp.ttl",
        "nbns.ttl",
        "nettl",
    ]
    assert [e["name"] for e in catalog.find("time to live", 10)] == ["ip.ttl", "nbns.ttl"]
    assert catalog.find("ip", 1) == [
        {"name": "ip", "desc": "Internet Protocol Version 4", "type": "protocol"}
    ]
    assert catalog.find("  ", 5) == []


# ---------------------------------------------------------------------- with tshark


@pytest.mark.tshark
def test_filter_hints(opened: PcapService, ctx: RequestContext) -> None:
    res = opened.filter_hints({"expr": 'sip.Method == "INVITE" || frame.len > 99999'}, ctx)
    assert res["fields"] == [
        {"name": "sip.Method", "present": False},
        {"name": "frame.len", "present": True},
    ]
    res = opened.filter_hints({"expr": 'http.host == "Example.com" && tcp.port == 80'}, ctx)
    assert all(f["present"] for f in res["fields"])
    assert res["caseHints"] == [
        {
            "field": "http.host",
            "value": "Example.com",
            "filter": 'lower(http.host) == "example.com"',
        }
    ]
    # No hint for a field no packet has (there is nothing to compare).
    res = opened.filter_hints({"expr": 'dns.qry.name == "Example.com"'}, ctx)
    assert res["caseHints"] == []
    assert opened.filter_hints({"expr": 'dns.qry.name == "Example.com"'}, ctx) is res  # cached
    with pytest.raises(FilterError):
        opened.filter_hints({"expr": "ip.addr =="}, ctx)
    with pytest.raises(InvalidParamsError):
        opened.filter_hints({"expr": " "}, ctx)


@pytest.mark.tshark
def test_field_values(service: PcapService, ctx: RequestContext, fixtures: Path) -> None:
    service.open({"path": str(fixtures / "mixed.pcapng")}, ctx)
    progress: list[dict[str, object]] = []
    res = service.field_values({"field": "dns.qry.name"}, RequestContext(progress=progress.append))
    assert res["type"] == "FT_STRING"
    assert res["values"] == [
        {"value": "example.com", "count": 2},
        {"value": "nonexistent.invalid", "count": 2},
        {"value": "wireshark.org", "count": 2},
    ]
    assert (res["packets"], res["distinct"], res["more"]) == (6, 3, 0)
    assert progress and progress[0]["phase"] == "values"
    # A packet holding a value twice counts once; limit cuts the list.
    res = service.field_values({"field": "ip.addr", "limit": 1}, ctx)
    assert len(res["values"]) == 1
    assert res["values"][0]["count"] <= res["packets"] == 25
    assert res["distinct"] > 1
    # A field no packet has.
    res = service.field_values({"field": "sip.Method"}, ctx)
    assert (res["values"], res["packets"]) == ([], 0)
    with pytest.raises(InvalidParamsError, match="not a field"):
        service.field_values({"field": "no.such.field"}, ctx)


@pytest.mark.tshark
def test_field_index_words(opened: PcapService, ctx: RequestContext) -> None:
    fields = opened.field_index({"words": "time to live", "limit": 3}, ctx)["fields"]
    assert fields[0]["name"] == "ip.ttl"
    assert len(fields) == 3

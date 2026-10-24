"""triage: the AI triage's fixed checks, counted by tshark in one pass."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from pcap_backend import triage
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_checks_are_unique_and_safe_for_io_stat() -> None:
    ids = [c.id for c in triage.CHECKS]
    assert len(ids) == len(set(ids))
    for c in triage.CHECKS:
        assert "," not in c.filter, c.id  # io,stat splits its arguments on commas


@pytest.mark.tshark
@pytest.mark.parametrize("capture", ["services.pcap", "credentials.pcap", "mixed.pcapng"])
def test_counts_and_first_last_match_the_filters(
    service: PcapService, ctx: RequestContext, capture: str
) -> None:
    service.open({"path": str(FIXTURES / capture)}, ctx)
    res = service.triage({}, ctx)
    assert res["total"] == service.capture_info({}, ctx)["frames"]
    assert [c["id"] for c in res["checks"]] == [c.id for c in triage.CHECKS]
    refused = [c for c in res["checks"] if "error" in c]
    assert not refused, "every check's filter compiles with this tshark"
    found = [c for c in res["checks"] if c["count"]]
    assert found
    for c in found:
        counted = service.count_matches({"filter": c["filter"], "limit": 100}, ctx)
        assert c["count"] == counted["count"], c["id"]
        assert c["first"] == counted["frames"][0], c["id"]
        if counted["count"] <= 100:
            assert c["last"] == counted["frames"][-1], c["id"]
    for c in res["checks"]:
        if not c["count"]:
            assert c["first"] is None and c["last"] is None


@pytest.mark.tshark
def test_what_the_fixtures_hold(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(FIXTURES / "services.pcap")}, ctx)
    found = {c["id"] for c in service.triage({}, ctx)["checks"] if c["count"]}
    assert {"dns_queries", "dns_responses", "http_client_errors"} <= found
    service.open({"path": str(FIXTURES / "credentials.pcap")}, ctx)
    found = {c["id"] for c in service.triage({}, ctx)["checks"] if c["count"]}
    assert "cleartext_credentials" in found


@pytest.mark.tshark
def test_some_checks_ignored_packets_and_refused_filters(
    service: PcapService, ctx: RequestContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    service.open({"path": str(FIXTURES / "services.pcap")}, ctx)
    with pytest.raises(InvalidParamsError):
        service.triage({"checks": ["no_such_check"]}, ctx)
    res = service.triage({"checks": ["dns_queries"]}, ctx)
    [dns] = res["checks"]
    assert dns["count"] > 1 and not res["ignored"]
    service.ignore_packets({"frames": [dns["first"]], "ignore": True}, ctx)
    res = service.triage({"checks": ["dns_queries"]}, ctx)
    assert res["ignored"]
    assert res["checks"][0]["count"] == dns["count"] - 1
    assert res["checks"][0]["first"] > dns["first"]
    monkeypatch.setattr(
        triage,
        "CHECKS",
        (*triage.CHECKS, triage.Check("bogus", "Bogus", "no_such_field.at_all == 1")),
    )
    res = service.triage({"checks": ["bogus", "dns_queries"]}, ctx)
    assert [c["id"] for c in res["checks"]] == ["dns_queries", "bogus"]
    assert res["checks"][0]["count"] == dns["count"] - 1
    assert "no_such_field" in res["checks"][1]["error"]


@pytest.mark.tshark
def test_waits_for_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)
    with pytest.raises(IndexingError):
        service.triage({}, ctx)
    slow_index.set()

"""triage: the AI triage's fixed checks, counted by tshark in one pass."""

from __future__ import annotations

import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from pcap_backend import triage
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import IndexingError, InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TWO_PASS = {c.id for c in triage.CHECKS if c.two_pass}


def two_pass_frames(capture: Path, flt: str) -> list[int]:
    """The packets matching ``flt`` when tshark reads the capture twice."""
    tshark = shutil.which("tshark")
    assert tshark
    out = subprocess.run(
        [tshark, "-n", "-2", "-r", str(capture), "-Y", flt, "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        check=True,
    ).stdout
    return [int(line) for line in out.split()]


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
    assert res["twoPass"]
    found = [c for c in res["checks"] if c["count"]]
    assert found
    for c in found:
        if c["id"] in TWO_PASS:
            frames = two_pass_frames(FIXTURES / capture, c["filter"])
            assert (c["count"], c["first"], c["last"]) == (len(frames), frames[0], frames[-1])
            continue
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
    assert {"dns_queries", "dns_responses", "http_client_errors", "icmp_unanswered"} <= found
    [icmp] = service.triage({"checks": ["icmp_unanswered"]}, ctx)["checks"]
    assert icmp["count"] == 1 and icmp["first"] == 61  # the echo request without a reply
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
def test_two_pass_checks_are_skipped_on_big_captures(
    service: PcapService, ctx: RequestContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    service.open({"path": str(FIXTURES / "services.pcap")}, ctx)
    monkeypatch.setattr(triage, "TWO_PASS_LIMIT", 10)
    res = service.triage({"checks": ["icmp_unanswered", "dns_queries"]}, ctx)
    assert not res["twoPass"]
    icmp, dns = res["checks"]
    assert dns["id"] == "dns_queries" and dns["count"] > 1
    assert icmp["id"] == "icmp_unanswered" and "count" not in icmp
    assert "two passes" in icmp["skipped"] and "error" not in icmp


@pytest.mark.tshark
def test_waits_for_indexing(
    service: PcapService, ctx: RequestContext, slow_index: threading.Event
) -> None:
    service.open({"path": str(FIXTURES / "http.pcap"), "stream": True}, ctx)
    with pytest.raises(IndexingError):
        service.triage({}, ctx)
    slow_index.set()

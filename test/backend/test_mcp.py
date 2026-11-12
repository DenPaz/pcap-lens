"""The MCP server (``python -m pcap_backend.mcp``): protocol, tools, limits."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

import pytest
from jsonschema import Draft202012Validator

from pcap_backend import mcp
from pcap_backend import triage as triage_checks
from pcap_backend.mcp import Captures, McpConfig, McpServer, Toolbox
from pcap_backend.mcp_schemas import OUTPUT_SCHEMAS
from pcap_backend.protocol import RequestContext
from pcap_backend.standins import AddressMasker

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
EXAMPLE_LUA = Path(__file__).resolve().parents[2] / "backend" / "dissectors" / "example.lua"
AS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
BACKEND = Path(__file__).resolve().parents[2] / "backend"


class Client:
    """An MCP server on pipes, in this process, and a client for it."""

    def __init__(self, config: McpConfig) -> None:
        to_server_r, to_server_w = os.pipe()
        to_client_r, to_client_w = os.pipe()
        self._in: BinaryIO = os.fdopen(to_server_w, "wb")
        self._out: BinaryIO = os.fdopen(to_client_r, "rb")
        self.captures = Captures(config)
        self._server_in: BinaryIO = os.fdopen(to_server_r, "rb")
        self._server_out: BinaryIO = os.fdopen(to_client_w, "wb")
        self.server = McpServer(
            self._server_in,
            self._server_out,
            Toolbox(self.captures),
            AddressMasker(config.stand_ins),
        )
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        self._next = 0
        self._output_schemas: dict[str, Any] | None = None
        self.checked: set[str] = set()  # tools whose results matched their outputSchema
        self._messages: list[dict[str, Any]] = []
        self._lock = threading.Condition()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        for line in self._out:
            with self._lock:
                self._messages.append(json.loads(line))
                self._lock.notify_all()

    def send(self, message: dict[str, Any]) -> None:
        self._in.write(json.dumps(message).encode() + b"\n")
        self._in.flush()

    def request(
        self, method: str, params: dict[str, Any] | None = None, timeout: float = 60
    ) -> Any:
        self._next += 1
        rid = self._next
        self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        response = self.wait(rid, timeout)
        if method == "tools/call":
            self._check_output((params or {}).get("name"), response.get("result") or {})
        return response

    def _check_output(self, name: Any, result: dict[str, Any]) -> None:
        """Every structured result a test gets matches its tool's outputSchema."""
        structured = result.get("structuredContent")
        if structured is None or result.get("isError"):
            return
        if self._output_schemas is None:
            tools = self.request("tools/list")["result"]["tools"]
            self._output_schemas = {t["name"]: t["outputSchema"] for t in tools}
        Draft202012Validator(self._output_schemas[name]).validate(structured)
        self.checked.add(name)

    def wait(self, rid: int, timeout: float = 60) -> dict[str, Any]:
        end = time.monotonic() + timeout
        with self._lock:
            while True:
                for m in self._messages:
                    if m.get("id") == rid:
                        self._messages.remove(m)
                        return m
                left = end - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"no response to {rid}")
                self._lock.wait(left)

    def notifications(self, method: str) -> list[dict[str, Any]]:
        with self._lock:
            return [m for m in self._messages if m.get("method") == method]

    def call(self, name: str, **arguments: Any) -> tuple[Any, bool]:
        """A tool's result (parsed JSON, or the error text) and whether it failed."""
        res = self.request("tools/call", {"name": name, "arguments": arguments})["result"]
        text = res["content"][0]["text"]
        return (text if res["isError"] else json.loads(text)), res["isError"]

    def close(self) -> None:
        self._in.close()  # the server's input ends: it shuts down
        self._thread.join(timeout=30)
        self.captures.shutdown()
        self._server_out.close()  # the reader's input ends
        self._reader.join(timeout=30)
        self._server_in.close()
        self._out.close()


@pytest.fixture
def client_for() -> Iterator[Any]:
    clients: list[Client] = []

    def make(**options: Any) -> Client:
        options.setdefault("roots", [FIXTURES])
        c = Client(McpConfig(**options))
        clients.append(c)
        return c

    yield make
    for c in clients:
        c.close()


def test_handshake_tools_and_errors(client_for: Any) -> None:
    c = client_for()
    init = c.request("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}})
    assert init["result"]["protocolVersion"] == "2025-03-26"
    assert init["result"]["serverInfo"]["name"] == "pcap-lens"
    assert init["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert str(FIXTURES) in init["result"]["instructions"]
    assert "not available" in init["result"]["instructions"]
    assert "running tshark" in init["result"]["instructions"]
    assert "plugins lists them" in init["result"]["instructions"]
    unknown = c.request("initialize", {"protocolVersion": "1999-01-01"})
    assert unknown["result"]["protocolVersion"] == mcp.DEFAULT_PROTOCOL
    c.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert c.request("ping")["result"] == {}
    tools = {t["name"]: t for t in c.request("tools/list")["result"]["tools"]}
    assert set(tools) == {
        "list_captures",
        "capture_info",
        "count_packets",
        "statistics",
        "triage",
        "compare_captures",
        "field_values",
        "validate_filter",
        "search_fields",
        "plugins",
        "overview",
        "sessions",
        "voip_calls",
        "tcp_stream",
        "rtp_stream",
        "sequence_check",
        "export_objects",
        "credentials",
    }, "no packet contents without --allow-packet-data"
    assert all(t["annotations"]["readOnlyHint"] for t in tools.values())
    assert tools["statistics"]["inputSchema"]["required"] == ["capture", "kind"]
    assert c.request("resources/list")["error"]["code"] == -32601
    bad = c.request("tools/call", {"name": "list_packets", "arguments": {}})
    assert bad["error"]["code"] == -32602
    c.send({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": []})
    assert c.wait(99)["error"]["code"] == -32602


def test_list_captures_and_roots(client_for: Any, tmp_path: Path) -> None:
    c = client_for()
    listed, failed = c.call("list_captures")
    assert not failed
    names = {Path(x["path"]).name for x in listed["captures"]}
    assert {"services.pcap", "mixed.pcapng", "http.pcap"} <= names
    assert all(x["size"] > 0 and x["modified"].endswith("Z") for x in listed["captures"])
    few, _ = c.call("list_captures", limit=2)
    assert len(few["captures"]) == 2 and few["more"]
    sub, _ = c.call("list_captures", folder="formats")
    assert sub["captures"] and all(
        "/formats/" in x["path"].replace("\\", "/") for x in sub["captures"]
    )
    text, failed = c.call("list_captures", folder=str(tmp_path))
    assert failed and "outside" in text

    outside = tmp_path / "x.pcap"
    shutil.copy(FIXTURES / "http.pcap", outside)
    text, failed = c.call("capture_info", capture=str(outside))
    assert failed and "outside the folders" in text
    text, failed = c.call("capture_info", capture="../fixtures/../../README.md")
    assert failed and "outside the folders" in text
    text, failed = c.call("capture_info", capture="nope.pcap")
    assert failed and "no such file" in text
    text, failed = c.call("capture_info", capture="")
    assert failed and "'capture' is missing" in text
    by_path, failed = c.call("capture_info", path="http.pcap")  # what models sometimes send
    assert not failed and by_path["packets"] > 0
    by_file, failed = c.call("capture_info", file="http.pcap")
    assert not failed and by_file == by_path


@pytest.mark.tshark
def test_statistics_tools(client_for: Any) -> None:
    c = client_for()
    info, failed = c.call("capture_info", capture="services.pcap")
    assert not failed
    assert info["packets"] == 61 and info["firstPacket"].endswith("Z")
    assert info["fileFormat"] and info["tshark"]

    counted, _ = c.call("count_packets", capture="services.pcap", filter="dns", examples=3)
    assert counted["count"] > 3 and len(counted["packets"]) == 3
    text, failed = c.call("count_packets", capture="services.pcap", filter="dns ==")
    assert failed and "filter" in text

    conv, _ = c.call("statistics", capture="services.pcap", kind="conversations", limit=2)
    assert conv["columns"][:4] == ["Address A", "Address B", "Packets", "Bytes"]
    assert len(conv["rows"]) == 2 and conv["omittedRows"] >= 1
    sizes = [r["cells"][3] for r in conv["rows"]]
    assert sizes == sorted(sizes, reverse=True)
    assert conv["rows"][0]["filter"].startswith("ip.addr ==")
    phs, _ = c.call("statistics", capture="services.pcap", kind="protocol_hierarchy")
    assert any("depth" in r for r in phs["rows"])
    text, failed = c.call("statistics", capture="services.pcap", kind="nope")
    assert failed and "kind" in text

    triage, _ = c.call("triage", capture="services.pcap")
    assert triage["packets"] == 61
    ids = {f["id"] for f in triage["found"]}
    assert {"dns_queries", "http_client_errors"} <= ids
    counts = [f["packets"] for f in triage["found"]]
    assert counts == sorted(counts, reverse=True)
    assert "malformed" in triage["none"]
    assert triage["twoPass"] and not triage["notAvailable"]
    assert triage["scans"] == []  # (no port scans or host sweeps in services.pcap)
    by_id = {f["id"]: f for f in triage["found"]}
    assert by_id["icmp_unanswered"]["firstPacket"] == 61  # found with two passes only
    assert "statistics kind=dns" in by_id["dns_queries"]["next"]
    assert "statistics kind=http" in by_id["http_client_errors"]["next"]

    dns, _ = c.call("statistics", capture="services.pcap", kind="dns")
    assert dns["omittedRows"] == 0, "tree reports default to 100 rows"

    valid, _ = c.call("validate_filter", filter="tcp.port == 80")
    assert valid == {"valid": True}
    invalid, _ = c.call("validate_filter", filter="tcp.port ==")
    assert invalid["valid"] is False and invalid["error"]
    fields, _ = c.call("search_fields", query="dns reply code", limit=5)
    assert any(f["name"] == "dns.flags.rcode" for f in fields["fields"])


@pytest.mark.tshark
def test_overview_and_sessions(client_for: Any) -> None:
    c = client_for()
    ov, failed = c.call("overview", capture="sessions.pcap", limit=2, buckets=6)
    assert not failed
    assert (ov["packets"], ov["bytes"]) == (62, 5154)
    assert sum(ov["timeline"]["packets"]) == 62 and len(ov["timeline"]["packets"]) <= 6
    assert ov["timeline"]["busiest"]["packets"] == max(ov["timeline"]["packets"])
    addresses = ov["addresses"]
    assert len(addresses["items"]) == 2 and addresses["more"] == addresses["total"] - 2
    assert addresses["items"][0]["filter"] == "ip.addr == 192.168.1.10"
    assert ov["http"]["requests"] == 7 and len(ov["http"]["statuses"]["items"]) == 2
    assert {"dns", "tls", "protocols", "services"} <= set(ov)
    limited, _ = c.call("overview", capture="sessions.pcap", filter="dns")
    assert limited["packets"] == 9 and limited["absent"] == ["http", "tls"]
    assert "absent" not in ov

    http, failed = c.call("sessions", capture="sessions.pcap", kind="http")
    assert not failed and http["summary"] == {"requests": 7, "unanswered": 1}
    assert http["matching"] == len(http["rows"]) == 7 and not http["more"]
    assert http["columns"][7] == "Status"
    bad, _ = c.call("sessions", capture="sessions.pcap", kind="http", only_problems=True)
    assert [r["cells"][7] for r in bad["rows"]] == [500, 404, None, 404]
    assert bad["rows"][2]["cells"][8] == "No response" and "response" not in bad["rows"][2]
    page, _ = c.call("sessions", capture="sessions.pcap", kind="http", offset=5, limit=1)
    assert [r["frame"] for r in page["rows"]] == [59] and page["more"]
    dns, _ = c.call("sessions", capture="sessions.pcap", kind="dns", only_problems=True)
    assert [r["cells"][7] for r in dns["rows"]] == ["NXDomain", "No response"]
    tls, _ = c.call("sessions", capture="sessions.pcap", kind="tls", only_problems=True)
    assert [r["cells"][1] for r in tls["rows"]] == ["cdn.example.net"]
    assert tls["rows"][0]["filter"] == "tcp.stream in {4}"
    text, failed = c.call("sessions", capture="sessions.pcap", kind="smtp")
    assert failed and "kind" in text
    text, failed = c.call("sessions", capture="sessions.pcap", kind="dns", only_problems="yes")
    assert failed and "true or false" in text


@pytest.mark.tshark
def test_tcp_stream(client_for: Any) -> None:
    c = client_for()
    retrans, _ = c.call(
        "count_packets", capture="office-after.pcap", filter="tcp.analysis.retransmission"
    )
    assert retrans["count"] >= 1
    first = retrans["packets"][0]
    health, failed = c.call("tcp_stream", capture="office-after.pcap", packet=first)
    assert not failed
    assert health["filter"] == f"tcp.stream == {health['stream']}"
    assert first in health["retransmissionPackets"]
    sent = [d for d in health["directions"] if d["retransmissions"]]
    assert len(sent) == 1 and sent[0]["retransmissionRate"] > 0
    assert sent[0]["direction"].startswith(health["endpoints"][0]) or sent[0][
        "direction"
    ].startswith(health["endpoints"][1])
    by_number, _ = c.call("tcp_stream", capture="office-after.pcap", stream=health["stream"])
    assert by_number == health
    web, _ = c.call("tcp_stream", capture="sessions.pcap", stream=0)
    assert web["syns"] == 2 and web["rtt"]["samples"] > 0
    assert web["rtt"]["minMs"] <= web["rtt"]["medianMs"] <= web["rtt"]["maxMs"]
    assert sum(d["packets"] for d in web["directions"]) == web["packets"]
    text, failed = c.call("tcp_stream", capture="sessions.pcap")
    assert failed and "stream" in text


def test_tcp_facts_of_points() -> None:
    fields = ["frame", "time", "dir", "seq", "len", "ack", "win", "rtt", "retrans", "syn"]
    points = [
        [1, 0.0, 0, 0, 0, 0, 8192, None, 0, 1],
        [2, 0.01, 1, 0, 0, 1, 4096, 0.01, 0, 1],
        [3, 0.02, 0, 1, 100, 1, 8192, 0.01, 0, 0],
        [4, 0.5, 0, 1, 100, 1, 8192, None, 1, 0],
        [5, 0.6, 1, 1, 0, 101, 0, 0.03, 0, 0],
        [6, 0.7, 1, 1, 0, 101, 2048, 0.02, 0, 0],
    ]
    facts = mcp.tcp_facts(points, fields, ["a:1", "b:2"])
    one, two = facts["directions"]
    assert (one["direction"], two["direction"]) == ("a:1 → b:2", "b:2 → a:1")
    assert (one["dataPackets"], one["bytes"], one["retransmissions"]) == (2, 200, 1)
    assert one["retransmissionRate"] == 0.5 and facts["retransmissionRate"] == 0.5
    assert (two["zeroWindows"], two["minWindow"], two["maxWindow"]) == (1, 2048, 2048)
    assert facts["rtt"] == {"samples": 4, "minMs": 10.0, "medianMs": 15.0, "maxMs": 30.0}
    assert facts["syns"] == 2 and facts["durationSeconds"] == 0.7
    assert (facts["retransmissionPackets"], facts["zeroWindowPackets"]) == ([4], [5])
    assert mcp.tcp_facts([], fields, [])["rtt"] is None


@pytest.mark.tshark
def test_voip_calls(client_for: Any) -> None:
    c = client_for()
    calls, failed = c.call("voip_calls", capture="voip-calls.pcap")
    assert not failed
    assert calls["summary"]["calls"] == 5 and calls["summary"]["withProblems"] >= 1
    assert sum(calls["summary"]["byState"].values()) == 5
    first = calls["calls"][0]
    assert (first["from"], first["endedBy"]) == ("dave@10.0.1.1", "callee")
    assert first["quality"]["mos"] > 4 and isinstance(first["messages"], int)
    # DTMF digits can be PINs: without --allow-packet-data only where and when.
    assert len(first["dtmf"]) == 3 and all("digit" not in e for e in first["dtmf"])
    assert "hidden" in calls["dtmfDigits"]
    one_way = calls["calls"][1]
    assert {p["kind"] for p in one_way["problems"]} >= {"one-way", "codec", "ssrc", "gap"}
    assert len(calls["registrations"]) == 3

    detail, _ = c.call("voip_calls", capture="voip-calls.pcap", call=0)
    assert detail["call"]["callId"] == "dtmf@10.0.1.1"
    assert detail["call"]["messages"][0] == {
        "packet": 1, "time": 0.0, "from": "10.0.1.1", "to": "10.0.1.2", "message": "INVITE (SDP)",
    }  # fmt: skip
    assert [s["stream"] for s in detail["streams"]] == first["streams"]
    assert all(s["filter"].startswith("rtp.ssrc == ") for s in detail["streams"])
    text, failed = c.call("voip_calls", capture="voip-calls.pcap", call=9)
    assert failed and "calls 0 to 4" in text

    shared = client_for(allow_packet_data=True)
    digits, _ = shared.call("voip_calls", capture="voip-calls.pcap", call=0)
    assert [e["digit"] for e in digits["call"]["dtmf"]] == ["4", "7", "#"]
    assert "dtmfDigits" not in digits

    # Nor in the signalling messages' names (IAX2 "DTMF 7", MGCP's observed
    # digits): Codex review of the 0.32.0 release PR.
    def messages(client: Any, call: int) -> list[str]:
        detail, failed = client.call("voip_calls", capture="voip-other.pcap", call=call)
        assert not failed and detail["call"]["protocol"] in ("IAX2", "MGCP")
        return [m["message"] for m in detail["call"]["messages"]]

    iax2, mgcp = messages(c, 3), messages(c, 5)
    assert "DTMF (digit hidden)" in iax2 and not any("DTMF 7" in m for m in iax2)
    assert "NTFY 4 DTMF digits hidden" in mgcp and not any("D/" in m for m in mgcp)
    assert "NTFY L/hd" in mgcp  # (other events stay)
    assert "DTMF 7" in messages(shared, 3) and "NTFY D/2,D/0,D/0,D/2" in messages(shared, 5)


@pytest.mark.tshark
def test_rtp_stream(client_for: Any) -> None:
    c = client_for()
    calls, _ = c.call("voip_calls", capture="voip.pcap")
    lossy = next(s for s in calls["calls"][0]["streams"])
    rtp, failed = c.call("rtp_stream", capture="voip.pcap", stream=lossy, buckets=4)
    assert not failed
    assert (rtp["stream"], rtp["call"]) == (lossy, calls["calls"][0]["id"])
    assert rtp["filter"].startswith("rtp.ssrc == ") and rtp["quality"]["mos"] > 3
    summary = rtp["summary"]
    assert (summary["packets"], summary["expected"], summary["lost"]) == (49, 50, 1)
    assert summary["maxDeltaPacket"] >= 1 and summary["durationSeconds"] > 0.9
    # The lost packet, with the sequence number after the gap.
    lost = [p for p in rtp["problems"] if p["problem"] == "lost"]
    assert len(lost) == 1 and lost[0]["lostBefore"] == 1 and rtp["moreProblems"] == 0
    # The timeline adds up to the summary and shows where the loss was.
    assert len(rtp["timeline"]) == 4
    assert sum(t["packets"] for t in rtp["timeline"]) == summary["packets"]
    assert sum(t["lost"] for t in rtp["timeline"]) == summary["lost"]
    assert max(t["maxJitterMs"] for t in rtp["timeline"]) == summary["maxJitter"]
    assert max(t["maxDeltaMs"] for t in rtp["timeline"]) == summary["maxDelta"]
    capped, _ = c.call("rtp_stream", capture="voip.pcap", stream=lossy, limit=0)
    assert capped["problems"] == [] and capped["moreProblems"] == len(rtp["problems"])
    text, failed = c.call("rtp_stream", capture="voip.pcap", stream=99)
    assert failed and "streams 0 to" in text
    text, failed = c.call("rtp_stream", capture="http.pcap", stream=0)
    assert failed and "no RTP streams" in text and "heuristic_rtp" in text
    # IAX2 voice isn't RTP, but is analysed the same way.
    other, _ = c.call("voip_calls", capture="voip-other.pcap")
    iax2 = next(s for s in _all_streams(c, "voip-other.pcap") if "iax2" in s)
    voice, failed = c.call("rtp_stream", capture="voip-other.pcap", stream=iax2["stream"])
    assert not failed and voice["iax2"] == iax2["iax2"] and voice["summary"]["packets"] == 50
    assert other["summary"]["calls"] > 0


def _all_streams(c: Any, capture: str) -> list[dict[str, Any]]:
    calls, _ = c.call("voip_calls", capture=capture)
    streams = list(calls["streamsWithoutCall"])
    for call in calls["calls"]:
        detail, _ = c.call("voip_calls", capture=capture, call=call["id"])
        streams += detail["streams"]
    return streams


@pytest.mark.tshark
def test_sequence_check(client_for: Any) -> None:
    c = client_for()
    seq, failed = c.call(
        "sequence_check",
        capture="sequences.pcap",
        sequence="gtp.seq_number",
        streams_by=["gtp.teid"],
        wrap_bits=16,
    )
    assert not failed
    assert seq["summary"]["streams"] == 4 and seq["summary"]["withProblems"] == 2
    assert (seq["summary"]["missing"], seq["summary"]["late"]) == (2, 1)
    assert seq["moreStreams"] == 0 and "keyValues" not in seq
    # Streams with problems first, each problem with its packet; tunnel ids
    # are numbers, so they are shown (and filter the stream).
    first = seq["streams"][0]
    assert first["key"] == {"gtp.teid": "0x00000200"} and first["missing"] == 2
    assert first["filter"] == "gtp.teid == 0x00000200 && gtp.seq_number"
    assert {p["kind"] for p in first["problems"]} >= {"gap", "late"}
    assert all(isinstance(p["packet"], int) for p in first["problems"])
    clean = seq["streams"][-1]
    assert clean["problems"] == [] and clean["missing"] == 0
    # Without wrap_bits, the 16-bit counter's wrap reads as a restart or a gap.
    unwrapped, _ = c.call(
        "sequence_check", capture="sequences.pcap", sequence="gtp.seq_number",
        streams_by="gtp.teid",
    )  # fmt: skip
    assert unwrapped["summary"] != seq["summary"] and unwrapped["streamsBy"] == ["gtp.teid"]
    few, _ = c.call(
        "sequence_check", capture="sequences.pcap", sequence="gtp.seq_number",
        streams_by=["gtp.teid"], wrap_bits=16, limit=1, problems=1,
    )  # fmt: skip
    assert len(few["streams"]) == 1 and few["moreStreams"] == 3
    assert len(few["streams"][0]["problems"]) == 1
    assert few["streams"][0]["moreProblems"] == len(first["problems"]) - 1
    # A text key (an address here; a LIID in a delivery) is packet contents:
    # streams are numbered, their problems' packets still given.
    by_address, _ = c.call(
        "sequence_check", capture="sequences.pcap", sequence="gtp.seq_number",
        streams_by=["ip.src"],
    )  # fmt: skip
    assert "hidden" in by_address["keyValues"]
    assert all("key" not in s and "filter" not in s for s in by_address["streams"])
    shown, _ = client_for(allow_packet_data=True).call(
        "sequence_check", capture="sequences.pcap", sequence="gtp.seq_number",
        streams_by=["ip.src"],
    )  # fmt: skip
    assert "keyValues" not in shown and "ip.src" in shown["streams"][0]["key"]
    for bad, words in (
        ({"sequence": ""}, "sequence"),
        ({"sequence": "gtp.seq_number", "wrap_bits": 12}, "wrap_bits"),
        ({"sequence": "no.such_field"}, "no.such_field"),
    ):
        text, failed = c.call("sequence_check", capture="sequences.pcap", **bad)
        assert failed and words in text, (bad, text)


def test_sequence_streams_of_the_panel_table() -> None:
    blank = [None] * 8
    rows = [
        {
            "cells": ["0x1", 9, 1, 12, 2, 0, 0, 0, "2 missing"],
            "frame": 3,
            "filter": "k",
            "depth": 0,
        },
        {"cells": ["Missing 4", *blank], "frame": 7, "depth": 1, "problem": "gap"},
        {"cells": ["… 1,234 more problems", *blank], "depth": 1},
        {"cells": ["0x2", 5, 1, 5, 0, 0, 0, 0, "fine"], "frame": 4, "depth": 0},
        {"cells": ["not … 9 more problems at all", *blank], "depth": 1},
    ]
    one, two = mcp._sequence_streams(rows, 1)
    assert (one["values"], one["missing"], one["firstPacket"], one["filter"]) == (
        ["0x1"],
        2,
        3,
        "k",
    )
    assert one["problems"] == [{"kind": "gap", "text": "Missing 4", "packet": 7}]
    assert one["moreProblems"] == 1234
    assert (two["problems"], two["moreProblems"], two["result"]) == ([], 0, "fine")


@pytest.mark.tshark
def test_export_objects_and_credentials(client_for: Any) -> None:
    c = client_for()
    found, failed = c.call("export_objects", capture="objects.pcap")
    assert not failed
    assert set(found["byProtocol"]) >= {"http", "tftp", "imf"}
    assert found["total"] == sum(p["files"] for p in found["byProtocol"].values())
    logo = next(f for f in found["files"] if f["name"] == "logo.png")
    assert (logo["contentType"], logo["host"], logo["size"]) == ("image/png", "example.com", 776)
    assert logo["filter"] == f"frame.number == {logo['packet']}"
    tftp, _ = c.call("export_objects", capture="objects.pcap", protocol="tftp", limit=1)
    assert {f["protocol"] for f in tftp["files"]} == {"tftp"} and tftp["protocol"] == "tftp"
    assert tftp["total"] == found["byProtocol"]["tftp"]["files"]
    text, failed = c.call("export_objects", capture="objects.pcap", protocol="gopher")
    assert failed and "protocol" in text

    logins, failed = c.call("credentials", capture="credentials.pcap")
    assert not failed and logins["total"] >= 4
    assert set(logins["byProtocol"]) >= {"HTTP basic auth", "FTP"}
    # User names are packet contents.
    assert all("username" not in row for row in logins["logins"])
    assert "hidden" in logins["usernames"]
    ftp = next(row for row in logins["logins"] if row["protocol"] == "FTP")
    assert ftp["usernamePacket"] < ftp["packet"]
    shared, _ = client_for(allow_packet_data=True).call("credentials", capture="credentials.pcap")
    assert {"alice", "bob"} <= {row["username"] for row in shared["logins"]}
    assert "usernames" not in shared
    # Triage's clear-text check points at it.
    triaged, _ = c.call("triage", capture="credentials.pcap")
    check = next(f for f in triaged["found"] if f["id"] == "cleartext_credentials")
    assert check["next"].startswith("credentials")


@pytest.mark.tshark
def test_expert_rows_keep_a_few_packets(client_for: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp, "MAX_EXPERT_FRAMES", 3)
    c = client_for()
    expert, _ = c.call("statistics", capture="office-after.pcap", kind="expert")
    many = [r for r in expert["rows"] if r["cells"][-1] > 3]
    assert many and all(len(r["frames"]) == 3 for r in many)
    assert all(r["moreFrames"] == r["cells"][-1] - 3 for r in many)
    assert all("moreFrames" not in r for r in expert["rows"] if r["cells"][-1] <= 3)


@pytest.mark.tshark
def test_structured_results(client_for: Any) -> None:
    c = client_for(stand_ins=True)
    c.request("initialize", {"protocolVersion": "2025-06-18"})
    res = c.request(
        "tools/call", {"name": "count_packets", "arguments": {"capture": "dns.pcap", "filter": ""}}
    )["result"]
    structured = res["structuredContent"]
    assert structured == json.loads(res["content"][0]["text"])
    assert structured["capture"] == "dns.pcap" and structured["count"] > 0
    conv = c.request(
        "tools/call",
        {"name": "statistics", "arguments": {"capture": "dns.pcap", "kind": "conversations"}},
    )["result"]
    assert conv["structuredContent"]["rows"][0]["cells"][0].startswith("IP_")  # (masked too)
    assert conv["structuredContent"] == json.loads(conv["content"][0]["text"])
    failed = c.request("tools/call", {"name": "overview", "arguments": {"capture": "x.pcap"}})
    assert failed["result"]["isError"] and "structuredContent" not in failed["result"]
    old = client_for()
    old.request("initialize", {"protocolVersion": "2025-03-26"})
    res = old.request(
        "tools/call", {"name": "count_packets", "arguments": {"capture": "dns.pcap", "filter": ""}}
    )["result"]
    assert "structuredContent" not in res


def test_output_schemas_are_listed_for_structured_clients(client_for: Any) -> None:
    for name, schema in OUTPUT_SCHEMAS.items():
        Draft202012Validator.check_schema(schema)
        assert schema["type"] == "object", name
    c = client_for(allow_packet_data=True)
    c.request("initialize", {"protocolVersion": "2025-06-18"})
    tools = c.request("tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} == set(OUTPUT_SCHEMAS)
    assert all(t["outputSchema"] == OUTPUT_SCHEMAS[t["name"]] for t in tools)
    old = client_for()
    old.request("initialize", {"protocolVersion": "2025-03-26"})
    assert not any("outputSchema" in t for t in old.request("tools/list")["result"]["tools"])


@pytest.mark.tshark
@pytest.mark.parametrize("stand_ins", [False, True])
def test_every_tool_output_matches_its_schema(client_for: Any, stand_ins: bool) -> None:
    # (Client.request checks each structured result; this calls every tool,
    # and the variants whose results differ in shape.)
    c = client_for(allow_packet_data=True, allow_packet_bytes=True, stand_ins=stand_ins)
    c.request("initialize", {"protocolVersion": "2025-06-18"})
    calls: list[tuple[str, dict[str, Any]]] = [
        ("list_captures", {"limit": 3}),
        ("plugins", {}),
        ("capture_info", {"capture": "http.pcap"}),
        ("count_packets", {"capture": "dns.pcap", "filter": "dns"}),
        *(
            ("statistics", {"capture": "services.pcap", "kind": kind})
            for kind in ("conversations", "protocol_hierarchy", "expert", "io", "dns", "http")
        ),
        ("statistics", {"capture": "network.pcap", "kind": "hosts", "filter": "dns"}),
        ("triage", {"capture": "office-after.pcap"}),
        ("overview", {"capture": "sessions.pcap", "limit": 2, "buckets": 4}),
        ("overview", {"capture": "dns.pcap", "filter": "udp"}),
        *(
            ("sessions", {"capture": "sessions.pcap", "kind": kind, "only_problems": True})
            for kind in ("http", "dns", "tls")
        ),
        ("voip_calls", {"capture": "voip-calls.pcap"}),
        ("voip_calls", {"capture": "voip-calls.pcap", "call": 0}),
        ("voip_calls", {"capture": "voip-media.pcap", "call": 0}),
        ("voip_calls", {"capture": "voip-other.pcap"}),
        ("tcp_stream", {"capture": "http.pcap", "stream": 0}),
        ("tcp_stream", {"capture": "office-after.pcap", "packet": 1}),
        ("rtp_stream", {"capture": "voip.pcap", "stream": 0}),
        ("rtp_stream", {"capture": "voip-other.pcap", "stream": 5, "limit": 0}),
        (
            "sequence_check",
            {"capture": "sequences.pcap", "sequence": "gtp.seq_number", "streams_by": ["ip.src"]},
        ),
        ("sequence_check", {"capture": "sequences.pcap", "sequence": "gtp.seq_number"}),
        ("export_objects", {"capture": "objects.pcap"}),
        ("credentials", {"capture": "credentials.pcap"}),
        ("compare_captures", {"before": "office-before.pcap", "after": "office-after.pcap"}),
        ("field_values", {"capture": "dns.pcap", "field": "dns.qry.name"}),
        ("validate_filter", {"filter": "dns"}),
        ("validate_filter", {"filter": "dns =="}),
        ("search_fields", {"query": "dns response code"}),
        ("list_packets", {"capture": "dns.pcap", "limit": 3}),
        ("packet_details", {"capture": "dns.pcap", "packet": 1, "protocols": ["dns"]}),
        ("follow_stream", {"capture": "http.pcap", "protocol": "tcp", "stream": 0}),
        ("follow_stream", {"capture": "streams.pcapng", "protocol": "http2", "stream": 0}),
    ]
    for name, args in calls:
        result, failed = c.call(name, **args)
        assert not failed, (name, args, result)
    assert c.checked == set(OUTPUT_SCHEMAS)
    # A result that doesn't match its schema fails the check.
    bad = {**c.call("count_packets", capture="dns.pcap", filter="dns")[0], "count": "six"}
    with pytest.raises(Exception, match="is not of type 'integer'"):
        Draft202012Validator(OUTPUT_SCHEMAS["count_packets"]).validate(bad)


@pytest.mark.tshark
def test_bare_names_labels_and_kind_spellings(client_for: Any, tmp_path: Path) -> None:
    for where in ("a/b/one.pcap", "x/two.pcap", "y/two.pcap"):
        (tmp_path / where).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(FIXTURES / "http.pcap", tmp_path / where)
    c = client_for(roots=[tmp_path])
    # A name list_captures showed, without its folder: the one file of that name.
    stats, failed = c.call("statistics", capture="one.pcap", kind="Protocol Hierarchy")
    assert not failed
    # Every result names its capture first (an assistant running two at once
    # mixed up which conversations came from which).
    assert next(iter(stats)) == "capture" and stats["capture"] == str(Path("a/b/one.pcap"))
    triaged, _ = c.call("triage", capture="a/b/one.pcap")
    assert triaged["capture"] == str(Path("a/b/one.pcap"))
    text, failed = c.call("capture_info", capture="two.pcap")
    assert failed and "several files" in text and "two.pcap" in text
    text, failed = c.call("capture_info", capture="three.pcap")
    assert failed and "no such file" in text and "list_captures" in text
    text, failed = c.call("capture_info", capture="a/one.pcap")  # a folder given: no search
    assert failed and "no such file" in text
    for kind in ("phs", "conversation", "Expert Information", "packet-lengths"):
        _, failed = c.call("statistics", capture="one.pcap", kind=kind)
        assert not failed, kind
    text, failed = c.call("statistics", capture="one.pcap", kind="nope")
    assert failed and "'nope'" in text and "protocol_hierarchy" in text


@pytest.mark.tshark
def test_compare_captures(client_for: Any) -> None:
    c = client_for(stand_ins=True)
    d, failed = c.call(
        "compare_captures", before="office-before.pcap", after="office-after.pcap", limit=3
    )
    assert not failed
    assert (d["before"]["name"], d["after"]["name"]) == ("office-before.pcap", "office-after.pcap")
    resets = next(x for x in d["checks"]["changed"] if x["id"] == "tcp_resets")
    assert (resets["before"], resets["after"]) == (0, 5) and resets["firstPacketAfter"]
    # The scanner's address has one stand-in, in the endpoints and in its flows.
    [scanner] = d["endpoints"]["new"]
    assert scanner["address"].startswith("IP_PRIVATE_")
    assert all(f["flow"].startswith(f"tcp {scanner['address']} → ") for f in d["flows"]["new"])
    assert len(d["flows"]["new"]) == 3 and d["flows"]["more"] == {"new": 2}
    text, failed = c.call(
        "compare_captures", before="office-after.pcap", after="./office-after.pcap"
    )
    assert failed and "same file" in text
    text, failed = c.call("compare_captures", before="office-before.pcap")
    assert failed and "'after' is missing" in text


@pytest.mark.tshark
def test_triage_skips_two_pass_checks_on_big_captures(
    client_for: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(triage_checks, "TWO_PASS_LIMIT", 10)
    c = client_for()
    res, _ = c.call("triage", capture="services.pcap")
    assert not res["twoPass"]
    skipped = {x["id"]: x["why"] for x in res["notAvailable"]}
    assert set(skipped) == {x.id for x in triage_checks.CHECKS if x.two_pass}
    assert all("two passes" in why for why in skipped.values())
    assert not set(skipped) & set(res["none"])


@pytest.mark.tshark
def test_field_values(client_for: Any) -> None:
    c = client_for()
    rcodes, failed = c.call(
        "field_values",
        capture="services.pcap",
        field="dns.flags.rcode",
        filter="dns.flags.response == 1",
    )
    assert not failed
    assert rcodes["type"] == "FT_UINT16" and rcodes["filter"] == "dns.flags.response == 1"
    values = {v["value"]: v["count"] for v in rcodes["values"]}
    assert set(values) >= {"0", "3"} and sum(values.values()) == rcodes["packets"]
    responses, _ = c.call(
        "count_packets", capture="services.pcap", filter="dns.flags.response == 1"
    )
    assert rcodes["packets"] == responses["count"]
    every, _ = c.call("field_values", capture="services.pcap", field="dns.flags.rcode")
    assert every["filter"] == "" and every["values"] == rcodes["values"], "only responses have one"

    text, failed = c.call("field_values", capture="services.pcap", field="dns.qry.name")
    assert failed and "packet contents" in text and "--allow-packet-data" in text
    text, failed = c.call("field_values", capture="services.pcap", field="no.such.field")
    assert failed and "search_fields" in text
    text, failed = c.call(
        "field_values", capture="services.pcap", field="dns.flags.rcode", filter="dns =="
    )
    assert failed

    names, failed = client_for(allow_packet_data=True).call(
        "field_values", capture="services.pcap", field="dns.qry.name", limit=1
    )
    assert (
        not failed and names["values"] == [{"value": "example.com", "count": 6}] and names["more"]
    )


@pytest.mark.tshark
def test_packet_tools(client_for: Any) -> None:
    c = client_for(allow_packet_data=True)
    names = {t["name"] for t in c.request("tools/list")["result"]["tools"]}
    assert {"list_packets", "packet_details", "follow_stream"} <= names
    assert "packet contents" in c.request("initialize")["result"]["instructions"]

    page, _ = c.call("list_packets", capture="http.pcap", filter="tcp", limit=3)
    assert page["columns"][0] == "No." and len(page["rows"]) == 3 and page["more"]
    nxt, _ = c.call("list_packets", capture="http.pcap", filter="tcp", offset=3, limit=3)
    assert len(nxt["rows"]) == 3 and nxt["rows"][0][0] != page["rows"][0][0]
    every, _ = c.call("list_packets", capture="http.pcap", filter="tcp", limit=6)
    assert page["rows"] + nxt["rows"] == every["rows"], "pages follow each other"

    get = next(r for r in page["rows"] + nxt["rows"] if "GET" in str(r[6]))
    detail, _ = c.call("packet_details", capture="http.pcap", packet=int(get[0]))
    assert detail["tree"].startswith("Frame ") and "Hypertext Transfer Protocol" in detail["tree"]
    assert "\n  " in detail["tree"]  # indented children
    short, _ = c.call("packet_details", capture="http.pcap", packet=int(get[0]), max_lines=20)
    assert short["truncated"] and short["tree"].count("\n") == 19
    text, failed = c.call("packet_details", capture="http.pcap", packet=10**6)
    assert failed and "out of range" in text

    # Only the layers asked for are expanded; the others keep their summary line.
    full, _ = c.call("packet_details", capture="services.pcap", packet=48)
    assert full["layers"] == ["frame", "eth", "ip", "udp", "dns"]
    dns, _ = c.call("packet_details", capture="services.pcap", packet=48, protocols=["DNS"])
    lines = dns["tree"].split("\n")
    tops = [line for line in lines if not line.startswith(" ")]
    assert [t.split()[0] for t in tops] == ["Frame", "Ethernet", "Internet", "User", "Domain"]
    assert lines[-1].startswith("  ") and "No such name" in dns["tree"]
    assert lines.index(tops[-1]) == 4, "frame, eth, ip and udp are one line each"
    assert not dns["truncated"] and len(lines) < len(full["tree"].split("\n"))
    short, _ = c.call(
        "packet_details", capture="services.pcap", packet=48, protocols="dns", max_lines=20
    )
    assert "Response: Message is a response" in short["tree"]
    both, _ = c.call("packet_details", capture="services.pcap", packet=48, protocols="udp, dns")
    assert "Source Port: 53" in both["tree"]
    text, failed = c.call("packet_details", capture="services.pcap", packet=48, protocols=["http"])
    assert failed and "frame, eth, ip, udp, dns" in text
    text, failed = c.call("packet_details", capture="services.pcap", packet=48, protocols=[1])
    assert failed and "protocols" in text

    stream, _ = c.call("follow_stream", capture="http.pcap", protocol="tcp", stream=0)
    joined = "".join(s["text"] for s in stream["segments"])
    assert "GET " in joined and "HTTP/1.1" in joined
    assert stream["filter"] and len(stream["endpoints"]) == 2
    cut, _ = c.call("follow_stream", capture="http.pcap", protocol="tcp", stream=0, max_bytes=256)
    assert cut["truncated"] and sum(len(s["text"]) for s in cut["segments"]) <= 256
    by_packet, _ = c.call("follow_stream", capture="http.pcap", protocol="tcp", packet=int(get[0]))
    assert by_packet["stream"] == 0
    text, failed = c.call("follow_stream", capture="http.pcap", protocol="tcp")
    assert failed and "stream" in text


@pytest.mark.tshark
def test_payload_bytes_only_when_allowed(client_for: Any) -> None:
    plain = client_for(allow_packet_data=True)
    full = client_for(allow_packet_data=True, allow_packet_bytes=True)
    page, _ = plain.call("list_packets", capture="udp_custom.pcap", filter="data", limit=1)
    number = int(page["rows"][0][0])
    hidden, _ = plain.call("packet_details", capture="udp_custom.pcap", packet=number)
    shown, _ = full.call("packet_details", capture="udp_custom.pcap", packet=number)
    assert "bytes not shown" in hidden["tree"]
    assert "bytes not shown" not in shown["tree"]


@pytest.mark.tshark
def test_stand_ins_in_results_and_arguments(client_for: Any) -> None:
    real = client_for()
    masked = client_for(stand_ins=True)
    assert "IP_PRIVATE_1" in masked.request("initialize")["result"]["instructions"]
    real_conv, _ = real.call("statistics", capture="services.pcap", kind="conversations")
    conv, _ = masked.call("statistics", capture="services.pcap", kind="conversations")
    a = conv["rows"][0]["cells"][0]
    assert a.startswith(("IP_PRIVATE_", "IP_PUBLIC_"))
    assert real_conv["rows"][0]["cells"][0].count(".") == 3
    # A filter naming stand-ins is turned back before tshark runs it.
    by_token, _ = masked.call("count_packets", capture="services.pcap", filter=f"ip.addr == {a}")
    by_real, _ = real.call(
        "count_packets",
        capture="services.pcap",
        filter=f"ip.addr == {real_conv['rows'][0]['cells'][0]}",
    )
    assert by_token["count"] == by_real["count"] > 0
    assert by_token["filter"] == f"ip.addr == {a}"


@pytest.mark.tshark
def test_captures_reopen_when_changed_and_stay_few(
    client_for: Any, tmp_path: Path, ctx: RequestContext
) -> None:
    for name in ("http.pcap", "dns.pcap", "services.pcap"):
        shutil.copy(FIXTURES / name, tmp_path / name)
    c = client_for(roots=[tmp_path], max_open=2)
    info, _ = c.call("capture_info", capture="http.pcap")
    first = c.captures.get(tmp_path / "http.pcap", ctx)
    shutil.copy(FIXTURES / "dns.pcap", tmp_path / "http.pcap")  # the file changes
    changed, _ = c.call("capture_info", capture="http.pcap")
    assert changed["packets"] != info["packets"]
    assert c.captures.get(tmp_path / "http.pcap", ctx) is not first
    c.call("capture_info", capture="dns.pcap")
    c.call("capture_info", capture="services.pcap")
    assert len(c.captures._entries) == 2


@pytest.mark.tshark
def test_a_capture_in_use_stays_open_when_evicted(
    client_for: Any, tmp_path: Path, ctx: RequestContext
) -> None:
    for name in ("http.pcap", "dns.pcap"):
        shutil.copy(FIXTURES / name, tmp_path / name)
    captures = client_for(roots=[tmp_path], max_open=1).captures
    with captures.pinned():
        busy = captures.get(tmp_path / "http.pcap", ctx)
        # Another call opens a second capture meanwhile: http.pcap leaves the table.
        other = threading.Thread(target=captures.get, args=(tmp_path / "dns.pcap", ctx))
        other.start()
        other.join()
        assert list(captures._entries) == [tmp_path / "dns.pcap"]
        assert busy._file is not None, "still usable by the call that has it"
        assert busy.capture_info({}, ctx)["frames"] > 0
    assert busy._file is None, "shut down once that call ended"


@pytest.mark.tshark
def test_cancelled_call_gets_no_answer(client_for: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    c = client_for()
    started = threading.Event()
    stopped = threading.Event()

    def slow(_args: dict[str, Any], ctx: RequestContext) -> Any:
        started.set()
        while not ctx.token.cancelled:
            time.sleep(0.01)
        stopped.set()
        ctx.token.raise_if_cancelled()

    monkeypatch.setattr(c.server.toolbox.tools["triage"], "run", slow)
    c.send(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "triage", "arguments": {}, "_meta": {"progressToken": "p"}},
        }
    )
    assert started.wait(10)
    c.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 7}})
    assert stopped.wait(10)
    with pytest.raises(TimeoutError):
        c.wait(7, timeout=0.5)
    assert c.request("ping")["result"] == {}


@pytest.mark.tshark
def test_progress_notifications(client_for: Any) -> None:
    c = client_for()
    res = c.request(
        "tools/call",
        {
            "name": "statistics",
            "arguments": {"capture": "services.pcap", "kind": "expert"},
            "_meta": {"progressToken": "tok"},
        },
    )
    assert not res["result"]["isError"]
    notes = c.notifications("notifications/progress")
    assert notes and all(n["params"]["progressToken"] == "tok" for n in notes)


def _options(path: Path, default: Any = None, folders: Any = None) -> Path:
    """A dissection options file as the extension writes it (--options)."""
    data = {"format": mcp.OPTIONS_FORMAT, "default": default or {}, "folders": folders or []}
    path.write_text(json.dumps(data))
    return path


def test_read_dissection(tmp_path: Path) -> None:
    missing = mcp.read_dissection(tmp_path / "none.json")
    assert missing.default == {} and missing.warning and "none.json" in missing.warning
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    with pytest.raises(mcp.ToolFailureError, match="valid JSON"):
        mcp.read_dissection(bad)
    bad.write_text('{"format": "other"}')
    with pytest.raises(mcp.ToolFailureError, match="isn't a PCAP Lens"):
        mcp.read_dissection(bad)
    outer, inner = tmp_path / "work", tmp_path / "work" / "li"
    inner.mkdir(parents=True)
    path = _options(
        tmp_path / "options.json",
        default={"decodeAs": ["udp.port==1,dns"], "names": {"network": True}},
        folders=[
            {"root": str(outer), "options": {"profile": "Work"}},
            {"root": str(inner), "options": {"lua": ["/x/li.lua"], "keys": [{"type": "ssh"}]}},
        ],
    )
    got = mcp.read_dissection(path)
    # Only dissection settings: never keys (secrets), and the MCP server's own -n stays.
    assert got.default == {"decodeAs": ["udp.port==1,dns"]}
    assert got.for_path(inner.resolve() / "a.pcap") == {"lua": ["/x/li.lua"]}, "deepest wins"
    assert got.for_path(outer.resolve() / "a.pcap") == {"profile": "Work"}
    assert got.for_path(tmp_path / "a.pcap") == got.default
    assert mcp._summary({"lua": ["/x/li.lua"], "prefs": {"b": 1, "a": 2}}) == {
        "luaScripts": ["li.lua"],
        "preferences": ["a", "b"],
    }


@pytest.mark.tshark
def test_captures_are_dissected_with_the_viewers_settings(client_for: Any, tmp_path: Path) -> None:
    for folder in ("a", "b"):
        (tmp_path / folder).mkdir()
        shutil.copy(FIXTURES / "mixed.pcapng", tmp_path / folder / "mixed.pcapng")
    decode = {"decodeAs": ["udp.port==9999,syslog"]}
    options = _options(
        tmp_path / "options.json", folders=[{"root": str(tmp_path / "a"), "options": decode}]
    )
    c = client_for(roots=[tmp_path], options_file=options)
    in_a, _ = c.call("count_packets", capture="a/mixed.pcapng", filter="syslog")
    in_b, _ = c.call("count_packets", capture="b/mixed.pcapng", filter="syslog")
    assert in_a["count"] > 0 and in_b["count"] == 0, "each folder's own settings"
    info, _ = c.call("capture_info", capture="a/mixed.pcapng")
    assert info["dissectedWith"] == {"decodeAs": ["udp.port==9999,syslog"]}
    # The settings change (VS Code rewrites the file): the capture is dissected again.
    _options(options, default=decode)
    again, _ = c.call("count_packets", capture="a/mixed.pcapng", filter="syslog")
    assert again["count"] == in_a["count"]
    now_b, _ = c.call("count_packets", capture="b/mixed.pcapng", filter="syslog")
    assert now_b["count"] == in_a["count"], "the default now decodes it too"
    _options(options)
    gone, _ = c.call("count_packets", capture="a/mixed.pcapng", filter="syslog")
    assert gone["count"] == 0
    # A file that can't be read fails the call rather than dissect differently.
    options.write_text("{")
    text, failed = c.call("count_packets", capture="a/mixed.pcapng", filter="syslog")
    assert failed and "valid JSON" in text


@pytest.mark.tshark
def test_a_missing_options_file_is_a_warning(client_for: Any, tmp_path: Path) -> None:
    c = client_for(options_file=tmp_path / "options.json")
    info, failed = c.call("capture_info", capture="http.pcap")
    assert not failed and info["dissectedWith"] == {}
    assert any("options.json" in w for w in info["warnings"])


@pytest.mark.tshark
@pytest.mark.skipif(AS_ROOT, reason="tshark disables Lua dissectors when running as root")
def test_lua_fields_validate_and_are_found(client_for: Any, tmp_path: Path) -> None:
    plain = client_for()
    res, _ = plain.call("validate_filter", filter="example.seq == 1")
    assert res["valid"] is False
    options = _options(tmp_path / "options.json", default={"lua": [str(EXAMPLE_LUA)]})
    c = client_for(options_file=options)
    res, _ = c.call("validate_filter", filter="example.seq == 1")
    assert res == {"valid": True}
    found, _ = c.call("search_fields", query="example sequence")
    assert "example.seq" in [f["name"] for f in found["fields"]]
    listed, _ = c.call("plugins")
    assert listed["luaScripts"] == ["example.lua"]


@pytest.mark.tshark
def test_plugins(client_for: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    c = client_for()
    res, failed = c.call("plugins")
    assert not failed and isinstance(res["plugins"], list) and res["tshark"]
    assert set(res["folders"]) >= {"personalPlugins", "globalPlugins"}
    if AS_ROOT:
        assert "root" in res["warnings"][0]
        return
    # A plugin folder given by WIRESHARK_PLUGIN_DIR (which the extension passes
    # on to the server) is where tshark looks for plugins.
    folder = tmp_path / "plugins"
    folder.mkdir()
    (folder / "mine.lua").write_text('local p = Proto("mineproto", "Mine")\n')
    monkeypatch.setenv("WIRESHARK_PLUGIN_DIR", str(folder))
    res, _ = client_for().call("plugins")
    assert "mine.lua" in [p["name"] for p in res["plugins"]]


def test_arguments_and_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    config, level = mcp.parse_args([])
    assert config.roots == [tmp_path.resolve()]
    assert not config.allow_packet_data and not config.stand_ins
    assert config.cache_dir == mcp.default_cache_dir() and level == "WARNING"
    config, _ = mcp.parse_args(
        ["--root", str(FIXTURES), "--allow-packet-bytes", "--no-cache", "--stand-ins"]
    )
    assert config.roots == [FIXTURES.resolve()] and config.cache_dir is None
    assert config.stand_ins and not config.allow_packet_bytes, "bytes need packet data"
    config, _ = mcp.parse_args(
        ["--allow-packet-data", "--allow-packet-bytes", "--cache-dir", "~/c"]
    )
    assert config.allow_packet_bytes and config.cache_dir == Path("~/c").expanduser()
    assert config.options_file is None
    config, _ = mcp.parse_args(["--options", "~/o.json"])
    assert config.options_file == Path("~/o.json").expanduser()
    with pytest.raises(SystemExit):
        mcp.parse_args(["--root", str(tmp_path / "missing")])
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    if sys.platform not in ("win32", "darwin"):
        assert mcp.default_cache_dir() == tmp_path / "pcap-lens" / "index-cache"


@pytest.mark.tshark
def test_runs_as_a_program(tmp_path: Path) -> None:
    """``python -m pcap_backend.mcp``: stdout holds only protocol messages."""
    env = {**os.environ, "PYTHONPATH": str(BACKEND)}
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "capture_info", "arguments": {"capture": "http.pcap"}},
        },
    ]
    proc = subprocess.Popen(
        [sys.executable, "-P", "-m", "pcap_backend.mcp", "--root", str(FIXTURES), "--cache-dir",
         str(tmp_path / "cache")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )  # fmt: skip
    answers: list[dict[str, Any]] = []
    try:
        assert proc.stdin is not None and proc.stdout is not None
        for r in requests:
            proc.stdin.write(json.dumps(r).encode() + b"\n")
            proc.stdin.flush()
        while len(answers) < 2:
            line = proc.stdout.readline()
            assert line, "the server ended early"
            answers.append(json.loads(line))
        proc.stdin.close()
        assert proc.wait(timeout=30) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()
    info = json.loads(answers[1]["result"]["content"][0]["text"])
    assert info["packets"] > 0
    assert any((tmp_path / "cache").iterdir()), "the index was saved"


def test_packet_times_outside_datetime_years() -> None:
    # Wireshark's cosine_coverage capture has packets tshark dates in year -1.
    assert mcp._iso(1_700_000_000) == "2023-11-14T22:13:20Z"
    assert mcp._iso(-62_169_984_000) == "-0001-11-30T00:00:00Z"
    assert mcp._iso(None) is None

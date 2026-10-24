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

from pcap_backend import mcp
from pcap_backend import triage as triage_checks
from pcap_backend.mcp import Captures, McpConfig, McpServer, Toolbox
from pcap_backend.protocol import RequestContext
from pcap_backend.standins import AddressMasker

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
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
        return self.wait(rid, timeout)

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
        "field_values",
        "validate_filter",
        "search_fields",
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
    assert failed and "packet contents" in text
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
    assert nxt["rows"][0][0] != page["rows"][0][0]

    get = next(r for r in page["rows"] + nxt["rows"] if "GET" in str(r[6]))
    detail, _ = c.call("packet_details", capture="http.pcap", packet=int(get[0]))
    assert detail["tree"].startswith("Frame ") and "Hypertext Transfer Protocol" in detail["tree"]
    assert "\n  " in detail["tree"]  # indented children
    short, _ = c.call("packet_details", capture="http.pcap", packet=int(get[0]), max_lines=20)
    assert short["truncated"] and short["tree"].count("\n") == 19
    text, failed = c.call("packet_details", capture="http.pcap", packet=10**6)
    assert failed and "out of range" in text

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
        [sys.executable, "-m", "pcap_backend.mcp", "--root", str(FIXTURES), "--cache-dir",
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

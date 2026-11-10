"""pcap-lens-replay (replay_cli.py): mapping rules, setup files, the plan,
results, and replays of replay.pcap into local servers."""

from __future__ import annotations

import io
import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from pcap_backend import replay_cli
from pcap_backend.replay_cli import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_PROBLEMS,
    EXIT_USAGE,
    UsageError,
    choose_destinations,
    dissection_options,
    make_plan,
    parse_rule,
    read_setup,
    results_text,
    target_outcome,
)
from test_replay import (
    DNS,
    FIXTURES,
    HI2,
    HI3,
    UDP,
    Collector,
    Datagrams,
    _free_port,
    _settle,
    generate,
)

CAPTURE = FIXTURES / "replay.pcap"
BACKEND = Path(__file__).resolve().parents[2] / "backend"
COLLECTOR = generate.REPLAY_COLLECTOR


def _target(key: str) -> dict[str, Any]:
    proto, rest = key.split(" ")
    ip, port = rest.rsplit(":", 1)
    return {"key": key, "proto": proto, "ip": ip.strip("[]"), "port": int(port)}


TARGETS = [_target(k) for k in (DNS, HI2, UDP, HI3)]


def run(*argv: str, encoding: str | None = None) -> tuple[int, str, str]:
    if encoding is None:
        out, err = io.StringIO(), io.StringIO()
        code = replay_cli.main(list(argv), out, err)
        return code, out.getvalue(), err.getvalue()
    # As a pipe or a file on Windows: the ANSI code page (cp1252 has no arrow).
    raw_out, raw_err = io.BytesIO(), io.BytesIO()
    wrapped = [io.TextIOWrapper(b, encoding=encoding) for b in (raw_out, raw_err)]
    code = replay_cli.main(list(argv), *wrapped)
    for w in wrapped:
        w.flush()
    return code, raw_out.getvalue().decode(encoding), raw_err.getvalue().decode(encoding)


def args(*argv: str) -> Any:
    return replay_cli._parser().parse_args(list(argv))


# -- mapping rules ----------------------------------------------------------------------


def test_map_rules() -> None:
    r = parse_rule(f"tcp/{COLLECTOR}:11000=127.0.0.1:2000")
    assert (r.proto, r.host, r.port, r.to_host, r.to_port, r.exact) == (
        "tcp", COLLECTOR, 11000, "127.0.0.1", 2000, True,
    )  # fmt: skip
    # Keys as replay_targets and --list write them, wildcards, the recorded port kept.
    assert parse_rule(f"{HI3}=localhost").to_port is None
    assert parse_rule(f"{HI3}=localhost").proto == "tcp"
    wild = parse_rule("*:11001=127.0.0.1")
    assert (wild.proto, wild.host, wild.port, wild.exact) == (None, None, 11001, False)
    assert parse_rule("udp/*:*=10.0.0.9").matches(_target(UDP))
    assert not parse_rule("udp/*:*=10.0.0.9").matches(_target(HI2))
    six = parse_rule("udp/[2001:db8::0001]:53=[::1]:5353")
    assert (six.host, six.to_host, six.to_port) == ("2001:db8::0001", "::1", 5353)
    assert six.matches(_target("udp [2001:db8::1]:53"))  # (the same address, written short)
    assert parse_rule("*/*:53=::1").to_host == "::1"  # (an IPv6 address alone: no port)
    for bad in (
        "tcp/*:11000",  # no destination
        "=127.0.0.1",
        "tcp/10.0.0.1=127.0.0.1",  # no port
        "tcp/*:70000=127.0.0.1",
        "tcp/*:11000=*",
        "tcp/[::1:53=127.0.0.1",
        "tcp/*:11000=127.0.0.1:x",
    ):
        with pytest.raises(UsageError):
            parse_rule(bad)


def test_destinations() -> None:
    rules = [
        parse_rule("tcp/*:*=10.0.0.9"),
        parse_rule(f"{HI3}=127.0.0.1:3000"),  # (exact: before the wildcard)
        parse_rule("udp/*:9999=127.0.0.1"),  # matches nothing
    ]
    chosen, left_out, unused = choose_destinations(TARGETS, rules, None)
    assert chosen == {
        HI2: {"ip": "10.0.0.9", "port": 11000},
        HI3: {"ip": "127.0.0.1", "port": 3000},
    }
    assert left_out == [DNS, UDP] and unused == [rules[2]]
    # --to fills the rest; a setup's targets come first, its unchecked ones stay out.
    setup = {
        DNS: {"ip": "127.0.0.1", "port": 53, "enabled": False},
        UDP: {"ip": "127.0.0.2", "port": 5000, "enabled": True},
        HI2: {"ip": "127.0.0.3", "port": 1, "enabled": True},
    }
    chosen, left_out, _ = choose_destinations(TARGETS, [rules[1]], "127.0.0.5", setup)
    assert chosen == {
        HI2: {"ip": "127.0.0.3", "port": 1},
        UDP: {"ip": "127.0.0.2", "port": 5000},
        HI3: {"ip": "127.0.0.1", "port": 3000},
    }
    assert left_out == [DNS]
    # A rule overrides the setup, even an unchecked target.
    chosen, _, _ = choose_destinations(TARGETS, [parse_rule("udp/*:53=127.0.0.7")], None, setup)
    assert chosen[DNS] == {"ip": "127.0.0.7", "port": 53}


# -- setup files and the plan -----------------------------------------------------------


def _setup(path: Path, **doc: Any) -> Path:
    path.write_text(json.dumps({"format": "pcap-lens-replay", "version": 1, **doc}))
    return path


def test_setup_files(tmp_path: Path) -> None:
    (tmp_path / "caps").mkdir()
    setup = read_setup(
        _setup(
            tmp_path / "lab.json",
            openCapture="caps/open.pcapng",
            includeOpenCapture=True,
            openCapturePosition=1,
            captures=[
                {"path": "caps/a.pcap"},
                {"path": "caps/b.pcap", "enabled": False},
                {"path": "caps/a.pcap"},  # (twice: once)
                {"enabled": True},
                {"path": str(tmp_path / "c.pcap")},
            ],
            filter=" tcp ",
            targets={
                HI2: {"ip": "127.0.0.1", "port": 2000},
                UDP: {"ip": "127.0.0.1", "port": 3000, "enabled": False},
                DNS: {"ip": "", "port": 53},
            },
            options={"speed": 0, "loops": 3, "scope": "filter", "order": "merged", "loss": 500},
        )
    )
    caps = tmp_path / "caps"
    assert setup.open_capture == caps / "open.pcapng"
    assert setup.captures == [
        (caps / "a.pcap", True), (caps / "b.pcap", False), (tmp_path / "c.pcap", True),
    ]  # fmt: skip
    assert setup.open_at == 1 and setup.filter == "tcp"
    assert setup.targets == {
        HI2: {"ip": "127.0.0.1", "port": 2000, "enabled": True},
        UDP: {"ip": "127.0.0.1", "port": 3000, "enabled": False},
    }
    assert setup.options == {
        "speed": 0.0, "loops": 3, "scope": "filter", "order": "merged", "jitter": 0.0, "loss": 0.0,
    }  # fmt: skip
    assert setup.problems == [
        "a capture without a path was left out",
        f"{DNS}: not a recorded target with an IP and port",
    ]
    plan = make_plan(args("--setup", str(tmp_path / "lab.json")))
    assert plan.files == [
        (caps / "a.pcap", ""),
        (caps / "open.pcapng", "tcp"),  # (the viewer's filter: the open capture's only)
        (tmp_path / "c.pcap", ""),
    ]
    assert plan.options == {"speed": 0.0, "loops": 3, "order": "merged", "jitter": 0.0, "loss": 0.0}
    # The command line overrides: the open capture, the filter, options.
    plan = make_plan(
        args("--setup", str(tmp_path / "lab.json"), "x.pcap", "--filter", "udp", "--loops", "1")
    )
    assert plan.files[1] == (Path("x.pcap"), "udp") and plan.options["loops"] == 1
    assert plan.open_capture == Path("x.pcap")
    # Older setups (0.25.2 to 0.29): no open capture's path or filter.
    old = read_setup(
        _setup(tmp_path / "old.json", options={"scope": "filter"}, targets={}, captures=[])
    )
    assert old.open_capture is None and "it plays the viewer's filter" in old.problems[0]
    with pytest.raises(UsageError, match="name it"):
        make_plan(args("--setup", str(tmp_path / "old.json")))
    assert make_plan(args("--setup", str(tmp_path / "old.json"), "y.pcap")).files == [
        (Path("y.pcap"), "")
    ]
    out = _setup(tmp_path / "out.json", includeOpenCapture=False, captures=[{"path": "z.pcap"}])
    assert make_plan(args("--setup", str(out))).files == [(tmp_path / "z.pcap", "")]
    with pytest.raises(UsageError, match="leaves the open capture out"):
        make_plan(args("--setup", str(out), "y.pcap"))
    # Files that aren't setups.
    (tmp_path / "bad.json").write_text("{")
    (tmp_path / "other.json").write_text('{"format": "x"}')
    newer = _setup(tmp_path / "newer.json", version=2)
    for bad, why in (
        (tmp_path / "bad.json", "isn't JSON"),
        (tmp_path / "other.json", "isn't a replay setup"),
        (newer, "newer PCAP Lens"),
        (tmp_path / "missing.json", "can't read"),
    ):
        with pytest.raises(UsageError, match=why):
            read_setup(bad)


def test_setup_paths_are_read_as_the_panel_wrote_them(tmp_path: Path) -> None:
    # The panel writes paths relative to the setup's folder as it names it
    # (Node's path.relative, no symlinks followed): through a symlinked folder
    # (macOS's /var is /private/var) they climb past it, so reading must not
    # follow the link either, or every path lands a folder off.
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "caps").mkdir()
    link = tmp_path / "l"
    try:
        link.symlink_to(tmp_path / "a" / "b", target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"can't make a symlink here: {exc}")
    setup = read_setup(
        _setup(link / "lab.json", openCapture="../caps/open.pcap", captures=[{"path": "../x.pcap"}])
    )
    assert setup.open_capture == tmp_path / "caps" / "open.pcap"
    assert setup.captures == [(tmp_path / "x.pcap", True)]


def test_plans_without_a_setup() -> None:
    plan = make_plan(args("a.pcap", "b.pcap", "--filter", " tcp ", "--speed", "0"))
    assert plan.files == [(Path("a.pcap"), "tcp"), (Path("b.pcap"), "tcp")]
    assert plan.options["speed"] == 0 and plan.options["loops"] == 1
    for argv, why in (
        ((), "name the captures"),
        (("a.pcap", "--speed", "2000"), "--speed"),
        (("a.pcap", "--loops", "-1"), "--loops"),
        (("a.pcap", "--jitter", "-1"), "--jitter"),
        (("a.pcap", "--loss", "101"), "--loss"),
    ):
        with pytest.raises(UsageError, match=why):
            make_plan(args(*argv))


def test_dissection_options(tmp_path: Path) -> None:
    options_file = tmp_path / "dissection.json"
    options_file.write_text(
        json.dumps(
            {
                "format": "pcap-lens-dissection",
                "default": {"decodeAs": ["udp.port==9999,dns"]},
                "folders": [{"root": str(tmp_path / "lab"), "options": {"lua": ["a.lua"]}}],
            }
        )
    )
    found, warnings = dissection_options(
        args("--options", str(options_file), "--lua", "b.lua", "--pref", "tcp.x:TRUE"),
        tmp_path / "lab" / "x.pcap",
    )
    assert found == {"names": {}, "lua": ["a.lua", "b.lua"], "prefs": {"tcp.x": "TRUE"}}
    assert warnings == []
    found, _ = dissection_options(args("--options", str(options_file)), tmp_path / "x.pcap")
    assert found == {"names": {}, "decodeAs": ["udp.port==9999,dns"]}
    found, warnings = dissection_options(
        args("--options", str(tmp_path / "none.json"), "--profile", "Lab"), tmp_path / "x.pcap"
    )
    assert found == {"names": {}, "profile": "Lab"} and "doesn't exist" in warnings[0]
    with pytest.raises(UsageError, match="NAME:VALUE"):
        dissection_options(args("--pref", "tcp.x"), tmp_path / "x.pcap")
    (tmp_path / "broken.json").write_text("[")
    with pytest.raises(UsageError, match="valid JSON"):
        dissection_options(args("--options", str(tmp_path / "broken.json")), tmp_path / "x.pcap")


def test_results_text_is_the_panel_s() -> None:
    # The run of replayModel.test.ts's "results" test: the same text.
    tcp = {
        "key": HI3, "to": "127.0.0.1:2325", "connections": 3, "opened": 2, "refused": 1,
        "reset": 0, "closedByPeer": 0, "packets": 6, "bytes": 1500, "dropped": 0,
        "received": 0, "datagrams": 0, "lost": 0, "errors": ["connection 3: refused"],
        "errorCount": 1,
    }  # fmt: skip
    udp = {**tcp, "key": UDP, "connections": 1, "opened": 0, "refused": 0}
    udp.update(datagrams=3, lost=1, bytes=24, errors=[], errorCount=0)
    run_ = {
        "capture": "/work/delivery.pcap",
        "started": "2026-10-29T14:00:00.000Z",
        "ended": "2026-10-29T14:00:12.500Z",
        "options": {
            "speed": 1,
            "loops": 0,
            "scope": "all",
            "order": "merged",
            "jitter": 5,
            "loss": 25,
        },
        "filter": "tcp || udp",
        "files": ["/work/later.pcap"],
        "includeOpen": True,
        "openAt": 1,
        "stopped": True,
        "seconds": 12.5,
        "loops": 3,
        "targets": [tcp, udp],
        "sources": [
            {
                "name": "later.pcap",
                "packets": 9,
                "bytes": 762,
                "lost": 1,
                "retransmissions": 0,
                "gaps": 0,
            },
            {
                "name": "delivery.pcap",
                "packets": 9,
                "bytes": 762,
                "lost": 0,
                "retransmissions": 2,
                "gaps": 1,
            },
        ],
        "log": [
            {"time": 0, "level": "info", "text": "loop 1"},
            {"time": 0.25, "level": "error", "text": "connection 3: refused", "target": HI3},
        ],
        "logOmitted": 4,
    }
    assert target_outcome(tcp) == (
        "2 of 3 connections opened, 1 refused, 1.5 KB sent, 0 B received, 1 error"
    )
    assert target_outcome(udp) == "3 datagrams, 1 datagram lost on purpose, 24 B sent, 0 B received"
    assert results_text(run_).split("\n") == [
        "PCAP Lens replay results",
        "",
        "Capture:  /work/delivery.pcap",
        "Started:  2026-10-29T14:00:00.000Z",
        "Ended:    2026-10-29T14:00:12.500Z (12.5 s, stopped)",
        (
            "Options:  speed 1\N{MULTIPLICATION SIGN} · until stopped (3 loops played) · "
            "merged by time · jitter ±5 ms · UDP loss 25% · packets: tcp || udp"
        ),
        "",
        "Captures:",
        "  later.pcap: 9 packets sent (762 B), 1 datagram lost on purpose",
        "  delivery.pcap: 9 packets sent (762 B), 2 retransmissions skipped, 1 gap in the capture",
        "",
        "Targets:",
        f"  {HI3} → 127.0.0.1:2325: {target_outcome(tcp)}",
        "    error: connection 3: refused",
        f"  {UDP} → 127.0.0.1:2325: {target_outcome(udp)}",
        "",
        "Log:",
        "       0.000 s  loop 1",
        f"       0.250 s  ERROR {HI3}  connection 3: refused",
        "  (4 more lines not kept)",
        "",
    ]


# -- replays ----------------------------------------------------------------------------


@pytest.mark.tshark
def test_list() -> None:
    code, out, err = run("--list", str(CAPTURE))
    assert code == EXIT_OK
    lines = out.splitlines()
    assert lines[0].split() == ["TARGET", "CONNECTIONS", "PACKETS", "BYTES", "NOTES"]
    assert [line.split("  ")[0] for line in lines[1:5]] == [DNS, HI2, UDP, HI3]
    assert "1 retransmission, 1 gap" in lines[4]
    assert "replay.pcap: 4 targets, 15 packets, 0.250 s recorded" in out
    assert "Reading replay.pcap" in err
    code, out, _ = run("--list", "--json", str(CAPTURE), "--filter", "udp")
    event = json.loads(out)
    assert event["type"] == "targets" and [t["key"] for t in event["targets"]] == [DNS, UDP]


@pytest.mark.tshark
def test_replay(tmp_path: Path) -> None:
    hi2, hi3, udp = Collector(answer=b"\x30\x03ack"), Collector(), Datagrams()
    try:
        code, out, err = run(
            str(CAPTURE),
            "--speed", "0",
            "--map", f"tcp/*:11000=127.0.0.1:{hi2.port}",
            "--map", f"{HI3}=localhost:{hi3.port}",
            "--map", f"udp/{COLLECTOR}:*=127.0.0.1:{udp.port}",
            "--results", str(tmp_path / "run.json"),
        )  # fmt: skip
        _settle()
    finally:
        hi2.close()
        hi3.close()
        udp.close()
    assert code == EXIT_OK, err
    assert sorted(hi3.received) == sorted(generate.REPLAY_EXPECTED[HI3])
    assert udp.received == generate.REPLAY_EXPECTED[UDP]
    assert len(hi2.received) == 3
    assert f"{HI2} → 127.0.0.1:{hi2.port}" in err  # (the mapping, before it starts)
    assert f"Left out: {DNS}" in err
    assert "connection 1 to" in err  # (the log)
    assert out.startswith("Done after ")
    assert f"  {HI3} → localhost:{hi3.port}: 2 of 2 connections opened" in out
    saved = json.loads((tmp_path / "run.json").read_text())
    assert saved["format"] == "pcap-lens-replay-results" and saved["version"] == 1
    assert (saved["capture"], saved["includeOpen"], saved["files"]) == (str(CAPTURE), True, [])
    assert {t["key"] for t in saved["targets"]} == {HI2, HI3, UDP}
    assert any("opened" in line["text"] for line in saved["log"])
    assert saved["options"]["speed"] == 0 and saved["stopped"] is False


@pytest.mark.tshark
def test_replay_problems_and_setup(tmp_path: Path) -> None:
    # A refused port: the replay runs, the exit status says it had problems.
    closed = _free_port()
    code, out, _ = run(
        str(CAPTURE), "--speed", "0", "--quiet", "--map", f"{HI3}=127.0.0.1:{closed}",
        "--results", str(tmp_path / "run.txt"), encoding="cp1252",
    )  # fmt: skip
    assert code == EXIT_PROBLEMS
    assert f"! {HI3} -> 127.0.0.1:{closed}: 0 of 2 connections opened, 2 refused" in out
    results = (tmp_path / "run.txt").read_text("utf-8")  # (the file keeps the panel's arrow)
    assert results.startswith("PCAP Lens replay results\n")
    assert f"{HI3} \u2192 127.0.0.1:{closed}" in results
    # A setup: the open capture's filter keeps HI3 only.
    hi3 = Collector()
    try:
        setup = _setup(
            tmp_path / "lab.json",
            openCapture=str(CAPTURE),
            filter="tcp.port == 11001",
            targets={HI3: {"ip": "127.0.0.1", "port": hi3.port}},
            options={"speed": 0, "scope": "filter"},
        )
        code, out, err = run("--setup", str(setup), "--json")
        _settle()
    finally:
        hi3.close()
    assert code == EXIT_OK, err
    events = [json.loads(line) for line in out.splitlines()]
    assert events[0]["type"] == "targets" and events[0]["leftOut"] == []
    assert events[0]["destinations"] == {HI3: {"ip": "127.0.0.1", "port": hi3.port}}
    assert {e["type"] for e in events[1:-1]} == {"progress"}
    assert events[-1]["type"] == "result" and events[-1]["targets"][0]["opened"] == 2
    assert sorted(hi3.received) == sorted(generate.REPLAY_EXPECTED[HI3])


@pytest.mark.tshark
def test_errors(tmp_path: Path) -> None:
    capture = str(CAPTURE)
    notes = tmp_path / "notes.pcap"
    notes.write_text("not a capture\n")
    for argv, code, why in (
        ((), EXIT_USAGE, "name the captures"),
        ((capture, "--map", "nonsense"), EXIT_USAGE, "PATTERN=DESTINATION"),
        ((capture, "--map", "tcp/*:9=127.0.0.1"), EXIT_USAGE, "no recorded target has"),
        ((capture, "--to", "127.0.0.1", "--filter", "tcp.port =="), EXIT_USAGE, "tcp.port"),
        ((capture, "--map", f"{HI2}=1.1.1.1"), EXIT_USAGE, "must be allowed explicitly"),
        ((str(notes), "--to", "127.0.0.1"), EXIT_FAILED, "notes.pcap can't be read"),
        ((str(tmp_path / "missing.pcap"), "--to", "127.0.0.1"), EXIT_USAGE, "missing.pcap"),
        ((capture, "--tshark", str(tmp_path / "no-tshark")), EXIT_FAILED, ""),
    ):
        got, _, err = run(*argv)
        assert (got, why in err) == (code, True), (argv, err)
    got, _, err = run(capture, "--map", f"{HI2}=127.0.0.1:{_free_port()}", "--map", "udp/*:1=x")
    assert "--map udp/*:1=x matches no recorded target" in err


@pytest.mark.tshark
def test_duration_stops_a_replay_until_stopped() -> None:
    hi3 = Collector()
    try:
        started = time.monotonic()
        code, out, err = run(
            str(CAPTURE), "--loops", "0", "--duration", "1", "--map", f"{HI3}=127.0.0.1:{hi3.port}"
        )
        took = time.monotonic() - started
    finally:
        hi3.close()
    assert code == EXIT_OK, err
    assert out.startswith("Stopped after ") and "Time is up: stopping" in err
    assert took < 15  # (one second of sending, then the drain)
    assert len(hi3.received) >= 2  # (at least one loop's two connections)


@pytest.mark.tshark
@pytest.mark.skipif(sys.platform == "win32", reason="SIGINT to a child process (POSIX)")
def test_the_launcher_and_ctrl_c() -> None:
    hi3 = Collector()
    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                str(BACKEND / "pcap-lens-replay.py"),
                str(CAPTURE),
                "--loops",
                "0",
                "--map",
                f"{HI3}=127.0.0.1:{hi3.port}",
            ],
            cwd=BACKEND.parent,  # (not backend: the script's folder is enough)
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 30
        while not hi3.received and time.monotonic() < deadline:
            time.sleep(0.05)
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=30)
    finally:
        hi3.close()
    assert proc.returncode == EXIT_OK, err
    assert out.startswith("Stopped after ") and "Stopping…" in err

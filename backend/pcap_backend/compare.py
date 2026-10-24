"""Comparing two captures from their statistics (``compare_profiles``, the
MCP server's ``compare_captures``, ``@pcap /compare``).

A *profile* sums up one capture: its size and duration, the protocol
hierarchy, flows, IP endpoints, the triage checks' counts and the expert
messages, all keyed so that the same thing has the same key in another
capture of the same network. A *diff* of two profiles lists what is new, what
is gone and what changed share; the triage checks are compared per 1,000
packets, since the two captures rarely have the same length. Port scans and
host sweeps are found in each profile's flows and listed as new, gone or in
both (``scans``): five two-packet flows to five ports read as five new
services to a model, which didn't call them a scan.

Flows are conversations without the client's port: ``tcp 10.0.0.5 →
93.184.216.34:443`` sums every connection from that client to that service.
The server is the end with the lower port (ephemeral ports are high), so a
flow keeps its key from one capture to the next while every connection's
client port changes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

PROFILE_VERSION = 1
# Flows and endpoints kept per profile (by bytes); the rest are summed.
MAX_PROFILE_ITEMS = 500
# Items per list in a diff.
MAX_DIFF_ITEMS = 15
# A share must move this many percentage points to count as changed.
MIN_SHARE_CHANGE = 1.0
# A scan: one client reaching MIN_SCAN_PORTS ports of one server (a port
# scan) or one port of MIN_SWEEP_HOSTS servers (a host sweep; more, since a
# client asking several DNS or NTP servers looks alike), in flows of at most
# SCAN_PACKETS packets per connection (a SYN and its reset, a few retries).
MIN_SCAN_PORTS = 4
MIN_SWEEP_HOSTS = 8
SCAN_PACKETS = 4


def _cells(table: Mapping[str, Any] | None) -> tuple[list[str], list[dict[str, Any]]]:
    if not table:
        return [], []
    ids = [str(c.get("id")) for c in table.get("columns", [])]
    return ids, list(table.get("rows", []))


def _num(value: object) -> float:
    return float(value) if isinstance(value, int | float) else 0.0


def _split_endpoint(text: str) -> tuple[str, int | None]:
    """``10.0.0.5:51000`` or ``2001:db8::1:443`` (tshark's form) → address, port."""
    address, _, port = text.rpartition(":")
    if address and port.isdigit():
        return address, int(port)
    return text, None


def _service(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def flow_key(proto: str, a: str, b: str) -> str:
    """A conversation's flow: client → server:port (the server has the lower port)."""
    (addr_a, port_a), (addr_b, port_b) = _split_endpoint(a), _split_endpoint(b)
    if port_a is None or port_b is None:
        return f"{proto} {min(a, b)} ↔ {max(a, b)}"
    if (port_a, addr_a) < (port_b, addr_b):
        (addr_a, port_a), (addr_b, port_b) = (addr_b, port_b), (addr_a, port_a)
    return f"{proto} {addr_a} → {_service(addr_b, port_b)}"


def _protocols(phs: Mapping[str, Any] | None) -> dict[str, list[float]]:
    ids, rows = _cells(phs)
    if "protocol" not in ids:
        return {}
    name, packets, size = ids.index("protocol"), ids.index("packets"), ids.index("bytes")
    out: dict[str, list[float]] = {}
    path: list[str] = []
    for row in rows:
        depth = int(row.get("depth", 0))
        del path[depth:]
        path.append(str(row["cells"][name]))
        key = "/".join(path)
        if key not in out:  # (the same path twice: tshark lists a protocol per parent)
            out[key] = [_num(row["cells"][packets]), _num(row["cells"][size])]
    return out


def _top(items: dict[str, list[float]], by: int) -> tuple[dict[str, list[float]], list[float]]:
    """The MAX_PROFILE_ITEMS largest items by column ``by``, and the sums of the rest."""
    ranked = sorted(items.items(), key=lambda kv: kv[1][by], reverse=True)
    kept = dict(ranked[:MAX_PROFILE_ITEMS])
    rest = [0.0] * (len(ranked[0][1]) if ranked else 0)
    for _, values in ranked[MAX_PROFILE_ITEMS:]:
        rest = [r + v for r, v in zip(rest, values, strict=True)]
    return kept, rest


def profile(
    info: Mapping[str, Any],
    phs: Mapping[str, Any] | None,
    conversations: Iterable[tuple[str, Mapping[str, Any] | None]],
    endpoints: Iterable[Mapping[str, Any] | None],
    triage: Mapping[str, Any] | None,
    expert: Mapping[str, Any] | None,
    missing: Sequence[str] = (),
) -> dict[str, Any]:
    """One capture's profile from its statistics tables (as ``stats`` returns
    them), ``capture_info`` and ``triage``; ``missing`` names the parts
    tshark couldn't compute."""
    protocols = _protocols(phs)
    depth0 = [v for k, v in protocols.items() if "/" not in k]
    flows: dict[str, list[float]] = {}  # conversations, packets, bytes
    for proto, table in conversations:
        ids, rows = _cells(table)
        if not {"a", "b", "packets", "bytes"} <= set(ids):
            continue
        a, b, packets, size = (ids.index(k) for k in ("a", "b", "packets", "bytes"))
        for row in rows:
            cells = row["cells"]
            key = flow_key(proto, str(cells[a]), str(cells[b]))
            entry = flows.setdefault(key, [0.0, 0.0, 0.0])
            entry[0] += 1
            entry[1] += _num(cells[packets])
            entry[2] += _num(cells[size])
    hosts: dict[str, list[float]] = {}  # packets, bytes
    for table in endpoints:
        ids, rows = _cells(table)
        if not {"address", "packets", "bytes"} <= set(ids):
            continue
        address, packets, size = (ids.index(k) for k in ("address", "packets", "bytes"))
        for row in rows:
            cells = row["cells"]
            hosts[str(cells[address])] = [_num(cells[packets]), _num(cells[size])]
    checks: dict[str, dict[str, Any]] = {}
    not_counted: dict[str, str] = {}
    for check in (triage or {}).get("checks", []):
        if "count" in check:
            checks[check["id"]] = {
                "title": check["title"],
                "filter": check["filter"],
                "count": check["count"],
                "first": check.get("first"),
            }
        else:
            not_counted[check["id"]] = str(check.get("skipped") or check.get("error") or "")
    messages: dict[str, float] = {}
    severities: dict[str, float] = {}
    ids, rows = _cells(expert)
    if {"severity", "summary", "group", "protocol", "count"} <= set(ids):
        i_sev, i_summary, i_group, i_proto, i_count = (
            ids.index(k) for k in ("severity", "summary", "group", "protocol", "count")
        )
        for row in rows:
            cells = row["cells"]
            # (tshark ends an HTTP status line's message with a literal "\r\n".)
            text = str(cells[i_summary]).replace("\\r\\n", "").strip()
            key = "|".join([str(cells[i_sev]), str(cells[i_group]), str(cells[i_proto]), text])
            messages[key] = messages.get(key, 0) + _num(cells[i_count])
            severity = str(cells[i_sev])
            severities[severity] = severities.get(severity, 0) + _num(cells[i_count])
    kept_flows, other_flows = _top(flows, 2)
    kept_hosts, other_hosts = _top(hosts, 1)
    start, end = info.get("startTime"), info.get("endTime")
    return {
        "version": PROFILE_VERSION,
        "packets": int(info.get("frames") or 0),
        "bytes": int(sum(v[1] for v in depth0)),
        "fileSize": info.get("size"),
        "start": start,
        "end": end,
        "duration": (end - start)
        if isinstance(start, int | float) and isinstance(end, int | float)
        else None,
        "linkType": info.get("linkType"),
        "protocols": protocols,
        "flows": kept_flows,
        "otherFlows": other_flows,
        "endpoints": kept_hosts,
        "otherEndpoints": other_hosts,
        "checks": checks,
        "notCounted": not_counted,
        "twoPass": bool((triage or {}).get("twoPass")),
        "expert": messages,
        "severities": severities,
        "missing": list(missing),
    }


def _rate(n: float, seconds: float | None) -> float | None:
    return round(n / seconds, 2) if seconds else None


def _totals(name: str, p: Mapping[str, Any]) -> dict[str, Any]:
    seconds = p.get("duration")
    return {
        "name": name,
        "packets": p["packets"],
        "bytes": p["bytes"],
        "durationSeconds": round(seconds, 3) if seconds is not None else None,
        "packetsPerSecond": _rate(p["packets"], seconds),
        "bytesPerSecond": _rate(p["bytes"], seconds),
        "start": p.get("start"),
        "end": p.get("end"),
    }


def _share(part: float, whole: float) -> float:
    return round(100 * part / whole, 2) if whole else 0.0


def _compare(
    before: Mapping[str, Sequence[float]],
    after: Mapping[str, Sequence[float]],
    columns: Sequence[str],
    share_of: int,
    totals: tuple[float, float],
    label: str,
    limit: int,
) -> dict[str, Any]:
    """New, gone and changed items of one kind (share = column ``share_of``
    as a percentage of the capture's total)."""

    def item(key: str, values: Sequence[float], total: float) -> dict[str, Any]:
        out: dict[str, Any] = {label: key}
        out.update({c: int(v) for c, v in zip(columns, values, strict=True)})
        out["share"] = _share(values[share_of], total)
        return out

    new = [item(k, v, totals[1]) for k, v in after.items() if k not in before]
    gone = [item(k, v, totals[0]) for k, v in before.items() if k not in after]
    changed = []
    for key in before.keys() & after.keys():
        b = item(key, before[key], totals[0])
        a = item(key, after[key], totals[1])
        delta = round(a["share"] - b["share"], 2)
        if abs(delta) >= MIN_SHARE_CHANGE:
            changed.append(
                {
                    label: key,
                    "before": {k: v for k, v in b.items() if k != label},
                    "after": {k: v for k, v in a.items() if k != label},
                    "shareChange": delta,
                }
            )
    by = columns[share_of]
    new.sort(key=lambda x: x[by], reverse=True)
    gone.sort(key=lambda x: x[by], reverse=True)
    changed.sort(key=lambda x: abs(x["shareChange"]), reverse=True)
    out: dict[str, Any] = {"new": new[:limit], "gone": gone[:limit], "changed": changed[:limit]}
    more = {
        k: n - limit
        for k, n in (("new", len(new)), ("gone", len(gone)), ("changed", len(changed)))
        if n > limit
    }
    if more:
        out["more"] = more
    return out


def _parse_flow(key: str) -> tuple[str, str, str, int] | None:
    """``tcp 10.0.0.5 → 10.0.0.80:443`` → protocol, client, server, port."""
    head, arrow, service = key.partition(" → ")
    proto, _, client = head.partition(" ")
    if not arrow or not client:
        return None
    server, port = _split_endpoint(service)
    if port is None:
        return None
    return proto, client, server.removeprefix("[").removesuffix("]"), port


def scans(flows: Mapping[str, Sequence[float]]) -> list[dict[str, Any]]:
    """Port scans (one client, one server, many ports) and host sweeps (one
    client, one port, many servers) among a profile's flows with few packets
    per connection. Only the profile's flows count (MAX_PROFILE_ITEMS by
    bytes), so a scan in a very large capture can be missed."""
    small: list[tuple[str, str, str, int, float]] = []
    for key, (connections, packets, _size) in flows.items():
        parsed = _parse_flow(key)
        if parsed and parsed[0] in ("tcp", "udp") and packets <= SCAN_PACKETS * max(connections, 1):
            small.append((*parsed, packets))
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for proto, client, server, port, packets in small:
        for kind, target, value in (("port scan", server, port), ("host sweep", str(port), server)):
            g = groups.setdefault((kind, proto, client, target), {"targets": set(), "packets": 0})
            g["targets"].add(value)
            g["packets"] += int(packets)
    out = []
    for (kind, proto, client, target), g in groups.items():
        if len(g["targets"]) < (MIN_SCAN_PORTS if kind == "port scan" else MIN_SWEEP_HOSTS):
            continue
        item: dict[str, Any] = {"kind": kind, "protocol": proto, "client": client}
        if kind == "port scan":
            item.update(server=target, ports=sorted(g["targets"]))
        else:
            item.update(port=int(target), servers=sorted(g["targets"]))
        item["packets"] = g["packets"]
        out.append(item)
    out.sort(key=lambda x: -len(x.get("ports") or x.get("servers") or []))
    return out


def _scan_key(item: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        item["kind"],
        item["protocol"],
        item["client"],
        str(item.get("server", item.get("port"))),
    )


def _scans(before: Mapping[str, Any], after: Mapping[str, Any], limit: int) -> dict[str, Any]:
    b, a = scans(before["flows"]), scans(after["flows"])
    b_keys, a_keys = {_scan_key(x) for x in b}, {_scan_key(x) for x in a}
    return {
        "new": [x for x in a if _scan_key(x) not in b_keys][:limit],
        "gone": [x for x in b if _scan_key(x) not in a_keys][:limit],
        "both": [x for x in a if _scan_key(x) in b_keys][:limit],
    }


def _per_1000(count: int, packets: int) -> float:
    return round(1000 * count / packets, 2) if packets else 0.0


def _checks(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    rows = []
    unchanged = 0
    for cid in before["checks"].keys() & after["checks"].keys():
        b, a = before["checks"][cid], after["checks"][cid]
        if b["count"] == a["count"] == 0:
            continue
        if b["count"] == a["count"]:
            unchanged += 1
            continue
        b1000, a1000 = (
            _per_1000(b["count"], before["packets"]),
            _per_1000(a["count"], after["packets"]),
        )
        rows.append(
            {
                "id": cid,
                "check": a["title"],
                "filter": a["filter"],
                "before": b["count"],
                "after": a["count"],
                "beforePer1000": b1000,
                "afterPer1000": a1000,
                "firstPacketBefore": b.get("first"),
                "firstPacketAfter": a.get("first"),
            }
        )
    rows.sort(key=lambda r: abs(r["afterPer1000"] - r["beforePer1000"]), reverse=True)
    not_compared = sorted(
        (before["notCounted"].keys() | after["notCounted"].keys())
        | (before["checks"].keys() ^ after["checks"].keys())
    )
    out: dict[str, Any] = {"changed": rows, "unchangedNonZero": unchanged}
    if not_compared:
        out["notCompared"] = not_compared
    return out


# Most severe first: a list cut at the limit keeps the errors and warnings
# (tshark 4.6 adds chat messages that outnumbered a new 503 on macOS CI).
_SEVERITY_RANK = {"error": 0, "warning": 1, "note": 2, "chat": 3, "comment": 4}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.lower(), len(_SEVERITY_RANK))


def _expert(before: Mapping[str, Any], after: Mapping[str, Any], limit: int) -> dict[str, Any]:
    def row(key: str, count: float) -> dict[str, Any]:
        severity, group, protocol, summary = key.split("|", 3)
        return {
            "severity": severity,
            "group": group,
            "protocol": protocol,
            "summary": summary,
            "count": int(count),
        }

    b, a = before["expert"], after["expert"]

    def order(r: dict[str, Any]) -> tuple[int, int]:
        return _severity_rank(r["severity"]), -r["count"]

    new = sorted((row(k, v) for k, v in a.items() if k not in b), key=order)
    gone = sorted((row(k, v) for k, v in b.items() if k not in a), key=order)
    changed = []
    for key in b.keys() & a.keys():
        b1000, a1000 = (
            _per_1000(int(b[key]), before["packets"]),
            _per_1000(int(a[key]), after["packets"]),
        )
        if b[key] != a[key]:
            r = row(key, a[key])
            del r["count"]
            changed.append(
                {
                    **r,
                    "before": int(b[key]),
                    "after": int(a[key]),
                    "beforePer1000": b1000,
                    "afterPer1000": a1000,
                }
            )
    changed.sort(
        key=lambda r: (_severity_rank(r["severity"]), -abs(r["afterPer1000"] - r["beforePer1000"]))
    )
    sev = sorted(before["severities"].keys() | after["severities"].keys())
    more = {
        k: n - limit
        for k, n in (("new", len(new)), ("gone", len(gone)), ("changed", len(changed)))
        if n > limit
    }
    return {
        "severities": {
            s: {
                "before": int(before["severities"].get(s, 0)),
                "after": int(after["severities"].get(s, 0)),
            }
            for s in sev
        },
        "new": new[:limit],
        "gone": gone[:limit],
        "changed": changed[:limit],
        **({"more": more} if more else {}),
    }


def diff(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    names: tuple[str, str] = ("before", "after"),
    limit: int = MAX_DIFF_ITEMS,
) -> dict[str, Any]:
    """What changed from ``before`` to ``after`` (two profiles)."""
    for p in (before, after):
        if p.get("version") != PROFILE_VERSION:
            raise ValueError(f"profile version {p.get('version')!r} (expected {PROFILE_VERSION})")
    packets = (float(before["packets"]), float(after["packets"]))
    size = (float(before["bytes"]), float(after["bytes"]))
    notes = []
    if before.get("twoPass") != after.get("twoPass"):
        notes.append(
            "Only one capture was small enough for the two-pass checks (requests without a "
            "response): those checks are not compared."
        )
    for name, p in zip(names, (before, after), strict=True):
        if p.get("missing"):
            notes.append(f"Not available for {name}: {', '.join(p['missing'])}.")
    if before.get("linkType") != after.get("linkType"):
        notes.append(f"Different link types: {before.get('linkType')} and {after.get('linkType')}.")
    out: dict[str, Any] = {
        "before": _totals(names[0], before),
        "after": _totals(names[1], after),
        "checks": _checks(before, after),
        "protocols": _compare(
            before["protocols"],
            after["protocols"],
            ("packets", "bytes"),
            0,
            packets,
            "protocol",
            limit,
        ),
        "flows": _compare(
            before["flows"],
            after["flows"],
            ("connections", "packets", "bytes"),
            2,
            size,
            "flow",
            limit,
        ),
        "endpoints": _compare(
            before["endpoints"], after["endpoints"], ("packets", "bytes"), 1, size, "address", limit
        ),
        "expert": _expert(before, after, limit),
        "scans": _scans(before, after, limit),
    }
    if notes:
        out["notes"] = notes
    return out

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

import bisect
import hashlib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

PROFILE_VERSION = 4
# Flows and endpoints kept per profile (by bytes); the rest are summed.
MAX_PROFILE_ITEMS = 500
# The rest are still known by a short hash (``member_id``), so a flow ranked
# 501st in one capture isn't reported as new or gone; at most this many.
MAX_MEMBER_IDS = 100_000
# Items per list in a diff.
MAX_DIFF_ITEMS = 15
# A share must move this many percentage points to count as changed.
MIN_SHARE_CHANGE = 1.0
# A check with the same count in both captures still changed when one
# capture's rate per 1,000 packets is this many times the other's.
RATE_CHANGE = 1.5
# A scan: one client reaching MIN_SCAN_PORTS ports of one server (a port
# scan) or one port of MIN_SWEEP_HOSTS servers (a host sweep; more, since a
# client asking several DNS or NTP servers looks alike), in flows of at most
# SCAN_PACKETS packets per connection (a SYN and its reset, a few retries).
MIN_SCAN_PORTS = 4
MIN_SWEEP_HOSTS = 8
SCAN_PACKETS = 4
# At most this many scans, each listing at most this many ports or servers
# (``targets`` counts them all).
MAX_SCANS = 20
MAX_SCAN_TARGETS = 50
# The fields of a TCP reset pass (``reset_counts``): the innermost addresses.
RESET_FIELDS = ("ip.src", "ipv6.src", "tcp.srcport", "ip.dst", "ipv6.dst", "tcp.dstport")
RESET_FILTER = "tcp.flags.reset == 1"


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


def member_id(key: str) -> str:
    """A flow's or endpoint's key as a short hash (for the items a profile doesn't keep)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


def _top(
    items: dict[str, list[float]], by: int
) -> tuple[dict[str, list[float]], list[float], dict[str, Any]]:
    """The MAX_PROFILE_ITEMS largest items by column ``by``, the sums of the
    rest, and the rest's ``member_id``s (``ids``, sorted; ``complete``)."""
    ranked = sorted(items.items(), key=lambda kv: kv[1][by], reverse=True)
    kept = dict(ranked[:MAX_PROFILE_ITEMS])
    rest = [0.0] * (len(ranked[0][1]) if ranked else 0)
    for _, values in ranked[MAX_PROFILE_ITEMS:]:
        rest = [r + v for r, v in zip(rest, values, strict=True)]
    others = ranked[MAX_PROFILE_ITEMS:]
    members = {
        "ids": sorted(member_id(k) for k, _ in others[:MAX_MEMBER_IDS]),
        "complete": len(others) <= MAX_MEMBER_IDS,
    }
    return kept, rest, members


def flows_of(
    conversations: Iterable[tuple[str, Mapping[str, Any] | None]],
) -> dict[str, list[float]]:
    """Conversation tables (``(protocol, stats table)``) as flows:
    ``flow_key`` → connections, packets, bytes."""
    flows: dict[str, list[float]] = {}
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
    return flows


def reset_counts(lines: Iterable[str]) -> dict[str, int]:
    """TCP resets the server end of each flow sent, from a ``RESET_FIELDS``
    pass (tab-separated lines, the last occurrence of each field: the
    innermost header). Only the server's: in a SYN scan of an open port the
    scanner resets after the SYN/ACK, and counting that would call the port
    closed (Codex review)."""
    out: dict[str, int] = {}
    for line in lines:
        cells = line.rstrip("\r").split("\t")
        if len(cells) < len(RESET_FIELDS):
            continue
        src4, src6, sport, dst4, dst6, dport = cells[: len(RESET_FIELDS)]
        src, dst = src6 or src4, dst6 or dst4
        if not (src and dst and sport.isdigit() and dport.isdigit()):
            continue
        # (flow_key's server is the end with the lower port, then address.)
        if (int(sport), src) >= (int(dport), dst):
            continue  # sent by the client
        key = flow_key("tcp", f"{src}:{sport}", f"{dst}:{dport}")
        out[key] = out.get(key, 0) + 1
    return out


def profile(
    info: Mapping[str, Any],
    phs: Mapping[str, Any] | None,
    conversations: Iterable[tuple[str, Mapping[str, Any] | None]],
    endpoints: Iterable[Mapping[str, Any] | None],
    triage: Mapping[str, Any] | None,
    expert: Mapping[str, Any] | None,
    missing: Sequence[str] = (),
    resets: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """One capture's profile from its statistics tables (as ``stats`` returns
    them), ``capture_info``, ``triage`` and the resets per flow
    (``reset_counts``); ``missing`` names the parts tshark couldn't compute.
    Its ``scans`` come from every flow, before the profile keeps the largest."""
    protocols = _protocols(phs)
    depth0 = [v for k, v in protocols.items() if "/" not in k]
    flows = flows_of(conversations)  # conversations, packets, bytes
    found_scans = scans(flows, resets, limit=None)
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
    kept_flows, other_flows, flow_members = _top(flows, 2)
    kept_hosts, other_hosts, host_members = _top(hosts, 1)
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
        "otherFlowIds": flow_members,
        "scans": found_scans[:MAX_SCANS],
        # Every scan's key, so one ranked outside the 20 kept here isn't new or gone.
        "scanKeys": sorted(scan_key(x) for x in found_scans[:MAX_MEMBER_IDS]),
        "endpoints": kept_hosts,
        "otherEndpoints": other_hosts,
        "otherEndpointIds": host_members,
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
    others: tuple[Mapping[str, Any] | None, Mapping[str, Any] | None] = (None, None),
) -> dict[str, Any]:
    """New, gone and changed items of one kind (share = column ``share_of``
    as a percentage of the capture's total). ``others``: each profile's
    ``member_id``s of the items it didn't keep; an item one profile keeps and
    the other only knows by id is in both (neither new nor gone, and its
    share there unknown), and an item missing from a profile whose ids are
    incomplete may be in it (counted as ``unsure``)."""
    unsure = {"new": 0, "gone": 0}

    def absent(key: str, members: Mapping[str, Any] | None, side: str) -> bool:
        if not members:
            return True
        if _sorted_has(members.get("ids") or [], member_id(key)):
            return False
        if not members.get("complete", True):
            unsure[side] += 1
            return False
        return True

    def item(key: str, values: Sequence[float], total: float) -> dict[str, Any]:
        out: dict[str, Any] = {label: key}
        out.update({c: int(v) for c, v in zip(columns, values, strict=True)})
        out["share"] = _share(values[share_of], total)
        return out

    new = [
        item(k, v, totals[1])
        for k, v in after.items()
        if k not in before and absent(k, others[0], "new")
    ]
    gone = [
        item(k, v, totals[0])
        for k, v in before.items()
        if k not in after and absent(k, others[1], "gone")
    ]
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
    if any(unsure.values()):
        out["unsure"] = {k: n for k, n in unsure.items() if n}
    return out


def _sorted_has(ids: Sequence[str], wanted: str) -> bool:
    i = bisect.bisect_left(ids, wanted)
    return i < len(ids) and ids[i] == wanted


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


def scans(
    flows: Mapping[str, Sequence[float]],
    resets: Mapping[str, int] | None = None,
    limit: int | None = MAX_SCANS,
) -> list[dict[str, Any]]:
    """Port scans (one client, one server, many ports) and host sweeps (one
    client, one port, many servers) among ``flows`` (``flows_of``) with few
    packets per connection, most targets first (at most MAX_SCANS). With
    ``resets`` (``reset_counts``; TCP only), ``reset`` counts the targets
    whose flow saw a reset: refused (closed port) or cut off. A model read
    the office scan's five resets as "server or network stability"."""
    small: list[tuple[str, str, str, int, float, str]] = []
    for key, (connections, packets, _size) in flows.items():
        parsed = _parse_flow(key)
        if parsed and parsed[0] in ("tcp", "udp") and packets <= SCAN_PACKETS * max(connections, 1):
            small.append((*parsed, packets, key))
    groups: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for proto, client, server, port, packets, key in small:
        for kind, target, value in (("port scan", server, port), ("host sweep", str(port), server)):
            g = groups.setdefault(
                (kind, proto, client, target), {"targets": set(), "packets": 0, "reset": 0}
            )
            g["targets"].add(value)
            g["packets"] += int(packets)
            g["reset"] += 1 if resets and resets.get(key) else 0
    out = []
    for (kind, proto, client, target), g in groups.items():
        if len(g["targets"]) < (MIN_SCAN_PORTS if kind == "port scan" else MIN_SWEEP_HOSTS):
            continue
        item: dict[str, Any] = {"kind": kind, "protocol": proto, "client": client}
        listed = sorted(g["targets"])[:MAX_SCAN_TARGETS]
        if kind == "port scan":
            item.update(server=target, ports=listed)
        else:
            item.update(port=int(target), servers=listed)
        item["targets"] = len(g["targets"])
        item["packets"] = g["packets"]
        if resets is not None and proto == "tcp":
            item["reset"] = g["reset"]
        out.append(item)
    out.sort(key=lambda x: -x["targets"])
    return out if limit is None else out[:limit]


def scan_key(item: Mapping[str, Any]) -> str:
    """A scan's identity: kind, protocol, client and server (port scan) or port (sweep)."""
    return "|".join(
        (item["kind"], item["protocol"], item["client"], str(item.get("server", item.get("port"))))
    )


def _scans(before: Mapping[str, Any], after: Mapping[str, Any], limit: int) -> dict[str, Any]:
    """New, gone and both, judged on every scan's key (``scanKeys``), not only
    the MAX_SCANS each profile details (Codex review: a scan pushed out of
    one profile's top 20 read as gone)."""
    b, a = before["scans"], after["scans"]
    b_keys = set(before.get("scanKeys") or map(scan_key, b))
    a_keys = set(after.get("scanKeys") or map(scan_key, a))
    return {
        "new": [x for x in a if scan_key(x) not in b_keys][:limit],
        "gone": [x for x in b if scan_key(x) not in a_keys][:limit],
        "both": [x for x in a if scan_key(x) in b_keys][:limit],
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
        b1000, a1000 = (
            _per_1000(b["count"], before["packets"]),
            _per_1000(a["count"], after["packets"]),
        )
        # (Equal counts in captures of very different lengths are different rates.)
        if b["count"] == a["count"] and max(a1000, b1000) < RATE_CHANGE * min(a1000, b1000):
            unchanged += 1
            continue
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
    notes.extend(
        f"{name} has more than {MAX_PROFILE_ITEMS + MAX_MEMBER_IDS:,} {kind}s: whether"
        f" some {kind}s are new or gone can't be told ('unsure' counts them)."
        for name, p in zip(names, (before, after), strict=True)
        for kind in ("flow", "endpoint")
        if not (p.get(f"other{kind.title()}Ids") or {}).get("complete", True)
    )
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
            (before.get("otherFlowIds"), after.get("otherFlowIds")),
        ),
        "endpoints": _compare(
            before["endpoints"],
            after["endpoints"],
            ("packets", "bytes"),
            1,
            size,
            "address",
            limit,
            (before.get("otherEndpointIds"), after.get("otherEndpointIds")),
        ),
        "expert": _expert(before, after, limit),
        "scans": _scans(before, after, limit),
    }
    if notes:
        out["notes"] = notes
    return out

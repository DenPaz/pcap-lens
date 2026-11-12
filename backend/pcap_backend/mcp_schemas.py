"""Output schemas of the MCP server's tools (``outputSchema``, protocol
2025-06-18 and later).

Each schema describes the object a tool returns as ``structuredContent`` (the
same object as its text result). They name every key a result can hold, with
its type, and require only the keys a successful result always has; objects
stay open (no ``additionalProperties: false``), so a new key in a result never
makes a client reject it. With ``--stand-ins`` only strings change, so the
types hold. ``test_mcp.py`` checks every result its tests receive against its
tool's schema (``jsonschema``, a development dependency only).
"""

from __future__ import annotations

from typing import Any

STR: dict[str, Any] = {"type": "string"}
INT: dict[str, Any] = {"type": "integer"}
NUM: dict[str, Any] = {"type": "number"}
BOOL: dict[str, Any] = {"type": "boolean"}
ANY_OBJECT: dict[str, Any] = {"type": "object"}
# A table cell: text, a number, or empty.
CELL: dict[str, Any] = {"type": ["string", "number", "boolean", "null"]}


def null(schema: dict[str, Any]) -> dict[str, Any]:
    """``schema`` or null."""
    return {"anyOf": [schema, {"type": "null"}]}


def arr(items: dict[str, Any], description: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"type": "array", "items": items}
    if description:
        out["description"] = description
    return out


def obj(
    props: dict[str, Any], required: tuple[str, ...] = (), description: str = ""
) -> dict[str, Any]:
    out: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        out["required"] = list(required)
    if description:
        out["description"] = description
    return out


def _about(text: str, schema: dict[str, Any]) -> dict[str, Any]:
    return {**schema, "description": text}


CAPTURE = _about("The capture, as given (relative to an allowed folder when inside one)", STR)
FILTER = _about("A display filter (empty: every packet)", STR)
PACKETS = arr(INT, "Packet numbers")

BREAKDOWN = obj(
    {
        "total": INT,
        "items": arr(
            obj(
                {
                    "label": STR,
                    "count": INT,
                    "bytes": INT,
                    "filter": _about("Display filter of this row's packets", STR),
                },
                ("label", "count"),
            )
        ),
        "more": _about("Rows left out", INT),
    },
    description="A breakdown: rows by count, each with its display filter",
)

SCAN = obj(
    {
        "kind": _about("port scan or host sweep", STR),
        "protocol": STR,
        "client": STR,
        "server": _about("The scanned server (port scan)", STR),
        "port": _about("The swept port (host sweep)", INT),
        "ports": arr(INT, "Ports reached (port scan; at most 50)"),
        "servers": arr(STR, "Servers reached (host sweep; at most 50)"),
        "targets": INT,
        "packets": INT,
        "reset": _about("Targets that answered with a reset (TCP)", INT),
    },
    ("kind", "protocol", "client", "targets", "packets"),
)

QUALITY = obj(
    {
        "r": NUM,
        "mos": _about("Mean opinion score from the E-model (1-4.5)", NUM),
        "rating": STR,
        "codec": STR,
        "assumed": _about("The codec was rated as G.711 (no E-model values for it)", BOOL),
        "stream": INT,
    }
)

DTMF = obj(
    {
        "digit": _about("Only when the server allows packet contents", STR),
        "frame": INT,
        "time": NUM,
        "method": STR,
        "src": STR,
        "duration": null(_about("Milliseconds, when the signalling gives it", NUM)),
    }
)

CALL = obj(
    {
        "id": INT,
        "protocol": STR,
        "from": STR,
        "to": STR,
        "caller": STR,
        "callee": STR,
        "state": STR,
        "final": STR,
        "reasons": arr(STR),
        "endedBy": STR,
        "dialed": STR,
        "quality": QUALITY,
        "problems": arr(
            obj(
                {"kind": STR, "text": STR, "frame": null(INT), "stream": null(INT)},
                ("kind", "text"),
            )
        ),
        "streams": arr(INT, "Indexes of the call's RTP streams"),
        "filter": STR,
        "startSeconds": NUM,
        "ringingSeconds": NUM,
        "setupSeconds": NUM,
        "durationSeconds": NUM,
        "dtmf": arr(DTMF),
        "callId": STR,
        "messages": {
            "anyOf": [
                _about("How many signalling messages (the call list)", INT),
                arr(
                    obj(
                        {"packet": INT, "time": NUM, "from": STR, "to": STR, "message": STR},
                        ("packet", "message"),
                    ),
                    "The signalling messages (one call)",
                ),
            ]
        },
        "moreMessages": INT,
    },
    ("id", "messages"),
)

STREAM = obj(
    {
        "stream": INT,
        "from": STR,
        "to": STR,
        "ssrc": STR,
        "iax2": _about("An IAX2 voice stream's call number (no SSRC: it isn't RTP)", INT),
        "payload": STR,
        "packets": INT,
        "lost": INT,
        "lostPercent": NUM,
        "meanJitter": NUM,
        "maxJitter": NUM,
        "maxDelta": NUM,
        "start": NUM,
        "end": NUM,
        "firstFrame": INT,
        "quality": QUALITY,
        "rtcp": obj(
            {
                "reports": INT,
                "fractionLost": NUM,
                "maxFractionLost": NUM,
                "cumulativeLost": INT,
                "maxJitter": NUM,
                "rtt": null(NUM),
                "maxRtt": null(NUM),
                "from": null(STR),
                "frame": null(INT),
            },
            description="What the stream's receiver reported in RTCP",
        ),
        "gaps": arr(arr(NUM), "Silences of 1 s or more: [packet, time, seconds]"),
        "problem": BOOL,
        "filter": STR,
        "dtmf": arr(DTMF),
    },
    ("stream", "from", "to"),
)

REGISTRATION = obj(
    {
        "aor": STR,
        "client": STR,
        "registrar": STR,
        "state": STR,
        "final": null(STR),
        "expires": null(INT),
        "requests": INT,
        "challenges": INT,
        "start": NUM,
        "frames": PACKETS,
        "filter": STR,
    },
    ("state",),
)

DIRECTION = obj(
    {
        "direction": STR,
        "packets": INT,
        "dataPackets": INT,
        "bytes": INT,
        "retransmissions": INT,
        "retransmissionRate": NUM,
        "zeroWindows": INT,
        "minWindow": INT,
        "maxWindow": INT,
    },
    ("direction", "packets"),
)

TOTALS = obj(
    {
        "name": STR,
        "packets": INT,
        "bytes": INT,
        "durationSeconds": null(NUM),
        "packetsPerSecond": null(NUM),
        "bytesPerSecond": null(NUM),
        "start": null(NUM),
        "end": null(NUM),
    },
    ("name", "packets", "bytes"),
)

_SHARE = obj({"packets": INT, "bytes": INT, "connections": INT, "share": NUM})
DIFF_ITEM = obj(
    {
        "protocol": STR,
        "flow": _about("client → server:port", STR),
        "address": STR,
        "connections": INT,
        "packets": INT,
        "bytes": INT,
        "share": _about("Percent of the capture's packets or bytes", NUM),
        "before": _SHARE,
        "after": _SHARE,
        "shareChange": _about("Percentage points", NUM),
    }
)
_COUNTS = obj({"new": INT, "gone": INT, "changed": INT})
DIFF_KIND = obj(
    {
        "new": arr(DIFF_ITEM),
        "gone": arr(DIFF_ITEM),
        "changed": arr(DIFF_ITEM),
        "more": _about("Items left out of each list", _COUNTS),
        "unsure": _about("Items that may be new or gone (too many to tell)", _COUNTS),
    },
    ("new", "gone", "changed"),
)
EXPERT_ITEM = obj(
    {
        "severity": STR,
        "group": STR,
        "protocol": STR,
        "summary": STR,
        "count": INT,
        "before": INT,
        "after": INT,
        "beforePer1000": NUM,
        "afterPer1000": NUM,
    },
    ("severity", "summary"),
)


def _capture_result(props: dict[str, Any], required: tuple[str, ...]) -> dict[str, Any]:
    """A result about one capture: ``capture`` first, as every such result has."""
    return obj({"capture": CAPTURE, **props}, ("capture", *required))


OUTPUT_SCHEMAS: dict[str, dict[str, Any]] = {
    "list_captures": obj(
        {
            "folders": arr(STR, "The folders listed"),
            "captures": arr(
                obj({"path": STR, "size": INT, "modified": null(STR)}, ("path", "size")),
            ),
            "more": _about("More captures than the limit", BOOL),
        },
        ("folders", "captures", "more"),
    ),
    "plugins": obj(
        {
            "plugins": arr(
                obj(
                    {"name": STR, "version": STR, "type": STR, "path": STR, "personal": BOOL},
                    ("name",),
                )
            ),
            "folders": obj({}, description="Where tshark loads plugins from, by kind"),
            "luaScripts": arr(STR),
            "warnings": arr(STR),
            "tshark": null(STR),
        },
        ("plugins", "folders", "luaScripts", "warnings"),
    ),
    "capture_info": _capture_result(
        {
            "packets": null(INT),
            "firstPacket": null(_about("ISO 8601, UTC", STR)),
            "lastPacket": null(_about("ISO 8601, UTC", STR)),
            "durationSeconds": null(NUM),
            "size": null(INT),
            "linkType": null(STR),
            "fileFormat": null(STR),
            "warnings": arr(STR),
            "dissectedWith": _about("The dissection settings used (Lua, Decode As…)", ANY_OBJECT),
            "tshark": null(STR),
        },
        ("packets", "warnings", "dissectedWith"),
    ),
    "count_packets": _capture_result(
        {
            "filter": FILTER,
            "count": INT,
            "total": _about("Packets in the capture", INT),
            "packets": arr(INT, "The first matching packets"),
        },
        ("filter", "count", "total", "packets"),
    ),
    "statistics": _capture_result(
        {
            "kind": STR,
            "type": STR,
            "title": null(STR),
            "filter": FILTER,
            "columns": arr(null(STR)),
            "rows": arr(
                obj(
                    {
                        "cells": arr(CELL),
                        "depth": _about("Nesting level (tree reports)", INT),
                        "filter": _about("Display filter of this row's packets", STR),
                        "frame": INT,
                        "frames": PACKETS,
                        "moreFrames": _about("Packets left out of frames (expert)", INT),
                    },
                    ("cells",),
                )
            ),
            "omittedRows": INT,
            "interval": _about("Seconds per row (io)", NUM),
            "unfiltered": _about("The report can't be limited to a filter", BOOL),
        },
        ("kind", "columns", "rows", "omittedRows"),
    ),
    "triage": _capture_result(
        {
            "packets": INT,
            "twoPass": _about("Read twice, so checks of unanswered requests ran", BOOL),
            "found": arr(
                obj(
                    {
                        "id": STR,
                        "check": STR,
                        "packets": INT,
                        "firstPacket": INT,
                        "lastPacket": INT,
                        "filter": STR,
                        "next": _about("Where to look next", STR),
                    },
                    ("id", "check", "packets", "filter"),
                ),
                "Checks that matched, most packets first",
            ),
            "scans": arr(SCAN),
            "none": arr(STR, "Checks that matched nothing"),
            "notAvailable": arr(obj({"id": STR, "why": null(STR)}, ("id",))),
        },
        ("packets", "found", "none", "notAvailable"),
    ),
    "overview": _capture_result(
        {
            "filter": FILTER,
            "packets": INT,
            "bytes": INT,
            "durationSeconds": null(NUM),
            "timeline": obj(
                {
                    "intervalSeconds": null(NUM),
                    "packets": arr(INT),
                    "bytes": arr(INT),
                    "busiest": obj({"fromSeconds": NUM, "packets": INT}),
                },
                ("packets", "bytes"),
            ),
            "addresses": BREAKDOWN,
            "protocols": BREAKDOWN,
            "services": BREAKDOWN,
            "http": obj(
                {
                    "requests": INT,
                    "responses": INT,
                    "methods": BREAKDOWN,
                    "statuses": BREAKDOWN,
                    "contentTypes": BREAKDOWN,
                    "hosts": BREAKDOWN,
                }
            ),
            "dns": obj(
                {
                    "queries": INT,
                    "responses": INT,
                    "rcodes": BREAKDOWN,
                    "types": BREAKDOWN,
                    "names": BREAKDOWN,
                }
            ),
            "tls": obj(
                {
                    "clientHellos": INT,
                    "serverHellos": INT,
                    "versions": BREAKDOWN,
                    "servers": BREAKDOWN,
                }
            ),
            "absent": arr(
                {"type": "string", "enum": ["http", "dns", "tls"]},
                "Protocols the capture has no requests, queries or hellos of",
            ),
        },
        ("packets", "bytes", "timeline"),
    ),
    "sessions": _capture_result(
        {
            "kind": {"type": "string", "enum": ["http", "dns", "tls"]},
            "filter": FILTER,
            "summary": _about("Totals over every row (counts)", ANY_OBJECT),
            "columns": arr(null(STR)),
            "matching": INT,
            "offset": INT,
            "rows": arr(
                obj(
                    {
                        "cells": arr(CELL),
                        "filter": STR,
                        "frame": INT,
                        "response": _about("The response's packet (HTTP)", INT),
                    },
                    ("cells",),
                )
            ),
            "more": BOOL,
            "onlyProblems": BOOL,
            "notListed": _about("Rows past the table's limit, not in 'matching'", INT),
        },
        ("kind", "summary", "columns", "matching", "offset", "rows", "more"),
    ),
    "voip_calls": {
        **_capture_result(
            {
                "summary": obj(
                    {
                        "calls": INT,
                        "byState": obj({}, description="Calls per state"),
                        "withProblems": INT,
                        "streams": INT,
                    },
                    ("calls",),
                ),
                "calls": arr(CALL),
                "moreCalls": INT,
                "streamsWithoutCall": arr(STREAM),
                "registrations": arr(REGISTRATION),
                "heuristicRtp": BOOL,
                "call": CALL,
                "streams": arr(STREAM),
                "dtmfDigits": _about("Why DTMF digits are left out", STR),
            },
            (),
        ),
        # The list, or one call's detail ('call' given).
        "anyOf": [
            {"required": ["summary", "calls", "streamsWithoutCall", "registrations"]},
            {"required": ["call", "streams"]},
        ],
    },
    "tcp_stream": _capture_result(
        {
            "stream": INT,
            "filter": STR,
            "endpoints": arr(STR),
            "packets": INT,
            "durationSeconds": NUM,
            "syns": INT,
            "directions": arr(DIRECTION),
            "rtt": null(
                obj(
                    {"samples": INT, "minMs": NUM, "medianMs": NUM, "maxMs": NUM},
                    description="Round-trip times from the acknowledgements",
                )
            ),
            "retransmissionRate": NUM,
            "retransmissionPackets": arr(INT, "The first retransmissions"),
            "zeroWindowPackets": arr(INT, "The first zero windows"),
        },
        ("stream", "filter", "packets", "directions"),
    ),
    "rtp_stream": _capture_result(
        {
            "stream": INT,
            "call": _about("The call the stream belongs to (voip_calls' id)", INT),
            "from": STR,
            "to": STR,
            "ssrc": STR,
            "iax2": STREAM["properties"]["iax2"],
            "payload": STR,
            "quality": QUALITY,
            "rtcp": STREAM["properties"]["rtcp"],
            "filter": STR,
            "summary": obj(
                {
                    "packets": INT,
                    "expected": INT,
                    "lost": INT,
                    "lostPercent": NUM,
                    "sequenceErrors": INT,
                    "maxDelta": _about("Largest gap between packets, ms", NUM),
                    "maxDeltaPacket": null(INT),
                    "maxJitter": _about("ms", NUM),
                    "meanJitter": _about("ms", NUM),
                    "maxSkew": _about("ms", NUM),
                    "clockRate": INT,
                    "payloadTypes": arr(INT),
                    "durationSeconds": NUM,
                }
            ),
            "problems": arr(
                obj(
                    {
                        "packet": INT,
                        "seq": INT,
                        "problem": _about("lost, out_of_order or payload_changed", STR),
                        "lostBefore": _about("Packets missing before this one", INT),
                    },
                    ("packet", "seq", "problem"),
                )
            ),
            "moreProblems": INT,
            "timeline": arr(
                obj(
                    {
                        "startSeconds": NUM,
                        "endSeconds": NUM,
                        "packets": INT,
                        "lost": INT,
                        "maxJitterMs": NUM,
                        "maxDeltaMs": NUM,
                    },
                    ("startSeconds", "endSeconds", "packets", "lost"),
                ),
                "Equal intervals from the stream's first packet",
            ),
        },
        ("stream", "summary", "problems", "moreProblems", "timeline"),
    ),
    "sequence_check": _capture_result(
        {
            "sequence": STR,
            "streamsBy": arr(STR),
            "wrapBits": INT,
            "restartDrop": INT,
            "filter": FILTER,
            "summary": obj(
                {
                    "streams": INT,
                    "withProblems": INT,
                    "messages": INT,
                    "missing": INT,
                    "duplicates": INT,
                    "late": INT,
                    "restarts": INT,
                    "unreadable": _about("Messages whose number isn't a number", INT),
                    "untracked": _about("Messages of streams past the tracked limit", INT),
                }
            ),
            "streams": arr(
                obj(
                    {
                        "stream": INT,
                        "key": _about(
                            "The streams_by fields' values (when they may be shown)", ANY_OBJECT
                        ),
                        "filter": STR,
                        "messages": INT,
                        "first": null(INT),
                        "last": null(INT),
                        "missing": INT,
                        "duplicates": INT,
                        "late": INT,
                        "restarts": INT,
                        "result": STR,
                        "firstPacket": null(INT),
                        "problems": arr(
                            obj(
                                {
                                    "kind": _about("gap, duplicate, late or restart", STR),
                                    "text": STR,
                                    "packet": null(INT),
                                },
                                ("kind", "text"),
                            )
                        ),
                        "moreProblems": INT,
                    },
                    ("stream", "messages", "problems"),
                ),
                "Streams with problems first",
            ),
            "moreStreams": INT,
            "keyValues": STR,
        },
        ("sequence", "streamsBy", "summary", "streams", "moreStreams"),
    ),
    "export_objects": _capture_result(
        {
            "protocol": _about("The protocol asked for (empty: all)", STR),
            "total": INT,
            "byProtocol": obj({}, description="{files, bytes} per protocol"),
            "files": arr(
                obj(
                    {
                        "protocol": STR,
                        "name": STR,
                        "size": INT,
                        "contentType": STR,
                        "host": STR,
                        "packet": INT,
                        "filter": STR,
                    },
                    ("protocol", "name", "size"),
                )
            ),
            "more": INT,
        },
        ("total", "byProtocol", "files", "more"),
    ),
    "credentials": _capture_result(
        {
            "filter": FILTER,
            "total": INT,
            "byProtocol": obj({}, description="Logins per protocol"),
            "logins": arr(
                obj(
                    {
                        "protocol": STR,
                        "packet": INT,
                        "usernamePacket": INT,
                        "username": _about("Only when the server allows packet contents", STR),
                        "filter": STR,
                    },
                    ("protocol", "packet"),
                )
            ),
            "more": INT,
            "unfiltered": BOOL,
            "usernames": STR,
        },
        ("total", "byProtocol", "logins", "more"),
    ),
    "compare_captures": obj(
        {
            "before": TOTALS,
            "after": TOTALS,
            "checks": obj(
                {
                    "changed": arr(
                        obj(
                            {
                                "id": STR,
                                "check": STR,
                                "filter": STR,
                                "before": INT,
                                "after": INT,
                                "beforePer1000": NUM,
                                "afterPer1000": NUM,
                                "firstPacketBefore": null(INT),
                                "firstPacketAfter": null(INT),
                            },
                            ("id", "check", "before", "after"),
                        )
                    ),
                    "unchangedNonZero": INT,
                },
                ("changed",),
            ),
            "protocols": DIFF_KIND,
            "flows": DIFF_KIND,
            "endpoints": DIFF_KIND,
            "expert": obj(
                {
                    "severities": obj({}, description="Items per severity: {before, after}"),
                    "new": arr(EXPERT_ITEM),
                    "gone": arr(EXPERT_ITEM),
                    "changed": arr(EXPERT_ITEM),
                    "more": _COUNTS,
                }
            ),
            "scans": obj({"new": arr(SCAN), "gone": arr(SCAN), "both": arr(SCAN)}),
            "notes": arr(STR),
        },
        ("before", "after", "checks", "protocols", "flows", "endpoints", "expert", "scans"),
    ),
    "field_values": _capture_result(
        {
            "field": STR,
            "type": _about("tshark's field type (FT_UINT8…)", STR),
            "filter": FILTER,
            "packets": _about("Packets holding the field", INT),
            "distinct": INT,
            "values": arr(
                obj({"value": {"type": ["string", "number"]}, "count": INT}, ("value", "count")),
                "Most frequent first",
            ),
            "more": BOOL,
        },
        ("field", "type", "packets", "distinct", "values", "more"),
    ),
    "validate_filter": obj(
        {
            "valid": BOOL,
            "error": STR,
            "span": arr(INT, "Where the error is: [start, end) in the filter"),
        },
        ("valid",),
    ),
    "search_fields": obj(
        {
            "fields": arr(
                obj(
                    {
                        "name": _about("The display filter name", STR),
                        "desc": STR,
                        "type": STR,
                        "proto": STR,
                        "blurb": STR,
                    },
                    ("name",),
                )
            )
        },
        ("fields",),
    ),
    "list_packets": _capture_result(
        {
            "filter": FILTER,
            "matching": INT,
            "offset": INT,
            "columns": arr(STR),
            "rows": arr(arr(CELL), "One row per packet, cells in the columns' order"),
            "more": BOOL,
        },
        ("filter", "matching", "offset", "columns", "rows", "more"),
    ),
    "packet_details": _capture_result(
        {
            "packet": INT,
            "layers": arr(STR, "The packet's protocols, outermost first"),
            "tree": _about("The dissection tree, one indented line per item", STR),
            "truncated": BOOL,
        },
        ("packet", "layers", "tree", "truncated"),
    ),
    "follow_stream": _capture_result(
        {
            "protocol": null(STR),
            "stream": null(INT),
            "filter": STR,
            "endpoints": arr(STR),
            "segments": arr(
                obj(
                    {"from": STR, "text": _about("Printable text, others as '.'", STR)},
                    ("from", "text"),
                )
            ),
            "truncated": BOOL,
            "substream": INT,
            "substreams": arr(INT),
            "hint": STR,
        },
        ("segments", "truncated"),
    ),
}

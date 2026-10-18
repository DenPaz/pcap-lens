"""Lua dissector checks, Decode As choices, protocol preferences and the field catalogue."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from pcap_backend.fields import FieldCatalog
from pcap_backend.prefs import Preference, parse_prefs, protocols_with_prefs
from pcap_backend.protocol import InvalidParamsError, RequestContext, param, str_list
from pcap_backend.tshark import EMPTY_CAPTURE, DissectionOptions, run

from .base import ServiceBase
from .helpers import _stderr_warnings
from .state import _FIELD_NAME_RE

# Lua names a chunk by its path, shortened to "...<tail>" when long.
_LUA_CHUNK_RE = re.compile(r"(?P<dots>\.\.\.)?(?P<path>[^\s:]*(?::[\\/][^\s:]*)?\.lua):\d+:")


def script_in_lua_message(scripts: Sequence[str], message: str) -> str | None:
    """Which configured script a Lua error message is about, if identifiable."""
    for script in scripts:
        if script in message:
            return script
    for m in _LUA_CHUNK_RE.finditer(message):
        tail = m["path"]
        hits = [
            s for s in scripts if s.endswith(tail) or (not m["dots"] and s.endswith(f"/{tail}"))
        ]
        if len(hits) == 1:
            return hits[0]
    return None


_CHOICE_RE = re.compile(r"^\t(?P<name>\S+) \((?P<desc>.*)\)$")


def parse_decode_as_choices(stderr: str) -> list[dict[str, str]]:
    """Parse the "Valid layer types are:" / "Valid protocols for layer type … are:"
    lists tshark prints for an invalid ``-d`` rule (one ``\tname (description)`` per line).
    """
    out: list[dict[str, str]] = []
    for line in stderr.split("\n"):
        m = _CHOICE_RE.match(line.rstrip("\r"))
        if m:
            out.append({"name": m["name"], "desc": m["desc"]})
    return out


_PROTOCOL_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def _merged_prefs(outputs: list[str]) -> dict[str, Preference]:
    """The preferences of tshark's listings (plain, then with the Lua scripts)."""
    merged: dict[str, Preference] = {}
    for text in outputs:
        merged.update(parse_prefs(text))
    return merged


class DissectionMixin(ServiceBase):
    """Lua dissector checks, Decode As choices, protocol preferences and the field catalogue."""

    def check_dissectors(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Load Lua scripts against an empty capture and report their errors.

        Fast (no packets are read), so the extension runs it before re-indexing
        on "Reload Dissectors". ``lua`` defaults to the open file's scripts.
        Returns ``errors`` (tshark's Lua messages, ``script`` when identifiable)
        and ``warnings`` (missing files, Lua disabled for root).
        """
        base = self._file.tshark if self._file else self._require_tshark()
        if "lua" in params:
            options = DissectionOptions.from_params(
                str_list(params, "lua"), base.options.decode_as, dict(base.options.prefs)
            )
        else:
            options = base.options
        tshark = base.with_options(options)
        warnings = options.check_scripts()
        errors: list[dict[str, str]] = []
        if options.lua_scripts:
            res = run(tshark.argv(capture=str(EMPTY_CAPTURE.get())), ctx.token)
            for message in _stderr_warnings(res.stderr):
                if message.startswith("Lua:"):  # missing files are in `warnings` already
                    script = script_in_lua_message(options.lua_scripts, message)
                    errors.append({"message": message, **({"script": script} if script else {})})
        return {"scripts": list(options.lua_scripts), "errors": errors, "warnings": warnings}

    def decode_as_options(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Valid "Decode As" choices, straight from tshark's own lists.

        Without ``layer``: the layer types (``tcp.port``, ``udp.port``, …).
        With ``layer``: the protocols that layer can be decoded as.
        """
        tshark = self._file.tshark if self._file else self._require_tshark()
        layer = param(params, "layer", str, "").strip()
        if layer and not _FIELD_NAME_RE.match(layer):
            raise InvalidParamsError(f"invalid layer type {layer!r}")
        key = f"decode-as:{layer}"
        cached = self._decode_as.get(key)
        if cached is None:
            # tshark lists the valid choices when given an invalid rule.
            probe = f"{layer}==0,no-such-protocol" if layer else "no-such-layer"
            res = run([str(tshark.path), "-d", probe, "-r", str(EMPTY_CAPTURE.get())], ctx.token)
            if layer and "Unknown layer type" in res.stderr:
                # tshark answered with the layer list, not protocols
                raise InvalidParamsError(f"unknown layer type {layer!r}")
            cached = parse_decode_as_choices(res.stderr)
            self._decode_as.put(key, cached)
        return {"layer": layer or None, "choices": cached}

    def protocol_prefs(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Wireshark's dissector preferences, from tshark's own listings.

        Without ``protocol``: ``protocols``, each with its number of
        preferences. With ``protocol`` (a preference module: ``tcp``, ``tls``…):
        its ``prefs`` in tshark's order, each with ``name``, ``description``,
        ``type`` (bool, uint, hex, range, color, file, directory, string,
        enum, other), ``choices`` for an enum, ``default`` and ``wireshark``
        (the value in the user's Wireshark preferences, which tshark applies
        unless ``pcapViewer.prefs`` overrides it). Lua scripts' preferences
        are included (``-G`` ignores ``-X lua_script``; see ``Tshark.glossary``).
        """
        tshark = self._file.tshark if self._file else self._require_tshark()
        protocol = param(params, "protocol", str, "").strip()
        if protocol and not _PROTOCOL_RE.match(protocol):
            raise InvalidParamsError(f"invalid protocol name {protocol!r}")
        key = (str(tshark.path), tuple(tshark.options.lua_scripts))
        defaults = self._default_prefs.get(key)
        if defaults is None:
            defaults = _merged_prefs(tshark.glossary("defaultprefs", ctx.token))
            self._default_prefs.put(key, defaults)
        if not protocol:
            return {"protocols": protocols_with_prefs(defaults)}
        prefs = [p for p in defaults.values() if p.module == protocol]
        if not prefs:
            raise InvalidParamsError(f"{protocol} has no preferences")
        # Not cached: the user may change Wireshark's preferences meanwhile.
        current = _merged_prefs(tshark.glossary("currentprefs", ctx.token))
        return {
            "protocol": protocol,
            "prefs": [
                {
                    **p.to_json(),
                    "default": p.value,
                    "wireshark": current[p.name].value if p.name in current else p.value,
                }
                for p in prefs
            ],
        }

    def field_index(self, params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Field/protocol names from ``tshark -G fields`` for autocomplete.

        Case-insensitive ``prefix`` search; ``limit`` caps each list (the
        catalogue has ~250k entries). Lua dissector fields are included because
        the catalogue is built with the file's ``-X lua_script`` options. Call
        with ``limit: 0`` to warm the cache without transferring anything.
        """
        prefix = param(params, "prefix", str, "")
        limit = max(0, min(param(params, "limit", int, 200), 100_000))
        catalog = self._catalog(ctx)
        return catalog.search(prefix, limit)

    def _catalog(self, ctx: RequestContext) -> FieldCatalog:
        tshark = self._file.tshark if self._file else self._require_tshark()
        key = tshark.options.lua_scripts
        catalog = self._field_index.get(key)
        if catalog is None:
            with self._build_lock:
                catalog = self._field_index.get(key)
                if catalog is None:
                    catalog = FieldCatalog.parse(tshark.field_list(ctx.token))
                    self._field_index.put(key, catalog)
        return catalog

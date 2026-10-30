"""Capture-file service: indexing, filtering, paging, sorting and packet detail.

One ``PcapService`` serves one capture file (the extension starts one backend
process per open editor). All heavy lifting is delegated to tshark:

* ``open`` runs a single ``-T fields`` pass and stores the packet-list columns
  on disk (:class:`~pcap_backend.cache.RowStore`).
* ``set_filter`` runs ``-Y <expr> -T fields -e frame.number`` once and keeps the
  matching frame numbers; scrolling never re-runs tshark. With ``stream`` the
  matches are shown as they come ("filter" notifications report the pass).
* ``packet_detail`` runs ``-T pdml`` and ``-x`` for one frame, reading only up
  to that frame (``-c N``) so dissection state from earlier packets (TCP
  reassembly etc.) is still correct.
* ``set_coloring`` runs one ``--color`` pass and keeps a one-byte rule index
  per frame; ``list_packets`` rows then carry their ``color``. ``open`` can
  evaluate the rules in its own pass instead (``coloring``), so colors come
  with the rows.
* ``export`` writes filtered captures with tshark (``-Y … -w``) and the packet
  list (CSV/JSON) straight from the row store.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .fields import parse_field_list
from .protocol import RequestContext, RpcError
from .service.capturing import CaptureMixin
from .service.colors import ColoringMixin
from .service.comparing import ComparingMixin
from .service.dissection import parse_decode_as_choices, script_in_lua_message
from .service.exported_objects import ObjectsMixin
from .service.exporting import ExportMixin
from .service.filterhelp import FilterHelpMixin
from .service.filtering import MAX_MATCH_FRAMES
from .service.flow import FlowGraphMixin
from .service.helpers import sniff_format
from .service.indexing import parse_capinfos
from .service.navigation import NavigationMixin
from .service.replaying import ReplayMixin
from .service.state import BASE_COLUMNS, MAX_PAGE, MAX_SELECTION, UNRESOLVED_FIELDS
from .service.streams import StreamsMixin, parse_tcp_graph
from .service.telephony import TelephonyMixin
from .service.tools import ToolsMixin


class PcapService(
    CaptureMixin,
    NavigationMixin,
    ExportMixin,
    StreamsMixin,
    TelephonyMixin,
    FlowGraphMixin,
    ColoringMixin,
    ToolsMixin,
    ObjectsMixin,
    FilterHelpMixin,
    ComparingMixin,
    ReplayMixin,
):
    """Every request handler; one instance serves one capture (see the module docstring)."""


def rpc_methods(service: PcapService) -> dict[str, Callable[[dict[str, Any], RequestContext], Any]]:
    return {
        "initialize": service.initialize,
        "open": service.open,
        "list_interfaces": service.list_interfaces,
        "extcap_config": service.extcap_config,
        "validate_capture_filter": service.validate_capture_filter,
        "capture_start": service.capture_start,
        "capture_stop": service.capture_stop,
        "capture_to_files": service.capture_to_files,
        "capture_files_stop": service.capture_files_stop,
        "replay_targets": service.replay_targets,
        "replay": service.replay,
        "replay_stop": service.replay_stop,
        "capture_info": service.capture_info,
        "validate_filter": service.validate_filter,
        "filter_hints": service.filter_hints,
        "field_values": service.field_values,
        "count_matches": service.count_matches,
        "set_filter": service.set_filter,
        "stop_filter": service.stop_filter,
        "list_packets": service.list_packets,
        "find_frame": service.find_frame,
        "view_frames": service.view_frames,
        "packet_detail": service.packet_detail,
        "field_index": service.field_index,
        "follow_stream": service.follow_stream,
        "stats": service.stats,
        "http_body": service.http_body,
        "overview": service.overview,
        "check_dissectors": service.check_dissectors,
        "decode_as_options": service.decode_as_options,
        "protocol_prefs": service.protocol_prefs,
        "expert_summary": service.expert_summary,
        "triage": service.triage,
        "capture_profile": service.capture_profile,
        "scans": service.scans,
        "compare_profiles": service.compare_profiles,
        "dissector_names": service.dissector_names,
        "enabled_protocols": service.enabled_protocols,
        "set_coloring": service.set_coloring,
        "find_packet": service.find_packet,
        "view_overview": service.view_overview,
        "neighbor_frame": service.neighbor_frame,
        "mark_packets": service.mark_packets,
        "unmark_all": service.unmark_all,
        "ignore_packets": service.ignore_packets,
        "unignore_all": service.unignore_all,
        "field_types": service.field_types,
        "export": service.export,
        "merge": service.merge,
        "import_hexdump": service.import_hexdump,
        "probe_file": service.probe_file,
        "split_ber": service.split_ber,
        "tshark_plugins": service.tshark_plugins,
        "wireshark_profiles": service.wireshark_profiles,
        "export_tls_keys": service.export_tls_keys,
        "export_pdu_taps": service.export_pdu_taps,
        "export_pdus": service.export_pdus,
        "file_format": service.file_format,
        "read_wireshark_profile": service.read_wireshark_profile,
        "edit_capture": service.edit_capture,
        "flow_graph": service.flow_graph,
        "tcp_graph": service.tcp_graph,
        "voip_calls": service.voip_calls,
        "rtp_stream": service.rtp_stream,
        "rtp_audio": service.rtp_audio,
        "call_audio": service.call_audio,
        "set_comments": service.set_comments,
        "packet_comments": service.packet_comments,
        "save_comments": service.save_comments,
        "export_objects": service.export_objects,
        "save_objects": service.save_objects,
        "close": service.close,
    }


__all__ = [
    "BASE_COLUMNS",
    "MAX_MATCH_FRAMES",
    "MAX_PAGE",
    "MAX_SELECTION",
    "UNRESOLVED_FIELDS",
    "PcapService",
    "RpcError",
    "parse_capinfos",
    "parse_decode_as_choices",
    "parse_field_list",
    "parse_tcp_graph",
    "rpc_methods",
    "script_in_lua_message",
    "sniff_format",
]

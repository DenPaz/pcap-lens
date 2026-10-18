from __future__ import annotations

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.prefs import parse_prefs, protocols_with_prefs
from pcap_backend.protocol import InvalidParamsError, RequestContext

# The shape of `tshark -G defaultprefs` (4.2 to 4.6), cut down.
LISTING = """\
# Configuration file for Wireshark 4.2.2.
#
# This file is regenerated each time preferences are saved within

####### User Interface ########

# Open a console window (Windows only)
# One of: NEVER, AUTOMATIC, ALWAYS
# (case-insensitive).
#gui.console_open: NEVER

####### Protocols ########

# Whether to validate the TCP checksum or not.
# TRUE or FALSE (case-insensitive)
#tcp.check_checksum: FALSE

# Make the TCP dissector use this scaling factor for streams
# One of: Not known, 0 (no scaling), 1 (multiply by 2)
# (case-insensitive).
tcp.default_window_scaling: 1 (multiply by 2)

# The name of a file which contains a list of (pre-)master secrets in one of the following formats:
#
# RSA <EPMS> <PMS>
# (All fields are in hex notation)
# A path to a file
#tls.keylog_file:

# Port range
# A string denoting an positive integer range (e.g., "1-20,30-40")
#foo.ports: 1-20,30-40

# The security suite
# One of: No Security, AES-128 Encryption, 64-bit Integrity Protection
# (case-insensitive).
#wpan.sec_suite: AES-128 Encryption, 64-bit Integrity Protection

# Mystery
# Something tshark doesn't describe
#bar.mystery: 7
"""


def test_parse_prefs_reads_the_protocols_section() -> None:
    prefs = parse_prefs(LISTING)
    assert list(prefs) == [
        "tcp.check_checksum",
        "tcp.default_window_scaling",
        "tls.keylog_file",
        "foo.ports",
        "wpan.sec_suite",
        "bar.mystery",
    ]  # not gui.*: only the "Protocols" section
    checksum = prefs["tcp.check_checksum"]
    assert (checksum.type, checksum.value, checksum.is_default) == ("bool", "FALSE", True)
    assert checksum.description.startswith("Whether to validate the TCP checksum")


def test_enums_values_and_changed_preferences() -> None:
    prefs = parse_prefs(LISTING)
    scaling = prefs["tcp.default_window_scaling"]
    assert scaling.type == "enum"
    assert scaling.choices == ["Not known", "0 (no scaling)", "1 (multiply by 2)"]
    # Not commented out: the listing's value differs from the default.
    assert (scaling.value, scaling.is_default) == ("1 (multiply by 2)", False)


def test_types_and_multi_line_descriptions() -> None:
    prefs = parse_prefs(LISTING)
    keylog = prefs["tls.keylog_file"]
    assert (keylog.type, keylog.value) == ("file", "")
    assert keylog.description == (
        "The name of a file which contains a list of (pre-)master secrets in one of the "
        "following formats: RSA <EPMS> <PMS> (All fields are in hex notation)"
    )
    assert prefs["foo.ports"].type == "range"
    assert prefs["bar.mystery"].type == "other"
    assert prefs["bar.mystery"].description == "Mystery Something tshark doesn't describe"


def test_an_enum_whose_choices_contain_commas_is_free_text() -> None:
    # The choices are joined with ", ", which this one's names contain too.
    suite = parse_prefs(LISTING)["wpan.sec_suite"]
    assert (suite.type, suite.choices) == ("other", [])
    assert suite.value == "AES-128 Encryption, 64-bit Integrity Protection"


def test_protocols_with_prefs_counts_per_module() -> None:
    assert protocols_with_prefs(parse_prefs(LISTING)) == [
        {"protocol": "bar", "count": 1},
        {"protocol": "foo", "count": 1},
        {"protocol": "tcp", "count": 2},
        {"protocol": "tls", "count": 1},
        {"protocol": "wpan", "count": 1},
    ]


@pytest.mark.tshark
def test_protocol_prefs_from_tshark(service: PcapService, ctx: RequestContext) -> None:
    protocols = service.protocol_prefs({}, ctx)["protocols"]
    assert {"tcp", "tls", "http", "ip"} <= {p["protocol"] for p in protocols}
    res = service.protocol_prefs({"protocol": "tcp"}, ctx)
    assert res["protocol"] == "tcp"
    by_name = {p["name"]: p for p in res["prefs"]}
    seq = by_name["tcp.analyze_sequence_numbers"]
    assert (seq["type"], seq["default"]) == ("bool", "TRUE")
    assert seq["description"]
    assert seq["wireshark"] in ("TRUE", "FALSE")
    assert all(p["name"].startswith("tcp.") for p in res["prefs"])
    assert any(p["type"] == "enum" and p["choices"] for p in res["prefs"])


@pytest.mark.tshark
def test_protocol_prefs_rejects_unknown_and_invalid_names(
    service: PcapService, ctx: RequestContext
) -> None:
    with pytest.raises(InvalidParamsError, match="no preferences"):
        service.protocol_prefs({"protocol": "no-such-protocol"}, ctx)
    with pytest.raises(InvalidParamsError, match="invalid protocol name"):
        service.protocol_prefs({"protocol": "tcp; rm"}, ctx)

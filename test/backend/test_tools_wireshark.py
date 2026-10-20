"""Tools from Wireshark's menu: Credentials and Export TLS Session Keys."""

from __future__ import annotations

from pathlib import Path

import pytest

from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import InvalidParamsError, RequestContext

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.tshark
def test_credentials(service: PcapService, ctx: RequestContext) -> None:
    service.open({"path": str(FIXTURES / "credentials.pcap")}, ctx)
    table = service.stats({"kind": "credentials"}, ctx)
    assert [(r["cells"][1], r["cells"][2]) for r in table["rows"]] == [
        ("HTTP basic auth", "alice"),
        ("FTP", "bob"),
        ("POP3", "carol"),
        ("IMAP", "dave"),
    ]
    # Each row goes to its packet; FTP's and POP's usernames came in an earlier one.
    ftp = table["rows"][1]
    assert ftp["frame"] > ftp["usernameFrame"] > 0
    assert service.count_matches({"filter": f"{ftp['filter']} && ftp"}, ctx)["count"] == 1
    # The tap has no filter of its own: a display filter limits the rows here.
    limited = service.stats({"kind": "credentials", "filter": "pop || imap"}, ctx)
    assert [r["cells"][2] for r in limited["rows"]] == ["carol", "dave"]
    # Ignored packets are left out like in every report.
    service.ignore_packets({"frames": [table["rows"][0]["frame"]]}, ctx)
    assert len(service.stats({"kind": "credentials"}, ctx)["rows"]) == 3


@pytest.mark.tshark
def test_export_tls_session_keys(
    service: PcapService, ctx: RequestContext, tls_keylog: tuple[Path, Path], tmp_path: Path
) -> None:
    capture, keylog = tls_keylog
    service.open({"path": str(capture), "prefs": {"tls.keylog_file": str(keylog)}}, ctx)
    dest = tmp_path / "keys.txt"
    res = service.export_tls_keys({"dest": str(dest)}, ctx)
    assert res["sessions"] == 1
    exported = dest.read_text().split()
    assert exported[0] == "CLIENT_RANDOM"
    assert exported[1] in keylog.read_text()
    # Without the key log nothing is decrypted: nothing to export, no file.
    service.open({"path": str(capture)}, ctx)
    empty = tmp_path / "none.txt"
    with pytest.raises(InvalidParamsError, match="no decrypted TLS sessions"):
        service.export_tls_keys({"dest": str(empty)}, ctx)
    assert not empty.exists()

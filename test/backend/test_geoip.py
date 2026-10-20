from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pcap_backend import geoip
from pcap_backend.geoip import GeoDatabases, MmdbError, MmdbReader
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.tshark import ToolNotFoundError, find_tool

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
GEOIP = FIXTURES / "geoip"
sys.path.insert(0, str(FIXTURES))
import mmdb  # noqa: E402 (test/fixtures/mmdb.py, the writer)


def _has_mmdbresolve() -> bool:
    """Whether tshark's GeoIP lookup helper is installed beside it."""
    try:
        find_tool("mmdbresolve", sibling_of=find_tool("tshark"))
    except ToolNotFoundError:
        return False
    return True


def test_the_fixture_databases_are_read_and_merged() -> None:
    geo = GeoDatabases([str(GEOIP)])
    try:
        assert sorted(r.database_type for r in geo.readers) == ["GeoLite2-ASN", "GeoLite2-City"]
        assert geo.lookup("93.184.216.34") == {
            "countryCode": "US",
            "country": "United States",
            "city": "Norwell",
            "lat": 42.1508,
            "lon": -70.8228,
            "asn": 15133,
            "org": "Edgecast",
        }
        assert geo.lookup("2001:db8:10::1")["city"] == "Berlin"
        assert geo.lookup("192.168.1.10") == {}
        assert geo.lookup("not an address") == {}
    finally:
        geo.close()


@pytest.mark.parametrize("record_size", [24, 28, 32])
def test_every_record_size(tmp_path: Path, record_size: int) -> None:
    networks = {"10.1.0.0/16": {"n": 1}, "10.2.3.0/24": {"n": 2}, "2001:db8::/32": {"n": 3}}
    path = tmp_path / "t.mmdb"
    path.write_bytes(mmdb.write_mmdb(networks, "Test", record_size))
    reader = MmdbReader(path)
    try:
        assert reader.record_size == record_size
        assert reader.lookup("10.1.200.3") == {"n": 1}
        assert reader.lookup("10.2.3.4") == {"n": 2}
        assert reader.lookup("2001:db8:1::1") == {"n": 3}
        assert reader.lookup("10.2.4.4") is None
        assert reader.lookup("::1") is None
    finally:
        reader.close()


def test_damaged_files_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "empty.mmdb").write_bytes(b"")
    (tmp_path / "junk.mmdb").write_bytes(b"not a database" * 100)
    with pytest.raises(MmdbError):
        MmdbReader(tmp_path / "junk.mmdb")
    geo = GeoDatabases([str(tmp_path), str(tmp_path / "missing")])
    assert not geo and len(geo.errors) == 2
    # The settings' folders come first, then tshark's usual ones, each once.
    folders = geoip.geo_folders(["/a", *geoip.DEFAULT_FOLDERS[:1]])
    assert folders == ["/a", *geoip.DEFAULT_FOLDERS]


@pytest.mark.tshark
def test_endpoints_get_locations_and_tshark_the_fields(
    service: PcapService, ctx: RequestContext
) -> None:
    service.open({"path": str(FIXTURES / "mixed.pcapng"), "geoip": [str(GEOIP)]}, ctx)
    table = service.stats({"kind": "endpoints", "type": "ip"}, ctx)
    assert table["geoip"] is True
    assert [c["id"] for c in table["columns"]][:5] == ["address", "country", "city", "asn", "org"]
    rows = {r["cells"][0]: r for r in table["rows"]}
    assert rows["8.8.8.8"]["cells"][1:5] == ["United States", "Mountain View", 15169, "Google LLC"]
    assert rows["8.8.8.8"]["geo"] == {"lat": 37.386, "lon": -122.0838}
    assert rows["192.168.1.10"]["cells"][1:5] == ["", "", "", ""]
    assert "geo" not in rows["192.168.1.10"]
    # tshark's own GeoIP fields work in filters (through maxmind_db_paths), where
    # its lookup helper is installed.
    if _has_mmdbresolve():
        expr = 'ip.geoip.country == "United States"'
        assert service.set_filter({"expr": expr}, ctx)["matchCount"] == 17
    # TCP endpoints have ports, not locations.
    assert "geoip" not in service.stats({"kind": "endpoints", "type": "tcp"}, ctx)

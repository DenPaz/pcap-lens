from __future__ import annotations

from pathlib import Path

import pytest

from pcap_backend import decryption, index_cache
from pcap_backend.pcap_service import PcapService
from pcap_backend.protocol import RequestContext
from pcap_backend.tshark import ConfigError, DissectionOptions

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

# The keys test/fixtures/generate.py encrypted wep.pcap and esp.pcap with.
WEP = {"type": "wep", "key": "0a:1b:2c:3d:4e"}
ESP = [
    {
        "type": "esp",
        "protocol": "IPv4",
        "src": "10.8.0.1",
        "dst": "10.8.0.2",
        "spi": "0x00001001",
        "encryption": "AES-CTR [RFC3686]",
        "encryptionKey": "0x00112233445566778899aabbccddeeff01020304",
        "authentication": "NULL",
    },
    {
        "type": "esp",
        "src": "10.8.0.2",
        "dst": "10.8.0.1",
        "spi": "0x00002002",
        "encryption": "AES-CTR [RFC3686]",
        "encryptionKey": "ffeeddccbbaa99887766554433221100a1a2a3a4",
    },
]


def test_keys_become_uat_records_and_preferences(tmp_path: Path) -> None:
    keylog, pem, keytab, geo = (
        str(tmp_path / n) for n in ("ssh.keys", "server.pem", "krb5.keytab", "geo")
    )
    items, files = decryption.options(
        [
            WEP,
            {"type": "wpa-pwd", "password": "pass:word%1", "ssid": "Café Wi-Fi"},
            {"type": "wpa-psk", "key": "ab" * 32},
            {"type": "rsa", "file": pem, "password": 'a"b\\c'},
            {"type": "ssh", "file": keylog},
            {"type": "kerberos", "file": keytab},
            ESP[1],
        ],
        [geo],
    )
    # (A UAT field escapes quotes and backslashes, Windows paths' included.)
    esc = decryption.uat_escape
    assert items == (
        ("wlan.enable_decryption", "TRUE"),
        ("ssh.keylog_file", keylog),
        ("kerberos.decrypt", "TRUE"),
        ("kerberos.file", keytab),
        ("esp.enable_encryption_decode", "TRUE"),
        ("uat:80211_keys", '"wep","0a1b2c3d4e"'),
        # Wireshark percent-decodes the passphrase and SSID (a colon separates them).
        ("uat:80211_keys", '"wpa-pwd","pass%3Aword%251:Caf%C3%A9%20Wi-Fi"'),
        ("uat:80211_keys", f'"wpa-psk","{"ab" * 32}"'),
        ("uat:rsa_keys", f'"{esc(pem)}","a\\x22b\\x5cc"'),
        (
            "uat:esp_sa",
            (
                '"IPv4","10.8.0.2","10.8.0.1","0x00002002","AES-CTR [RFC3686]",'
                '"0xffeeddccbbaa99887766554433221100a1a2a3a4","NULL",""'
            ),
        ),
        ("uat:maxmind_db_paths", f'"{esc(geo)}"'),
    )
    assert files == (pem, keylog, keytab, geo)
    assert esc('C:\\keys\\"x".pem') == "C:\\x5ckeys\\x5c\\x22x\\x22.pem"
    # The secrets stay out of the options' repr (it may be logged).
    options = DissectionOptions.from_params(keys=[WEP])
    assert "0a1b2c3d4e" not in repr(options)
    assert options.args()[-2:] == ["-o", 'uat:80211_keys:"wep","0a1b2c3d4e"']


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ({"type": "wep", "key": "0102"}, "5 or 13 or 16 bytes"),
        ({"type": "wpa-psk", "key": "zz" * 32}, "hexadecimal"),
        ({"type": "wpa-pwd", "password": "short"}, "8 to 63"),
        ({"type": "wpa-pwd", "password": "long enough", "ssid": "x" * 33}, "at most 32"),
        ({"type": "rsa", "file": "relative.pem"}, "absolute path"),
        ({"type": "esp", "encryption": "ROT13"}, "unknown encryption"),
        ({"type": "esp", "spi": "0x1; rm"}, "spi"),
        ({"type": "esp", "src": "10.0.0.1,evil"}, "src"),
        ({"type": "ssh", "file": "/a\n/b"}, "one line"),
        ({"type": "magic"}, "type must be one of"),
    ],
)
def test_bad_keys_are_refused(key: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        DissectionOptions.from_params(keys=[key])


def test_one_file_per_preference(tmp_path: Path) -> None:
    a, b = str(tmp_path / "a.keys"), str(tmp_path / "b.keys")
    with pytest.raises(ConfigError, match="one ssh file"):
        DissectionOptions.from_params(keys=[{"type": "ssh", "file": a}, {"type": "ssh", "file": b}])
    with pytest.raises(ConfigError, match="absolute path"):
        DissectionOptions.from_params(geoip=["geo"])


def test_keys_and_their_files_are_part_of_the_index_key(tmp_path: Path) -> None:
    key = {
        "capture": FIXTURES / "esp.pcap",
        "tshark": Path("/usr/bin/tshark"),
        "tshark_version": "4.2.2",
        "lua_scripts": [],
        "decode_as": [],
        "prefs": {},
        "columns": [],
        "config": [],
    }
    plain = index_cache.index_key(**key)
    keyed = index_cache.index_key(**key, secrets=[("uat:80211_keys", '"wep","0a1b2c3d4e"')])
    assert plain != keyed
    keylog = tmp_path / "wg.keys"
    keylog.write_text("LOCAL_STATIC_PRIVATE_KEY = AAAA\n")
    before = index_cache.index_key(**key, files=[str(keylog)])
    keylog.write_text("LOCAL_STATIC_PRIVATE_KEY = AAAA\nREMOTE_STATIC_PUBLIC_KEY = BBBB\n")
    assert index_cache.index_key(**key, files=[str(keylog)]) != before


@pytest.mark.tshark
def test_wep_frames_are_decrypted_with_the_key(service: PcapService, ctx: RequestContext) -> None:
    wep = str(FIXTURES / "wep.pcap")
    service.open({"path": wep}, ctx)
    assert service.set_filter({"expr": "icmp"}, ctx)["matchCount"] == 0
    service.open({"path": wep, "keys": [WEP]}, ctx)
    assert service.set_filter({"expr": "icmp"}, ctx)["matchCount"] == 4
    detail = service.packet_detail({"number": 1}, ctx)
    assert any(node.get("name") == "icmp" for node in detail["tree"])


@pytest.mark.tshark
def test_esp_is_decrypted_per_security_association(
    service: PcapService, ctx: RequestContext, tmp_path: Path
) -> None:
    esp = str(FIXTURES / "esp.pcap")
    service.open({"path": esp}, ctx)
    assert service.set_filter({"expr": "icmp"}, ctx)["matchCount"] == 0
    service.open({"path": esp, "keys": ESP[:1]}, ctx)
    assert service.set_filter({"expr": "icmp"}, ctx)["matchCount"] == 2
    service.open({"path": esp, "keys": ESP}, ctx)
    assert service.set_filter({"expr": "icmp.type == 0"}, ctx)["matchCount"] == 2
    stats = service.stats({"kind": "phs"}, ctx)
    assert any(row["cells"][0] == "icmp" for row in stats["rows"])
    # A key file that isn't there is a warning, not a failure.
    res = service.open(
        {"path": esp, "keys": [*ESP, {"type": "wireguard", "file": str(tmp_path / "no.keys")}]},
        ctx,
    )
    assert any("no.keys" in w for w in res["warnings"])

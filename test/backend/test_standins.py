"""Address stand-ins (standins.py), as the extension's aiPrivacy.ts does them."""

from __future__ import annotations

import threading

from pcap_backend.standins import AddressMasker


def test_ipv4_tokens_and_kept_addresses() -> None:
    m = AddressMasker()
    text = (
        "192.168.1.10 → 93.184.216.34, again 192.168.1.10; 10.0.0.1 and 172.20.0.5; "
        "CGNAT 100.64.1.1, link-local 169.254.3.4; kept: 0.0.0.0 127.0.0.1 224.0.0.251 "
        "255.255.255.255"
    )
    assert m.mask(text) == (
        "IP_PRIVATE_1 → IP_PUBLIC_1, again IP_PRIVATE_1; IP_PRIVATE_2 and IP_PRIVATE_3; "
        "CGNAT IP_PRIVATE_4, link-local IP_PRIVATE_5; kept: 0.0.0.0 127.0.0.1 224.0.0.251 "
        "255.255.255.255"
    )
    assert m.restore(m.mask(text)) == text
    assert m.size == 6


def test_lookalikes_are_not_addresses() -> None:
    m = AddressMasker()
    text = "tshark 4.2.2, OID 1.3.6.1.2.1, 300.1.2.3, v1.2.3.4, frame 12.5, at 12:34:56"
    assert m.mask(text) == text


def test_ipv6_and_mac() -> None:
    m = AddressMasker()
    text = (
        "fe80::1c2a:3bff:fe4d:5e6f to 2001:db8::42 and fd00::7; kept ::1 ff02::fb ::; "
        "00:1a:2b:3c:4d:5e, 00-1A-2B-3C-4D-5E, Apple_12:34:56; kept ff:ff:ff:ff:ff:ff "
        "01:00:5e:00:00:fb 00:00:00:00:00:00"
    )
    assert m.mask(text) == (
        "IP6_LOCAL_1 to IP6_PUBLIC_1 and IP6_LOCAL_2; kept ::1 ff02::fb ::; "
        "MAC_1, MAC_1, MAC_2; kept ff:ff:ff:ff:ff:ff 01:00:5e:00:00:fb 00:00:00:00:00:00"
    )
    assert m.restore("MAC_1 talks to IP6_PUBLIC_1") == "00:1a:2b:3c:4d:5e talks to 2001:db8::42"


def test_filters_and_deep_restore() -> None:
    m = AddressMasker()
    masked = m.mask("ip.addr == 10.1.2.3 && eth.src == 00:1a:2b:3c:4d:5e && ip.dst == 8.8.8.0/24")
    assert masked == "ip.addr == IP_PRIVATE_1 && eth.src == MAC_1 && ip.dst == IP_PUBLIC_1/24"
    assert m.restore_deep(
        {"filter": "ip.src == IP_PRIVATE_1 || ip.src == IP_PUBLIC_9", "n": 3}
    ) == {
        "filter": "ip.src == 10.1.2.3 || ip.src == IP_PUBLIC_9",
        "n": 3,
    }
    assert m.restore_deep(["MAC_1", 1, None]) == ["00:1a:2b:3c:4d:5e", 1, None]


def test_off_changes_nothing() -> None:
    m = AddressMasker(enabled=False)
    assert m.mask("10.0.0.1") == "10.0.0.1"
    assert m.restore("IP_PRIVATE_1") == "IP_PRIVATE_1"


def test_one_token_per_address_across_threads() -> None:
    m = AddressMasker()
    results: list[str] = []

    def work() -> None:
        results.extend(m.mask(f"10.0.0.{i}") for i in range(1, 51))

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert m.size == 50
    assert len(set(results)) == 50

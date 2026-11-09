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


def test_ipv4_mapped_ipv6() -> None:
    m = AddressMasker()
    text = (
        "::ffff:192.168.1.2 is 192.168.1.2; 0:0:0:0:0:ffff:10.0.0.1, 64:ff9b::8.8.8.8, "
        "kept ::ffff:127.0.0.1, not an address ::ffff:1.2.3, at 12:34:56.789"
    )
    assert m.mask(text) == (
        "::ffff:IP_PRIVATE_1 is IP_PRIVATE_1; 0:0:0:0:0:ffff:IP_PRIVATE_2, IP6_PUBLIC_1, "
        "kept ::ffff:127.0.0.1, not an address ::ffff:1.2.3, at 12:34:56.789"
    )
    assert m.restore(m.mask(text)) == text


def test_reverse_lookup_names_and_ipv6_spellings() -> None:
    # PTR and mDNS queries name the address backwards: the ip6.arpa form spells
    # out a whole IPv6 address, which stayed readable.
    m = AddressMasker()
    v6 = "b.a.9.0.8.7.6.5.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
    text = (
        f"PTR 4.1.168.192.in-addr.arpa for 192.168.1.4; PTR {v6}.ip6.arpa for "
        "2001:db8:0:1:2:3:5678:9ab and 2001:0DB8:0000:0001:0002:0003:5678:09AB; "
        "zone 1.168.192.in-addr.arpa and 8.b.d.0.1.0.0.2.ip6.arpa stay"
    )
    assert m.mask(text) == (
        "PTR IP_PRIVATE_1.in-addr.arpa for IP_PRIVATE_1; PTR IP6_PUBLIC_1.ip6.arpa for "
        "IP6_PUBLIC_1 and IP6_PUBLIC_1; "
        "zone 1.168.192.in-addr.arpa and 8.b.d.0.1.0.0.2.ip6.arpa stay"
    )
    assert m.mask("2001:0db8:0:0:1:2:3:4") == m.mask("2001:db8::1:2:3:4")
    # Restored, a reverse name is written backwards again (a filter or a tool
    # call naming it finds the same packets).
    assert m.restore(m.mask(f'dns.qry.name == "4.1.168.192.in-addr.arpa" || {v6}.IP6.ARPA')) == (
        f'dns.qry.name == "4.1.168.192.in-addr.arpa" || {v6}.IP6.ARPA'
    )
    assert m.restore("MAC_1.in-addr.arpa HOST_9.ip6.arpa") == "MAC_1.in-addr.arpa HOST_9.ip6.arpa"


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

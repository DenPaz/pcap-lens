import * as assert from "node:assert/strict";
import { FIREWALL_PRODUCTS, firewallRules, packetEndpoints } from "../../../src/firewall";

// A trimmed packet_detail tree of an HTTP request (Ethernet / IPv4 / TCP).
const TREE = [
  {
    name: "eth",
    children: [
      { name: "eth.dst", show: "02:00:00:00:00:02" },
      { name: "eth.src", show: "02:00:00:00:00:01" },
    ],
  },
  {
    name: "ip",
    children: [
      { name: "ip.src", show: "192.168.1.10" },
      { name: "ip.dst", show: "93.184.216.34" },
    ],
  },
  {
    name: "tcp",
    children: [
      { name: "tcp.srcport", show: "50000" },
      { name: "tcp.dstport", show: "80" },
    ],
  },
];

suite("firewall ACL rules", () => {
  test("packetEndpoints: the innermost addresses and ports", () => {
    assert.deepEqual(packetEndpoints(TREE), {
      ethSrc: "02:00:00:00:00:01",
      ipSrc: "192.168.1.10",
      ipDst: "93.184.216.34",
      ipv6: false,
      proto: "tcp",
      srcPort: 50000,
      dstPort: 80,
    });
    const v6 = packetEndpoints([
      { name: "ipv6", children: [{ name: "ipv6.src", show: "2001:db8::1" }] },
      { name: "udp", children: [{ name: "udp.dstport", show: "53" }] },
      { name: "eth.src", show: "not a mac" },
    ]);
    assert.deepEqual(v6, { ipSrc: "2001:db8::1", ipv6: true, proto: "udp", dstPort: 53 });
  });

  test("Netfilter: deny inbound, allow outbound", () => {
    const p = packetEndpoints(TREE);
    assert.deepEqual(firewallRules(p, "iptables", { deny: true, inbound: true }), [
      {
        kind: "MAC source address",
        rule: "iptables --append INPUT --in-interface eth0 --mac-source 02:00:00:00:00:01 --jump DROP",
      },
      {
        kind: "IPv4 source address",
        rule: "iptables --append INPUT --in-interface eth0 --source 192.168.1.10/32 --jump DROP",
      },
      {
        kind: "IPv4 destination address",
        rule: "iptables --append INPUT --in-interface eth0 --destination 93.184.216.34/32 --jump DROP",
      },
      {
        kind: "TCP destination port",
        rule: "iptables --append INPUT --in-interface eth0 --protocol tcp --destination-port 80 --jump DROP",
      },
      {
        kind: "IPv4 source address and TCP destination port",
        rule: "iptables --append INPUT --in-interface eth0 --protocol tcp --source 192.168.1.10/32 --destination-port 80 --jump DROP",
      },
    ]);
    const out = firewallRules(p, "iptables", { deny: false, inbound: false });
    assert.equal(out.length, 4, "no MAC rule going out");
    assert.equal(
      out[0].rule,
      "iptables --append OUTPUT --out-interface eth0 --source 192.168.1.10/32 --jump ACCEPT",
    );
    const v6 = firewallRules({ ipSrc: "2001:db8::1", ipv6: true }, "nftables", {
      deny: true,
      inbound: true,
    });
    assert.deepEqual(v6, [
      {
        kind: "IPv6 source address",
        rule: "nft add rule inet filter input ip6 saddr 2001:db8::1 drop",
      },
    ]);
  });

  test("every product, a rule per kind it can express", () => {
    const p = packetEndpoints(TREE);
    const rules = Object.fromEntries(
      FIREWALL_PRODUCTS.map((product) => [
        product.id,
        firewallRules(p, product.id, { deny: true, inbound: true }).map((r) => r.rule),
      ]),
    );
    assert.deepEqual(rules.ciscoStandard, ["access-list 1 deny host 192.168.1.10"]);
    assert.deepEqual(rules.ciscoExtended, [
      "access-list 101 deny ip host 192.168.1.10 any",
      "access-list 101 deny ip any host 93.184.216.34",
      "access-list 101 deny tcp any any eq 80",
      "access-list 101 deny tcp host 192.168.1.10 any eq 80",
    ]);
    assert.equal(rules.ipfilter[2], "block in on le0 proto tcp from any to any port = 80");
    assert.equal(rules.ipfw[0], "add deny MAC any 02:00:00:00:00:01 in");
    assert.equal(rules.pf[3], "block in on $ext_if proto tcp from 192.168.1.10 to any port 80");
    assert.deepEqual(rules.netsh, [
      'netsh advfirewall firewall add rule name="PCAP Lens" dir=in action=block remoteip=192.168.1.10',
      'netsh advfirewall firewall add rule name="PCAP Lens" dir=in action=block protocol=TCP localport=80',
      'netsh advfirewall firewall add rule name="PCAP Lens" dir=in action=block protocol=TCP remoteip=192.168.1.10 localport=80',
    ]);
    // A packet without addresses (ARP) gives a MAC rule at most.
    assert.deepEqual(
      firewallRules({ ethSrc: "02:00:00:00:00:01" }, "pf", { deny: true, inbound: true }),
      [],
    );
  });
});

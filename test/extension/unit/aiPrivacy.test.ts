import * as assert from "node:assert/strict";
import {
  AddressMasker,
  STAND_IN_NOTE,
  maskedLoopModel,
  namesInRows,
  namesInTree,
} from "../../../src/aiPrivacy";
import type { LoopMessage, LoopPart, LoopModel } from "../../../src/aiTools";

suite("AI address stand-ins", () => {
  test("IPv4: private and public tokens, the same address the same token, special ones kept", () => {
    const m = new AddressMasker();
    const text =
      "192.168.1.10 → 93.184.216.34, again 192.168.1.10; 10.0.0.1 and 172.20.0.5; " +
      "CGNAT 100.64.1.1, link-local 169.254.3.4; kept: 0.0.0.0 127.0.0.1 224.0.0.251 255.255.255.255";
    assert.equal(
      m.mask(text),
      "IP_PRIVATE_1 → IP_PUBLIC_1, again IP_PRIVATE_1; IP_PRIVATE_2 and IP_PRIVATE_3; " +
        "CGNAT IP_PRIVATE_4, link-local IP_PRIVATE_5; kept: 0.0.0.0 127.0.0.1 224.0.0.251 255.255.255.255",
    );
    assert.equal(m.restore(m.mask(text)), text);
    assert.equal(m.size, 6);
  });

  test("IPv4 lookalikes aren't touched: versions, OIDs, out-of-range octets", () => {
    const m = new AddressMasker();
    const text = "tshark 4.2.2, OID 1.3.6.1.2.1, 300.1.2.3, v1.2.3.4, frame 12.5";
    assert.equal(m.mask(text), text);
  });

  test("IPv6 and MAC addresses; times and group addresses aren't", () => {
    const m = new AddressMasker();
    const text =
      "fe80::1c2a:3bff:fe4d:5e6f to 2001:db8::42 and fd00::7; kept ::1 ff02::fb :: 12:34:56; " +
      "00:1a:2b:3c:4d:5e, 00-1A-2B-3C-4D-5E, Apple_12:34:56; kept ff:ff:ff:ff:ff:ff 01:00:5e:00:00:fb";
    assert.equal(
      m.mask(text),
      "IP6_LOCAL_1 to IP6_PUBLIC_1 and IP6_LOCAL_2; kept ::1 ff02::fb :: 12:34:56; " +
        "MAC_1, MAC_1, MAC_2; kept ff:ff:ff:ff:ff:ff 01:00:5e:00:00:fb",
    );
    assert.equal(
      m.restore("MAC_1 talks to IP6_PUBLIC_1"),
      "00:1a:2b:3c:4d:5e talks to 2001:db8::42",
    );
  });

  test("IPv4-mapped IPv6 addresses: the IPv4 host's token, never a partial match", () => {
    const m = new AddressMasker();
    const text =
      "::ffff:192.168.1.2 is 192.168.1.2; 0:0:0:0:0:ffff:10.0.0.1, 64:ff9b::8.8.8.8, " +
      "kept ::ffff:127.0.0.1, not an address ::ffff:1.2.3, at 12:34:56.789";
    assert.equal(
      m.mask(text),
      "::ffff:IP_PRIVATE_1 is IP_PRIVATE_1; 0:0:0:0:0:ffff:IP_PRIVATE_2, IP6_PUBLIC_1, " +
        "kept ::ffff:127.0.0.1, not an address ::ffff:1.2.3, at 12:34:56.789",
    );
    assert.equal(m.restore(m.mask(text)), text);
  });

  test("display filters keep working with tokens; unknown tokens stay", () => {
    const m = new AddressMasker();
    const masked = m.mask(
      "ip.addr == 10.1.2.3 && eth.src == 00:1a:2b:3c:4d:5e && ip.dst == 8.8.8.0/24",
    );
    assert.equal(masked, "ip.addr == IP_PRIVATE_1 && eth.src == MAC_1 && ip.dst == IP_PUBLIC_1/24");
    assert.equal(
      m.restore("ip.src == IP_PRIVATE_1 || ip.src == IP_PUBLIC_9"),
      "ip.src == 10.1.2.3 || ip.src == IP_PUBLIC_9",
    );
  });

  test("learned host names: with their address's token, else a HOST token", () => {
    const m = new AddressMasker();
    m.learnNames([
      { name: "printer.lan", address: "192.168.1.20" },
      { name: "fileserver" },
      { name: "ab" }, // too short
      { name: "10.0.0.9" }, // an address, not a name
    ]);
    assert.equal(
      m.mask("printer.lan (192.168.1.20) and fileserver; printer.lan."),
      "IP_PRIVATE_1 (IP_PRIVATE_1) and HOST_1; IP_PRIVATE_1.",
    );
    assert.equal(m.mask("printer.land"), "printer.land", "whole names only");
    assert.equal(m.restore("HOST_1 answers"), "fileserver answers");
  });

  test("off: nothing changes", () => {
    const m = new AddressMasker(false);
    m.learnNames([{ name: "fileserver" }]);
    assert.equal(m.mask("10.0.0.1 fileserver"), "10.0.0.1 fileserver");
    assert.equal(m.restore("IP_PRIVATE_1"), "IP_PRIVATE_1");
  });

  test("a streamed answer is restored even when a token is split between chunks", () => {
    const m = new AddressMasker();
    m.mask("10.0.0.1 and 8.8.8.8");
    const r = m.restorer();
    const chunks = ["Host IP_PRI", "VATE_1 asks IP_", "PUBLIC_1", " for DNS. IP"];
    const out = chunks.map((c) => r.push(c)).join("") + r.end();
    assert.equal(out, "Host 10.0.0.1 asks 8.8.8.8 for DNS. IP");
  });

  test("names from packet rows and dissection trees", () => {
    assert.deepEqual(
      namesInRows([
        { cells: ["1", "0.0", "laptop.lan", "93.184.216.34"], addresses: ["192.168.1.5", ""] },
        { cells: ["2", "0.1", "10.0.0.1", "10.0.0.2"] },
      ]),
      [{ name: "laptop.lan", address: "192.168.1.5" }],
    );
    assert.deepEqual(
      namesInTree([
        {
          name: "ip",
          children: [
            { name: "ip.src", show: "192.168.1.5" },
            { name: "ip.src_host", show: "laptop.lan" },
            { name: "ip.dst_host", show: "example.com" },
          ],
        },
      ]),
      [
        { name: "laptop.lan", address: "192.168.1.5" },
        { name: "example.com", address: undefined },
      ],
    );
  });

  test("the tool loop sees stand-ins; tools get real values back", async () => {
    const m = new AddressMasker();
    const seen: LoopMessage[][] = [];
    const inner: LoopModel = {
      async *send(messages) {
        seen.push(messages.map((x) => structuredClone(x)));
        yield { type: "text", text: "Checking IP_PRIV" } satisfies LoopPart;
        yield { type: "text", text: "ATE_1…" } satisfies LoopPart;
        yield {
          type: "call",
          callId: "c1",
          name: "pcap_count",
          input: { filter: "ip.addr == IP_PRIVATE_1" },
        } satisfies LoopPart;
      },
    };
    const parts: LoopPart[] = [];
    for await (const p of maskedLoopModel(inner, m).send(
      [
        { role: "user", parts: [{ type: "text", text: "Who talks to 10.0.0.1?" }] },
        { role: "user", parts: [{ type: "result", callId: "c0", text: "10.0.0.1: 5 packets" }] },
      ],
      [],
    )) {
      parts.push(p);
    }
    const first = seen[0][0].parts[0];
    assert.ok(first.type === "text" && first.text.startsWith(STAND_IN_NOTE));
    assert.ok(first.type === "text" && first.text.endsWith("Who talks to IP_PRIVATE_1?"));
    assert.deepEqual(seen[0][1].parts[0], {
      type: "result",
      callId: "c0",
      text: "IP_PRIVATE_1: 5 packets",
    });
    assert.equal(
      parts
        .filter((p) => p.type === "text")
        .map((p) => (p.type === "text" ? p.text : ""))
        .join(""),
      "Checking 10.0.0.1…",
    );
    assert.deepEqual(parts.at(-1), {
      type: "call",
      callId: "c1",
      name: "pcap_count",
      input: { filter: "ip.addr == 10.0.0.1" },
    });
  });
});

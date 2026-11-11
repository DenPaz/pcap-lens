import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as zlib from "node:zlib";
import {
  BasicCapture,
  CaptureFormatError,
  NeedsToolsError,
  TreeNode,
  basicRequest,
  dissect,
} from "../../../src/basicCapture";

const ROOT = path.resolve(__dirname, "../../../..");
const FIXTURES = path.join(ROOT, "test", "fixtures");

function fixture(name: string): string {
  return path.join(FIXTURES, name);
}

function find(nodes: TreeNode[], name: string): TreeNode | undefined {
  for (const n of nodes) {
    if (n.name === name) {
      return n;
    }
    const inner = n.children && find(n.children, name);
    if (inner) {
      return inner;
    }
  }
  return undefined;
}

let tmp: string;

suite("basic view: captures read without tshark", () => {
  suiteSetup(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "basic-capture-"));
  });
  suiteTeardown(() => fs.rmSync(tmp, { recursive: true, force: true }));

  test("a pcap: the packet list's columns, as tshark -n shows them", async () => {
    const c = await BasicCapture.open(fixture("http.pcap"));
    try {
      assert.equal(c.count, 11);
      assert.equal(c.fileType, "pcap");
      assert.equal(c.linkTypeName(), "Ethernet");
      assert.deepEqual(c.row(1).cells, [
        "1",
        "0.000000000",
        "192.168.1.10",
        "93.184.216.34",
        "TCP",
        "54",
        // (raw sequence numbers: tshark's relative ones need its TCP analysis)
        "50000 → 80 [SYN] Seq=999 Win=8192 Len=0",
      ]);
      assert.deepEqual(c.row(2).cells.slice(1, 5), [
        "0.001000000",
        "93.184.216.34",
        "192.168.1.10",
        "TCP",
      ]);
      assert.equal(c.row(2).cells[6], "80 → 50000 [SYN, ACK] Seq=4999 Ack=1000 Win=8192 Len=0");
      assert.deepEqual(c.row(4).cells.slice(4), ["HTTP", "144", "GET /index.html HTTP/1.1"]);
      const span = c.timeSpan();
      assert.ok(span.start !== null && span.end !== null);
      assert.ok(Math.abs(span.end - span.start - 0.01) < 1e-6);
    } finally {
      c.close();
    }
  });

  test("pcapng, also gzip-compressed: ARP, ICMP and DNS", async () => {
    for (const name of ["mixed.pcapng", "formats/mixed.pcapng.gz", "formats/mixed.ntar"]) {
      const c = await BasicCapture.open(fixture(name));
      try {
        assert.equal(c.count, 26, name);
        assert.equal(c.fileType, "pcapng");
        assert.equal(c.compressed, name.endsWith(".gz"));
        const info = (n: number) => c.row(n).cells[6];
        assert.equal(info(1), "Who has 192.168.1.1? Tell 192.168.1.10");
        assert.deepEqual(c.row(1).cells.slice(2, 5), [
          "02:00:00:00:00:01",
          "ff:ff:ff:ff:ff:ff",
          "ARP",
        ]);
        assert.equal(info(2), "Echo (ping) request  id=0x0001, seq=1/256, ttl=64");
        assert.equal(info(4), "Standard query 0x1000 A example.com");
        assert.equal(info(5), "Standard query response 0x1000 A example.com A 93.184.216.34");
        assert.equal(info(9), "Standard query response 0x1002 No such name A nonexistent.invalid");
      } finally {
        c.close();
      }
    }
  });

  test("details: a Frame tree, then each layer with its fields' bytes", async () => {
    const c = await BasicCapture.open(fixture("http.pcap"));
    try {
      const { tree, sources } = c.detail(4);
      assert.deepEqual(
        tree.map((n) => n.name),
        ["frame", "eth", "ip", "tcp", "http"],
      );
      assert.match(tree[0].label, /^Frame 4: 144 bytes on wire/);
      assert.equal(sources.length, 1);
      assert.equal(sources[0].name, "Frame");
      assert.equal(sources[0].hex.length, 144 * 2);
      const src = find(tree, "ip.src")!;
      assert.equal(src.show, "192.168.1.10");
      assert.equal(sources[0].hex.slice(src.pos! * 2, (src.pos! + src.size!) * 2), "c0a8010a");
      assert.equal(find(tree, "tcp.dstport")?.show, "80");
      const ids = new Set<number>();
      const walk = (nodes: TreeNode[]) =>
        nodes.forEach((n) => {
          assert.ok(!ids.has(n.id), "ids are unique");
          ids.add(n.id);
          walk(n.children ?? []);
        });
      walk(tree);
    } finally {
      c.close();
    }
  });

  test("802.11 frames: source and destination by the DS bits", async () => {
    const c = await BasicCapture.open(fixture("wep.pcap"));
    try {
      assert.deepEqual(c.row(1).cells.slice(2, 5), [
        "02:00:00:00:0a:02",
        "02:00:00:00:0a:03",
        "802.11",
      ]);
    } finally {
      c.close();
    }
  });

  test("a damaged file shows the packets before the damage and says where", async () => {
    const c = await BasicCapture.open(fixture("truncated.pcap"));
    try {
      assert.equal(c.count, 10);
      assert.deepEqual(c.warnings, [
        "The file ends inside packet 11; the 10 packets before it are shown.",
      ]);
    } finally {
      c.close();
    }
    // A record claiming more than 256 KB.
    const good = fs.readFileSync(fixture("http.pcap"));
    const bad = Buffer.from(good);
    bad.writeUInt32LE(1_000_000, 24 + 8);
    const file = path.join(tmp, "huge-record.pcap");
    fs.writeFileSync(file, bad);
    const d = await BasicCapture.open(file);
    assert.equal(d.count, 0);
    assert.match(d.warnings[0], /claims 1000000 bytes/);
    d.close();
  });

  test("files it can't read say why", async () => {
    for (const [name, why] of [
      ["formats/http.pcap.zst", /zstd and lz4/],
      ["formats/mixed.pcapng.lz4", /zstd and lz4/],
      ["formats/notes.log", /isn't a pcap or pcapng file/],
      ["formats/http.snoop", /isn't a pcap or pcapng file/],
    ] as const) {
      await assert.rejects(BasicCapture.open(fixture(name)), (err: unknown) => {
        assert.ok(err instanceof CaptureFormatError, name);
        assert.match(err.message, why);
        return true;
      });
    }
    // A gzip file unpacking past the limit stops there.
    const bomb = path.join(tmp, "bomb.pcap.gz");
    fs.writeFileSync(bomb, zlib.gzipSync(Buffer.alloc(64 * 1024)));
    await assert.rejects(BasicCapture.open(bomb, 1024), /more than/);
    const empty = path.join(tmp, "empty.pcap");
    fs.writeFileSync(empty, "");
    await assert.rejects(BasicCapture.open(empty), /empty or too short/);
  });

  test("big-endian nanosecond pcap with raw IP, and pcapng's own time resolution", async () => {
    // One raw-IPv6 UDP datagram (link type 101), written big-endian with nanoseconds.
    const ip6 = Buffer.alloc(48);
    ip6[0] = 0x60;
    ip6.writeUInt16BE(8, 4); // payload length
    ip6[6] = 17; // UDP
    ip6[7] = 64;
    ip6.write("20010db8000000000000000000000001", 8, "hex");
    ip6.write("ff020000000000000000000000000002", 24, "hex");
    ip6.writeUInt16BE(546, 40);
    ip6.writeUInt16BE(547, 42);
    ip6.writeUInt16BE(8, 44);
    const header = Buffer.alloc(24);
    header.writeUInt32BE(0xa1b23c4d, 0);
    header.writeUInt16BE(2, 4);
    header.writeUInt16BE(4, 6);
    header.writeUInt32BE(65535, 16);
    header.writeUInt32BE(101, 20);
    const records = [0, 1].map((i) => {
      const rec = Buffer.alloc(16);
      rec.writeUInt32BE(1_700_000_000, 0);
      rec.writeUInt32BE(i * 123_456_789, 4);
      rec.writeUInt32BE(ip6.length, 8);
      rec.writeUInt32BE(ip6.length, 12);
      return Buffer.concat([rec, ip6]);
    });
    const file = path.join(tmp, "be-ns.pcap");
    fs.writeFileSync(file, Buffer.concat([header, ...records]));
    const c = await BasicCapture.open(file);
    assert.equal(c.linkTypeName(), "Raw IP");
    assert.deepEqual(c.row(2).cells.slice(1, 5), ["0.123456789", "2001:db8::1", "ff02::2", "UDP"]);
    assert.equal(c.row(2).cells[6], "546 → 547 Len=0");
    c.close();

    // pcapng: an interface with if_tsresol 9 (nanoseconds), an enhanced and a simple packet block.
    const block = (type: number, body: Buffer) => {
      const len = 12 + body.length;
      const out = Buffer.alloc(len);
      out.writeUInt32LE(type, 0);
      out.writeUInt32LE(len, 4);
      body.copy(out, 8);
      out.writeUInt32LE(len, len - 4);
      return out;
    };
    const shb = Buffer.alloc(16);
    shb.writeUInt32LE(0x1a2b3c4d, 0);
    shb.writeUInt16LE(1, 4);
    shb.writeBigInt64LE(-1n, 8);
    const idb = Buffer.alloc(16);
    idb.writeUInt16LE(101, 0);
    idb.writeUInt32LE(65535, 4);
    idb.writeUInt16LE(9, 8); // if_tsresol
    idb.writeUInt16LE(1, 10);
    idb[12] = 9;
    const epb = Buffer.alloc(20 + ip6.length);
    const ticks = 1_700_000_000_500_000_000n;
    epb.writeUInt32LE(Number(ticks >> 32n), 4);
    epb.writeUInt32LE(Number(ticks & 0xffffffffn), 8);
    epb.writeUInt32LE(ip6.length, 12);
    epb.writeUInt32LE(ip6.length, 16);
    ip6.copy(epb, 20);
    const spb = Buffer.alloc(4 + ip6.length);
    spb.writeUInt32LE(ip6.length, 0);
    ip6.copy(spb, 4);
    const ng = path.join(tmp, "ns.pcapng");
    fs.writeFileSync(
      ng,
      Buffer.concat([block(0x0a0d0d0a, shb), block(1, idb), block(6, epb), block(3, spb)]),
    );
    const n = await BasicCapture.open(ng);
    assert.equal(n.count, 2);
    assert.equal(n.seconds[0], 1_700_000_000);
    assert.equal(n.nanos[0], 500_000_000);
    assert.equal(n.seconds[1], null, "a simple packet block has no time");
    assert.equal(n.row(2).cells[1], "");
    assert.equal(n.row(2).cells[4], "UDP");
    n.close();
  });

  test("a header cut short is marked malformed, not thrown", () => {
    // Ethernet + the first 10 bytes of an IPv4 header.
    const d = Buffer.alloc(24);
    d.writeUInt16BE(0x0800, 12);
    d[14] = 0x45;
    const out = dissect(d, 1, true);
    assert.match(out.info, /Malformed/);
    assert.ok(find(out.tree, "_ws.malformed"));
  });

  test("requests: the list, details and positions; the rest needs tshark", async () => {
    const c = await BasicCapture.open(fixture("http.pcap"));
    try {
      const page = basicRequest(c, "list_packets", {
        offset: 9,
        limit: 5,
        columns: ["http.host"],
      }) as { rows: { number: number; cells: string[] }[]; total: number; columns: string[] };
      assert.deepEqual(
        page.rows.map((r) => r.number),
        [10, 11],
      );
      assert.equal(page.total, 11);
      assert.equal(page.rows[0].cells.length, 8, "custom columns are blank");
      assert.equal(page.columns.at(-1), "http.host");
      const picked = basicRequest(c, "list_packets", { frames: [7, 2, 99] }) as {
        rows: { number: number }[];
      };
      assert.deepEqual(
        picked.rows.map((r) => r.number),
        [2, 7],
      );
      assert.deepEqual(basicRequest(c, "find_frame", { number: 5 }), { index: 4, filterId: 1 });
      assert.deepEqual(basicRequest(c, "find_frame", { number: 50 }), { index: -1, filterId: 1 });
      assert.deepEqual(basicRequest(c, "view_frames", { offset: 1, limit: 3 }), {
        frames: [2, 3, 4],
        filterId: 1,
      });
      const detail = basicRequest(c, "packet_detail", { number: 1, mode: "quick" }) as {
        tree: TreeNode[];
      };
      assert.equal(detail.tree[0].name, "frame");
      assert.throws(() => basicRequest(c, "packet_detail", { number: 12 }), RangeError);
      assert.deepEqual(basicRequest(c, "field_types", { names: ["ip.src"] }), { types: {} });
      assert.throws(
        () => basicRequest(c, "set_filter", { expr: "tcp" }),
        (err: unknown) =>
          err instanceof NeedsToolsError && /^Filtering needs tshark/.test(err.message),
      );
      assert.throws(() => basicRequest(c, "expert_summary", {}), NeedsToolsError);
    } finally {
      c.close();
    }
  });
});

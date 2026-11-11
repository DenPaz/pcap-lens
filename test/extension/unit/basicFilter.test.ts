import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  BasicCancelledError,
  BasicCapture,
  basicRequest,
  type BasicRequestContext,
} from "../../../src/basicCapture";
import {
  BASIC_FIELDS,
  BasicFilterError,
  basicFieldType,
  compileBasicFilter,
  filterNames,
  findBasicFields,
  ipv6Number,
  matchesFilter,
  normalizeMac,
  searchBasicFields,
  type FieldValue,
} from "../../../src/basicFilter";

const FIXTURES = path.resolve(__dirname, "../../../../test/fixtures");

/** Does `expr` match a packet with these fields? */
function test1(expr: string, fields: Record<string, FieldValue[]>): boolean {
  return matchesFilter(compileBasicFilter(expr), (name) => fields[name] ?? []);
}

/** The error (and span) `expr` is refused with. */
function refusal(expr: string): { message: string; span: [number, number] | null } {
  try {
    compileBasicFilter(expr);
  } catch (err) {
    if (err instanceof BasicFilterError) {
      return { message: err.message, span: err.span };
    }
    throw err;
  }
  assert.fail(`${expr} was accepted`);
}

/** The frames of the view after applying `expr`. */
async function frames(c: BasicCapture, expr: string): Promise<number[]> {
  await basicRequest(c, "set_filter", { expr });
  return c.viewSlice(0, c.viewCount);
}

suite("basic view: display filters", () => {
  const packet = {
    ip: [Buffer.from("4500", "hex")],
    "ip.src": ["192.168.1.10"],
    "ip.dst": ["93.184.216.34"],
    "ip.addr": ["192.168.1.10", "93.184.216.34"],
    "ipv6.addr": ["2001:db8::1"],
    tcp: [Buffer.from("GET / HTTP/1.1", "latin1")],
    "tcp.port": [50000, 80],
    "tcp.flags.syn": [1],
    "tcp.flags.ack": [0],
    "eth.src": ["00:11:22:33:44:55"],
    "http.request.method": ["GET"],
    "http.request": [""],
    "dns.qry.name": ["www.Example.com"],
  };

  test("names alone test presence; comparisons need the field", () => {
    assert.equal(test1("tcp", packet), true);
    assert.equal(test1("udp", packet), false);
    assert.equal(test1("http.request", packet), true);
    assert.equal(test1("udp.port == 53", packet), false);
    assert.equal(
      test1("udp.port != 53", packet),
      false,
      "a comparison with an absent field is false",
    );
    assert.equal(test1("!(udp.port == 53)", packet), true);
  });

  test("==, != (no value equals), === (all), !== (any differs) and order", () => {
    assert.equal(test1("ip.addr == 192.168.1.10", packet), true);
    assert.equal(
      test1("ip.addr != 192.168.1.10", packet),
      false,
      "!= is all_ne, as in Wireshark 4",
    );
    assert.equal(test1("ip.addr !== 192.168.1.10", packet), true);
    assert.equal(test1("ip.addr === 192.168.1.10", packet), false);
    assert.equal(test1("tcp.port all_eq 80", packet), false);
    assert.equal(test1("tcp.port eq 80 and tcp.port gt 49999", packet), true);
    assert.equal(test1("tcp.port > 60000", packet), false);
    assert.equal(test1("tcp.port <= 80", packet), true);
    assert.equal(test1("tcp.port == 0x50", packet), true, "hex numbers");
  });

  test("addresses: IPv4 and IPv6 networks, MAC forms", () => {
    assert.equal(test1("ip.src == 192.168.0.0/16", packet), true);
    assert.equal(test1("ip.dst == 192.168.0.0/16", packet), false);
    assert.equal(test1("ip.addr == 0.0.0.0/0", packet), true);
    assert.equal(test1("ipv6.addr == 2001:db8::/32", packet), true);
    assert.equal(test1("ipv6.addr == 2001:0db8:0:0::1", packet), true);
    assert.equal(test1("ipv6.addr == fe80::/10", packet), false);
    assert.equal(test1("eth.src == 00-11-22-33-44-55", packet), true);
    assert.equal(test1("eth.src == 0011.2233.4455", packet), true);
    assert.equal(test1("eth.src == 00:11:22:33:44:56", packet), false);
    assert.equal(normalizeMac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff");
    assert.equal(ipv6Number("::ffff:1.2.3.4"), 0xffff01020304n);
    assert.equal(ipv6Number("1::2::3"), null);
  });

  test("and binds tighter than or; xor; not; parentheses", () => {
    assert.equal(test1("udp or tcp and tcp.port == 80", packet), true);
    assert.equal(test1("tcp or udp and udp.port == 53", packet), true);
    assert.equal(test1("(tcp or udp) and udp.port == 53", packet), false);
    assert.equal(test1("tcp xor ip", packet), false);
    assert.equal(test1("tcp ^^ udp", packet), true);
    assert.equal(test1("not not tcp", packet), true);
    assert.equal(test1("!tcp || ip", packet), true);
  });

  test("sets with ranges; booleans; contains and matches", () => {
    assert.equal(test1("tcp.port in {443, 8080}", packet), false);
    assert.equal(test1("tcp.port in {443 80}", packet), true);
    assert.equal(test1("tcp.port in {1..1023}", packet), true);
    assert.equal(test1("tcp.port not in {80, 50000}", packet), false);
    assert.equal(test1("ip.addr in {10.0.0.0/8, 93.184.216.0/24}", packet), true);
    assert.equal(test1("tcp.flags.syn == True && tcp.flags.ack == 0", packet), true);
    assert.equal(test1("tcp.flags.syn == 2", packet), true, "as tshark: any other number is true");
    assert.equal(test1('tcp contains "GET"', packet), true);
    assert.equal(test1("tcp contains 47:45:54", packet), true);
    assert.equal(test1('tcp contains "get"', packet), false);
    assert.equal(test1('tcp matches "(?i)get"', packet), true);
    assert.equal(test1('dns.qry.name contains "Example"', packet), true);
    assert.equal(test1('dns.qry.name matches "example\\\\.com$"', packet), false);
    assert.equal(test1('dns.qry.name matches "(?i)example\\\\.com$"', packet), true);
    assert.equal(test1('http.request.method == "GET"', packet), true);
    assert.equal(test1("http.request.method == GET", packet), true, "a bare word is a string");
    assert.equal(test1('frame contains "\\x47E"', { frame: [Buffer.from("GET")] }), true);
  });

  test("refused filters say why and where (UTF-16 spans, as tshark's)", () => {
    assert.deepEqual(refusal("tcp.port == 99999"), {
      message: '"99999" too big for this field, maximum 65535.',
      span: [12, 17],
    });
    assert.deepEqual(refusal("ip.addr == 300.1.1.1").span, [11, 20]);
    assert.match(refusal("ip.addr == 300.1.1.1").message, /isn't an IPv4 address/);
    assert.deepEqual(refusal("tcp.port == "), {
      message: "Unexpected end of filter expression.",
      span: [11, 11],
    });
    const unknown = refusal("tcp && http.user_agent");
    assert.match(unknown.message, /"http.user_agent" isn't a field the basic view reads/);
    assert.deepEqual(unknown.span, [7, 22]);
    assert.match(refusal("frame[0:2] == 00:11").message, /^Slices/);
    assert.match(refusal("len(http.request.uri) > 5").message, /^Functions such as len\(\)/);
    assert.match(refusal("tcp.port == ${port}").message, /^Field references/);
    assert.match(refusal("tcp.len + 1 > 2").message, /^Arithmetic/);
    assert.match(refusal('tcp.port contains "x"').message, /can't hold text/);
    assert.match(refusal("http.request == 1").message, /can only be tested for being there/);
    assert.match(refusal('dns.qry.name matches "("').message, /regular expression is invalid/);
    assert.match(refusal('ip.src == "x').message, /no closing quote/);
    assert.match(refusal("(tcp").message, /Unexpected end/);
    assert.match(refusal("tcp ) udp").message, /"\)" was unexpected/);
    assert.match(refusal("tcp.port in {}").message, /The set is empty/);
    assert.match(refusal("tcp.flags.syn == yes").message, /isn't a boolean/);
    assert.match(refusal("frame.time_relative > soon").message, /isn't a time in seconds/);
  });

  test("the field list: types, prefix search, words, and the names a filter uses", () => {
    assert.equal(basicFieldType("tcp"), "FT_PROTOCOL");
    assert.equal(basicFieldType("ip.ttl"), "FT_UINT8");
    assert.equal(basicFieldType("http.user_agent"), undefined);
    const names = BASIC_FIELDS.map((f) => f.name);
    assert.deepEqual(names, [...names].sort(), "kept sorted, like tshark's catalogue");
    const tcp = searchBasicFields("tcp.f", 3);
    assert.deepEqual(
      tcp.fields.map((f) => f.name),
      ["tcp.flags", "tcp.flags.ack", "tcp.flags.fin"],
    );
    assert.equal(tcp.truncated, true);
    assert.deepEqual(
      searchBasicFields("ud", 10).protocols.map((p) => p.name),
      ["udp"],
    );
    assert.deepEqual(
      findBasicFields("ttl", 5).map((f) => f.name),
      ["ip.ttl"],
    );
    assert.equal(findBasicFields("source port", 10)[0].name, "tcp.port");
    assert.deepEqual(
      [...filterNames(compileBasicFilter("tcp && !(ip.ttl > 3 || tcp)"))],
      ["tcp", "ip.ttl"],
    );
  });
});

suite("basic view: filtering a capture (counts checked against tshark -Y)", () => {
  test("http.pcap: the view, its positions and the Time column's displayed deltas", async () => {
    const c = await BasicCapture.open(path.join(FIXTURES, "http.pcap"));
    try {
      assert.deepEqual(await frames(c, "ip.addr == 192.168.1.10 && tcp.len > 0"), [4, 6, 7]);
      assert.deepEqual(await frames(c, "tcp.flags.syn == 1"), [1, 2]);
      assert.deepEqual(await frames(c, 'frame contains "GET"'), [4]);
      assert.deepEqual(
        await frames(c, "tcp.port == 80 and !(frame.len > 100)"),
        [1, 2, 3, 5, 8, 9, 10, 11],
      );
      const res = (await basicRequest(c, "set_filter", { expr: "tcp.len > 0" })) as {
        matchCount: number;
        total: number;
        filterId: number;
      };
      assert.equal(res.matchCount, 3);
      assert.equal(res.total, 11);
      assert.ok(res.filterId > 1);
      const page = basicRequest(c, "list_packets", {
        offset: 0,
        limit: 10,
        timeFormat: "delta_displayed",
      }) as { rows: { number: number; cells: string[] }[]; total: number; filterId: number };
      assert.equal(page.total, 3);
      assert.equal(page.filterId, res.filterId);
      assert.deepEqual(
        page.rows.map((r) => r.number),
        [4, 6, 7],
      );
      assert.equal(page.rows[0].cells[1], "0.000000", "nothing shown before packet 4");
      assert.equal(
        page.rows[1].cells[1],
        c.timeText(6, "delta_displayed", null, 4),
        "since packet 4, the previous one shown",
      );
      assert.notEqual(page.rows[1].cells[1], c.timeText(6, "delta_captured", null));
      assert.deepEqual(basicRequest(c, "find_frame", { number: 6 }), {
        index: 1,
        filterId: res.filterId,
      });
      assert.equal((basicRequest(c, "find_frame", { number: 5 }) as { index: number }).index, -1);
      assert.deepEqual(
        (basicRequest(c, "view_frames", { frames: [7, 1, 4] }) as { frames: number[] }).frames,
        [4, 7],
      );
      assert.deepEqual(
        (
          basicRequest(c, "list_packets", { frames: [7, 1] }) as { rows: { number: number }[] }
        ).rows.map((r) => r.number),
        [7],
      );
      assert.equal((basicRequest(c, "view_overview", {}) as { rows: number }).rows, 3);
      assert.deepEqual(await frames(c, ""), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
      await assert.rejects(
        Promise.resolve().then(() => basicRequest(c, "set_filter", { expr: "tcp.port == x" })),
        BasicFilterError,
      );
      assert.equal(c.viewCount, 11, "a refused filter leaves the view");
      assert.deepEqual(basicRequest(c, "validate_filter", { expr: "tcp.port == 99999" }), {
        valid: false,
        error: '"99999" too big for this field, maximum 65535.',
        span: [12, 17],
      });
      assert.deepEqual(basicRequest(c, "validate_filter", { expr: "tcp" }), { valid: true });
    } finally {
      c.close();
    }
  });

  test("dns.pcap and mixed.pcapng: DNS, ARP, ICMP and broadcast", async () => {
    const dns = await BasicCapture.open(path.join(FIXTURES, "dns.pcap"));
    const mixed = await BasicCapture.open(path.join(FIXTURES, "mixed.pcapng"));
    try {
      assert.deepEqual(await frames(dns, 'dns.qry.name contains "example"'), [1, 2]);
      assert.deepEqual(await frames(dns, "dns.flags.response == 1"), [2, 4, 6]);
      assert.deepEqual(await frames(dns, "dns.a"), [2, 4]);
      assert.deepEqual(await frames(dns, "udp.port == 53 and ip.ttl > 60"), [1, 2, 3, 4, 5, 6]);
      assert.deepEqual(await frames(dns, 'udp contains "example"'), [1, 2]);
      assert.deepEqual(await frames(mixed, "arp"), [1]);
      assert.deepEqual(await frames(mixed, "icmp"), [2, 3]);
      assert.deepEqual(await frames(mixed, "eth.addr == ff:ff:ff:ff:ff:ff"), [1]);
      assert.deepEqual(await frames(mixed, "ipv6 || mdns"), []);
    } finally {
      dns.close();
      mixed.close();
    }
  });

  test("Find Packet: a filter, text in the bytes, the list or the details, hex, marks", async () => {
    const c = await BasicCapture.open(path.join(FIXTURES, "http.pcap"));
    try {
      const find = (params: Record<string, unknown>) =>
        basicRequest(c, "find_packet", params) as Promise<{
          frame: number | null;
          index: number | null;
          wrapped?: boolean;
        }>;
      assert.equal((await find({ mode: "filter", value: "tcp.len > 0", from: 4 })).frame, 6);
      const back = await find({
        mode: "filter",
        value: "tcp.len > 0",
        from: 4,
        direction: "previous",
      });
      assert.deepEqual([back.frame, back.wrapped], [7, true]);
      assert.equal((await find({ mode: "string", value: "get /", from: 1 })).frame, 4);
      assert.equal(
        (await find({ mode: "string", value: "get /", from: 1, caseSensitive: true })).frame,
        null,
      );
      assert.equal((await find({ mode: "regex", value: "HTTP/1\\.[01] 200" })).frame, 6);
      assert.equal((await find({ mode: "hex", value: "47 45 54" })).frame, 4);
      assert.equal((await find({ mode: "string", value: "93.184", in: "list", from: 1 })).frame, 2);
      assert.equal(
        (await find({ mode: "string", value: "Time to Live: 64", in: "details", from: 2 })).frame,
        3,
      );
      await assert.rejects(find({ mode: "hex", value: "zz" }), RangeError);
      await assert.rejects(find({ mode: "filter", value: "nope.nope" }), BasicFilterError);
      // Marks (and ignoring) toggle like the backend's; rows carry them.
      assert.deepEqual(basicRequest(c, "mark_packets", { frames: [3, 9] }), {
        count: 2,
        marked: [3, 9],
        unmarked: [],
      });
      assert.equal((await find({ mode: "marked", from: 3 })).frame, 9);
      assert.deepEqual(basicRequest(c, "ignore_packets", { frames: [2], ignore: true }), {
        count: 1,
        ignored: [2],
        unignored: [],
      });
      const rows = (
        basicRequest(c, "list_packets", { offset: 1, limit: 2 }) as {
          rows: { marked?: boolean; ignored?: boolean }[];
        }
      ).rows;
      assert.deepEqual(rows, [
        { ...rows[0], ignored: true },
        { ...rows[1], marked: true },
      ]);
      assert.equal(rows[0].marked, undefined);
      assert.deepEqual(basicRequest(c, "mark_packets", { frames: [3, 9] }), {
        count: 0,
        marked: [],
        unmarked: [3, 9],
      });
      assert.deepEqual(basicRequest(c, "unignore_all", {}), { count: 0 });
    } finally {
      c.close();
    }
  });

  test("the filter builder's values and the empty list's hints", async () => {
    const c = await BasicCapture.open(path.join(FIXTURES, "http.pcap"));
    try {
      const ports = (await basicRequest(c, "field_values", { field: "tcp.dstport" })) as {
        values: { value: string; count: number }[];
        packets: number;
        distinct: number;
        type: string;
      };
      assert.deepEqual(ports.values, [
        { value: "80", count: 6 },
        { value: "50000", count: 5 },
      ]);
      assert.equal(ports.packets, 11);
      assert.equal(ports.type, "FT_UINT16");
      const scoped = (await basicRequest(c, "field_values", {
        field: "ip.src",
        filter: "tcp.len > 0",
      })) as { values: { value: string; count: number }[]; filter: string };
      assert.deepEqual(scoped.values, [
        { value: "93.184.216.34", count: 2 },
        { value: "192.168.1.10", count: 1 },
      ]);
      assert.equal(scoped.filter, "tcp.len > 0");
      await assert.rejects(
        Promise.resolve().then(() => basicRequest(c, "field_values", { field: "x.y" })),
        RangeError,
      );
      assert.deepEqual(await basicRequest(c, "filter_hints", { expr: "dns || tcp.port == 1" }), {
        expr: "dns || tcp.port == 1",
        fields: [
          { name: "dns", present: false },
          { name: "tcp.port", present: true },
        ],
        caseHints: [],
      });
      const index = basicRequest(c, "field_index", { prefix: "ip.", limit: 2 }) as {
        fields: { name: string }[];
      };
      assert.deepEqual(
        index.fields.map((f) => f.name),
        ["ip.addr", "ip.checksum"],
      );
      const words = basicRequest(c, "field_index", { words: "hop limit", limit: 5 }) as {
        fields: { name: string }[];
      };
      assert.deepEqual(
        words.fields.map((f) => f.name),
        ["ipv6.hlim"],
      );
    } finally {
      c.close();
    }
  });

  test("a cancelled filter stops, a newer one replaces it, and the view stays as it was", async () => {
    // 5000 Ethernet/IPv4/UDP packets: a filter checks for a cancel every 2000.
    const header = Buffer.from("d4c3b2a1020004000000000000000000ffff000001000000", "hex");
    const frame = Buffer.from(
      "ffffffffffff001122334455080045000020000000004011000001020304050607080035003500080000" +
        "00000000",
      "hex",
    );
    const records = Array.from({ length: 5000 }, (_, i) => {
      const rec = Buffer.alloc(16);
      rec.writeUInt32LE(i, 0);
      rec.writeUInt32LE(frame.length, 8);
      rec.writeUInt32LE(frame.length, 12);
      return Buffer.concat([rec, frame]);
    });
    const file = path.join(os.tmpdir(), `pcap-lens-basic-${process.pid}.pcap`);
    fs.writeFileSync(file, Buffer.concat([header, ...records]));
    const c = await BasicCapture.open(file);
    try {
      assert.equal(c.count, 5000);
      const fractions: number[] = [];
      const ctx: BasicRequestContext = { progress: (fraction) => fractions.push(fraction) };
      const running = basicRequest(c, "set_filter", { expr: "udp.port == 53" }, ctx);
      ctx.cancelled = true;
      await assert.rejects(running as Promise<unknown>, BasicCancelledError);
      assert.deepEqual(fractions, [0.4]);
      assert.equal(c.view.expr, "", "the view is unchanged");
      const first = basicRequest(c, "set_filter", { expr: "udp" }) as Promise<unknown>;
      const second = basicRequest(c, "set_filter", { expr: "ip.ttl == 64" }) as Promise<unknown>;
      await assert.rejects(first, BasicCancelledError);
      assert.deepEqual(await second, {
        expr: "ip.ttl == 64",
        matchCount: 5000,
        total: 5000,
        filterId: c.view.filterId,
      });
      assert.equal(c.view.expr, "ip.ttl == 64");
    } finally {
      c.close();
      fs.rmSync(file, { force: true });
    }
  });
});

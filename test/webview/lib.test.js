// Unit tests for the webview's pure helpers (src/webview/lib.js), run with mocha under Node.
const assert = require("node:assert/strict");
const lib = require("../../src/webview/lib.js");

suite("webview lib: virtualization", () => {
  const base = { viewportHeight: 220, rowHeight: 22 };

  test("unscaled window", () => {
    const w = lib.computeWindow({ ...base, scrollTop: 0, total: 1000 });
    assert.deepEqual(w, { first: 0, count: 11, top: 0, virtualHeight: 22000, scaled: false });
    const w2 = lib.computeWindow({ ...base, scrollTop: 230, total: 1000 });
    assert.equal(w2.first, 10);
    assert.equal(w2.top, 220);
  });

  test("window clamps at the end and for tiny lists", () => {
    const w = lib.computeWindow({ ...base, scrollTop: 21780, total: 1000 });
    assert.equal(w.first + w.count, 1000);
    const small = lib.computeWindow({ ...base, scrollTop: 0, total: 3 });
    assert.equal(small.count, 3);
    const empty = lib.computeWindow({ ...base, scrollTop: 0, total: 0 });
    assert.equal(empty.count, 0);
  });

  test("scaled window maps scroll range onto all rows", () => {
    const total = 5_000_000; // 110M px unscaled
    const p = { ...base, total, maxScrollHeight: 1_000_000 };
    const top = lib.computeWindow({ ...p, scrollTop: 0 });
    assert.equal(top.scaled, true);
    assert.equal(top.virtualHeight, 1_000_000);
    assert.equal(top.first, 0);
    const bottom = lib.computeWindow({ ...p, scrollTop: 1_000_000 - 220 });
    assert.equal(bottom.first + bottom.count, total);
    const mid = lib.computeWindow({ ...p, scrollTop: (1_000_000 - 220) / 2 });
    assert.ok(Math.abs(mid.first - total / 2) < 10);
    assert.equal(mid.top, (1_000_000 - 220) / 2);
  });

  test("scrollTopForIndex round-trips (unscaled and scaled)", () => {
    for (const total of [1000, 5_000_000]) {
      const p = { ...base, total, maxScrollHeight: 1_000_000 };
      for (const index of [0, 1, 500, 999, total - 1]) {
        const scrollTop = lib.scrollTopForIndex({ ...p, index, scrollTop: 0 });
        const w = lib.computeWindow({ ...p, scrollTop });
        assert.ok(
          index >= w.first && index < w.first + w.count,
          `index ${index} of ${total} visible`,
        );
      }
      const centered = lib.scrollTopForIndex({ ...p, index: 500, scrollTop: 0, center: true });
      const w = lib.computeWindow({ ...p, scrollTop: centered });
      assert.ok(500 - w.first >= 3, "centered row is not at the top edge");
    }
  });

  test("scrollTopForIndex keeps position when already visible", () => {
    assert.equal(lib.scrollTopForIndex({ ...base, total: 1000, index: 12, scrollTop: 220 }), 220);
  });

  test("pagesForRange", () => {
    assert.deepEqual(lib.pagesForRange(0, 30, 200, 1000), [0]);
    assert.deepEqual(lib.pagesForRange(190, 30, 200, 1000), [0, 1]);
    assert.deepEqual(lib.pagesForRange(390, 30, 200, 1000, 1), [0, 1, 2, 3]);
    assert.deepEqual(lib.pagesForRange(990, 30, 200, 1000, 1), [3, 4]);
    assert.deepEqual(lib.pagesForRange(0, 0, 200, 0), []);
  });

  test("LruMap evicts least recently used", () => {
    const m = new lib.LruMap(2);
    m.set("a", 1);
    m.set("b", 2);
    assert.equal(m.get("a"), 1);
    m.set("c", 3);
    assert.equal(m.has("b"), false);
    assert.equal(m.has("a"), true);
    assert.equal(m.size, 2);
    // delete: the packet list drops the short last page when the list grows.
    assert.equal(m.delete("a"), true);
    assert.equal(m.delete("a"), false);
    assert.deepEqual([...m.entries()], [["c", 3]]);
  });
});

suite("webview lib: filters", () => {
  test("relatedKind: requests, responses, ACKs and the rest", () => {
    assert.equal(lib.relatedKind("dns.response_to"), "request");
    assert.equal(lib.relatedKind("http.request_in"), "request");
    assert.equal(lib.relatedKind("dns.response_in"), "response");
    assert.equal(lib.relatedKind("http.response_in"), "response");
    assert.equal(lib.relatedKind("tcp.analysis.acks_frame"), "ack");
    assert.equal(lib.relatedKind("tcp.analysis.duplicate_ack_frame"), "dup-ack");
    assert.equal(lib.relatedKind("tcp.reassembled_in"), "related");
    assert.equal(lib.relatedKind("http.prev_request_in"), "related");
  });

  test("comparePackets: aligns fields by name path, marks changed and one-sided rows", () => {
    const n = (name, label, children) => ({ name, label, ...(children ? { children } : {}) });
    const a = [
      n("frame", "Frame 4", [n("frame.number", "Frame Number: 4"), n("frame.len", "Length: 60")]),
      n("tcp", "TCP", [
        n("tcp.flags", "Flags: 0x018 (PSH, ACK)"),
        n("tcp.option", "Option: NOP"),
        n("tcp.option", "Option: Timestamps"),
        n("", "[Expert: retransmission]"),
      ]),
      n("http", "HTTP", [n("http.request.method", "Request Method: GET")]),
    ];
    const b = [
      n("frame", "Frame 7", [n("frame.number", "Frame Number: 7"), n("frame.len", "Length: 60")]),
      n("tcp", "TCP", [
        n("tcp.flags", "Flags: 0x018 (PSH, ACK)"),
        n("tcp.option", "Option: NOP"),
        n("tcp.window", "Window: 512"),
      ]),
    ];
    const rows = lib.comparePackets(a, b);
    assert.deepEqual(
      rows.map((r) => [r.depth, r.a, r.b, r.status, r.differs]),
      [
        [0, "Frame 4", "Frame 7", "changed", true],
        [1, "Frame Number: 4", "Frame Number: 7", "changed", true],
        [1, "Length: 60", "Length: 60", "same", false],
        [0, "TCP", "TCP", "same", true],
        [1, "Flags: 0x018 (PSH, ACK)", "Flags: 0x018 (PSH, ACK)", "same", false],
        [1, "Option: NOP", "Option: NOP", "same", false],
        // The second tcp.option has no partner; B's window comes after the last match.
        [1, "Option: Timestamps", null, "a", true],
        [1, "[Expert: retransmission]", null, "a", true],
        [1, null, "Window: 512", "b", true],
        [0, "HTTP", null, "a", true],
        [1, "Request Method: GET", null, "a", true],
      ],
    );
    const same = lib.comparePackets(b, b);
    assert.ok(same.every((r) => r.status === "same" && !r.differs));
    assert.deepEqual(lib.comparePackets([], []), []);
  });

  test("conversationFilters: Ethernet, IP and stream conversations, innermost values", () => {
    const f = (name, show, children) => ({ name, show, ...(children ? { children } : {}) });
    const tree = [
      {
        name: "eth",
        children: [f("eth.dst", "00:00:5e:00:53:02"), f("eth.src", "00:00:5e:00:53:01")],
      },
      { name: "ip", children: [f("ip.src", "192.0.2.1"), f("ip.dst", "192.0.2.2")] },
      // A tunnel: the inner header wins.
      { name: "ip", children: [f("ip.src", "10.0.0.1"), f("ip.dst", "10.0.0.2")] },
      { name: "tcp", children: [f("tcp.srcport", "80"), f("tcp.stream", "3")] },
    ];
    assert.deepEqual(lib.conversationFilters(tree), [
      {
        label: "Ethernet",
        filter: "eth.addr == 00:00:5e:00:53:01 && eth.addr == 00:00:5e:00:53:02",
      },
      { label: "IPv4", filter: "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2" },
      { label: "TCP", filter: "tcp.stream eq 3" },
    ]);
    assert.deepEqual(
      lib.conversationFilters([
        { name: "ipv6", children: [f("ipv6.src", "2001:db8::1"), f("ipv6.dst", "2001:db8::2")] },
        { name: "udp", children: [f("udp.stream", "0")] },
      ]),
      [
        { label: "IPv6", filter: "ipv6.addr == 2001:db8::1 && ipv6.addr == 2001:db8::2" },
        { label: "UDP", filter: "udp.stream eq 0" },
      ],
    );
    // Only addresses and numbers go into a filter.
    assert.deepEqual(
      lib.conversationFilters([
        { name: "ip", children: [f("ip.src", "a || frame"), f("ip.dst", "10.0.0.2")] },
      ]),
      [],
    );
    assert.deepEqual(lib.conversationFilters([]), []);
  });

  test("relatedFrames: the packets the selected one refers to", () => {
    const types = { "dns.response_to": "FT_FRAMENUM", "tcp.segment": "FT_FRAMENUM" };
    const tree = [
      { name: "frame", children: [{ name: "frame.number", show: "7" }] },
      {
        name: "dns",
        children: [
          { name: "dns.response_to", show: "5" },
          { name: "dns.id", show: "4660" }, // (not a frame number)
        ],
      },
      {
        name: "tcp.segments",
        children: [
          { name: "tcp.segment", show: "5" },
          { name: "tcp.segment", show: "7" },
          { name: "tcp.segment", show: "6" },
        ],
      },
    ];
    const related = lib.relatedFrames(tree, (n) => types[n], 7);
    assert.deepEqual(
      [...related],
      [
        [5, "request"],
        [6, "related"],
      ],
    );
  });

  test("expertStatus: the most severe of errors, warnings and notes", () => {
    const counts = { error: 0, warning: 2, note: 5, chat: 6, comment: 0 };
    assert.deepEqual(lib.expertStatus(counts), {
      severity: "warning",
      label: "2 warnings",
      title:
        "Expert information: 0 errors, 2 warnings, 5 notes, 6 chats, 0 comments. Click to open it.",
    });
    assert.equal(lib.expertStatus({ ...counts, error: 1 }).label, "1 error");
    assert.equal(lib.expertStatus({ note: 1 }).severity, "note");
    assert.deepEqual(
      [lib.expertStatus({ chat: 3 }).severity, lib.expertStatus({ chat: 3 }).label],
      ["ok", "No problems"],
    );
  });

  test("bitPattern: tshark's bit field labels", () => {
    assert.deepEqual(lib.bitPattern("0100 .... = Version: 4"), {
      width: 8,
      first: 0,
      last: 3,
      rest: "Version: 4",
    });
    assert.deepEqual(lib.bitPattern("...0 0000 0000 0000 = Fragment Offset: 0"), {
      width: 16,
      first: 3,
      last: 15,
      rest: "Fragment Offset: 0",
    });
    assert.equal(lib.bitPattern(".... .... = Nothing shown"), null);
    assert.equal(lib.bitPattern("Total Length: 130"), null);
    assert.equal(lib.bitPattern("01 = too short"), null);
  });

  // IPv4 and TCP headers as tshark's PDML labels them (pos/size in bytes).
  const f = (name, label, pos, size, children) => ({ name, label, pos, size, children });
  const IPV4 = {
    name: "ip",
    proto: true,
    label: "Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2",
    pos: 14,
    size: 20,
    children: [
      f("ip.version", "0100 .... = Version: 4", 14, 1),
      f("ip.hdr_len", ".... 0101 = Header Length: 20 bytes (5)", 14, 1),
      f("ip.dsfield", "Differentiated Services Field: 0x00", 15, 1, [
        f("ip.dsfield.dscp", "0000 00.. = Differentiated Services Codepoint: Default (0)", 15, 1),
        f("ip.dsfield.ecn", ".... ..00 = Explicit Congestion Notification: Not-ECT (0)", 15, 1),
      ]),
      f("ip.len", "Total Length: 130", 16, 2),
      f("ip.id", "Identification: 0x0004 (4)", 18, 2),
      f("ip.flags", "000. .... = Flags: 0x0", 20, 1),
      f("ip.frag_offset", "...0 0000 0000 0000 = Fragment Offset: 0", 20, 2),
      f("ip.ttl", "Time to Live: 64", 22, 1),
      f("ip.proto", "Protocol: TCP (6)", 23, 1),
      f("ip.checksum", "Header Checksum: 0x82e5", 24, 2),
      { name: "ip.checksum.status", label: "Header checksum status: Unverified" },
      f("ip.src", "Source Address: 10.0.0.1", 26, 4),
      f("ip.dst", "Destination Address: 10.0.0.2", 30, 4),
    ],
  };
  /** @param {any} p */
  const layout = (p) =>
    p.rows.map((r) =>
      r.cells.map(
        (c) => `${c.width}:${c.item < 0 ? "-" : p.items[c.item].name}${c.cont ? "…" : ""}`,
      ),
    );

  test("packetDiagram: IPv4's header to the bit, 32 bits a row", () => {
    const [ip] = lib.packetDiagram([
      { name: "frame", proto: true, label: "Frame 1", pos: 0, size: 54 },
      IPV4,
    ]);
    assert.equal(ip.title, "Internet Protocol Version 4");
    assert.deepEqual(layout(ip), [
      ["4:Version", "4:Header Length", "8:Differentiated Services Field", "16:Total Length"],
      ["16:Identification", "3:Flags", "13:Fragment Offset"],
      ["8:Time to Live", "8:Protocol", "16:Header Checksum"],
      ["32:Source Address"],
      ["32:Destination Address"],
    ]);
    assert.deepEqual(
      ip.rows.map((r) => r.offset),
      [0, 32, 64, 96, 128],
    );
    const version = ip.items[0];
    assert.equal(version.value, "4");
    assert.equal(version.node.name, "ip.version");
  });

  test("packetDiagram: TCP's flags, overlapping and outside fields", () => {
    const flag = (bits, label) => f("tcp.flags.x", `${bits} = ${label}`, 47, 1);
    const tcp = {
      name: "tcp",
      proto: true,
      label: "Transmission Control Protocol, Src Port: 50000",
      pos: 34,
      size: 20,
      children: [
        f("tcp.srcport", "Source Port: 50000", 34, 2),
        f("tcp.dstport", "Destination Port: 80", 36, 2),
        f("tcp.seq", "Sequence Number: 1    (relative sequence number)", 38, 4),
        f("tcp.seq_raw", "Sequence Number (raw): 1000", 38, 4),
        f("tcp.ack", "Acknowledgment Number: 1", 42, 4),
        f("tcp.hdr_len", "0101 .... = Header Length: 20 bytes (5)", 46, 1),
        // The flags' patterns are 12 bits wide, the low 12 of the 2 bytes.
        f("tcp.flags", "Flags: 0x018 (PSH, ACK)", 46, 2, [
          flag("000. .... ....", "Reserved: Not set"),
          flag("...0 .... ....", "Accurate ECN: Not set"),
          flag(".... 0000 0000", "The rest"),
          f("tcp.flags.str", "TCP Flags: ·······AP···", 46, 2),
        ]),
        f("tcp.window_size_value", "Window: 8192", 48, 2),
        f("tcp.window_size", "Calculated window size: 8192", 48, 2),
        f("tcp.checksum", "Checksum: 0xad29", 50, 2),
        f("tcp.urgent_pointer", "Urgent Pointer: 0", 52, 2),
        f("tcp.payload", "TCP payload (90 bytes)", 54, 90),
      ],
    };
    const [d] = lib.packetDiagram([tcp]);
    assert.deepEqual(layout(d), [
      ["16:Source Port", "16:Destination Port"],
      ["32:Sequence Number"],
      ["32:Acknowledgment Number"],
      ["4:Header Length", "12:Flags", "16:Window"],
      ["16:Checksum", "16:Urgent Pointer"],
    ]);
    assert.equal(d.items[2].value, "1    (relative sequence number)");
  });

  test("packetDiagram: gaps, long fields elided, row limit", () => {
    const proto = (children, size) => ({
      name: "x",
      proto: true,
      label: "X",
      pos: 0,
      size,
      children,
    });
    // A 2-byte field, then 2 bytes nobody describes, then 40 bytes of data.
    const [d] = lib.packetDiagram([
      proto([f("x.a", "A: 1", 0, 2), f("x.data", "Data (40 bytes)", 4, 40)], 44),
    ]);
    assert.deepEqual(layout(d), [["16:A", "16:-"], ["32:Data (40 bytes)"]]);
    assert.equal(d.rows[1].cells[0].rows, 10); // one row stands for ten
    assert.equal(d.rows[1].offset, 32);
    // Two full rows are drawn as they are; a field starting mid-row continues.
    const [e] = lib.packetDiagram([proto([f("x.a", "A: 1", 0, 2), f("x.b", "B", 2, 8)], 10)]);
    assert.deepEqual(layout(e), [["16:A", "16:B"], ["32:B…"], ["16:B…"]]);
    // Hundreds of small fields: 64 rows at most.
    const many = Array.from({ length: 300 }, (_, i) => f(`x.f${i}`, `F${i}: 0`, i * 4, 4));
    const [m] = lib.packetDiagram([proto(many, 1200)]);
    assert.equal(m.rows.length, 64);
    assert.equal(m.more, true);
    // Nothing to draw: no protocol bytes, or only the frame.
    assert.deepEqual(
      lib.packetDiagram([{ name: "frame", proto: true, label: "F", pos: 0, size: 9 }]),
      [],
    );
    assert.deepEqual(lib.packetDiagram([{ name: "x", proto: true, label: "X" }]), []);
  });

  test("prefsProtocol: a tree node's top-level protocol", () => {
    assert.equal(lib.prefsProtocol([{ name: "tcp" }, { name: "tcp.flags" }]), "tcp");
    assert.equal(lib.prefsProtocol([{ name: "tls" }]), "tls");
    assert.equal(lib.prefsProtocol([{ name: "geninfo" }]), null);
    assert.equal(lib.prefsProtocol([{ name: "fake-field-wrapper" }]), null);
    assert.equal(lib.prefsProtocol([{}]), null);
    assert.equal(lib.prefsProtocol([]), null);
  });

  test("buildFieldFilter picks literal forms", () => {
    assert.equal(lib.buildFieldFilter({ name: "ip.src", show: "10.0.0.1" }), "ip.src == 10.0.0.1");
    assert.equal(lib.buildFieldFilter({ name: "tcp.port", show: "443" }), "tcp.port == 443");
    assert.equal(lib.buildFieldFilter({ name: "ip.flags", show: "0x02" }), "ip.flags == 0x02");
    assert.equal(
      lib.buildFieldFilter({ name: "eth.src", show: "02:00:00:00:00:01" }),
      "eth.src == 02:00:00:00:00:01",
    );
    assert.equal(
      lib.buildFieldFilter({ name: "ipv6.src", show: "fe80::1" }),
      "ipv6.src == fe80::1",
    );
    assert.equal(
      lib.buildFieldFilter({ name: "tcp.flags.syn", show: "True" }),
      "tcp.flags.syn == 1",
    );
    assert.equal(lib.buildFieldFilter({ name: "http", proto: true, show: "x" }), "http");
    assert.equal(lib.buildFieldFilter({ name: "tcp.segments", show: "" }), "tcp.segments");
  });

  test("buildFieldFilter quotes and escapes strings", () => {
    assert.equal(
      lib.buildFieldFilter({ name: "http.host", show: "example.com" }),
      'http.host == "example.com"',
    );
    assert.equal(
      lib.buildFieldFilter({ name: "http.user_agent", show: 'a "b" \\c' }),
      'http.user_agent == "a \\"b\\" \\\\c"',
    );
  });

  test("buildFieldFilter rejects unfilterable nodes", () => {
    assert.equal(lib.buildFieldFilter({ show: "text" }), null);
    assert.equal(lib.buildFieldFilter({ name: "", show: "x" }), null);
    assert.equal(lib.buildFieldFilter({ name: "a b", show: "x" }), null);
  });

  test("combineFilter", () => {
    assert.equal(lib.combineFilter("", "tcp", "and"), "tcp");
    assert.equal(lib.combineFilter("ip", "tcp", "replace"), "tcp");
    assert.equal(lib.combineFilter("ip", "tcp", "and"), "(ip) && (tcp)");
    assert.equal(lib.combineFilter("ip", "tcp", "or"), "(ip) || (tcp)");
    assert.equal(lib.combineFilter("ip", "tcp", "not"), "(ip) && !(tcp)");
    assert.equal(lib.combineFilter("", "tcp", "not"), "!(tcp)");
  });
});

suite("webview lib: bytes", () => {
  const tree = [
    {
      id: 1,
      label: "Ethernet",
      name: "eth",
      pos: 0,
      size: 14,
      src: 0,
      children: [
        {
          id: 2,
          label: "Dst",
          name: "eth.dst",
          pos: 0,
          size: 6,
          src: 0,
          children: [{ id: 3, label: "OUI", name: "eth.dst.oui", pos: 0, size: 3, src: 0 }],
        },
      ],
    },
    {
      id: 4,
      label: "IP",
      name: "ip",
      pos: 14,
      size: 20,
      src: 0,
      children: [{ id: 5, label: "Src", name: "ip.src", pos: 26, size: 4, src: 0 }],
    },
    { id: 6, label: "HTTP", name: "http", pos: 0, size: 40, src: 1 },
  ];

  test("findNodeForByte returns the smallest enclosing field", () => {
    assert.deepEqual(
      lib.findNodeForByte(tree, 0, 1).map((n) => n.id),
      [1, 2, 3],
    );
    assert.deepEqual(
      lib.findNodeForByte(tree, 0, 4).map((n) => n.id),
      [1, 2],
    );
    assert.deepEqual(
      lib.findNodeForByte(tree, 0, 27).map((n) => n.id),
      [4, 5],
    );
    assert.deepEqual(
      lib.findNodeForByte(tree, 1, 1).map((n) => n.id),
      [6],
    );
    assert.equal(lib.findNodeForByte(tree, 0, 100), null);
  });

  test("nodeKey is stable across packets", () => {
    assert.equal(
      lib.nodeKey([{ name: "ip", label: "IPv4" }, { label: "Flags: 0x2" }]),
      "ip/Flags: #x#",
    );
  });

  test("hex and formatting helpers", () => {
    assert.deepEqual([...lib.hexToBytes("00ff10")], [0, 255, 16]);
    assert.equal(lib.asciiChar(0x41), "A");
    assert.equal(lib.asciiChar(0x0a), ".");
    assert.equal(lib.formatOffset(16, 100), "0010");
    assert.equal(lib.formatOffset(16, 70000), "00000010");
    assert.equal(lib.formatRelativeTime("0.001000000"), "0.001000");
    assert.equal(lib.formatRelativeTime(""), "");
    assert.equal(lib.formatBytes(512), "512 B");
    assert.equal(lib.formatBytes(1536), "1.5 KB");
    assert.equal(lib.formatDuration(5.9), "0:05");
    assert.equal(lib.formatDuration(754), "12:34");
    assert.equal(lib.formatDuration(3723), "1:02:03");
    assert.equal(lib.formatDuration(-1), "0:00");
  });
});

suite("webview lib: autocomplete", () => {
  const ctx = (text, cursor = text.length) => lib.completionContext(text, cursor);

  test("field context at the start and after logical operators", () => {
    assert.deepEqual(ctx("ip.sr"), { kind: "field", prefix: "ip.sr", start: 0, end: 5 });
    assert.equal(ctx("").kind, "field");
    assert.deepEqual(ctx("tcp.port == 80 && ht"), {
      kind: "field",
      prefix: "ht",
      start: 18,
      end: 20,
    });
    assert.equal(ctx("!ht").kind, "field");
    assert.equal(ctx("frame.len > 100 || ").kind, "field");
    assert.equal(ctx("(ht").kind, "field");
    assert.equal(ctx("http and d").kind, "field");
  });

  test("the whole word under the cursor is replaced", () => {
    assert.deepEqual(ctx("ip.src == 1", 4), { kind: "field", prefix: "ip.s", start: 0, end: 6 });
  });

  test("operator context after a field", () => {
    assert.deepEqual(ctx("ip.src "), { kind: "operator", prefix: "", start: 7, end: 7 });
    assert.deepEqual(ctx("ip.src co"), { kind: "operator", prefix: "co", start: 7, end: 9 });
    assert.equal(ctx("http ").kind, "operator");
  });

  test("logical context after a complete comparison", () => {
    for (const text of [
      "ip.src == 10.0.0.1 ",
      "ip.src == 10.0.0.1 a",
      "(ip.src==1.2.3.4) ",
      'http.host contains "x" ',
      "tcp.port in {80 443} ",
      "eth.src == 00:11:22:33:44:55 ",
      "tcp.port == 80 ",
    ]) {
      assert.equal(ctx(text).kind, "logical", text);
    }
  });

  test("no completions inside strings or where a value is expected", () => {
    assert.equal(ctx('http.host == "ex').kind, "none");
    assert.equal(ctx('http.host == "a \\" b').kind, "none");
    assert.equal(ctx("ip.src == ").kind, "none");
    assert.equal(ctx("ip.src == 10").kind, "none");
    assert.equal(ctx("80").kind, "none");
  });

  test("operator suggestions filter by prefix", () => {
    assert.deepEqual(
      lib.operatorSuggestions("operator", "co").map((o) => o.label),
      ["contains"],
    );
    assert.deepEqual(
      lib.operatorSuggestions("logical", "").map((o) => o.label),
      ["&&", "||", "and", "or", "^^"],
    );
    assert.deepEqual(
      lib.operatorSuggestions("operator", "!").map((o) => o.label),
      ["!="],
    );
  });

  test("applyCompletion inserts fields as-is and pads operators", () => {
    assert.deepEqual(lib.applyCompletion("ip.sr", { start: 0, end: 5 }, "ip.src", false), {
      text: "ip.src",
      cursor: 6,
    });
    assert.deepEqual(lib.applyCompletion("ip.src ", { start: 7, end: 7 }, "==", true), {
      text: "ip.src == ",
      cursor: 10,
    });
    assert.deepEqual(lib.applyCompletion("ip.src co 1", { start: 7, end: 9 }, "contains", true), {
      text: "ip.src contains 1",
      cursor: 16,
    });
    assert.deepEqual(lib.applyCompletion("ip.s == 1", { start: 0, end: 4 }, "ip.src", false), {
      text: "ip.src == 1",
      cursor: 6,
    });
  });

  test("friendlyType", () => {
    assert.equal(lib.friendlyType("FT_IPv4"), "IPv4 address");
    assert.equal(lib.friendlyType("FT_UINT16"), "unsigned integer, 2 bytes");
    assert.equal(lib.friendlyType("FT_INT8"), "signed integer, 1 byte");
    assert.equal(lib.friendlyType("FT_STRING"), "character string");
    assert.equal(lib.friendlyType("FT_SOMETHING_NEW"), "something_new");
  });
});

suite("webview lib: columns", () => {
  test("acceptedColumns keeps configured titles for accepted fields only", () => {
    const configured = [
      { field: "tcp.stream", title: "Stream" },
      { field: "no.such.field", title: "Typo" },
      { field: "http.host", title: "Host" },
    ];
    const accepted = [{ field: "tcp.stream" }, { field: "http.host" }];
    assert.deepEqual(lib.acceptedColumns(configured, accepted), [
      { field: "tcp.stream", title: "Stream" },
      { field: "http.host", title: "Host" },
    ]);
    assert.deepEqual(lib.acceptedColumns(configured, []), []);
  });
});

suite("webview lib: follow stream and statistics helpers", () => {
  test("bytesToAscii keeps text, newlines and tabs; drops CR before LF", () => {
    assert.equal(
      lib.bytesToAscii(new Uint8Array([0x47, 0x0d, 0x0a, 0x00, 0x09, 0xc8, 0x0d])),
      "G\n.\t..",
    );
  });

  test("hexDump lays out 16 bytes per line with offsets and ASCII", () => {
    const dump = lib.hexDump(new Uint8Array([...Buffer.from("HTTP/1.1 200 OK\r\nX")]), 16);
    assert.deepEqual(dump.split("\n"), [
      "00000010  48 54 54 50 2f 31 2e 31  20 32 30 30 20 4f 4b 0d  HTTP/1.1 200 OK.",
      "00000020  0a 58                                             .X",
    ]);
    assert.equal(lib.hexDump(new Uint8Array([])), "");
  });

  test("findRanges: case-insensitive, non-overlapping, capped", () => {
    assert.deepEqual(lib.findRanges("GET / HTTP/1.1\nHost: x\nhttp", "http"), [
      [6, 10],
      [23, 27],
    ]);
    assert.deepEqual(lib.findRanges("aaaa", "aa"), [
      [0, 2],
      [2, 4],
    ]);
    assert.deepEqual(lib.findRanges("abcabc", "b", 1), [[1, 2]]);
    assert.deepEqual(lib.findRanges("abc", ""), []);
    assert.deepEqual(lib.findRanges("abc", "x"), []);
  });

  test("findTreeMatch: the first matching node, as a path", () => {
    const tree = [
      { label: "Frame 7: 345 bytes", children: [{ label: "Frame Number: 7" }] },
      {
        label: "Hypertext Transfer Protocol",
        children: [
          { label: "HTTP/1.1 200 OK", children: [{ label: "Status Code: 200" }] },
          { label: "Content-Type: text/html" },
        ],
      },
    ];
    const labels = (path) => path?.map((n) => n.label) ?? null;
    assert.deepEqual(labels(lib.findTreeMatch(tree, { value: "content-type" })), [
      "Hypertext Transfer Protocol",
      "Content-Type: text/html",
    ]);
    assert.deepEqual(labels(lib.findTreeMatch(tree, { value: "status code" })), [
      "Hypertext Transfer Protocol",
      "HTTP/1.1 200 OK",
      "Status Code: 200",
    ]);
    assert.equal(lib.findTreeMatch(tree, { value: "content-type", caseSensitive: true }), null);
    assert.deepEqual(
      labels(lib.findTreeMatch(tree, { value: "^frame number: \\d+$", regex: true })),
      ["Frame 7: 345 bytes", "Frame Number: 7"],
    );
    assert.equal(lib.findTreeMatch(tree, { value: "(?P<x>a)", regex: true }), null, "not JS");
    assert.equal(lib.findTreeMatch(tree, { value: "" }), null);
  });

  test("fieldStatus: Wireshark's status bar text for the selected field", () => {
    assert.equal(
      lib.fieldStatus({ name: "ip.ttl", size: 1 }, "Time to Live"),
      "Time to Live (ip.ttl), 1 byte",
    );
    assert.equal(
      lib.fieldStatus({ name: "ip.src", size: 4 }, "Source Address"),
      "Source Address (ip.src), 4 bytes",
    );
    assert.equal(
      lib.fieldStatus({ name: "tcp.stream" }, "Stream index"),
      "Stream index (tcp.stream)",
    );
    assert.equal(
      lib.fieldStatus({ name: "ip.ttl", size: 1 }),
      "ip.ttl, 1 byte",
      "while the catalogue loads",
    );
    assert.equal(lib.fieldStatus({ size: 20 }), "", "a text line");
  });

  test("shortcutSections: the viewer's keys, then the commands' bindings by title", () => {
    const commands = [
      { title: "Toggle Mark", keys: { key: "ctrl+m", mac: "cmd+m" } },
      { title: "Conversations" },
      { title: "Next Mark", keys: { key: "ctrl+shift+n", mac: "cmd+shift+n" } },
    ];
    const pc = lib.shortcutSections(commands, false);
    assert.deepEqual(
      pc.map((s) => s.area),
      ["Packet list", "Packet details", "Find and filter", "Help", "Commands"],
    );
    assert.deepEqual(pc.at(-1).keys, [
      ["Ctrl+Shift+N", "Next Mark"],
      ["Ctrl+M", "Toggle Mark"],
    ]);
    assert.ok(pc[2].keys.some(([k]) => k === "Ctrl+F"));
    const mac = lib.shortcutSections(commands, true);
    assert.ok(
      mac[2].keys.some(([k]) => k === "⌘F"),
      "Ctrl reads ⌘ on macOS",
    );
    assert.deepEqual(mac.at(-1).keys[1], ["⌘M", "Toggle Mark"]);
    assert.equal(lib.shortcutSections([], false).at(-1).area, "Help", "no commands section");
  });

  test("overview strip geometry", () => {
    assert.deepEqual(lib.overviewBox(0, 10, 100, 200), { y: 0, h: 20 });
    assert.deepEqual(lib.overviewBox(50, 10, 100, 200), { y: 100, h: 20 });
    assert.deepEqual(
      lib.overviewBox(999_990, 40, 1_000_000, 300),
      { y: 296, h: 4 },
      "at least 4 px, inside",
    );
    assert.deepEqual(lib.overviewBox(0, 11, 11, 300), { y: 0, h: 300 });
    assert.equal(lib.overviewBox(0, 0, 0, 300), null);
    assert.equal(lib.overviewIndexAt(0, 200, 100), 0);
    assert.equal(lib.overviewIndexAt(100, 200, 100), 50);
    assert.equal(lib.overviewIndexAt(250, 200, 100), 99, "clamped");
    assert.equal(lib.overviewIndexAt(-5, 200, 100), 0);
    assert.equal(lib.overviewIndexAt(10, 200, 0), null);
  });

  test("streamFilter", () => {
    assert.equal(lib.streamFilter("tcp", 3), "tcp.stream eq 3");
    assert.equal(lib.streamFilter("http", 0), "tcp.stream eq 0");
    assert.equal(lib.streamFilter("udp", 7), "udp.stream eq 7");
    assert.equal(lib.streamFilter("websocket", 1), "tcp.stream eq 1");
    assert.equal(lib.streamFilter("http2", 0), "tcp.stream eq 0");
    assert.equal(lib.streamFilter("http2", 0, 3), "tcp.stream eq 0 and http2.streamid eq 3");
    assert.equal(lib.streamFilter("quic", 2), "quic.connection.number eq 2");
    assert.equal(
      lib.streamFilter("quic", 2, 0),
      "quic.connection.number eq 2 and quic.stream.stream_id eq 0",
    );
    assert.equal(lib.streamFilter("tcp", 3, 1), "tcp.stream eq 3", "no sub-streams in TCP");
  });

  test("decodeStream: the text views", () => {
    const bytes = (...b) => new Uint8Array(b);
    // "é" in UTF-8, CR LF, a NUL, a tab.
    const utf8 = bytes(0x63, 0x61, 0x66, 0xc3, 0xa9, 0x0d, 0x0a, 0x00, 0x09);
    assert.equal(lib.decodeStream(utf8, "ascii"), "caf..\n.\t");
    assert.equal(lib.decodeStream(utf8, "utf-8"), "café\n.\t");
    assert.equal(lib.decodeStream(utf8, "latin1"), "cafÃ©\n.\t");
    assert.equal(lib.decodeStream(bytes(0xff), "utf-8"), "\ufffd", "undecodable bytes");
    assert.equal(lib.decodeStream(bytes(0x80, 0x9f, 0xa0), "latin1"), "..\u00a0", "C1 controls");
    assert.equal(lib.decodeStream(bytes(0x68, 0, 0x69, 0, 0x0a, 0), "utf-16"), "hi\n");
    // EBCDIC "Hello" (code page 037), newline 0x25, a control.
    assert.equal(
      lib.decodeStream(bytes(0xc8, 0x85, 0x93, 0x93, 0x96, 0x25, 0x00), "ebcdic"),
      "Hello\n.",
    );
    assert.equal(lib.decodeStream(bytes(0x4a, 0x5b, 0xe0), "ebcdic"), "¢$\\");
  });

  test("cArray: eight bytes a line, named by peer and index", () => {
    const bytes = new Uint8Array([...Array(10).keys()]);
    assert.equal(
      lib.cArray(bytes, 1, 2),
      "char peer1_2[] = {\n0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,\n0x08, 0x09 };",
    );
  });

  test("YAML view: peers, then segments as base64", () => {
    assert.equal(
      lib.yamlPeers(["10.0.0.1:50300", "fe80::1:443"]),
      [
        "peers:",
        "  - peer: 0",
        "    host: '10.0.0.1'",
        "    port: 50300",
        "  - peer: 1",
        "    host: 'fe80::1'",
        "    port: 443",
        "packets:",
      ].join("\n"),
    );
    assert.equal(lib.yamlPeers([""]), "peers:\n  - peer: 0\n    host: ''\npackets:");
    assert.equal(
      lib.yamlSegment(new Uint8Array(Buffer.from("GET /hello.txt\r\n")), 0, 3),
      "  - peer: 0\n    index: 3\n    data: !!binary |\n      R0VUIC9oZWxsby50eHQNCg==",
    );
    const long = lib.yamlSegment(new Uint8Array(60), 1, 0).split("\n");
    assert.deepEqual(long.slice(3), ["      " + "A".repeat(64), "      " + "A".repeat(16)]);
    assert.equal(lib.bytesToBase64(new Uint8Array(70000)).length, 93336, "past one chunk");
  });

  test("formatCell", () => {
    assert.equal(lib.formatCell(1234567), "1,234,567");
    assert.equal(lib.formatCell(0.0001234567), "0.000123");
    assert.equal(lib.formatCell("x"), "x");
    assert.equal(lib.formatCell(undefined), "");
  });

  test("sortRows is stable, numeric for numbers, natural for text", () => {
    const rows = [
      { cells: ["b", 2] },
      { cells: ["A", 10] },
      { cells: ["a", 1] },
      { cells: ["x10", 3] },
      { cells: ["x9", 3] },
    ];
    assert.deepEqual(
      lib.sortRows(rows, 0, false).map((r) => r.cells[0]),
      ["A", "a", "b", "x9", "x10"],
    );
    assert.deepEqual(
      lib.sortRows(rows, 1, true).map((r) => r.cells[1]),
      [10, 3, 3, 2, 1],
    );
    assert.deepEqual(
      lib
        .sortRows(rows, 1, true)
        .map((r) => r.cells[0])
        .slice(1, 3),
      ["x10", "x9"],
    ); // ties keep order
  });

  test("tableToCsv quotes where needed", () => {
    assert.equal(
      lib.tableToCsv(
        [{ label: "a" }, { label: "b,c" }],
        [{ cells: [1, 'x"y'] }, { cells: ["line\nbreak", null] }],
      ),
      'a,"b,c"\n1,"x""y"\n"line\nbreak",',
    );
  });

  test("rowsToText: tab-separated rows, optional header, one line per row", () => {
    const rows = [
      ["1", "GET /\tx", "a\r\nb"],
      ["2", "", "c"],
    ];
    assert.equal(
      lib.rowsToText(["No.", "Info", "More"], rows, true),
      "No.\tInfo\tMore\n1\tGET / x\ta b\n2\t\tc",
    );
    assert.equal(lib.rowsToText(["No."], [["7"]], false), "7");
  });

  test("logTicks: powers of ten around the values; ioSeries checks the stored graphs", () => {
    assert.deepEqual(lib.logTicks(3, 561), [1, 10, 100, 1000]);
    assert.deepEqual(lib.logTicks(0.0009, 0.02), [0.0001, 0.001, 0.01, 0.1]);
    assert.deepEqual(lib.logTicks(10, 10), [10, 100]);
    assert.deepEqual(lib.logTicks(0, 0), [1, 10]);
    assert.deepEqual(
      lib.ioSeries([
        { metric: "avg", field: " tcp.len ", filter: "tcp", style: "bar" },
        { metric: "median" },
        "junk",
        null,
      ]),
      [
        { metric: "avg", filter: "tcp", field: "tcp.len", style: "bar" },
        { metric: "packets", filter: "", field: "", style: "line" },
      ],
    );
    assert.equal(lib.ioSeries(Array(12).fill({})).length, 8);
    assert.deepEqual(lib.ioSeries("nope"), []);
  });

  test("Show Packet Bytes: decoders, compression format, image type and text views", () => {
    const enc = (/** @type {string} */ t) => new TextEncoder().encode(t);
    const dec = (/** @type {Uint8Array} */ b) => new TextDecoder().decode(b);
    assert.equal(dec(lib.decodeBytes(enc("aGVs bG8=\n"), "base64").bytes), "hello");
    assert.equal(dec(lib.decodeBytes(enc("aGVsbG8"), "base64").bytes), "hello", "unpadded");
    assert.equal(dec(lib.decodeBytes(enc("-_8"), "base64").bytes), "\ufffd\ufffd", "URL-safe");
    assert.equal(lib.decodeBytes(enc("a*b"), "base64").error, "Not valid Base64");
    assert.equal(dec(lib.decodeBytes(enc("68:65 6c-6C 0x6f"), "hex").bytes), "hello");
    assert.match(lib.decodeBytes(enc("abc"), "hex").error, /even number/);
    assert.equal(dec(lib.decodeBytes(enc("a%20b+c%2"), "percent").bytes), "a b c%2");
    assert.equal(
      dec(lib.decodeBytes(enc("caf=C3=A9 =\r\nok=3"), "quoted-printable").bytes),
      "café ok=3",
    );
    assert.equal(dec(lib.decodeBytes(enc("Uryyb, Jbeyq!"), "rot13").bytes), "Hello, World!");
    assert.equal(dec(lib.decodeBytes(enc("same"), "none").bytes), "same");

    assert.equal(lib.compressionFormat(Uint8Array.of(0x1f, 0x8b, 8)), "gzip");
    assert.equal(lib.compressionFormat(Uint8Array.of(0x78, 0x9c)), "deflate");
    assert.equal(lib.compressionFormat(Uint8Array.of(0xcb, 0x48)), "deflate-raw");

    assert.equal(lib.imageMime(Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d)), "image/png");
    assert.equal(lib.imageMime(Uint8Array.of(0xff, 0xd8, 0xff, 0xe0)), "image/jpeg");
    assert.equal(lib.imageMime(enc('<?xml version="1.0"?>\n<svg xmlns="x">')), "image/svg+xml");
    assert.equal(lib.imageMime(enc("<html>")), null);

    const bytes = Uint8Array.of(0x48, 0x69, 0x0a, 0x00, 0xff);
    assert.equal(lib.bytesAs(bytes, "ascii"), "Hi\n..");
    assert.equal(lib.bytesAs(bytes, "ascii-control"), "Hi\u240a\n\u2400.");
    assert.equal(lib.bytesAs(bytes, "latin1"), "Hi\n\u0000ÿ");
    assert.equal(lib.bytesAs(bytes, "hex"), "48690a00ff");
    assert.equal(
      lib.bytesAs(bytes, "c", "http.file_data"),
      "static const unsigned char http_file_data[5] = {\n    0x48, 0x69, 0x0a, 0x00, 0xff\n};",
    );
    assert.equal(
      lib.bytesAs(bytes, "rust", "1x"),
      "let _1x: [u8; 5] = [\n    0x48, 0x69, 0x0a, 0x00, 0xff\n];",
    );
    assert.equal(
      lib.bytesAs(bytes, "yaml", "data"),
      "# Packet Bytes: Base64 encoded\ndata: !!binary |\n  SGkKAP8=",
    );
    assert.ok(lib.bytesAs(bytes, "hexdump").startsWith("00000000  48 69 0a 00 ff"));
  });

  test("niceTicks covers the maximum with 1-2-5 steps", () => {
    assert.deepEqual(lib.niceTicks(561), [0, 200, 400, 600]);
    assert.deepEqual(lib.niceTicks(1000), [0, 500, 1000]);
    assert.deepEqual(lib.niceTicks(5), [0, 2, 4, 6]);
    assert.deepEqual(lib.niceTicks(0), [0, 1]);
    assert.deepEqual(lib.niceTicks(0.9), [0, 0.5, 1]);
  });
});

suite("webview lib: coloring", () => {
  const coloring = {
    id: 3,
    rules: [
      { foreground: "#000000", background: "#e4ffc7" },
      { foreground: "red", background: "#ffffff" },
    ],
  };

  test("rowColors uses the rule of the current coloring only", () => {
    assert.deepEqual(lib.rowColors({ color: 0, cid: 3 }, coloring), coloring.rules[0]);
    assert.equal(lib.rowColors({ color: 0, cid: 2 }, coloring), null); // stale page
    assert.equal(lib.rowColors({ cid: 3 }, coloring), null); // no rule matched
    assert.equal(lib.rowColors({ color: 5, cid: 3 }, coloring), null);
    assert.equal(lib.rowColors({ color: 1, cid: 3 }, coloring), null); // invalid color
    assert.equal(lib.rowColors({ color: 0, cid: 3 }, null), null);
    assert.equal(lib.rowColors(undefined, coloring), null);
  });

  test("themeKind reads the theme class VS Code puts on <body>", () => {
    const classes = (...names) => ({ contains: (n) => names.includes(n) });
    assert.equal(lib.themeKind(classes("vscode-light")), "light");
    assert.equal(lib.themeKind(classes("vscode-dark")), "dark");
    assert.equal(lib.themeKind(classes("vscode-high-contrast")), "hc-dark");
    assert.equal(lib.themeKind(classes("vscode-high-contrast-light")), "hc-light");
    assert.equal(lib.themeKind(classes()), "light"); // (outside VS Code)
  });

  test("luminance", () => {
    assert.equal(lib.luminance("#000000"), 0);
    assert.equal(lib.luminance("#ffffff"), 1);
    assert.ok(Math.abs(lib.luminance("#a0a0a0") - 0.35) < 0.01);
  });

  test("ruleStyle: auto follows the theme, the other styles apply everywhere", () => {
    const pastel = { foreground: "#12272e", background: "#e4ffc7" }; // Wireshark's HTTP
    const gray = { foreground: "#12272e", background: "#a0a0a0" }; // TCP SYN/FIN
    const forDark = { foreground: "#f78787", background: "#12272e" }; // Bad TCP
    const style = (rule, kind, s = "auto") => lib.ruleStyle(rule, kind, s);
    // Light themes: as defined; the stripe is the rule's background, deepened when pale.
    assert.deepEqual(style(pastel, "light"), { mode: "full", stripe: "#7d8c6d" });
    assert.deepEqual(style(forDark, "light"), { mode: "full", stripe: "#12272e" });
    // Dark themes: rules made for light themes become a tint; the stripe is the
    // background, or the text color of rules made for dark backgrounds.
    assert.deepEqual(style(pastel, "dark"), { mode: "subtle", stripe: "#e4ffc7" });
    assert.deepEqual(style(gray, "dark"), { mode: "subtle", stripe: "#a0a0a0" });
    assert.deepEqual(style(forDark, "dark"), { mode: "full", stripe: "#f78787" });
    // High contrast: only a stripe.
    assert.deepEqual(style(pastel, "hc-dark"), { mode: "stripe", stripe: "#e4ffc7" });
    assert.deepEqual(style(pastel, "hc-light"), { mode: "stripe", stripe: "#7d8c6d" });
    assert.deepEqual(style(gray, "hc-light"), { mode: "stripe", stripe: "#a0a0a0" });
    // An explicit style wins.
    assert.equal(style(pastel, "dark", "full").mode, "full");
    assert.equal(style(forDark, "light", "subtle").mode, "subtle");
    assert.equal(style(pastel, "light", "stripe").mode, "stripe");
    assert.equal(style(pastel, "hc-dark", "full").mode, "full");
    assert.equal(style(pastel, "dark", "nonsense").mode, "subtle"); // unknown = auto
  });
});

suite("webview lib: navigation and customisation", () => {
  const col = (id, extra = {}) => ({ id, field: id, ...extra });

  test("flowArrow places arrows between endpoint columns", () => {
    const layout = { gutter: 100, column: 50 };
    assert.deepEqual(lib.flowArrow(0, 2, 3, layout), { x1: 125, x2: 225, self: false });
    assert.deepEqual(lib.flowArrow(1, 1, 3, layout), { x1: 175, x2: 175, self: true });
    assert.equal(lib.flowArrow(-1, 0, 3, layout).x1, 275, "past the limit: the 'other' column");
    assert.equal(lib.truncate("abcdef", 4), "abc…");
    assert.equal(lib.truncate("abc", 4), "abc");
    assert.equal(lib.truncate("abc", 0), "");
  });

  test("niceRange covers min..max with round ticks", () => {
    assert.deepEqual(lib.niceRange(0.018, 0.038), [0.015, 0.02, 0.025, 0.03, 0.035, 0.04]);
    assert.deepEqual(lib.niceRange(120, 480), [100, 200, 300, 400, 500]);
    assert.deepEqual(lib.niceRange(5, 5), lib.niceTicks(5));
  });

  test("tcpGraphSeries builds the four TCP stream graphs", () => {
    // frame, time, dir, seq, len, ack, win, rtt, retrans
    const pts = [
      [1, 0, 0, 0, 0, 0, 8192, null, 0],
      [2, 0.1, 1, 0, 0, 1, 8192, 0.1, 0],
      [3, 0.2, 0, 1, 100, 1, 8192, null, 0],
      [4, 0.3, 1, 1, 0, 101, 4096, 0.1, 0],
      [5, 0.4, 0, 101, 100, 1, 8192, null, 0],
      [6, 0.5, 0, 101, 100, 1, 8192, null, 1],
    ];
    const stevens = lib.tcpGraphSeries(pts, 0, "stevens");
    assert.deepEqual(
      stevens.points.map((/** @type {any} */ p) => [p.frame, p.y, p.y2, p.flag]),
      [
        [3, 1, 101, false],
        [5, 101, 201, false],
        [6, 101, 201, true],
      ],
    );
    const tput = lib.tcpGraphSeries(pts, 0, "throughput", { window: 0.25 });
    assert.deepEqual(
      tput.points.map((/** @type {any} */ p) => p.y),
      [400, 800, 800],
      "bytes in the last 0.25 s, per second",
    );
    const rtt = lib.tcpGraphSeries(pts, 0, "rtt");
    assert.deepEqual(
      rtt.points.map((/** @type {any} */ p) => [p.frame, p.y]),
      [
        [2, 100],
        [4, 100],
      ],
      "the receiver's ACKs, in ms",
    );
    const win = lib.tcpGraphSeries(pts, 0, "window");
    assert.deepEqual(
      win.line.map((/** @type {any} */ p) => p.y),
      [8192, 4096],
    );
    assert.deepEqual(
      win.points.map((/** @type {any} */ p) => p.y),
      [100, 100, 100],
      "bytes sent but not acknowledged",
    );
    assert.equal(lib.tcpGraphSeries(pts, 1, "stevens").points.length, 0, "no data that way");
  });

  test("filterObjects filters Export Objects rows by protocol and text", () => {
    const objs = [
      { id: 0, protocol: "http", name: "logo.png", host: "example.com", contentType: "image/png" },
      {
        id: 1,
        protocol: "tftp",
        name: "config.bin",
        host: "",
        contentType: "application/octet-stream",
      },
      {
        id: 2,
        protocol: "http",
        name: "report",
        host: "cdn.example.org",
        contentType: "text/plain",
      },
    ];
    const ids = (/** @type {{id: number}[]} */ list) => list.map((o) => o.id);
    assert.deepEqual(ids(lib.filterObjects(objs, "", "")), [0, 1, 2]);
    assert.deepEqual(ids(lib.filterObjects(objs, "http", "")), [0, 2]);
    assert.deepEqual(ids(lib.filterObjects(objs, "", "  PNG ")), [0]);
    assert.deepEqual(ids(lib.filterObjects(objs, "", "example")), [0, 2]);
    assert.deepEqual(ids(lib.filterObjects(objs, "tftp", "example")), []);
  });

  test("cellAddress finds the address behind a resolved name", () => {
    const row = {
      cells: ["1", "0", "example.com", "Broadcast", "ARP"],
      addresses: ["93.184.216.34", "ff:ff:ff:ff:ff:ff"],
    };
    assert.equal(lib.cellAddress(col("source"), row), "93.184.216.34");
    assert.equal(lib.cellAddress(col("destination"), row), "ff:ff:ff:ff:ff:ff");
    assert.equal(
      lib.cellFilter(col("destination"), lib.cellAddress(col("destination"), row)),
      "eth.dst == ff:ff:ff:ff:ff:ff",
    );
    assert.equal(lib.cellAddress(col("protocol"), row), null);
    const same = {
      cells: ["1", "0", "10.0.0.1", "example.com"],
      addresses: ["10.0.0.1", "93.184.216.34"],
    };
    assert.equal(lib.cellAddress(col("source"), same), null, "the cell already shows the address");
    assert.equal(lib.cellAddress(col("source"), { cells: ["1", "0", "10.0.0.1"] }), null);
    assert.equal(lib.cellAddress(col("source"), undefined), null);
  });

  test("cellFilter builds filters from packet-list cells", () => {
    assert.equal(lib.cellFilter(col("source"), "192.168.1.10"), "ip.src == 192.168.1.10");
    assert.equal(lib.cellFilter(col("destination"), "93.184.216.34"), "ip.dst == 93.184.216.34");
    assert.equal(lib.cellFilter(col("source"), "fe80::1"), "ipv6.src == fe80::1");
    assert.equal(lib.cellFilter(col("destination"), "2001:db8::2"), "ipv6.dst == 2001:db8::2");
    assert.equal(
      lib.cellFilter(col("source"), "02:00:00:00:00:01"),
      "eth.src == 02:00:00:00:00:01",
    );
    assert.equal(lib.cellFilter(col("destination"), "Broadcast"), null); // a resolved name: no field to match
    assert.equal(lib.cellFilter(col("protocol"), "DNS"), "dns");
    assert.equal(lib.cellFilter(col("protocol"), "TLSv1.3"), "tls");
    assert.equal(lib.cellFilter(col("protocol"), "HTTP/JSON"), "http");
    assert.equal(lib.cellFilter(col("protocol"), "0x86dd"), null);
    assert.equal(lib.cellFilter(col("length"), "144"), "frame.len == 144");
    assert.equal(lib.cellFilter(col("number"), "4"), "frame.number == 4");
    assert.equal(lib.cellFilter(col("time"), "0.001000"), null);
    assert.equal(lib.cellFilter(col("info"), "GET /"), null);
    assert.equal(
      lib.cellFilter(col("custom:http.host", { field: "http.host", custom: true }), "example.com"),
      'http.host == "example.com"',
    );
    assert.equal(
      lib.cellFilter(col("custom:tcp.stream", { field: "tcp.stream", custom: true }), "3"),
      "tcp.stream == 3",
    );
    assert.equal(
      lib.cellFilter(col("custom:ip.ttl", { field: "ip.ttl", custom: true }), "64,63"),
      "ip.ttl == 64",
    ); // first occurrence
    assert.equal(
      lib.cellFilter(col("custom:x.y", { field: "x.y", custom: true }), 'say "hi"'),
      'x.y == "say \\"hi\\""',
    );
    assert.equal(lib.cellFilter(col("source"), ""), null);
  });

  test("parseHexBytes accepts the usual spellings", () => {
    assert.deepEqual(lib.parseHexBytes("474554"), ["47", "45", "54"]);
    assert.deepEqual(lib.parseHexBytes("47 45 54"), ["47", "45", "54"]);
    assert.deepEqual(lib.parseHexBytes("47:45:54"), ["47", "45", "54"]);
    assert.deepEqual(lib.parseHexBytes("0x47, 0x45"), ["47", "45"]);
    assert.deepEqual(lib.parseHexBytes("A b"), ["0a", "0b"]);
    assert.equal(lib.parseHexBytes("abc"), null);
    assert.equal(lib.parseHexBytes("zz"), null);
    assert.equal(lib.parseHexBytes("   "), null);
  });

  test("formatBytesAs: the bytes pane's copy formats", () => {
    const b = Uint8Array.from([0x47, 0x45, 0x54, 0x20, 0x2f, 0x0d, 0x0a, 0x00, 0x41]);
    assert.equal(lib.formatBytesAs(b, "hex"), "474554202f0d0a0041");
    assert.equal(lib.formatBytesAs(b, "escaped"), "\\x47\\x45\\x54\\x20\\x2f\\x0d\\x0a\\x00\\x41");
    assert.equal(lib.formatBytesAs(b, "base64"), Buffer.from(b).toString("base64"));
    assert.equal(lib.formatBytesAs(b, "text"), "GET /\nA");
    assert.equal(
      lib.formatBytesAs(b, "c"),
      "static const unsigned char packet_bytes[9] = {\n  0x47, 0x45, 0x54, 0x20, 0x2f, 0x0d, 0x0a, 0x00,\n  0x41\n};",
    );
    assert.equal(
      lib.formatBytesAs(b, "hexdump", 0x10),
      "00000010  47 45 54 20 2f 0d 0a 00  41                       GET /...A",
    );
    for (const n of [0, 1, 2, 3, 4, 5]) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => i * 37);
      assert.equal(lib.toBase64(bytes), Buffer.from(bytes).toString("base64"));
    }
  });

  test("layoutColumns and moveColumn", () => {
    const all = ["number", "time", "source", "info", "custom:tcp.stream"].map((id) => ({ id }));
    const ids = (layout) => lib.layoutColumns(all, layout).map((c) => `${c.column.id}@${c.index}`);
    assert.deepEqual(ids(undefined), [
      "number@0",
      "time@1",
      "source@2",
      "info@3",
      "custom:tcp.stream@4",
    ]);
    assert.deepEqual(ids({ hidden: ["time"] }), [
      "number@0",
      "source@2",
      "info@3",
      "custom:tcp.stream@4",
    ]);
    assert.deepEqual(ids({ order: ["info", "number"] }), [
      "info@3",
      "number@0",
      "time@1",
      "source@2",
      "custom:tcp.stream@4",
    ]);
    assert.deepEqual(ids({ hidden: all.map((c) => c.id) }), ["number@0"]); // never zero columns
    assert.deepEqual(lib.moveColumn(["a", "b", "c", "d"], "d", "b"), ["a", "d", "b", "c"]);
    assert.deepEqual(lib.moveColumn(["a", "b", "c"], "a", null), ["b", "c", "a"]);
  });

  test("indexingLabel: percentage, packets, and the catching-up phase", () => {
    const n = (v) => v.toLocaleString();
    assert.equal(
      lib.indexingLabel({ frames: 420000, fraction: 0.4213 }),
      `Indexing… 42% · ${n(420000)} packets`,
    );
    assert.equal(lib.indexingLabel({ frames: 7, fraction: null }), "Indexing… 7 packets");
    assert.equal(lib.indexingLabel({ frames: 7, fraction: 1.7 }), "Indexing… 100% · 7 packets");
    assert.equal(
      lib.indexingLabel({ frames: 50000, fraction: 0.1, phase: "catching-up", resumedAt: 50000 }),
      `Resuming… re-reading packets 1–${n(50000)} (already shown)`,
    );
    assert.equal(
      lib.indexingLabel({ frames: 50001, fraction: 0.2, phase: "indexing", resumedAt: 50000 }),
      `Indexing… 20% · ${n(50001)} packets`,
    );
  });

  test("progressView: indexing first, then filter, export, coloring, other work", () => {
    const hidden = { visible: false, fraction: null, secondary: false, label: "" };
    assert.deepEqual(lib.progressView({}), hidden);
    assert.deepEqual(lib.progressView({ index: null, filter: undefined }), hidden);
    assert.deepEqual(lib.progressView({ index: { frames: 10, fraction: 0.25 }, filter: 0.9 }), {
      visible: true,
      fraction: 0.25,
      secondary: false,
      label: "Indexing packets",
    });
    assert.deepEqual(lib.progressView({ index: { frames: 10, fraction: null } }), {
      visible: true,
      fraction: null,
      secondary: false,
      label: "Indexing packets",
    });
    const resuming = lib.progressView({
      index: { frames: 10, fraction: 0.1, phase: "catching-up", resumedAt: 10 },
    });
    assert.deepEqual(resuming, {
      visible: true,
      fraction: 0.1,
      secondary: true,
      label: "Resuming indexing",
    });
    assert.deepEqual(lib.progressView({ filter: 0.5, exporting: 0.1 }).label, "Filtering packets");
    assert.deepEqual(lib.progressView({ exporting: null, coloring: 0.3 }), {
      visible: true,
      fraction: null,
      secondary: false,
      label: "Exporting",
    });
    assert.equal(lib.progressView({ coloring: 0.3, busy: null }).label, "Coloring packets");
    assert.equal(lib.progressView({ busy: -2 }).fraction, 0, "clamped to 0–1");
    assert.equal(lib.progressView({ busy: 0 }).visible, true, "0% is still running");
  });

  test("callFlow: endpoint columns and SIP/RTP rows in time order", () => {
    const streams = [
      { src: "10.0.0.2", dst: "10.0.0.1", start: 1.021, payload: "g711U", packets: 50, lost: 0 },
      {
        src: "10.0.0.1",
        dst: "10.0.0.2",
        start: 1.0213,
        payload: "g711U",
        packets: 49,
        lost: 1,
        lostPercent: 2,
      },
      { src: "10.0.0.9", dst: "10.0.0.8", start: 0, payload: "g729", packets: 1, lost: 0 },
    ];
    const call = {
      messages: [
        [1, 0, "10.0.0.1", "10.0.0.2", "INVITE (SDP)"],
        [4, 1.0, "10.0.0.2", "10.0.0.1", "200 OK (SDP)"],
        [105, 2.07, "10.0.0.1", "10.0.0.3", "BYE"],
      ],
      streams: [0, 1],
    };
    const { nodes, rows } = lib.callFlow(call, streams);
    assert.deepEqual(nodes, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
    assert.deepEqual(
      rows.map((r) => [r.from, r.to, r.label, r.frame ?? `stream ${r.stream}`]),
      [
        [0, 1, "INVITE (SDP)", 1],
        [1, 0, "200 OK (SDP)", 4],
        [1, 0, "RTP g711U · 50 packets", "stream 0"],
        [0, 1, "RTP g711U · 49 packets · 1 lost (2.0%)", "stream 1"],
        [0, 2, "BYE", 105],
      ],
    );
    assert.equal(
      lib.rtpStreamLabel({ payload: "g711A", packets: 10, lost: -2 }),
      "g711A · 10 packets · 2 duplicated",
    );
  });

  test("rtpProblems lists sequence gaps, late packets and payload changes", () => {
    const points = [
      [7, 0, 1000, 0, 0, 0, 1, 0, 0],
      [48, 0.42, 1021, 42.3, 1.05, -2.6, 0, 1, 1],
      [50, 0.44, 1024, 20, 1, 0, 0, 1, 2],
      [51, 0.45, 1022, 1, 1, 0, 0, 2, 0],
      [52, 0.46, 1025, 20, 1, 0, 0, 3, 0],
    ];
    assert.deepEqual(lib.rtpProblems(points), [
      { frame: 48, text: "1 packet lost before seq 1021" },
      { frame: 50, text: "2 packets lost before seq 1024" },
      { frame: 51, text: "Seq 1022 out of order or duplicated" },
      { frame: 52, text: "Payload type changed at seq 1025" },
    ]);
  });

  test("call details: timings, ending, quality and DTMF labels", () => {
    const call = {
      ringing: 0.3,
      setup: 1.5,
      duration: 2.1,
      final: "200 OK",
      endedBy: "callee",
      caller: "10.0.1.1",
      callee: "10.0.1.2",
      reasons: ["Q.850 cause 16: Normal call clearing"],
    };
    assert.deepEqual(lib.callFacts(call), [
      "Rang after 0.300 s",
      "answered after 1.500 s",
      "lasted 0:02",
      "final response 200 OK",
      "ended by the callee (10.0.1.2)",
      "Reason: Q.850 cause 16: Normal call clearing",
    ]);
    assert.deepEqual(
      lib.callFacts({
        ringing: null,
        setup: null,
        duration: null,
        final: "480 Temporarily Unavailable",
        endedBy: "callee",
        caller: "a",
        callee: "b",
      }),
      ["Not answered", "final response 480 Temporarily Unavailable", "ended by the callee (b)"],
    );
    const streams = [{ src: "10.0.0.1", srcPort: 40000, dst: "10.0.0.2", dstPort: 50000 }];
    const q = { mos: 4.23, r: 85.9, rating: "High", codec: "G.711", assumed: false, stream: 0 };
    assert.equal(lib.mosLabel(q), "4.23 (High)");
    assert.equal(lib.mosLabel(null), "");
    assert.equal(
      lib.callQualityText(q, streams),
      "MOS 4.23 (High, R 85.9) for 10.0.0.1:40000 → 10.0.0.2:50000, the call's worst stream; G.711",
    );
    assert.match(
      lib.callQualityText({ ...q, assumed: true, stream: 5 }, streams),
      /^MOS 4\.23 \(High, R 85\.9\); codec not known to the E-model: rated as G\.711$/,
    );
    assert.equal(lib.callQualityText(null, streams), "No RTP to rate.");
    assert.equal(
      lib.dtmfLabel({ digit: "4", method: "RFC 4733", src: "10.0.1.1", duration: 80 }),
      "4 · RFC 4733 from 10.0.1.1, 80 ms",
    );
    assert.equal(
      lib.dtmfLabel({ digit: "*", method: "SIP INFO", src: "10.0.1.2", duration: null }),
      "* · SIP INFO from 10.0.1.2",
    );
  });

  test("waveformPath and rtcpLabel", () => {
    assert.equal(lib.waveformPath([], 100, 40), "M0,20H100");
    // Two buckets: an envelope around the row's middle (y 20 + top), closed.
    assert.equal(
      lib.waveformPath([1000, 0], 100, 40, 40),
      "M0,60L25,41L75,59.5L100,60L75,60.5L25,79Z",
    );
    assert.equal(lib.rtcpLabel(null), "No RTCP reports about this stream.");
    assert.equal(
      lib.rtcpLabel({
        reports: 1,
        from: "10.0.1.7",
        fractionLost: 10.2,
        maxFractionLost: 10.2,
        cumulativeLost: 2,
        maxJitter: 5,
        rtt: 41,
      }),
      "RTCP from 10.0.1.7 (1 report): 10.2% lost (at most 10.2%), 2 lost in all, jitter up to 5 ms, round trip 41 ms",
    );
    assert.match(
      lib.rtcpLabel({
        reports: 3,
        from: "a",
        fractionLost: 0,
        maxFractionLost: 1.2,
        cumulativeLost: 0,
        maxJitter: 0.1254,
        rtt: null,
      }),
      /^RTCP from a \(3 reports\): .* jitter up to 0\.125 ms$/,
    );
  });

  test("groupCommands: headings in order, commands in their order, unknown groups under Other", () => {
    const c = (id, group) => ({ id, title: id, category: "PCAP", group });
    const groups = lib.groupCommands([
      c("other1", "Other"),
      c("stats1", "Statistics"),
      c("filter1", "Filters"),
      c("odd", "Something New"),
      c("stats2", "Statistics"),
      c("ai1", "AI"),
    ]);
    assert.deepEqual(
      groups.map((g) => [g.group, g.commands.map((x) => x.id)]),
      [
        ["Filters", ["filter1"]],
        ["Statistics", ["stats1", "stats2"]],
        ["AI", ["ai1"]],
        ["Other", ["other1", "odd"]],
      ],
    );
    assert.deepEqual(lib.groupCommands([]), []);
    assert.deepEqual(lib.COMMAND_GROUP_ORDER.slice(0, 3), ["Filters", "Packets", "Statistics"]);
  });

  test("commandMenuRows: headings fold their commands, except while searching", () => {
    const c = (id, group) => ({ id, title: id, category: "PCAP", group });
    const groups = lib.groupCommands([
      c("f1", "Filters"),
      c("s1", "Statistics"),
      c("s2", "Statistics"),
    ]);
    const shape = (rows) =>
      rows.map((r) =>
        r.kind === "group" ? `${r.open ? "▾" : "▸"}${r.group}(${r.count})` : r.command.id,
      );
    assert.deepEqual(shape(lib.commandMenuRows(groups, new Set(), false)), [
      "▸Filters(1)",
      "▸Statistics(2)",
    ]);
    const open = lib.commandMenuRows(groups, new Set(["Statistics"]), false);
    assert.deepEqual(shape(open), ["▸Filters(1)", "▾Statistics(2)", "s1", "s2"]);
    assert.ok(open.filter((r) => r.kind === "group").every((r) => r.foldable));
    const searching = lib.commandMenuRows(groups, new Set(), true);
    assert.deepEqual(shape(searching), ["▾Filters(1)", "f1", "▾Statistics(2)", "s1", "s2"]);
    assert.ok(searching.filter((r) => r.kind === "group").every((r) => !r.foldable));
  });

  test("filterCommands: every word, case-insensitive, in the title, heading or category", () => {
    const commands = [
      { id: "a", title: "Conversations", category: "PCAP Statistics", group: "Statistics" },
      { id: "b", title: "Export Objects…", category: "PCAP", group: "Export" },
      { id: "c", title: "Follow TCP Stream", category: "PCAP", group: "Statistics" },
    ];
    const ids = (text) => lib.filterCommands(commands, text).map((c) => c.id);
    assert.deepEqual(ids(""), ["a", "b", "c"]);
    assert.deepEqual(ids("   "), ["a", "b", "c"]);
    assert.deepEqual(ids("CONV"), ["a"]);
    assert.deepEqual(ids("statistics"), ["a", "c"], "heading or category");
    assert.deepEqual(ids("pcap statistics tcp"), ["c"]);
    assert.deepEqual(ids("export"), ["b"]);
    assert.deepEqual(ids("nothing"), []);
  });

  test("formatKeybinding: Ctrl+… on Windows and Linux, symbols (the mac binding) on macOS", () => {
    const f = lib.formatKeybinding;
    assert.equal(f({ key: "ctrl+/", mac: "cmd+/" }, false), "Ctrl+/");
    assert.equal(f({ key: "ctrl+/", mac: "cmd+/" }, true), "⌘/");
    assert.equal(f({ key: "ctrl+shift+n", mac: "cmd+shift+n" }, false), "Ctrl+Shift+N");
    assert.equal(f({ key: "ctrl+shift+n", mac: "cmd+shift+n" }, true), "⌘⇧N");
    assert.equal(f({ key: "ctrl+alt+c", mac: "cmd+alt+c" }, true), "⌘⌥C");
    assert.equal(f({ key: "alt+left", mac: "alt+left" }, false), "Alt+Left");
    assert.equal(f({ key: "alt+left", mac: "alt+left" }, true), "⌥←");
    assert.equal(f({ key: "ctrl+g" }, true), "⌃G", "no mac binding: the key binding, in symbols");
    assert.equal(f({ key: "ctrl+k ctrl+s" }, false), "Ctrl+K Ctrl+S", "chords");
    assert.equal(f(undefined, false), "");
  });

  test("commandUnavailable: the first unmet requirement's reason, or null", () => {
    const ctx = { selected: false, marks: 0, filter: false, capturing: false, ai: false };
    const cmd = (requires) => ({ id: "x", title: "X", category: "PCAP", group: "Other", requires });
    assert.equal(lib.commandUnavailable(cmd(undefined), ctx), null);
    assert.equal(lib.commandUnavailable(cmd(["selection"]), ctx), "Select a packet first");
    assert.equal(lib.commandUnavailable(cmd(["selection"]), { ...ctx, selected: true }), null);
    assert.equal(lib.commandUnavailable(cmd(["marks"]), ctx), "No packets are marked");
    assert.equal(lib.commandUnavailable(cmd(["marks"]), { ...ctx, marks: 2 }), null);
    assert.equal(lib.commandUnavailable(cmd(["filter"]), ctx), "No display filter is applied");
    assert.equal(lib.commandUnavailable(cmd(["capturing"]), ctx), "No capture is running");
    assert.match(lib.commandUnavailable(cmd(["ai", "selection"]), ctx), /^AI help isn't available/);
    assert.equal(
      lib.commandUnavailable(cmd(["ai", "selection"]), { ...ctx, ai: true }),
      "Select a packet first",
    );
    assert.equal(lib.commandUnavailable(cmd(["something new"]), ctx), null, "unknown: allowed");
  });

  test("filterButtonTitle: the comment above the filter", () => {
    assert.equal(lib.filterButtonTitle({ filter: "dns" }), "dns");
    assert.equal(
      lib.filterButtonTitle({ filter: "dns.flags.rcode != 0", comment: "Failed lookups" }),
      "Failed lookups\ndns.flags.rcode != 0",
    );
  });
});

suite("webview lib: empty list and filter builder", () => {
  const base = { ready: true, total: 0, filter: "" };

  test("what the empty list says", () => {
    assert.equal(lib.emptyState({ ...base, ready: false }), null);
    assert.equal(lib.emptyState({ ...base, total: 3, filter: "x" }), null);
    assert.deepEqual(lib.emptyState({ ...base, filter: "dns", filtering: true, fraction: 0.425 }), {
      kind: "searching",
      title: "Looking for matching packets…",
      detail: "42% of the capture read. Matches appear here as they are found.",
    });
    assert.equal(
      lib.emptyState({ ...base, filter: "dns", filtering: true }).detail,
      "Matches appear here as they are found.",
    );
    assert.deepEqual(lib.emptyState({ ...base, filter: "dns" }), {
      kind: "no-match",
      title: "No packets match this filter",
      detail: "",
    });
    assert.match(lib.emptyState({ ...base, filter: "dns", partial: true }).detail, /stopped/);
    assert.match(lib.emptyState({ ...base, filter: "dns", indexing: true }).detail, /later ones/);
    const capture = { running: true, interfaces: ["eth0", "lo"], filter: "port 53" };
    assert.deepEqual(lib.emptyState({ ...base, indexing: true, capture }), {
      kind: "waiting",
      title: "Waiting for packets on eth0, lo…",
      detail: "Capture filter: port 53",
    });
    assert.equal(lib.emptyState({ ...base, indexing: true }).kind, "reading");
    assert.equal(lib.emptyState(base).kind, "empty");
  });

  test("hints for a filter matching nothing", () => {
    const fields = (present) => present.map(([name, p]) => ({ name, present: p }));
    assert.deepEqual(
      lib.filterHintItems({
        fields: fields([
          ["sip", false],
          ["sip.Method", false],
          ["ip.addr", true],
        ]),
        caseHints: [],
      }),
      [{ type: "missing", names: ["sip", "sip.Method"] }],
    );
    const caseHint = { field: "http.host", value: "Ex", filter: 'lower(http.host) == "ex"' };
    assert.deepEqual(
      lib.filterHintItems({ fields: fields([["http.host", true]]), caseHints: [caseHint] }),
      [{ type: "case", ...caseHint }],
    );
    // Every field occurs: their values are worth a look (fields, not bare protocols).
    assert.deepEqual(
      lib.filterHintItems({
        fields: fields([
          ["tcp", true],
          ["tcp.port", true],
          ["ip.ttl", true],
          ["ip.src", true],
          ["ip.dst", true],
        ]),
        caseHints: [],
      }),
      [{ type: "values", names: ["tcp.port", "ip.ttl", "ip.src"] }],
    );
    assert.deepEqual(lib.filterHintItems({ fields: fields([["tcp", true]]), caseHints: [] }), []);
  });

  test("relations by field type", () => {
    const ops = (t) => lib.builderOperators(t).map((o) => o.op);
    assert.deepEqual(ops("FT_NONE"), ["present", "absent"]);
    assert.deepEqual(ops("protocol"), ["present", "absent", "contains"]);
    assert.deepEqual(ops("FT_BOOLEAN"), ["present", "absent", "==", "!="]);
    assert.deepEqual(ops("FT_STRING"), [
      "present",
      "absent",
      "==",
      "!=",
      "contains",
      "matches",
      "in",
    ]);
    assert.deepEqual(ops("FT_UINT16"), [
      "present",
      "absent",
      "==",
      "!=",
      ">",
      "<",
      ">=",
      "<=",
      "in",
    ]);
    assert.deepEqual(ops("FT_ABSOLUTE_TIME"), ops("FT_UINT16"));
    assert.deepEqual(ops("FT_ETHER"), ["present", "absent", "==", "!=", "contains", "in"]);
    assert.deepEqual(ops("FT_IPv4"), ["present", "absent", "==", "!=", "in"]);
    assert.equal(lib.builderOperators("FT_UINT8")[0].value, false);
    assert.equal(lib.builderOperators("FT_UINT8")[2].label, "== (equal)");
  });

  test("values and terms the builder writes", () => {
    assert.equal(lib.filterLiteral("FT_BOOLEAN", "True"), "1");
    assert.equal(lib.filterLiteral("FT_BOOLEAN", "false"), "0");
    assert.equal(lib.filterLiteral("FT_STRING", 'say "hi" \\o/'), '"say \\"hi\\" \\\\o/"');
    assert.equal(lib.filterLiteral("FT_STRING", '"already"'), '"already"');
    assert.equal(lib.filterLiteral("FT_IPv4", " 10.0.0.1 "), "10.0.0.1");

    assert.equal(lib.builderTerm("tcp", "protocol", "present", ""), "tcp");
    assert.equal(lib.builderTerm("tcp", "protocol", "absent", ""), "!tcp");
    assert.equal(lib.builderTerm("ip.ttl", "FT_UINT8", "==", " "), null);
    assert.equal(lib.builderTerm("ip.ttl", "FT_UINT8", ">=", "64"), "ip.ttl >= 64");
    assert.equal(
      lib.builderTerm("tcp.flags.syn", "FT_BOOLEAN", "==", "True"),
      "tcp.flags.syn == 1",
    );
    assert.equal(
      lib.builderTerm("http.host", "FT_STRING", "matches", "^example\\.com$"),
      'http.host matches "^example\\\\.com$"',
    );
    assert.equal(lib.builderTerm("frame", "protocol", "contains", "GET"), 'frame contains "GET"');
    assert.equal(
      lib.builderTerm("frame", "protocol", "contains", "47:45:54"),
      "frame contains 47:45:54",
    );
    assert.equal(
      lib.builderTerm("eth.src", "FT_ETHER", "contains", "02:00"),
      "eth.src contains 02:00",
    );
    assert.equal(
      lib.builderTerm("http.request.method", "FT_STRING", "in", "GET, POST,"),
      'http.request.method in {"GET", "POST"}',
    );
    assert.equal(lib.builderTerm("tcp.port", "FT_UINT16", "in", "80,443"), "tcp.port in {80, 443}");
    assert.equal(lib.builderTerm("tcp.port", "FT_UINT16", "in", " , "), null);
  });
});

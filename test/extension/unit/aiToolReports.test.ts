/**
 * The report tools (aiTools.ts, aiToolReports.ts) that Copilot's agent mode
 * and the PCAP Lens agent call: against the real backend on the fixtures
 * (skipped without tshark), and their consent and argument checks.
 */
import * as assert from "node:assert/strict";
import * as path from "node:path";
import { CaptureDiff } from "../../../src/aiCompare";
import {
  ALL_TOOLS,
  PCAP_TOOLS,
  ToolBackend,
  ToolConsent,
  VIEWER_TOOLS,
  runTool,
} from "../../../src/aiTools";
import {
  compareReport,
  packetDetailsReport,
  rtpPoints,
  sessionProblem,
  triageReport,
  voipCallsReport,
  withoutDigits,
} from "../../../src/aiToolReports";
import { BackendClient } from "../../../src/backendClient";
import { FIXTURES, HAVE_TSHARK, makeClient, startIsolated } from "./backendTesting";

const ALL: ToolConsent = { statistics: true, packetData: true };
const STATS_ONLY: ToolConsent = { statistics: true, packetData: false };
const NONE: ToolConsent = { statistics: false, packetData: false };

/** A backend that must not be asked anything. */
const silent: ToolBackend & { asked: string[] } = {
  asked: [],
  async request<T>(method: string): Promise<T> {
    silent.asked.push(method);
    throw new Error(`unexpected ${method}`);
  },
};

suite("AI report tools", () => {
  test("consent: sessions and packet details are packet data, the rest statistics", async () => {
    for (const name of ["pcap_sessions", "pcap_packet_details"]) {
      const res = await runTool(name, { kind: "http", packets: [1] }, silent, STATS_ONLY);
      assert.equal(res.refused, "packetData", name);
      assert.match(res.text, /pcapViewer\.ai\.allowPacketData/, name);
    }
    for (const name of ["pcap_triage", "pcap_overview", "pcap_tcp_stream", "pcap_compare"]) {
      assert.equal((await runTool(name, {}, silent, NONE)).refused, "statistics", name);
    }
    assert.deepEqual(silent.asked, [], "nothing was asked of the backend");
  });

  test("the VoIP, RTP, sequence, export objects and credentials tools need statistics", async () => {
    for (const name of [
      "pcap_voip_calls",
      "pcap_rtp_stream",
      "pcap_sequence_check",
      "pcap_export_objects",
      "pcap_credentials",
    ]) {
      assert.equal((await runTool(name, { stream: 0 }, silent, NONE)).refused, "statistics", name);
    }
    for (const [name, args, words] of [
      ["pcap_voip_calls", { call: "x" }, /call must be a call number/],
      ["pcap_rtp_stream", {}, /Give the stream number/],
      ["pcap_sequence_check", {}, /Give the field that numbers the messages/],
      [
        "pcap_sequence_check",
        { sequence: "gtp.seq_number", wrap_bits: 12 },
        /wrap_bits must be one of 0, 8, 16, 24, 32/,
      ],
      ["pcap_export_objects", { protocol: "nfs" }, /protocol must be one of http, smb/],
    ] as const) {
      assert.match((await runTool(name, args, silent, ALL)).text, words, name);
    }
    assert.deepEqual(silent.asked, [], "nothing was asked of the backend");
  });

  test("DTMF digits come out of IAX2 and MGCP message names", () => {
    assert.equal(withoutDigits("DTMF 7"), "DTMF (digit hidden)");
    assert.equal(withoutDigits("NTFY D/2,D/0"), "NTFY 2 DTMF digits hidden");
    assert.equal(withoutDigits("NTFY L/hd,D/5"), "NTFY L/hd, 1 DTMF digit hidden");
    assert.equal(withoutDigits("INVITE (SDP)"), "INVITE (SDP)");
    assert.equal(withoutDigits("CRCX aaln/1@gw1"), "CRCX aaln/1@gw1", "an endpoint isn't a digit");
  });

  test("an MGCP call's dialled digits aren't sent as its destination without packet data", () => {
    const call = {
      id: 0,
      protocol: "MGCP",
      from: "aaln/1@gw1.example.net",
      to: "4321",
      dialed: "4321",
      caller: "10.0.4.11",
      callee: "",
      state: "Rejected",
      setup: null,
      duration: null,
      messages: [[3, 1, "10.0.4.11", "10.0.4.1", "NTFY D/4,D/3,D/2,D/1"]] as [
        number,
        number,
        string,
        string,
        string,
      ][],
      streams: [],
    };
    const data = { calls: [call], streams: [] };
    for (const opts of [{}, { call: 0 }]) {
      const hidden = voipCallsReport(data, {
        ...opts,
        limit: 5,
        packetData: false,
        maxChars: 9000,
      });
      assert.doesNotMatch(hidden.text, /4321|D\/4/, JSON.stringify(opts));
      assert.match(hidden.text, /\(dialled number hidden\)/);
      assert.deepEqual(hidden.names, [{ name: "aaln/1@gw1.example.net" }]);
      const shown = voipCallsReport(data, { ...opts, limit: 5, packetData: true, maxChars: 9000 });
      assert.match(shown.text, /4321/);
    }
  });

  test("RTP loss is the numbers that never came, across the 16-bit wrap too", () => {
    const fields = ["frame", "time", "seq", "delta", "jitter", "skew", "marker", "status", "gap"];
    const point = (frame: number, seq: number, status = 0, gap = 0) => [
      frame,
      frame / 50,
      seq,
      20,
      0,
      0,
      0,
      status,
      gap,
    ];
    // 1, 3, 2, 4: a gap at 3, then 2 late: nothing lost.
    const reordered = rtpPoints(
      fields,
      [point(1, 1), point(2, 3, 1, 1), point(3, 2, 2), point(4, 4)],
      2,
    );
    assert.deepEqual(reordered.problems, [{ packet: 3, seq: 2, problem: "out of order" }]);
    assert.equal(
      reordered.timeline.reduce((n, b) => n + b.lost, 0),
      0,
    );
    // 65534, then 1 skips 65535 and 0; 0 comes later.
    const wrapped = rtpPoints(
      fields,
      [point(1, 65534), point(2, 1, 1, 2), point(3, 0, 2), point(4, 2)],
      1,
    );
    assert.deepEqual(wrapped.problems[0], {
      packet: 2,
      seq: 1,
      problem: "lost",
      lostBefore: 1,
      arrivedLater: 1,
    });
    assert.equal(wrapped.timeline[0].lost, 1);
    assert.deepEqual(rtpPoints(["frame"], [[1]], 2), { problems: [], timeline: [] });
  });

  test("arguments are checked before the backend is asked", async () => {
    assert.match(
      (await runTool("pcap_sessions", { kind: "smtp" }, silent, ALL)).text,
      /kind must be one of http, dns, tls/,
    );
    assert.match(
      (await runTool("pcap_tcp_stream", {}, silent, ALL)).text,
      /Give the tcp\.stream number/,
    );
    assert.match(
      (await runTool("pcap_packet_details", { packets: ["x", 0, -2] }, silent, ALL)).text,
      /Give the packet numbers/,
    );
    assert.match((await runTool("pcap_compare", {}, silent, ALL)).text, /other capture's path/);
    assert.match(
      (await runTool("pcap_compare", { other: "b.pcap" }, silent, ALL)).text,
      /isn't available here/,
      "no host to read the other capture",
    );
    assert.deepEqual(silent.asked, []);
  });

  test("a capture argument: read through the host, after the consent check", async () => {
    const opened: string[] = [];
    const other: ToolBackend = {
      request: <T>(method: string) =>
        Promise.resolve(
          (method === "capture_info"
            ? {
                frames: 7,
                startTime: null,
                endTime: null,
                size: 10,
                linkType: null,
                fileType: null,
              }
            : {}) as T,
        ),
    };
    const host = {
      open: async (capture: string) => {
        opened.push(capture);
        return capture === "missing.pcap"
          ? "No capture file missing.pcap."
          : { backend: other, host: {} };
      },
    };
    const info = await runTool(
      "pcap_capture_info",
      { capture: "b.pcap" },
      silent,
      ALL,
      undefined,
      host,
    );
    assert.match(info.text, /^Packets: 7$/m, "the named capture's backend answered");
    assert.equal(
      (
        await runTool(
          "pcap_count",
          { capture: "missing.pcap", filter: "" },
          silent,
          ALL,
          undefined,
          host,
        )
      ).text,
      "No capture file missing.pcap.",
    );
    assert.equal(
      (await runTool("pcap_triage", { capture: "b.pcap" }, silent, NONE, undefined, host)).refused,
      "statistics",
    );
    assert.deepEqual(opened, ["b.pcap", "missing.pcap"], "nothing opened without consent");
    assert.match(
      (await runTool("pcap_triage", { capture: "b.pcap" }, silent, ALL)).text,
      /Only the capture open in PCAP Lens/,
      "no host to open it",
    );
    assert.ok(
      PCAP_TOOLS.filter((t) => t.name !== "pcap_field_search").every(
        (t) => "capture" in ((t.inputSchema.properties as object) ?? {}),
      ),
      "every capture tool takes it",
    );
    assert.deepEqual(silent.asked, []);
  });

  test("the viewer tools are declared but not in @pcap's loop", () => {
    assert.deepEqual(
      VIEWER_TOOLS.map((t) => t.name),
      ["pcap_apply_filter", "pcap_go_to_packet"],
    );
    for (const t of VIEWER_TOOLS) {
      assert.ok(!PCAP_TOOLS.includes(t), t.name);
      assert.ok(ALL_TOOLS.includes(t), t.name);
    }
  });

  test("session problems: HTTP errors and no response, DNS failures, TLS without ServerHello", () => {
    const cells = (values: Record<string, unknown>) => (id: string) => values[id];
    assert.equal(sessionProblem("http", cells({ status: 200 })), false);
    assert.equal(sessionProblem("http", cells({ status: 404 })), true);
    assert.equal(sessionProblem("http", cells({ status: "" })), true, "no response");
    assert.equal(sessionProblem("dns", cells({ rcode: "NoError" })), false);
    assert.equal(sessionProblem("dns", cells({ rcode: "No response" })), true);
    assert.equal(sessionProblem("tls", cells({ unanswered: 0 })), false);
    assert.equal(sessionProblem("tls", cells({ unanswered: 2 })), true);
  });

  test("reports stay within their size and say what is missing", () => {
    const triage = triageReport(
      {
        checks: [
          { id: "a", title: "A", filter: "tcp", count: 0 },
          { id: "b", title: "B", filter: "x.y", error: "unknown field" },
        ],
      },
      2000,
    );
    assert.match(triage.text, /0 of 2 found packets/);
    assert.match(triage.text, /Not available with this tshark: b/);
    assert.match(triage.text, /No packets: a\./);
    assert.match(triage.text, /Scan detection: not available\./);
    const big = packetDetailsReport(
      [
        {
          number: 1,
          tree: Array.from({ length: 400 }, (_, i) => ({ label: `field ${i} ${"x".repeat(100)}` })),
        },
      ],
      [],
      { maxLines: 250, maxDepth: 10, maxLabel: 160, maxChars: 3000 },
    );
    assert.ok(big.text.length <= 3000, `${big.text.length} characters`);
    assert.match(big.text, /\[result cut short\]$/);
    const diff: CaptureDiff = {
      before: { name: "a.pcap", packets: 10 },
      after: { name: "b.pcap", packets: 20 },
      checks: {
        changed: Array.from({ length: 50 }, (_, i) => ({ id: `c${i}`, padding: "y".repeat(80) })),
      },
    };
    const compared = compareReport(diff, 15, 2500);
    assert.ok(compared.text.length <= 2500, `${compared.text.length} characters`);
    assert.match(
      compared.text,
      /^Before \(baseline\): a\.pcap, 10 packets\. After: b\.pcap, 20 packets\./,
    );
  });
});

suite("AI report tools on the real backend", function () {
  this.timeout(120_000);
  const clients: BackendClient[] = [];
  const open = async (file: string): Promise<BackendClient> => {
    const client = makeClient();
    clients.push(client);
    startIsolated(client);
    await client.request("initialize", {}, { timeoutMs: 60_000 });
    await client.request("open", { path: path.join(FIXTURES, file), names: {} }, { timeoutMs: 0 });
    return client;
  };

  suiteTeardown(async () => {
    await Promise.all(clients.map((c) => c.dispose()));
  });

  (HAVE_TSHARK ? test : test.skip)(
    "overview, session tables, a TCP stream and packet details",
    async () => {
      const backend = await open("sessions.pcap");
      const overview = await runTool("pcap_overview", {}, backend, ALL);
      assert.match(overview.text, /^Capture overview: 62 packets, 5\.6 kB over 3 s\./);
      assert.match(overview.text, /^HTTP: 7 requests, 6 responses$/m);
      assert.match(
        overview.text,
        /^- NXDomain: 1 — dns\.flags\.response == 1 && dns\.flags\.rcode == 3$/m,
      );
      assert.match(overview.text, /^- cdn\.example\.net: 1 — /m);
      assert.ok(
        overview.names?.some((n) => n.name === "missing.example.com"),
        "DNS names get stand-ins",
      );

      const http = await runTool(
        "pcap_sessions",
        { kind: "http", only_problems: true },
        backend,
        ALL,
      );
      assert.match(http.text, /^HTTP requests: requests 7, unanswered 1\.\n4 with problems:/);
      assert.match(http.text, /\| POST \| www\.example\.com \| \/api\/items \| 500 \|/);
      assert.match(http.text, /\| \/slow \| {2}\| No response \|/);
      assert.doesNotMatch(http.text, /\| 200 \|/, "only the problems");
      const dns = await runTool(
        "pcap_sessions",
        { kind: "dns", only_problems: true },
        backend,
        ALL,
      );
      assert.match(dns.text, /^2 with problems:/m);
      assert.match(dns.text, /missing\.example\.com \| A \| NXDomain/);
      assert.match(dns.text, /lost\.example\.com \| A \| No response/);
      const tls = await runTool(
        "pcap_sessions",
        { kind: "tls", only_problems: true },
        backend,
        ALL,
      );
      assert.match(tls.text, /^203\.0\.113\.5:443 \| cdn\.example\.net \| TCP \| 1 \| 1 \|/m);
      assert.match(
        tls.text,
        /\| api\.example\.com \| PCAP Lens Test CA \| 2021-01-01 \| Expired 2021-01-01 \|/,
      );
      assert.deepEqual((tls.names ?? []).map((n) => n.name).sort(), [
        "api.example.com",
        "cdn.example.net",
      ]);

      const stream = await runTool("pcap_tcp_stream", { packet: 4 }, backend, ALL);
      assert.equal(stream.filter, "tcp.stream == 0");
      assert.match(stream.text, /^TCP stream 0 \(filter: tcp\.stream == 0\):\nPackets: 18 over/);
      assert.match(stream.text, /221 B of payload, 368 B\/s on average/, "rates are rounded");
      assert.match(stream.text, /^No retransmissions\.$/m);
      assert.equal(
        (await runTool("pcap_tcp_stream", { stream: 0 }, backend, ALL)).text,
        stream.text,
        "by stream number or by packet",
      );

      const details = await runTool("pcap_packet_details", { packets: [4, 999, 4] }, backend, ALL);
      // (tshark 4.6 writes "Frame 4: Packet, 124 bytes on wire".)
      assert.match(details.text, /^## Packet 4\nFrame 4: (Packet, )?124 bytes on wire/);
      assert.match(details.text, /^ {2}Host: www\.example\.com\\r\\n$/m);
      assert.match(details.text, /tcp\.payload: \[70 bytes not sent\]/, "no byte dumps");
      assert.match(details.text, /No such packet: 999\.$/);
      assert.equal(details.text.match(/^## Packet/gm)?.length, 1, "each packet once");
      assert.ok(details.names?.some((n) => n.name === "www.example.com"));
    },
  );

  (HAVE_TSHARK ? test : test.skip)(
    "VoIP calls, one call, an RTP stream; DTMF digits only with packet data",
    async () => {
      const calls = await open("voip-calls.pcap");
      const list = await runTool("pcap_voip_calls", {}, calls, STATS_ONLY);
      assert.match(
        list.text,
        /^VoIP calls: 5 \(Completed 3, Cancelled 1, Rejected 1\), 2 with problems; 4 media streams\.$/m,
      );
      assert.match(
        list.text,
        /^1 \| SIP \| frank@10\.0\.1\.3 \| erin@10\.0\.1\.2 \| Completed \| 200 OK \| .* \| one-way, codec, ssrc, gap \| /m,
      );
      assert.match(
        list.text,
        /^- frank@example\.test from 10\.0\.1\.3 to 10\.0\.1\.100: Failed \(403 Forbidden\)/m,
      );
      assert.ok(
        list.names?.some((n) => n.name === "dave@10.0.1.1"),
        "the parties get stand-ins",
      );
      const hidden = await runTool("pcap_voip_calls", { call: 0 }, calls, STATS_ONLY);
      assert.match(hidden.text, /^Call 0 \(SIP\): dave@10\.0\.1\.1 → erin@10\.0\.1\.2\.$/m);
      assert.match(hidden.text, /^85 \| 2\.3 \| 10\.0\.1\.2 \| 10\.0\.1\.1 \| INFO$/m);
      assert.match(
        hidden.text,
        /^- stream 3: 10\.0\.1\.1:30000 → 10\.0\.1\.2:32000, SSRC 0x55555555, .*, sent by the caller$/m,
      );
      assert.match(
        hidden.text,
        /^DTMF: a digit \(RFC 4733, packet 46\), a digit \(SIP INFO, packet 85\)/m,
      );
      assert.match(hidden.text, /DTMF digits are hidden: .*pcapViewer\.ai\.allowPacketData/);
      const shown = await runTool("pcap_voip_calls", { call: 0 }, calls, ALL);
      assert.match(
        shown.text,
        /^DTMF: "4" \(RFC 4733, packet 46\), "7" \(SIP INFO, packet 85\), "#"/m,
      );
      assert.doesNotMatch(shown.text, /are hidden/);
      assert.match(
        (await runTool("pcap_voip_calls", { call: 9 }, calls, ALL)).text,
        /^No call 9: the capture has calls 0 to 4\.$/,
      );

      const other = await open("voip-other.pcap");
      const iax = await runTool("pcap_voip_calls", { call: 3 }, other, STATS_ONLY);
      assert.match(iax.text, /^Call 3 \(IAX2\): /);
      assert.match(iax.text, /\| DTMF \(digit hidden\)$/m, "IAX2's DTMF message without its digit");
      assert.doesNotMatch(iax.text, /DTMF 7/);

      const rtp = await open("voip.pcap");
      const stream = await runTool("pcap_rtp_stream", { stream: 0, buckets: 4 }, rtp, STATS_ONLY);
      assert.match(stream.text, /^Stream 0 \(call 0\):/);
      assert.match(stream.text, /^Analysis: 49 packets of 50 expected, 1 lost \(2%\)/m);
      assert.match(stream.text, /^- packet 48 \(seq 1021\): lost, 1 lost before it$/m);
      const rows = stream.text.split("Timeline")[1].trim().split("\n").slice(1);
      assert.equal(rows.length, 4);
      assert.equal(
        rows.reduce((n, r) => n + Number(r.split(" | ")[3]), 0),
        1,
        "adds up to the loss",
      );
      assert.match(stream.filter ?? "", /^rtp\.ssrc == 0x11111111 && /);
      assert.match(
        (await runTool("pcap_rtp_stream", { stream: 9 }, rtp, ALL)).text,
        /^No stream 9: pcap_voip_calls lists streams 0 to \d+\.$/,
      );
    },
  );

  (HAVE_TSHARK ? test : test.skip)(
    "the sequence check, export objects and credentials; contents only with packet data",
    async () => {
      const seq = await open("sequences.pcap");
      const tunnels = await runTool(
        "pcap_sequence_check",
        { sequence: "gtp.seq_number", streams_by: "gtp.teid", wrap_bits: 16 },
        seq,
        STATS_ONLY,
      );
      assert.match(
        tunnels.text,
        /^Sequence check of gtp\.seq_number per gtp\.teid, a 16-bit counter: streams 4, withProblems 2,/,
      );
      assert.match(
        tunnels.text,
        /^1 \| 0x00000200 \| 9 \| 1 \| 10 \| 2 \| 1 \| 1 \| 0 \| .* \| gtp\.teid == 0x00000200 && gtp\.seq_number$/m,
      );
      assert.match(tunnels.text, /^ {2}- gap: Missing 4–5 \(2\) \(packet 14\)$/m);
      assert.match(
        tunnels.text,
        /^4 \| 0x00000300 \| 6 \| 65533 \| 2 \| 0 \|/m,
        "the wrap is no gap",
      );
      // A text key (an address here; a LIID in a delivery): numbered streams, no filters.
      const byAddress = await runTool(
        "pcap_sequence_check",
        { sequence: "gtp.seq_number", streams_by: "ip.src" },
        seq,
        STATS_ONLY,
      );
      assert.match(byAddress.text, /key values are text fields/);
      assert.doesNotMatch(byAddress.text, /ip\.src ==|10\.\d+\.\d+\.\d+/);
      assert.match(
        (
          await runTool(
            "pcap_sequence_check",
            { sequence: "gtp.seq_number", streams_by: ["ip.src"] },
            seq,
            ALL,
          )
        ).text,
        /^stream \| ip\.src \| messages/m,
        "shown with packet data",
      );
      // The sequence field's values come back as numbers: a text field is packet contents.
      const text = await runTool(
        "pcap_sequence_check",
        { sequence: "ftp.request.arg" },
        seq,
        STATS_ONLY,
      );
      assert.equal(text.refused, "packetData");
      assert.match(text.text, /^ftp\.request\.arg is a FT_STRING field: .*allowPacketData/);

      const objects = await open("objects.pcap");
      const files = await runTool("pcap_export_objects", {}, objects, STATS_ONLY);
      assert.match(
        files.text,
        /^Files the capture carries \(Export Objects\): http 5 \(1\.7 kB\), tftp 1 \(612 B\), imf 1 \(107 B\)\.$/m,
      );
      assert.match(
        files.text,
        /^- http, 776 B, image\/png, from example\.com, packet 6 \(frame\.number == 6\)$/m,
      );
      assert.doesNotMatch(files.text, /logo\.png/, "no file names without packet data");
      const named = await runTool("pcap_export_objects", { protocol: "http" }, objects, ALL);
      assert.match(named.text, /^- http logo\.png, 776 B/m);
      assert.doesNotMatch(named.text, /tftp,/, "only the protocol asked for");

      const creds = await open("credentials.pcap");
      const logins = await runTool("pcap_credentials", {}, creds, STATS_ONLY);
      assert.match(
        logins.text,
        /^Clear-text credentials tshark found: HTTP basic auth 1, FTP 1, POP3 1, IMAP 1\.$/m,
      );
      assert.match(
        logins.text,
        /^- FTP, packet 20 \(user name in packet 16\) — frame\.number == 20$/m,
      );
      assert.doesNotMatch(logins.text, /alice|bob|carol/);
      assert.match(
        (await runTool("pcap_credentials", {}, creds, ALL)).text,
        /^- FTP user bob, packet 20/m,
      );
    },
  );

  (HAVE_TSHARK ? test : test.skip)("triage and comparing with another capture", async () => {
    const after = await open("office-after.pcap");
    const before = await open("office-before.pcap");
    const triage = await runTool("pcap_triage", {}, after, ALL);
    assert.match(
      triage.text,
      /^tcp_resets \| TCP resets \(RST\) \| 5 \| 60 \| 80 \| tcp\.flags\.reset == 1$/m,
    );
    assert.match(
      triage.text,
      /^- Port scan: 10\.0\.0\.66 reached 5 TCP ports of 10\.0\.0\.80 \(22, 23, 445, 3389, 5900\).* Filter: ip\.src == 10\.0\.0\.66 && ip\.dst == 10\.0\.0\.80 && tcp\.dstport in \{22,23,445,3389,5900\}$/m,
    );
    assert.match(triage.text, /^Expert information by severity: Warning 5,/m);
    assert.match(triage.text, /^No packets: .*\bmalformed\.$/m);

    const asked: [string, string][] = [];
    const host = {
      compare: async (other: string, open: "before" | "after") => {
        asked.push([other, open]);
        const [mine, theirs] = await Promise.all([
          after.request("capture_profile", {}, { timeoutMs: 0 }),
          before.request("capture_profile", {}, { timeoutMs: 0 }),
        ]);
        return after.request<CaptureDiff>("compare_profiles", {
          before: theirs,
          after: mine,
          names: [other, "office-after.pcap"],
        });
      },
    };
    const compared = await runTool(
      "pcap_compare",
      { other: "office-before.pcap" },
      after,
      ALL,
      undefined,
      host,
    );
    assert.deepEqual(asked, [["office-before.pcap", "after"]], "the other capture is the baseline");
    assert.match(
      compared.text,
      /^Before \(baseline\): office-before\.pcap, 96 packets\. After: office-after\.pcap, 103 packets\./,
    );
    assert.match(
      compared.text,
      /^- Port scan, only in the after capture: 10\.0\.0\.66 reached 5 TCP ports/m,
    );
    assert.match(compared.text, /"id":"tcp_resets"[^}]*"before":0,"after":5/);
    await runTool("pcap_compare", { other: "x", baseline: "open" }, after, ALL, undefined, {
      compare: async (other, open) => {
        asked.push([other, open]);
        return "No capture file x.";
      },
    });
    assert.deepEqual(asked.at(-1), ["x", "before"], "the open capture is the baseline");
  });
});

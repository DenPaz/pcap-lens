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
  sessionProblem,
  triageReport,
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
      assert.match(overview.text, /^Capture overview: 62 packets, 5\.2 kB over 3 s\./);
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
      assert.deepEqual(tls.names, [{ name: "cdn.example.net" }]);

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

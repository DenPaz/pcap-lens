import * as assert from "node:assert/strict";
import { STATISTICS_CONSENT } from "../../../src/aiConsent";
import { Scan } from "../../../src/aiScans";
import { Requester, StatsTable, buildSummaryPrompt, gatherSummary } from "../../../src/aiSummary";
import {
  TRIAGE_LIMITS,
  TriageCheck,
  TriageInput,
  buildTriagePrompt,
  gatherTriage,
  knownFrames,
  parseTriage,
  sortFindings,
  triageQuery,
} from "../../../src/aiTriage";
import { buildReport } from "../../../src/captureReport";

const col = (id: string, label: string, numeric = false) => ({ id, label, numeric });

const SCAN: Scan = {
  kind: "port scan",
  protocol: "tcp",
  client: "10.0.0.66",
  server: "10.0.0.80",
  ports: [22, 23, 445, 3389, 5900],
  targets: 5,
  packets: 10,
  reset: 5,
};

const CHECKS: TriageCheck[] = [
  {
    id: "tcp_resets",
    title: "TCP resets (RST)",
    filter: "tcp.flags.reset == 1",
    count: 12,
    first: 40,
    last: 900,
  },
  {
    id: "dns_errors",
    title: "DNS error responses",
    filter: "dns.flags.rcode != 0",
    count: 0,
    first: null,
    last: null,
  },
  { id: "kerberos_errors", title: "Kerberos errors", filter: "kerberos.error_code", error: "x" },
  {
    id: "dns_unanswered",
    title: "DNS queries without a response",
    filter: "dns.flags.response == 0 && !dns.response_in",
    skipped: "needs two passes",
  },
];

const EXPERT: StatsTable = {
  columns: [
    col("severity", "Severity"),
    col("summary", "Summary"),
    col("group", "Group"),
    col("protocol", "Protocol"),
    col("count", "Count", true),
  ],
  rows: [{ cells: ["Error", "Malformed Packet", "Malformed", "DNS", 1], frames: [12] }],
};

const INPUT: TriageInput = {
  question: "why\nis it slow?",
  info: {
    frames: 1000,
    startTime: 1_700_000_000,
    endTime: 1_700_000_010,
    size: 200_000,
    linkType: "Ethernet",
    fileType: "pcapng",
  },
  checks: CHECKS,
  ignored: true,
  expert: EXPERT,
  missing: ["UDP conversations"],
};

suite("aiTriage", () => {
  test("the prompt: properties, the checks as counted, the expert information, what's missing", () => {
    const prompt = buildTriagePrompt(INPUT);
    assert.match(prompt, /Answer with JSON only/);
    assert.match(prompt, /Focus: why is it slow\?/);
    assert.match(prompt, /## Checks \(ignored packets left out\)/);
    assert.match(
      prompt,
      /tcp_resets \| TCP resets \(RST\) \| 12 \| 40 \| 900 \| tcp\.flags\.reset == 1/,
    );
    assert.match(prompt, /dns_errors \| DNS error responses \| 0 \| - \| - \|/);
    assert.match(prompt, /\[Not available with this tshark: kerberos_errors\]/);
    assert.ok(!/kerberos_errors \|/.test(prompt));
    assert.match(prompt, /\[Not checked \(needs two passes, too many packets\): dns_unanswered\]/);
    assert.ok(!/dns_unanswered \|/.test(prompt));
    assert.match(prompt, /Malformed Packet/);
    assert.match(prompt, /Not available \(could not be computed\): UDP conversations\./);
    assert.ok(prompt.length <= TRIAGE_LIMITS.maxPromptChars);
  });

  test("a big conversation table is cut until the prompt fits", () => {
    const conv: StatsTable = {
      columns: [col("a", "Address A"), col("bytes", "Bytes", true)],
      rows: Array.from({ length: 500 }, (_, i) => ({ cells: [`host-${i}-${"x".repeat(60)}`, i] })),
    };
    const prompt = buildTriagePrompt({ ...INPUT, conversations: [conv, conv, conv, conv] });
    assert.ok(prompt.length <= TRIAGE_LIMITS.maxPromptChars);
  });

  test("findings are cleaned: severities, check filters, packets the data named", () => {
    assert.deepEqual(
      [...knownFrames(INPUT)].sort((a, b) => a - b),
      [12, 40, 900],
    );
    const answer =
      "Sure!\n```json\n" +
      JSON.stringify({
        summary: "Mostly\nhealthy.",
        findings: [
          {
            severity: "LOW",
            title: "Malformed DNS",
            detail: "One packet.",
            filter: "_ws.malformed",
            frames: [12, 13],
          },
          {
            severity: "high",
            title: "Many resets",
            detail: "12 resets.",
            check: "tcp_resets",
            filter: "tcp.flags.reset == 1 && ip.addr == 1.2.3.4",
            frames: ["900", 5],
          },
          { severity: "critical", title: "Odd", detail: "?", check: "kerberos_errors" },
          { severity: "low", title: "Lost", detail: "?", check: "dns_unanswered" },
          { title: "" },
          "nonsense",
        ],
      }) +
      "\n```";
    const report = parseTriage(answer, INPUT);
    assert.deepEqual(report, {
      summary: "Mostly healthy.",
      findings: [
        {
          severity: "low",
          title: "Malformed DNS",
          detail: "One packet.",
          filter: "_ws.malformed",
          frames: [12],
        },
        {
          severity: "high",
          title: "Many resets",
          detail: "12 resets.",
          filter: "tcp.flags.reset == 1",
          frames: [40, 900],
          check: "tcp_resets",
        },
        { severity: "info", title: "Odd", detail: "?", frames: [] },
        { severity: "low", title: "Lost", detail: "?", frames: [] },
      ],
    });
    assert.deepEqual(
      sortFindings(report?.findings ?? []).map((f) => f.severity),
      ["high", "low", "low", "info"],
    );
    assert.equal(parseTriage("I can't.", INPUT), undefined);
    const many = { findings: Array.from({ length: 20 }, (_, i) => ({ title: `F${i}` })) };
    assert.equal(
      parseTriage(JSON.stringify(many), INPUT)?.findings.length,
      TRIAGE_LIMITS.maxFindings,
    );
  });

  test("the chat query and the consent", () => {
    assert.equal(triageQuery(), "@pcap /triage");
    assert.equal(triageQuery(" dns\nonly "), "@pcap /triage dns only");
    assert.match(STATISTICS_CONSENT, /triaging or comparing captures/);
    assert.match(STATISTICS_CONSENT, /first and last packet number/);
  });

  test("the capture report's Findings section, marked as the model's", () => {
    const md = buildReport(
      {
        name: "t.pcapng",
        path: "/t.pcapng",
        generated: new Date("2026-10-24T00:00:00Z"),
        filter: "",
        info: INPUT.info,
        findings: {
          model: "GPT-4o (GitHub Copilot)",
          report: {
            summary: "Resets | everywhere",
            findings: [
              { severity: "info", title: "Fine", detail: "ok", frames: [] },
              {
                severity: "high",
                title: "Resets <b>",
                detail: "12",
                filter: "tcp.flags.reset == 1",
                frames: [40, 900],
              },
            ],
          },
        },
      },
      "markdown",
    );
    assert.match(md, /## Findings\n\n_Written by a language model \(GPT-4o \(GitHub Copilot\)\)/);
    assert.match(md, /Resets \\\| everywhere/);
    assert.match(
      md,
      /\| High \| Resets \\<b\\> \| 12 \| tcp.flags.reset == 1 \| 40, 900 \|\n\| Info \|/,
    );
    assert.ok(md.indexOf("## Findings") < md.indexOf("## Expert") || !md.includes("## Expert"));
    const html = buildReport(
      {
        name: "t.pcapng",
        path: "/t.pcapng",
        generated: new Date(),
        filter: "",
        info: INPUT.info,
        findings: {
          model: "m",
          report: { summary: "", findings: [] },
        },
      },
      "html",
    );
    assert.match(html, /No findings\./);
  });
  test("gathering: the backend's answers become the input, failed tables are named", async () => {
    const asked: string[] = [];
    const failed: string[] = [];
    const table: StatsTable = { columns: [col("protocol", "Protocol")], rows: [] };
    const request: Requester = async <T>(method: string, params: Record<string, unknown>) => {
      const what = (
        method === "stats" ? `stats ${String(params.kind)} ${String(params.type ?? "")}` : method
      ).trim();
      asked.push(what);
      if (what === "stats conversations udp" || what === "stats io") {
        throw new Error("tshark refused");
      }
      if (method === "capture_info") {
        return INPUT.info as T;
      }
      if (method === "triage") {
        return { checks: CHECKS, ignored: true } as T;
      }
      if (method === "scans") {
        return { scans: [SCAN] } as T;
      }
      return table as T;
    };
    const input = await gatherTriage(request, "why?", (kind, message) =>
      failed.push(`${kind}: ${message}`),
    );
    assert.deepEqual(
      asked.sort(),
      [
        "capture_info",
        "scans",
        "stats conversations tcp",
        "stats conversations udp",
        "stats expert",
        "stats phs",
        "triage",
      ].sort(),
    );
    assert.deepEqual(failed, ["conversations: tshark refused"]);
    assert.equal(input.question, "why?");
    assert.equal(input.ignored, true);
    assert.equal(input.checks, CHECKS);
    assert.deepEqual(input.conversations, [table]);
    assert.deepEqual(input.missing, ["UDP conversations"]);
    assert.deepEqual(input.scans, [SCAN]);
    // The scans are in the prompt as sentences, with what tshark counted.
    const prompt = buildTriagePrompt(input);
    assert.match(prompt, /## Scans tshark's numbers show\n/);
    assert.match(
      prompt,
      /- Port scan: 10\.0\.0\.66 reached 5 TCP ports of 10\.0\.0\.80 \(22, 23, 445, 3389, 5900\), 10 packets, a few per connection; 5 of the 5 ports answered with a TCP reset/,
    );
    assert.match(prompt, /Give each scan tshark found its own finding/);
    assert.doesNotMatch(buildTriagePrompt({ ...input, scans: [] }), /## Scans/);

    asked.length = 0;
    const summary = await gatherSummary(request, { question: "q", currentFilter: "dns" });
    assert.equal(asked.length, 8);
    assert.deepEqual(summary.missing, ["UDP conversations", "traffic over time"]);
    assert.match(buildSummaryPrompt(summary), /- Port scan: 10\.0\.0\.66 reached 5 TCP ports/);
    // An older backend without scans: named as missing, nothing else changes.
    const noScans: Requester = async <T>(method: string, params: Record<string, unknown>) => {
      if (method === "scans") {
        throw new Error("unknown method");
      }
      return request<T>(method, params);
    };
    const without = await gatherTriage(noScans, "");
    assert.equal(without.scans, undefined);
    assert.deepEqual(without.missing, ["scan detection", "UDP conversations"]);
    assert.deepEqual(summary.endpoints, [table]);
    assert.equal(summary.currentFilter, "dns");
    // capture_info failing fails the whole gathering (there is nothing to say without it).
    const broken: Requester = async (method) => {
      throw new Error(`${method} failed`);
    };
    await assert.rejects(gatherTriage(broken, ""), /capture_info failed|triage failed/);
  });
});

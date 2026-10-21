import * as assert from "node:assert/strict";
import type { StatsTable } from "../../../src/aiSummary";
import {
  ReportInput,
  buildReport,
  htmlEscape,
  markdownEscape,
  reportFileName,
} from "../../../src/captureReport";

const col = (id: string, label: string, numeric = false) => ({ id, label, numeric });

const PHS: StatsTable = {
  columns: [
    col("protocol", "Protocol"),
    col("packets", "Packets", true),
    col("bytes", "Bytes", true),
  ],
  rows: [
    { cells: ["eth", 10, 1000], depth: 0 },
    { cells: ["ip", 10, 860], depth: 1 },
  ],
};

const TCP: StatsTable = {
  columns: [col("a", "Address A"), col("b", "Address B"), col("bytes", "Bytes", true)],
  rows: Array.from({ length: 25 }, (_, i) => ({ cells: [`10.0.0.${i}`, "10.0.1.1", i * 100] })),
};

const EXPERT: StatsTable = {
  columns: [
    col("severity", "Severity"),
    col("group", "Group"),
    col("protocol", "Protocol"),
    col("summary", "Summary"),
    col("count", "Count", true),
  ],
  rows: [
    { cells: ["Warning", "Sequence", "TCP", "Previous segment not captured", 2] },
    { cells: ["Error", "Malformed", "DNS", "Malformed packet", 1] },
  ],
};

const INPUT: ReportInput = {
  name: "trace.pcapng",
  path: "/captures/trace.pcapng",
  generated: new Date("2026-10-21T12:00:00.123Z"),
  filter: "tcp",
  info: {
    frames: 10,
    startTime: 1_700_000_000,
    endTime: 1_700_000_010,
    size: 2048,
    linkType: "Ethernet",
    fileType: "pcapng",
  },
  protocols: PHS,
  conversations: [{ title: "TCP conversations", table: TCP }],
  expert: EXPERT,
  packets: {
    columns: ["Time", "Info"],
    rows: [{ number: 1, cells: ["0.000000", "<script>alert(1)</script> | x"] }],
    total: 3,
  },
  missing: ["endpoints"],
};

suite("captureReport", () => {
  test("Markdown: sections, the top rows by bytes, escaped cells", () => {
    const md = buildReport(INPUT, "markdown");
    assert.match(md, /^# Capture report: trace\.pcapng\n/);
    assert.match(md, /Made by PCAP Lens on 2026-10-21T12:00:00Z\./);
    assert.match(md, /\| Packets \| 10 \|/);
    assert.match(md, /\| First packet \| 2023-11-14T22:13:20Z \|/);
    assert.match(md, /\| Average rate \| 1 packets\/s \|/);
    assert.match(
      md,
      /## Protocol hierarchy\n\n\| Protocol \| Packets \| % of packets \| Bytes \|\n\| --- \| ---: \| ---: \| ---: \|/,
    );
    assert.match(md, /\| \u00a0\u00a0ip \| 10 \|/, "indented by depth");
    // The 20 largest conversations, largest first, and a note for the rest.
    assert.match(md, /## Top TCP conversations\n\n\| Address A \| Address B \| Bytes \|/);
    assert.match(md, /\| 10\.0\.0\.24 \| 10\.0\.1\.1 \| 2,400 \|/);
    assert.doesNotMatch(md, /\| 10\.0\.0\.4 \|/);
    assert.match(md, /_5 more not shown \(by bytes\)\._/);
    // Expert information: errors first.
    assert.match(md, /\| Error \| 1 \|\n\| Warning \| 2 \|/);
    // Packets: escaped so the cell can't break the table or add markup.
    assert.match(md, /The 3 packets matching tcp/);
    assert.match(md, /\\<script\\>alert\(1\)\\<\/script\\> \\\| x/);
    assert.match(md, /_Only the first 1 are listed\._/);
    assert.match(md, /_Not available: endpoints\._\n$/);
  });

  test("HTML: one self-contained page with nothing unescaped", () => {
    const html = buildReport(INPUT, "html");
    assert.match(html, /^<!doctype html>/);
    assert.match(html, /content="default-src 'none'; style-src 'unsafe-inline'"/);
    assert.match(html, /<title>Capture report: trace\.pcapng<\/title>/);
    assert.match(html, /<h1>Capture report: trace\.pcapng<\/h1>/);
    assert.match(html, /<td>&lt;script&gt;alert\(1\)&lt;\/script&gt; \| x<\/td>/);
    assert.doesNotMatch(html, /<script/);
    assert.match(html, /<td class="n">2,400<\/td>/, "numbers right-aligned");
  });

  test("escaping and file names", () => {
    assert.equal(markdownEscape("a|b*c_[d]"), "a\\|b\\*c\\_\\[d\\]");
    assert.equal(
      htmlEscape(`<a href="x">'&'</a>`),
      "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;",
    );
    assert.equal(reportFileName("trace.pcapng", "markdown"), "trace-report.md");
    assert.equal(reportFileName("trace.pcap.gz", "html"), "trace-report.html");
    assert.equal(reportFileName(".pcap", "markdown"), "capture-report.md");
  });
});

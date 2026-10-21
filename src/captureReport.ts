/**
 * Capture report (pure): the capture's properties, protocol hierarchy, top
 * conversations and endpoints, expert information and optionally the
 * displayed packets, as Markdown or as one self-contained HTML file (inline
 * styles, a CSP that allows nothing else). Everything from the capture is
 * untrusted text: escaped for the format, one line per cell.
 */
import {
  CaptureFacts,
  StatsRow,
  StatsTable,
  expertCounts,
  formatBytes,
  formatNumber,
  formatSeconds,
  topRows,
} from "./aiSummary";

export interface ReportPackets {
  columns: string[];
  rows: { number: number; cells: string[] }[];
  /** Packets in the view (more than the rows when cut). */
  total: number;
}

export interface ReportInput {
  /** The capture file's name and path. */
  name: string;
  path: string;
  generated: Date;
  /** The display filter of the view (the packet list section's). */
  filter: string;
  info: CaptureFacts;
  protocols?: StatsTable;
  conversations?: { title: string; table: StatsTable }[];
  endpoints?: { title: string; table: StatsTable }[];
  expert?: StatsTable;
  packets?: ReportPackets;
  /** Sections that could not be computed. */
  missing?: string[];
}

export const REPORT_LIMITS = { topRows: 20, expertMessages: 25, maxCell: 200, packets: 1000 };

export type ReportFormat = "markdown" | "html";

/** One block of the report, rendered by either format. */
type Block =
  | { kind: "heading"; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "table"; head: string[]; rows: string[][]; numeric?: boolean[] }
  | { kind: "note"; text: string };

const cell = (v: unknown, max = REPORT_LIMITS.maxCell): string => {
  const text = (v === null || v === undefined ? "" : String(v)).replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
};

const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? v : 0);

function isoTime(seconds: number | null): string {
  return seconds === null ? "" : new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

function propertyRows(input: ReportInput): string[][] {
  const { info } = input;
  const span =
    info.startTime !== null && info.endTime !== null
      ? Math.max(0, info.endTime - info.startTime)
      : 0;
  const rows: string[][] = [
    ["File", input.name],
    ["Location", input.path],
    ["Size", formatBytes(info.size)],
    ["Format", info.fileType ?? ""],
    ["Link type", info.linkType ?? ""],
    ["Packets", formatNumber(info.frames)],
    ["First packet", isoTime(info.startTime)],
    ["Last packet", isoTime(info.endTime)],
    ["Duration", info.startTime !== null ? formatSeconds(span) : ""],
  ];
  if (span > 0) {
    rows.push(["Average rate", `${formatNumber(info.frames / span)} packets/s`]);
  }
  return rows.filter(([, v]) => v);
}

function statsTable(table: StatsTable, rows: readonly StatsRow[]): Block {
  return {
    kind: "table",
    head: table.columns.map((c) => cell(c.label)),
    rows: rows.map((r) =>
      table.columns.map((_c, i) => {
        const v = r.cells[i];
        return typeof v === "number" ? formatNumber(v) : cell(v);
      }),
    ),
    numeric: table.columns.map((c) => c.numeric),
  };
}

function protocolBlock(table: StatsTable): Block {
  const at = (id: string) => table.columns.findIndex((c) => c.id === id);
  const [proto, pct, packets, bytes] = ["protocol", "percent_packets", "packets", "bytes"].map(at);
  return {
    kind: "table",
    head: ["Protocol", "Packets", "% of packets", "Bytes"],
    rows: table.rows.map((r) => [
      // (Non-breaking spaces keep the indentation in both formats.)
      `${"\u00a0\u00a0".repeat(r.depth ?? 0)}${cell(r.cells[proto >= 0 ? proto : 0])}`,
      packets >= 0 ? formatNumber(num(r.cells[packets])) : "",
      pct >= 0 ? `${formatNumber(num(r.cells[pct]))}%` : "",
      bytes >= 0 ? formatBytes(num(r.cells[bytes])) : "",
    ]),
    numeric: [false, true, true, true],
  };
}

/** The report's blocks, in order. */
export function reportBlocks(input: ReportInput): Block[] {
  const blocks: Block[] = [
    { kind: "heading", text: `Capture report: ${cell(input.name)}` },
    {
      kind: "paragraph",
      text: `Made by PCAP Lens on ${input.generated.toISOString().replace(/\.\d{3}Z$/, "Z")}.`,
    },
    { kind: "heading", text: "Properties" },
    { kind: "table", head: ["Property", "Value"], rows: propertyRows(input) },
  ];
  if (input.protocols?.rows.length) {
    blocks.push({ kind: "heading", text: "Protocol hierarchy" }, protocolBlock(input.protocols));
  }
  const top = (title: string, table: StatsTable) => {
    if (!table.rows.length) {
      return;
    }
    const { rows, omitted } = topRows(table, REPORT_LIMITS.topRows);
    blocks.push({ kind: "heading", text: title }, statsTable(table, rows));
    if (omitted) {
      blocks.push({ kind: "note", text: `${formatNumber(omitted)} more not shown (by bytes).` });
    }
  };
  for (const { title, table } of input.conversations ?? []) {
    top(`Top ${title}`, table);
  }
  for (const { title, table } of input.endpoints ?? []) {
    top(`Top ${title}`, table);
  }
  if (input.expert) {
    const counts = expertCounts(input.expert, REPORT_LIMITS.expertMessages);
    blocks.push({ kind: "heading", text: "Expert information" });
    if (!counts.bySeverity.length) {
      blocks.push({ kind: "paragraph", text: "No expert information." });
    } else {
      blocks.push(
        {
          kind: "table",
          head: ["Severity", "Entries"],
          rows: counts.bySeverity.map(([s, n]) => [cell(s), formatNumber(n)]),
          numeric: [false, true],
        },
        {
          kind: "table",
          head: ["Severity", "Group", "Protocol", "Message", "Count"],
          rows: counts.top.map((e) => [
            cell(e.severity),
            cell(e.group),
            cell(e.protocol),
            cell(e.summary),
            formatNumber(e.count),
          ]),
          numeric: [false, false, false, false, true],
        },
      );
      if (counts.omitted) {
        blocks.push({ kind: "note", text: `${formatNumber(counts.omitted)} more messages.` });
      }
    }
  }
  if (input.packets) {
    const { packets } = input;
    blocks.push(
      { kind: "heading", text: "Packets" },
      {
        kind: "paragraph",
        text: input.filter
          ? `The ${formatNumber(packets.total)} packets matching ${cell(input.filter, 1000)}`
          : `All ${formatNumber(packets.total)} packets`,
      },
      {
        kind: "table",
        head: ["No.", ...packets.columns.map((c) => cell(c))],
        rows: packets.rows.map((r) => [String(r.number), ...r.cells.map((c) => cell(c))]),
      },
    );
    if (packets.total > packets.rows.length) {
      blocks.push({
        kind: "note",
        text: `Only the first ${formatNumber(packets.rows.length)} are listed.`,
      });
    }
  }
  if (input.missing?.length) {
    blocks.push({
      kind: "note",
      text: `Not available: ${input.missing.join(", ")}.`,
    });
  }
  return blocks;
}

/** Markdown: tables with `|` (escaped in cells), so any viewer shows it. */
export function markdownEscape(text: string): string {
  return text.replace(/([\\`*_{}[\]<>|#])/g, "\\$1");
}

function markdown(blocks: Block[]): string {
  const out: string[] = [];
  let first = true;
  for (const b of blocks) {
    switch (b.kind) {
      case "heading":
        out.push(`${first ? "#" : "##"} ${markdownEscape(b.text)}`, "");
        first = false;
        break;
      case "paragraph":
        out.push(markdownEscape(b.text), "");
        break;
      case "note":
        out.push(`_${markdownEscape(b.text)}_`, "");
        break;
      case "table": {
        const row = (cells: string[]) => `| ${cells.map(markdownEscape).join(" | ")} |`;
        out.push(row(b.head));
        out.push(`| ${b.head.map((_, i) => (b.numeric?.[i] ? "---:" : "---")).join(" | ")} |`);
        out.push(...b.rows.map(row), "");
        break;
      }
    }
  }
  return `${out.join("\n").trimEnd()}\n`;
}

export function htmlEscape(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const STYLE = `
body { font: 14px/1.45 system-ui, sans-serif; margin: 2rem auto; max-width: 72rem; padding: 0 1rem; color: #1f2328; background: #fff; }
h1 { font-size: 1.6rem; } h2 { font-size: 1.2rem; margin-top: 2rem; border-bottom: 1px solid #d0d7de; padding-bottom: .25rem; }
table { border-collapse: collapse; margin: .5rem 0 1rem; font-size: 13px; }
th, td { border: 1px solid #d0d7de; padding: .25rem .5rem; text-align: left; vertical-align: top; }
th { background: #f6f8fa; } td.n { text-align: right; font-variant-numeric: tabular-nums; }
tr:nth-child(even) td { background: #fafbfc; } .note { color: #59636e; font-style: italic; }
@media (prefers-color-scheme: dark) {
  body { color: #e6edf3; background: #0d1117; } th { background: #161b22; }
  th, td, h2 { border-color: #30363d; } tr:nth-child(even) td { background: #11161d; } .note { color: #9198a1; }
}`;

function html(blocks: Block[], title: string): string {
  const parts: string[] = [];
  let first = true;
  for (const b of blocks) {
    switch (b.kind) {
      case "heading":
        parts.push(`<h${first ? 1 : 2}>${htmlEscape(b.text)}</h${first ? 1 : 2}>`);
        first = false;
        break;
      case "paragraph":
        parts.push(`<p>${htmlEscape(b.text)}</p>`);
        break;
      case "note":
        parts.push(`<p class="note">${htmlEscape(b.text)}</p>`);
        break;
      case "table": {
        const head = b.head.map((h) => `<th scope="col">${htmlEscape(h)}</th>`).join("");
        const rows = b.rows
          .map(
            (r) =>
              `<tr>${r
                .map((c, i) => `<td${b.numeric?.[i] ? ' class="n"' : ""}>${htmlEscape(c)}</td>`)
                .join("")}</tr>`,
          )
          .join("\n");
        parts.push(
          `<table>\n<thead><tr>${head}</tr></thead>\n<tbody>\n${rows}\n</tbody>\n</table>`,
        );
        break;
      }
    }
  }
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${htmlEscape(title)}</title>`,
    `<style>${STYLE}\n</style>`,
    "</head>",
    "<body>",
    ...parts,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

export function buildReport(input: ReportInput, format: ReportFormat): string {
  const blocks = reportBlocks(input);
  return format === "html" ? html(blocks, `Capture report: ${cell(input.name)}`) : markdown(blocks);
}

/** The report's file name next to the capture: `trace.pcapng` → `trace-report.md`. */
export function reportFileName(captureName: string, format: ReportFormat): string {
  const stem = captureName.replace(/(\.(pcapng|pcap|cap|ntar|gz|zst|lz4))+$/i, "") || "capture";
  return `${stem}-report.${format === "html" ? "html" : "md"}`;
}

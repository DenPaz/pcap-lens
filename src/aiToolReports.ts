/**
 * The text results of the report tools (aiTools.ts): triage, the capture
 * overview, the session tables, a TCP stream, packet details and a
 * comparison, written for a model that calls them in Copilot's agent mode
 * (or @pcap). Data only, no instructions beyond what to call next: in agent
 * mode the model, not PCAP Lens, writes the answer. No `vscode` import:
 * unit-tested.
 */
import { CaptureDiff, scanLines, shrinkDiff } from "./aiCompare";
import { TreeNode, treeLines } from "./aiExplain";
import { TcpPoint, TCP_POINT, tcpFactLines, tcpFacts } from "./aiAnomaly";
import { Scan, scanFilter, scanSentence } from "./aiScans";
import {
  StatsTable,
  expertCounts,
  formatBytes,
  formatNumber,
  formatSeconds,
  oneLine,
} from "./aiSummary";
import { TriageCheck, checkLines } from "./aiTriage";

/** A host name a result shows (stand-ins replace it), with its address when known. */
export interface ShownName {
  name: string;
  address?: string;
}

export interface Report {
  text: string;
  names?: ShownName[];
}

const cut = (text: string, max: number): string =>
  text.length <= max ? text : `${text.slice(0, max - 30)}\n[result cut short]`;

// ---------------------------------------------------------------------- triage

export interface TriageData {
  checks: TriageCheck[];
  ignored?: boolean;
  /** Undefined when the backend couldn't compute them. */
  scans?: Scan[];
  expert?: StatsTable;
}

/** Checks that found packets (most first), scans, expert counts; then what came back empty. */
export function triageReport(data: TriageData, maxChars: number): Report {
  const found = data.checks
    .filter((c) => c.error === undefined && c.skipped === undefined && (c.count ?? 0) > 0)
    .sort((a, b) => (b.count ?? 0) - (a.count ?? 0));
  const quiet = data.checks.filter(
    (c) => c.error === undefined && c.skipped === undefined && !c.count,
  );
  const lines = [
    `Triage checks counted by tshark${data.ignored ? " (ignored packets left out)" : ""}: ${found.length} of ${data.checks.length} found packets.`,
  ];
  if (found.length) {
    lines.push(
      ...checkLines([
        ...found,
        ...data.checks.filter((c) => c.error !== undefined || c.skipped !== undefined),
      ]),
    );
  } else {
    lines.push(...checkLines(data.checks).slice(1)); // (only the refused and skipped notes)
  }
  if (quiet.length) {
    lines.push(`No packets: ${quiet.map((c) => c.id).join(", ")}.`);
  }
  lines.push("");
  if (data.scans === undefined) {
    lines.push("Scan detection: not available.");
  } else if (!data.scans.length) {
    lines.push("Scans: none (no client reached many ports of one server or one port of many).");
  } else {
    lines.push("Scans tshark's numbers show (report them as scans, not as new services):");
    for (const scan of data.scans) {
      const filter = scanFilter(scan);
      lines.push(`- ${scanSentence(scan)}${filter ? ` Filter: ${filter}` : ""}`);
    }
  }
  if (data.expert) {
    const counts = expertCounts(data.expert, 10);
    lines.push(
      "",
      `Expert information by severity: ${counts.bySeverity.map(([s, n]) => `${s} ${formatNumber(n)}`).join(", ") || "none"}`,
      ...counts.top
        .slice(0, 10)
        .map(
          (e) =>
            `- ${e.severity} ${e.group} (${e.protocol}): ${oneLine(e.summary, 160)} × ${e.count}`,
        ),
    );
  }
  lines.push(
    "",
    "Next: pcap_count or pcap_list_packets with a check's filter, pcap_sessions for HTTP/DNS/TLS problems, pcap_tcp_stream for one connection.",
  );
  return { text: cut(lines.join("\n"), maxChars) };
}

// ---------------------------------------------------------------------- overview

interface Breakdown {
  total?: number;
  items?: { label: string; count: number; bytes?: number; filter?: string }[];
  more?: number;
}

/** The backend's `overview` result (the parts the report reads). */
export interface OverviewData {
  packets: number;
  bytes: number;
  duration: number | null;
  filter?: string;
  timeline?: { interval: number; packets: number[]; bytes: number[] };
  addresses?: Breakdown;
  protocols?: Breakdown;
  services?: Breakdown;
  http?: Record<string, unknown>;
  dns?: Record<string, unknown>;
  tls?: Record<string, unknown>;
}

const isBreakdown = (v: unknown): v is Breakdown =>
  !!v && typeof v === "object" && Array.isArray((v as Breakdown).items);

function breakdownLines(title: string, b: Breakdown | undefined, limit: number): string[] {
  const items = b?.items ?? [];
  if (!items.length) {
    return [];
  }
  const more = items.length - Math.min(limit, items.length) + (b?.more ?? 0);
  return [
    `${title}:`,
    ...items
      .slice(0, limit)
      .map(
        (i) =>
          `- ${oneLine(i.label, 100)}: ${formatNumber(i.count)}${i.bytes !== undefined ? ` (${formatBytes(i.bytes)})` : ""}${i.filter ? ` — ${i.filter}` : ""}`,
      ),
    ...(more > 0 ? [`- [${more} more]`] : []),
  ];
}

const COUNT_LABELS: Record<string, string> = {
  requests: "requests",
  responses: "responses",
  queries: "queries",
  clientHellos: "ClientHellos",
  serverHellos: "ServerHellos",
};

/** Section names of the HTTP, DNS and TLS cards. */
const PART_LABELS: Record<string, string> = {
  methods: "methods",
  hosts: "hosts",
  codes: "status codes",
  statuses: "status codes",
  types: "types",
  contentTypes: "content types",
  rcodes: "results",
  names: "names",
  versions: "versions chosen",
  servers: "server names",
};

/** Host names in the overview's HTTP hosts, DNS names and TLS server names (stand-ins replace them). */
function overviewNames(data: OverviewData): ShownName[] {
  const out: ShownName[] = [];
  for (const [part, keys] of [
    [data.http, ["hosts"]],
    [data.dns, ["names"]],
    [data.tls, ["servers", "names"]],
  ] as const) {
    for (const key of keys) {
      const b = part?.[key];
      if (isBreakdown(b)) {
        out.push(...(b.items ?? []).map((i) => ({ name: i.label })));
      }
    }
  }
  return out;
}

/** Totals, the busiest interval and the top rows of every breakdown, each with its display filter. */
export function overviewReport(data: OverviewData, limit: number, maxChars: number): Report {
  const lines = [
    `Capture overview${data.filter ? ` (limited to \`${data.filter}\`)` : ""}: ${formatNumber(data.packets)} packets, ${formatBytes(data.bytes)}${data.duration !== null ? ` over ${formatSeconds(data.duration)}` : ""}.`,
  ];
  const tl = data.timeline;
  if (tl && tl.packets.length && Math.max(...tl.packets) > 0) {
    const peak = tl.packets.indexOf(Math.max(...tl.packets));
    lines.push(
      `Busiest ${formatSeconds(tl.interval)} interval: from ${formatSeconds(peak * tl.interval)} after the first packet, ${formatNumber(tl.packets[peak])} packets (${formatBytes(tl.bytes[peak] ?? 0)}).`,
    );
  }
  lines.push(
    ...breakdownLines("Top addresses (packets, bytes)", data.addresses, limit),
    ...breakdownLines("Protocols (packets)", data.protocols, limit),
    ...breakdownLines("TCP services (connections)", data.services, limit),
  );
  const absent: string[] = [];
  for (const [name, part] of [
    ["HTTP", data.http],
    ["DNS", data.dns],
    ["TLS", data.tls],
  ] as const) {
    const counts = Object.entries(part ?? {}).filter(
      (e): e is [string, number] => typeof e[1] === "number",
    );
    if (!counts.some(([, n]) => n > 0)) {
      absent.push(name);
      continue;
    }
    lines.push(
      `${name}: ${counts.map(([k, n]) => `${formatNumber(n)} ${COUNT_LABELS[k] ?? k}`).join(", ")}`,
    );
    for (const [key, value] of Object.entries(part ?? {})) {
      if (isBreakdown(value)) {
        lines.push(...breakdownLines(`${name} ${PART_LABELS[key] ?? key}`, value, limit));
      }
    }
  }
  if (absent.length) {
    lines.push(`Not in this capture: ${absent.join(", ")}.`);
  }
  return { text: cut(lines.join("\n"), maxChars), names: overviewNames(data) };
}

// ---------------------------------------------------------------------- session tables

export const SESSION_KINDS = { http: "http_requests", dns: "dns_queries", tls: "tls_servers" };
export type SessionKind = keyof typeof SESSION_KINDS;

/** A session table (the statistics panel's `stats` result for a session kind). */
export interface SessionTable {
  columns: { id: string; label: string }[];
  rows: { cells: unknown[]; filter?: string; frame?: number; response?: number }[];
  summary?: Record<string, number>;
  more?: number;
}

/** Whether a row is a problem: an HTTP error or no response, a failed or unanswered DNS query, a TLS server with handshakes that got no ServerHello (the MCP server's rule). */
export function sessionProblem(kind: SessionKind, cell: (id: string) => unknown): boolean {
  if (kind === "http") {
    const status = cell("status");
    return typeof status !== "number" || status >= 400;
  }
  if (kind === "dns") {
    return cell("rcode") !== "NoError";
  }
  const unanswered = cell("unanswered");
  return typeof unanswered === "number" && unanswered > 0;
}

/** Host names in a session table: HTTP hosts, DNS names, TLS server names. */
const NAME_COLUMNS: Record<SessionKind, string> = { http: "host", dns: "name", tls: "sni" };

/** The table's rows (only the problems, when asked), at most `limit`, each with its filter. */
export function sessionReport(
  kind: SessionKind,
  table: SessionTable,
  opts: { onlyProblems: boolean; limit: number; maxChars: number },
): Report {
  const ids = table.columns.map((c) => c.id);
  const cellOf = (row: SessionTable["rows"][number]) => (id: string) => {
    const i = ids.indexOf(id);
    return i >= 0 ? row.cells[i] : undefined;
  };
  const rows = opts.onlyProblems
    ? table.rows.filter((r) => sessionProblem(kind, cellOf(r)))
    : table.rows;
  const summary = Object.entries(table.summary ?? {})
    .map(([k, n]) => `${k} ${formatNumber(n)}`)
    .join(", ");
  const lines = [
    `${{ http: "HTTP requests", dns: "DNS queries", tls: "TLS servers" }[kind]}: ${summary || "none"}${table.more ? ` (${formatNumber(table.more)} more not listed by the viewer)` : ""}.`,
    opts.onlyProblems
      ? `${formatNumber(rows.length)} with problems${rows.length > opts.limit ? `, the first ${opts.limit}` : ""}:`
      : `${rows.length > opts.limit ? `The first ${opts.limit} of ${formatNumber(rows.length)}` : `All ${rows.length}`}:`,
    [...table.columns.map((c) => c.label), "Filter"].join(" | "),
    ...rows
      .slice(0, opts.limit)
      .map((r) =>
        [
          ...r.cells.map((c) => oneLine(c === null || c === undefined ? "" : String(c), 80)),
          r.filter ?? "",
        ].join(" | "),
      ),
  ];
  const nameColumn = ids.indexOf(NAME_COLUMNS[kind]);
  const names =
    nameColumn < 0
      ? []
      : rows
          .slice(0, opts.limit)
          .map((r) => r.cells[nameColumn])
          .filter((n): n is string => typeof n === "string" && n !== "")
          .map((name) => ({ name }));
  return { text: cut(lines.join("\n"), opts.maxChars), names };
}

// ---------------------------------------------------------------------- TCP stream

/** The backend's `tcp_graph` result. */
export interface TcpGraph {
  stream: number;
  endpoints: string[];
  points: TcpPoint[];
}

/** The stream's health (aiAnomaly.ts' facts) plus its first retransmissions and zero windows. */
export function tcpStreamReport(graph: TcpGraph, maxChars: number): Report {
  if (!graph.points.length) {
    return { text: `The capture has no TCP stream ${graph.stream}.` };
  }
  const facts = tcpFacts(graph.points, graph.endpoints);
  const frames = (test: (p: TcpPoint) => boolean) =>
    graph.points
      .filter(test)
      .slice(0, 10)
      .map((p) => p[TCP_POINT.frame]);
  const retrans = frames((p) => !!p[TCP_POINT.retrans]);
  const zero = frames((p) => p[TCP_POINT.win] === 0 && !p[TCP_POINT.syn]);
  const lines = [
    `TCP stream ${graph.stream} (filter: tcp.stream == ${graph.stream}):`,
    ...tcpFactLines(facts),
    retrans.length ? `First retransmissions: packets ${retrans.join(", ")}` : "No retransmissions.",
    zero.length ? `First zero-window packets: ${zero.join(", ")}` : "No zero windows.",
  ];
  return { text: cut(lines.join("\n"), maxChars) };
}

// ---------------------------------------------------------------------- packet details

export interface PacketDetail {
  number: number;
  tree: TreeNode[];
  approximate?: boolean;
  window?: [number, number];
}

/** Each packet's dissection as indented lines; byte dumps left out ("[N bytes not sent]"). */
export function packetDetailsReport(
  details: readonly PacketDetail[],
  missing: readonly number[],
  opts: { maxLines: number; maxDepth: number; maxLabel: number; maxChars: number },
): Report {
  const lines: string[] = [];
  const perPacket = Math.max(20, Math.floor(opts.maxLines / Math.max(1, details.length)));
  for (const d of details) {
    const { lines: tree, truncated } = treeLines(d.tree, {
      maxLines: perPacket,
      maxDepth: opts.maxDepth,
      maxLabel: opts.maxLabel,
      includeBytes: false,
    });
    lines.push(`## Packet ${d.number}`);
    if (d.approximate && d.window) {
      lines.push(
        `(Approximate: only packets ${d.window[0]}-${d.number} were dissected, so state from earlier packets can be missing.)`,
      );
    }
    lines.push(...tree, ...(truncated ? ["[dissection cut short]"] : []), "");
  }
  if (missing.length) {
    lines.push(`No such packet: ${missing.join(", ")}.`);
  }
  return { text: cut(lines.join("\n").trimEnd(), opts.maxChars) };
}

// ---------------------------------------------------------------------- comparison

/** The diff of two captures: scans in words, then the differences as JSON (lists shortened to fit). */
export function compareReport(diff: CaptureDiff, maxItems: number, maxChars: number): Report {
  const head = [
    `Before (baseline): ${diff.before.name}, ${formatNumber(diff.before.packets)} packets. After: ${diff.after.name}, ${formatNumber(diff.after.packets)} packets.`,
    "Packet numbers and filters below apply to the capture open in PCAP Lens. Compare rates, not raw counts, when the captures differ in length.",
    ...(scanLines(diff).length
      ? [
          "Scans tshark's numbers show (report them as scans, not as new services):",
          ...scanLines(diff),
        ]
      : []),
    "Differences (JSON):",
  ].join("\n");
  let n = maxItems;
  let body: string;
  for (;;) {
    body = JSON.stringify(shrinkDiff(diff, n));
    if (head.length + body.length + 1 <= maxChars || n <= 1) {
      break;
    }
    n = Math.max(1, Math.floor(n / 2));
  }
  return { text: cut(`${head}\n${body}`, maxChars) };
}

/**
 * The text results of the report tools (aiTools.ts): triage, the capture
 * overview, the session tables, a TCP stream, packet details, a
 * comparison, VoIP calls, an RTP stream, the sequence check, exported
 * objects and clear-text credentials, written for a model that calls them in Copilot's agent mode
 * (or @pcap). Data only, no instructions beyond what to call next: in agent
 * mode the model, not PCAP Lens, writes the answer. No `vscode` import:
 * unit-tested.
 */
import { CaptureDiff, scanLines, shrinkDiff } from "./aiCompare";
import { TreeNode, treeLines } from "./aiExplain";
import {
  TcpPoint,
  TCP_POINT,
  VoipCallData,
  VoipStreamData,
  tcpFactLines,
  tcpFacts,
} from "./aiAnomaly";
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

// ---------------------------------------------------------------------- VoIP calls

/** A DTMF event (voip.py): its digit only goes out with packet data allowed. */
export interface DtmfEvent {
  digit?: string;
  frame?: number;
  time?: number;
  method?: string;
  src?: string;
  duration?: number | null;
}

/** A call as voip_calls lists it (the fields the reports read). */
export interface VoipCallRow extends VoipCallData {
  id: number;
  callId?: string;
  start?: number | null;
  dialed?: string;
  filter?: string;
  quality?: { mos: number; r: number; rating: string; stream?: number } | null;
  dtmf?: DtmfEvent[];
}

/** An RTP (or IAX2 voice) stream as voip_calls lists it. */
export interface VoipStreamRow extends VoipStreamData {
  ssrc?: string;
  iax2?: number;
  start?: number;
  end?: number;
  firstFrame?: number | null;
  problem?: boolean;
  filter?: string;
  dtmf?: DtmfEvent[];
  gaps?: unknown[];
}

/** voip_calls' result. */
export interface VoipCallsData {
  calls: VoipCallRow[];
  streams: VoipStreamRow[];
  registrations?: {
    aor?: string;
    client?: string;
    registrar?: string;
    state?: string;
    final?: string;
    expires?: number | null;
    challenges?: number;
    frames?: [number, number];
    filter?: string;
  }[];
  heuristic?: boolean;
}

// DTMF digits in message labels: IAX2's "DTMF 7", MGCP's observed events
// "NTFY D/2,D/0" (the MCP server's _without_digits).
const IAX2_DTMF = /^DTMF\s+\S+$/;
const MGCP_DIGIT = /(?<![\w/])D\/[^,\s)]+/g;

/** A message label with its DTMF digits left out (they can be PINs or card numbers). */
export function withoutDigits(label: string): string {
  if (IAX2_DTMF.test(label)) {
    return "DTMF (digit hidden)";
  }
  const digits = label.match(MGCP_DIGIT)?.length ?? 0;
  if (!digits) {
    return label;
  }
  const rest = label
    .replace(MGCP_DIGIT, "")
    .split(",")
    .filter((e) => e.trim())
    .join(",")
    .trim();
  const hidden = `${digits} DTMF digit${digits > 1 ? "s" : ""} hidden`;
  return rest.startsWith("NTFY") && rest !== "NTFY" ? `${rest}, ${hidden}` : `NTFY ${hidden}`;
}

const DIGITS_HIDDEN =
  "DTMF digits are hidden: they can be PINs or card numbers, packet contents the user hasn't allowed (pcapViewer.ai.allowPacketData).";

const msText = (v: number | null | undefined) =>
  typeof v === "number" ? `${formatNumber(v)} ms` : "-";
const secText = (v: number | null | undefined) => (typeof v === "number" ? formatSeconds(v) : "-");

function dtmfText(events: readonly DtmfEvent[], packetData: boolean): string {
  return events
    .slice(0, 30)
    .map(
      (e) =>
        `${packetData && e.digit !== undefined ? `"${e.digit}"` : "a digit"} (${e.method ?? "?"}, packet ${e.frame ?? "?"})`,
    )
    .join(", ");
}

function streamLine(index: number, s: VoipStreamRow): string {
  const lost = `${formatNumber(s.lost)} lost (${formatNumber(s.lostPercent ?? 0)}%)`;
  const mos = s.quality ? `MOS ${s.quality.mos.toFixed(2)} ${s.quality.rating}` : "MOS -";
  const r = s.rtcp;
  const rtcp = r
    ? `; RTCP from the receiver: ${formatNumber(r.fractionLost)}% lost, jitter ${msText(r.maxJitter)}, round trip ${msText(r.rtt)}`
    : "";
  const kind = s.iax2 !== undefined ? `IAX2 call ${s.iax2}` : `SSRC ${s.ssrc ?? "?"}`;
  return `- stream ${index}: ${s.src}:${s.srcPort} → ${s.dst}:${s.dstPort}, ${kind}, ${oneLine(s.payload, 40)}, ${formatNumber(s.packets)} packets, ${lost}, max jitter ${msText(s.maxJitter)}, max delta ${msText(s.maxDelta)}, ${mos}${rtcp}${s.problem ? " (tshark flags a problem)" : ""}${s.filter ? ` — ${s.filter}` : ""}`;
}

/** The parties' addresses of record name people and hosts: stand-ins replace them. */
function partyNames(calls: readonly VoipCallRow[]): ShownName[] {
  return calls.flatMap((c) => [c.from, c.to].filter(Boolean).map((name) => ({ name })));
}

/**
 * The calls (summary, one line each), the streams no call set up and the
 * SIP registrations; or one call's message flow, streams, problems and DTMF.
 * DTMF digits (and the digits in IAX2 and MGCP message names) only with
 * packet data.
 */
export function voipCallsReport(
  data: VoipCallsData,
  opts: { call?: number; limit: number; packetData: boolean; maxChars: number },
): Report {
  const { calls, streams } = data;
  if (opts.call !== undefined) {
    const call = calls.find((c) => c.id === opts.call);
    if (!call) {
      return {
        text: calls.length
          ? `No call ${opts.call}: the capture has calls 0 to ${calls.length - 1}.`
          : `No call ${opts.call}: the capture has no calls.`,
      };
    }
    const label = opts.packetData ? (t: string) => t : withoutDigits;
    const protocol = call.protocol ?? "SIP";
    const linked = call.streams.filter((i) => streams[i]);
    const lines = [
      `Call ${call.id} (${protocol}): ${call.from} → ${call.to}${call.dialed ? `, dialled ${opts.packetData ? call.dialed : "(digits hidden)"}` : ""}.`,
      `State: ${call.state}; final: ${call.final || "-"}; ended by: ${call.endedBy ?? "-"}.`,
      `Starts ${secText(call.start)} into the capture; ringing after ${secText(call.ringing)}, answered after ${secText(call.setup)}, talk time ${secText(call.duration)}.`,
      ...(call.reasons?.length
        ? [
            `${protocol === "SIP" ? "Reason headers" : "Causes"}: ${call.reasons.map((r) => oneLine(r, 120)).join("; ")}`,
          ]
        : []),
      ...(call.quality
        ? [`Quality (worst stream): MOS ${call.quality.mos.toFixed(2)} ${call.quality.rating}`]
        : []),
      ...(call.filter ? [`Filter: ${call.filter}`] : []),
      "",
      `${protocol} messages (packet | time s | from | to | message):`,
      ...call.messages
        .slice(0, 60)
        .map(
          ([frame, time, src, dst, text]) =>
            `${frame} | ${formatNumber(time)} | ${src} | ${dst} | ${oneLine(label(text), 120)}`,
        ),
      ...(call.messages.length > 60 ? [`[${call.messages.length - 60} more messages]`] : []),
      "",
      "Media streams (pcap_rtp_stream with the stream number analyses one):",
      ...(linked.length
        ? linked.map(
            (i, n) => `${streamLine(i, streams[i])}, sent by the ${call.sides?.[n] ?? "?"}`,
          )
        : ["- none linked to this call"]),
      "",
      "Problems the viewer detected:",
      ...(call.problems?.length
        ? call.problems.map(
            (p) => `- ${p.kind}: ${oneLine(p.text, 200)}${p.frame ? ` (packet ${p.frame})` : ""}`,
          )
        : ["- none"]),
    ];
    if (call.dtmf?.length) {
      lines.push("", `DTMF: ${dtmfText(call.dtmf, opts.packetData)}`);
    }
    if (!opts.packetData && (call.dtmf?.length || call.dialed)) {
      lines.push(DIGITS_HIDDEN);
    }
    return { text: cut(lines.join("\n"), opts.maxChars), names: partyNames([call]) };
  }
  const states = new Map<string, number>();
  for (const c of calls) {
    states.set(c.state || "?", (states.get(c.state || "?") ?? 0) + 1);
  }
  const linked = new Set(calls.flatMap((c) => c.streams));
  const others = streams.map((_, i) => i).filter((i) => !linked.has(i));
  const shown = calls.slice(0, opts.limit);
  const lines = [
    `VoIP calls: ${calls.length}${calls.length ? ` (${[...states].map(([s, n]) => `${s} ${n}`).join(", ")})` : ""}, ${calls.filter((c) => c.problems?.length).length} with problems; ${streams.length} media streams${data.heuristic ? " (RTP found heuristically too)" : ""}.`,
  ];
  if (shown.length) {
    lines.push(
      "call | protocol | from | to | state | final | setup | talk time | MOS | problems | filter",
      ...shown.map((c) =>
        [
          c.id,
          c.protocol ?? "SIP",
          c.from,
          c.to,
          c.state,
          c.final || "-",
          secText(c.setup),
          secText(c.duration),
          c.quality ? `${c.quality.mos.toFixed(2)} ${c.quality.rating}` : "-",
          c.problems?.length ? c.problems.map((p) => p.kind).join(", ") : "-",
          c.filter ?? "",
        ].join(" | "),
      ),
      ...(calls.length > shown.length ? [`[${calls.length - shown.length} more calls]`] : []),
    );
  }
  if (others.length) {
    lines.push(
      "",
      "Media streams without a call:",
      ...others.slice(0, opts.limit).map((i) => streamLine(i, streams[i])),
      ...(others.length > opts.limit ? [`[${others.length - opts.limit} more streams]`] : []),
    );
  }
  const regs = data.registrations ?? [];
  if (regs.length) {
    lines.push(
      "",
      "SIP registrations:",
      ...regs
        .slice(0, opts.limit)
        .map(
          (r) =>
            `- ${r.aor ?? "?"} from ${r.client ?? "?"} to ${r.registrar ?? "?"}: ${r.state ?? "?"}${r.final ? ` (${r.final})` : ""}${r.challenges ? `, ${r.challenges} challenges` : ""}${r.expires !== null && r.expires !== undefined ? `, expires ${r.expires} s` : ""}${r.frames ? `, packets ${r.frames[0]}-${r.frames[1]}` : ""}${r.filter ? ` — ${r.filter}` : ""}`,
        ),
      ...(regs.length > opts.limit ? [`[${regs.length - opts.limit} more registrations]`] : []),
    );
  }
  if (!calls.length && !streams.length && !regs.length) {
    lines.push(
      data.heuristic
        ? "No SIP, H.323, MGCP or IAX2 calls and no RTP."
        : "No SIP, H.323, MGCP or IAX2 calls and no RTP (heuristic_rtp finds RTP no signalling set up).",
    );
  }
  lines.push(
    "",
    "Next: pcap_voip_calls with `call` for one call's messages, streams and problems; pcap_rtp_stream with a stream number for its loss and jitter over time.",
  );
  const names = [
    ...partyNames(shown),
    ...regs.slice(0, opts.limit).flatMap((r) => (r.aor ? [{ name: r.aor }] : [])),
  ];
  return { text: cut(lines.join("\n"), opts.maxChars), names };
}

// ---------------------------------------------------------------------- RTP stream

/** rtp_stream's result (voip.py POINT_FIELDS points and a summary). */
export interface RtpAnalysis {
  fields: string[];
  points: (number | null)[][];
  summary: Record<string, unknown>;
}

const RTP_PROBLEMS: Record<number, string> = { 1: "lost", 2: "out of order", 3: "payload changed" };

export interface RtpProblem {
  packet: number;
  seq: number;
  problem: string;
  lostBefore?: number;
  arrivedLater?: number;
}

export interface RtpBucket {
  start: number;
  end: number;
  packets: number;
  lost: number;
  maxJitter: number;
  maxDelta: number;
}

/**
 * The points' problem packets and a timeline of `buckets` intervals (the MCP
 * server's _rtp_points): a gap's loss is the numbers that never came (16-bit
 * numbers unwrapped), so reordering isn't loss and the timeline adds up to
 * the summary's.
 */
export function rtpPoints(
  fields: readonly string[],
  points: readonly (readonly (number | null)[])[],
  buckets: number,
): { problems: RtpProblem[]; timeline: RtpBucket[] } {
  const at = new Map(fields.map((f, i) => [f, i]));
  const col = (p: readonly (number | null)[], name: string) => {
    const i = at.get(name);
    return i === undefined ? 0 : Number(p[i] ?? 0);
  };
  if (!points.length || !["frame", "time", "seq", "status"].every((f) => at.has(f))) {
    return { problems: [], timeline: [] };
  }
  const extended: number[] = [];
  for (const p of points) {
    const seq = col(p, "seq") & 0xffff;
    if (extended.length) {
      const last = extended[extended.length - 1];
      const step = (seq - last) & 0xffff;
      extended.push(last + (step >= 0x8000 ? step - 0x10000 : step));
    } else {
      extended.push(seq);
    }
  }
  const arrived = new Set(extended);
  const duration = Math.max(col(points[points.length - 1], "time"), 0);
  const width = duration > 0 ? duration / buckets : 0;
  const count = width ? buckets : 1;
  const round = (v: number) => Math.round(v * 1000) / 1000;
  const timeline: RtpBucket[] = Array.from({ length: count }, (_, i) => ({
    start: round(i * width),
    end: width ? round((i + 1) * width) : round(duration),
    packets: 0,
    lost: 0,
    maxJitter: 0,
    maxDelta: 0,
  }));
  const problems: RtpProblem[] = [];
  points.forEach((p, n) => {
    const ext = extended[n];
    const status = col(p, "status");
    const skipped = at.has("gap") ? col(p, "gap") : 0;
    let gap = 0;
    for (let s = ext - skipped; s < ext; s++) {
      gap += arrived.has(s) ? 0 : 1;
    }
    if (RTP_PROBLEMS[status] && !(skipped && !gap)) {
      const problem: RtpProblem = {
        packet: col(p, "frame"),
        seq: col(p, "seq"),
        problem: RTP_PROBLEMS[status],
      };
      if (gap) {
        problem.lostBefore = gap;
      }
      if (skipped > gap) {
        problem.arrivedLater = skipped - gap;
      }
      problems.push(problem);
    }
    const time = Math.max(col(p, "time"), 0);
    const cell = timeline[width ? Math.min(Math.floor(time / width), count - 1) : 0];
    cell.packets += 1;
    cell.lost += gap;
    cell.maxJitter = Math.max(cell.maxJitter, col(p, "jitter"));
    cell.maxDelta = Math.max(cell.maxDelta, col(p, "delta"));
  });
  return { problems, timeline };
}

/** One stream's summary, its problem packets and its timeline. */
export function rtpStreamReport(
  index: number,
  stream: VoipStreamRow,
  call: number | undefined,
  analysis: RtpAnalysis,
  opts: { limit: number; buckets: number; maxChars: number },
): Report {
  const s = analysis.summary;
  const num = (k: string) => (typeof s[k] === "number" ? (s[k] as number) : undefined);
  const { problems, timeline } = rtpPoints(analysis.fields, analysis.points, opts.buckets);
  const lines = [
    `Stream ${index}${call !== undefined ? ` (call ${call})` : ""}:`,
    streamLine(index, stream).replace(/^- /, ""),
    `Analysis: ${num("packets") ?? "?"} packets of ${num("expected") ?? "?"} expected, ${num("lost") ?? "?"} lost (${formatNumber(num("lostPercent") ?? 0)}%), ${num("sequenceErrors") ?? 0} sequence errors; max delta ${msText(num("maxDelta"))} (packet ${num("maxDeltaFrame") ?? "?"}), max jitter ${msText(num("maxJitter"))}, mean jitter ${msText(num("meanJitter"))}, max skew ${msText(num("maxSkew"))}, clock ${num("clockRate") ?? "?"} Hz, ${secText(num("duration"))}.`,
    "",
    problems.length
      ? `Problem packets (${problems.length}${problems.length > opts.limit ? `, the first ${opts.limit}` : ""}):`
      : "No lost, late or changed packets.",
    ...problems
      .slice(0, opts.limit)
      .map(
        (p) =>
          `- packet ${p.packet} (seq ${p.seq}): ${p.problem}${p.lostBefore ? `, ${p.lostBefore} lost before it` : ""}${p.arrivedLater ? `, ${p.arrivedLater} skipped that came later` : ""}`,
      ),
    "",
    "Timeline (from s | to s | packets | lost | max jitter ms | max delta ms):",
    ...timeline.map(
      (b) =>
        `${formatNumber(b.start)} | ${formatNumber(b.end)} | ${b.packets} | ${b.lost} | ${formatNumber(b.maxJitter)} | ${formatNumber(b.maxDelta)}`,
    ),
  ];
  return { text: cut(lines.join("\n"), opts.maxChars) };
}

// ---------------------------------------------------------------------- sequence check

/** stats {kind: "sequences"}' table (sequence.table). */
export interface SequenceTable {
  rows: { cells: unknown[]; depth?: number; frame?: number; filter?: string; problem?: string }[];
  summary?: Record<string, number>;
}

export interface SequenceStream {
  values: unknown[];
  counts: unknown[];
  firstPacket?: number;
  filter?: string;
  problems: { kind: string; text: string; packet?: number }[];
  moreProblems: number;
}

const MORE_PROBLEMS = /^… ([\d,]+) more problems$/;

/** The table back as streams (the MCP server's _sequence_streams). */
export function sequenceStreams(table: SequenceTable, keyCount: number): SequenceStream[] {
  const out: SequenceStream[] = [];
  for (const row of table.rows) {
    const cells = row.cells ?? [];
    if (!row.depth) {
      const counts = cells.slice(keyCount);
      if (counts.length < 8) {
        continue;
      }
      out.push({
        values: cells.slice(0, keyCount),
        counts,
        firstPacket: row.frame,
        filter: row.filter,
        problems: [],
        moreProblems: 0,
      });
      continue;
    }
    const last = out[out.length - 1];
    const more = MORE_PROBLEMS.exec(String(cells[0] ?? ""));
    if (last && row.problem) {
      last.problems.push({ kind: row.problem, text: String(cells[0] ?? ""), packet: row.frame });
    } else if (last && more) {
      last.moreProblems += Number(more[1].replace(/,/g, ""));
    }
  }
  return out;
}

/** The check's summary and each stream (problems first), key values only when they may be sent. */
export function sequenceReport(
  table: SequenceTable,
  params: { seq: string; keys: readonly string[]; wrapBits: number; filter: string },
  opts: { showKeys: boolean; limit: number; problems: number; maxChars: number },
): Report {
  const keys = params.keys;
  const streams = sequenceStreams(table, keys.length || 1);
  const summary = Object.entries(table.summary ?? {})
    .filter(([k]) => k !== "more")
    .map(([k, n]) => `${k} ${formatNumber(n)}`)
    .join(", ");
  const lines = [
    `Sequence check of ${params.seq}${keys.length ? ` per ${keys.join(", ")}` : ""}${params.wrapBits ? `, a ${params.wrapBits}-bit counter` : ""}${params.filter ? ` (limited to \`${params.filter}\`)` : ""}: ${summary || "nothing counted"}.`,
  ];
  if (!opts.showKeys && keys.length) {
    lines.push(
      "The streams' key values are text fields, packet contents the user hasn't allowed (pcapViewer.ai.allowPacketData): streams are numbered instead, and their problems' packets are given.",
    );
  }
  lines.push(
    `stream | ${keys.length && opts.showKeys ? `${keys.join(" | ")} | ` : ""}messages | first | last | missing | duplicates | late | restarts | result | first packet${opts.showKeys ? " | filter" : ""}`,
  );
  streams.slice(0, opts.limit).forEach((s, i) => {
    lines.push(
      [
        i + 1,
        ...(keys.length && opts.showKeys ? s.values.map((v) => oneLine(String(v ?? ""), 60)) : []),
        ...s.counts.slice(0, 8).map((v) => oneLine(String(v ?? ""), 60)),
        s.firstPacket ?? "-",
        ...(opts.showKeys ? [s.filter ?? ""] : []),
      ].join(" | "),
    );
    for (const p of s.problems.slice(0, opts.problems)) {
      lines.push(
        `  - ${p.kind}: ${oneLine(p.text, 160)}${p.packet ? ` (packet ${p.packet})` : ""}`,
      );
    }
    const more = s.moreProblems + Math.max(0, s.problems.length - opts.problems);
    if (more) {
      lines.push(`  - [${formatNumber(more)} more problems]`);
    }
  });
  const moreStreams = (table.summary?.more ?? 0) + Math.max(0, streams.length - opts.limit);
  if (moreStreams) {
    lines.push(`[${formatNumber(moreStreams)} more streams]`);
  }
  return { text: cut(lines.join("\n"), opts.maxChars) };
}

// ---------------------------------------------------------------------- export objects

export interface ExportedObject {
  protocol: string;
  name: string;
  size: number;
  contentType?: string;
  host?: string;
  frame?: number | null;
}

/** The files the capture carries by protocol; names only with packet data (URLs, mail subjects). */
export function objectsReport(
  objects: readonly ExportedObject[],
  opts: { protocol: string; limit: number; packetData: boolean; maxChars: number },
): Report {
  const by = new Map<string, { files: number; bytes: number }>();
  for (const o of objects) {
    const c = by.get(o.protocol) ?? { files: 0, bytes: 0 };
    c.files += 1;
    c.bytes += o.size || 0;
    by.set(o.protocol, c);
  }
  const chosen = objects.filter((o) => !opts.protocol || o.protocol === opts.protocol);
  const lines = [
    `Files the capture carries (Export Objects): ${objects.length ? [...by].map(([p, c]) => `${p} ${c.files} (${formatBytes(c.bytes)})`).join(", ") : "none"}.`,
  ];
  if (!opts.packetData && chosen.length) {
    lines.push(
      "File names are left out: they come from URLs and mail subjects, packet contents the user hasn't allowed (pcapViewer.ai.allowPacketData).",
    );
  }
  const shown = chosen.slice(0, opts.limit);
  if (shown.length) {
    lines.push(
      `${opts.protocol ? `${opts.protocol} files` : "Files"}${chosen.length > shown.length ? ` (the first ${shown.length} of ${chosen.length})` : ""}:`,
      ...shown.map(
        (o) =>
          `- ${o.protocol}${opts.packetData ? ` ${oneLine(o.name, 120)}` : ""}, ${formatBytes(o.size || 0)}${o.contentType ? `, ${oneLine(o.contentType, 60)}` : ""}${o.host ? `, from ${oneLine(o.host, 80)}` : ""}${o.frame ? `, packet ${o.frame} (frame.number == ${o.frame})` : ""}`,
      ),
    );
  }
  const names = shown.flatMap((o) => (o.host ? [{ name: o.host }] : []));
  return { text: cut(lines.join("\n"), opts.maxChars), names };
}

// ---------------------------------------------------------------------- credentials

/** stats {kind: "credentials"}' table. */
export interface CredentialsTable {
  rows: { cells: unknown[]; frame?: number; usernameFrame?: number; filter?: string }[];
  unfiltered?: boolean;
}

/** Clear-text logins by protocol with their packets; user names only with packet data. */
export function credentialsReport(
  table: CredentialsTable,
  opts: { filter: string; limit: number; packetData: boolean; maxChars: number },
): Report {
  const rows = table.rows.filter((r) => (r.cells ?? []).length >= 3);
  const by = new Map<string, number>();
  for (const r of rows) {
    by.set(String(r.cells[1]), (by.get(String(r.cells[1])) ?? 0) + 1);
  }
  const lines = [
    `Clear-text credentials tshark found${opts.filter ? ` (limited to \`${opts.filter}\`)` : ""}: ${rows.length ? [...by].map(([p, n]) => `${p} ${n}`).join(", ") : "none"}.`,
    ...(table.unfiltered ? ["(tshark's credentials report can't be limited by a filter.)"] : []),
    ...(!opts.packetData && rows.length
      ? [
          "User names are left out: packet contents the user hasn't allowed (pcapViewer.ai.allowPacketData). Passwords are never shown.",
        ]
      : []),
    ...rows
      .slice(0, opts.limit)
      .map(
        (r) =>
          `- ${String(r.cells[1])}${opts.packetData ? ` user ${oneLine(String(r.cells[2] ?? ""), 80)}` : ""}, packet ${r.frame ?? r.cells[0]}${r.usernameFrame ? ` (user name in packet ${r.usernameFrame})` : ""}${r.filter ? ` — ${r.filter}` : ""}`,
      ),
    ...(rows.length > opts.limit ? [`[${rows.length - opts.limit} more logins]`] : []),
  ];
  return { text: cut(lines.join("\n"), opts.maxChars) };
}

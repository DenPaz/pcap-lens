/**
 * What the viewer's AI buttons ask the PCAP Lens agent when
 * `pcapViewer.ai.askIn` is "agent": a plain chat request that names the
 * capture and the `#pcap…` tools to use, instead of an `@pcap` command (VS
 * Code's Copilot harness runs no chat participants; the Local harness that
 * runs `@pcap` goes in 2027-02). The tools compute everything and enforce
 * the consent settings, so a query names packets, streams and files only:
 * never packet text (an expert row's message is left out). No `vscode`
 * import: unit-tested.
 */
import type { ExpertRow } from "./aiAnomaly";
import { explainArgs } from "./aiExplain";

/** Where the viewer's AI buttons ask: `@pcap` (as before) or the PCAP Lens agent. */
export type AskIn = "pcap" | "agent";

/** The setting's value, anything unknown being "pcap". */
export function askInSetting(value: unknown): AskIn {
  return value === "agent" ? "agent" : "pcap";
}

/** The agent's name (agents/pcap-lens.agent.md), which `workbench.action.chat.open`'s `mode` takes. */
export const AGENT_MODE = "PCAP Lens";

/** At most this many expert rows, and packets per row, are named. */
export const AGENT_QUERY_LIMITS = { expertRows: 10, framesPerRow: 5 } as const;

export type AgentAsk =
  | { kind: "summary"; capture: string; question?: string }
  | { kind: "triage"; capture: string; question?: string }
  | { kind: "compare"; capture: string; other: string; baseline: "other" | "open" }
  | { kind: "stream"; capture: string; stream: number; question?: string }
  | { kind: "call"; capture: string; call: number; heuristic?: boolean; question?: string }
  | { kind: "expert"; capture: string; rows: readonly ExpertRow[]; question?: string }
  | { kind: "packets"; capture: string; frames: readonly number[]; question?: string };

const oneLine = (s: string | undefined): string => (s ?? "").replace(/\s+/g, " ").trim();
const quoted = (file: string): string => `\`${file.replace(/`/g, "'")}\``;

function expertLine(row: ExpertRow): string {
  const frames = row.frames.slice(0, AGENT_QUERY_LIMITS.framesPerRow);
  const more = row.frames.length > frames.length ? "…" : "";
  const where = [row.group, row.protocol].filter(Boolean).join(", ");
  return `- ${row.severity}${where ? ` (${where})` : ""}, ${row.count} packets${frames.length ? `: ${frames.join(", ")}${more}` : ""}`;
}

/** The chat request for `ask`. */
export function agentQuery(ask: AgentAsk): string {
  const cap = quoted(ask.capture);
  switch (ask.kind) {
    case "summary":
      return `${oneLine(ask.question) || `Summarize the capture ${cap}: what it holds, who talks to whom, and anything unusual.`} Use #pcapOverview and #pcapTriage on ${cap}.`;
    case "triage":
      return `${oneLine(ask.question) || `Triage the capture ${cap}: what is wrong, most serious first, with packet numbers and display filters.`} Start with #pcapTriage on ${cap}, then drill down (#pcapSessions, #pcapTcpStream).`;
    case "compare": {
      const other = quoted(ask.other);
      const [before, after] = ask.baseline === "other" ? [other, cap] : [cap, other];
      return `Compare the capture ${cap} with ${other}: ${before} is the baseline and ${after} the later one. What changed, and why does it matter? Use #pcapCompare on ${cap} with ${other} as the other capture (baseline: "${ask.baseline}").`;
    }
    case "stream":
      return `${oneLine(ask.question) || "Is anything wrong with this TCP connection, and why?"} TCP stream ${ask.stream} of the capture ${cap}: use #pcapTcpStream.`;
    case "call":
      return `${oneLine(ask.question) || "Explain this call: did it work, and how was its audio?"} Call ${ask.call} of the capture ${cap}: use #pcapVoipCalls with call ${ask.call}${ask.heuristic ? " and heuristic_rtp: true" : ""}, then #pcapRtpStream for a stream with problems.`;
    case "expert": {
      const rows = ask.rows.slice(0, AGENT_QUERY_LIMITS.expertRows);
      if (!rows.length) {
        return `${oneLine(ask.question) || `What do the errors and warnings in the expert information of ${cap} point to?`} Use #pcapStats (kind expert) and #pcapTriage on ${cap}, then #pcapPacketDetails for a few packets.`;
      }
      const lines = rows.map(expertLine);
      if (ask.rows.length > rows.length) {
        lines.push(`- and ${ask.rows.length - rows.length} more entries`);
      }
      return [
        `${oneLine(ask.question) || "What do these expert information entries mean, and what causes them?"} Expert information of the capture ${cap}:`,
        ...lines,
        "Use #pcapPacketDetails on a few of these packets and #pcapStats (kind expert).",
      ].join("\n");
    }
    case "packets":
      return `${oneLine(ask.question) || "Explain these packets: what they are, and anything unusual."} Packets ${explainArgs(ask.frames)} of the capture ${cap}: use #pcapPacketDetails.`;
  }
}

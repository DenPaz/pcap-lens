/**
 * AI capture filter help: a description ("only traffic to 10.0.0.5 on port
 * 443, no SSH") becomes capture (BPF) filters, which dumpcap compiles
 * (`validate_capture_filter`) before they are offered; when none compiles,
 * the model gets one retry with dumpcap's errors. Like display filter help it
 * sends only the description, the current capture filter and the chosen
 * interfaces' names, never capture data. No `vscode` import: unit-tested.
 */
import { FilterSuggestion, MAX_SUGGESTIONS, Rejected, SuggestDeps, suggestWith } from "./aiFilter";

export interface CaptureFilterInput {
  request: string;
  currentFilter: string;
  /** The interfaces the filter is for (names only; loopback ones say so). */
  interfaces: readonly { name: string; loopback?: boolean }[];
}

const oneLine = (s: string, max: number) => s.replace(/\s+/g, " ").trim().slice(0, max);

/** The prompt (one user turn: VS Code's LM API has no system role in 1.90). */
export function buildCaptureFilterPrompt(input: CaptureFilterInput): string {
  const interfaces = input.interfaces
    .slice(0, 8)
    .map((i) => `${oneLine(i.name, 80)}${i.loopback ? " (loopback)" : ""}`);
  return [
    "You write capture filters in the pcap-filter (BPF) language that tcpdump, dumpcap and Wireshark's",
    "capture options take. They are NOT Wireshark display filters: no field names such as ip.addr, tcp.port",
    "or http; use primitives such as host, src host, dst net 10.0.0.0/8, port 443, portrange 1-1024, tcp,",
    "udp, icmp, icmp6, arp, ip6, ether host, vlan, joined with and, or, not and parentheses.",
    `Suggest up to ${MAX_SUGGESTIONS} capture filters for the request below, best first.`,
    "Answer with JSON only (no prose, no code fences), exactly in this shape:",
    '[{"filter": "<capture filter>", "explanation": "<one short sentence>"}]',
    "Rules:",
    "- Each filter must be one complete capture filter on a single line.",
    "- If the request refines the current capture filter, combine them with and.",
    "- Keep each explanation under 20 words.",
    "",
    `Request: ${oneLine(input.request, 500)}`,
    `Current capture filter: ${oneLine(input.currentFilter, 500) || "(none)"}`,
    `Capturing on: ${interfaces.join(", ") || "(unknown)"}`,
  ].join("\n");
}

/** Follow-up turn after dumpcap compiled none of the first answer's filters. */
export function buildCaptureRetryPrompt(rejected: readonly Rejected[]): string {
  if (!rejected.length) {
    return 'That was not the JSON array requested. Reply with JSON only: [{"filter": "...", "explanation": "..."}]';
  }
  return [
    "dumpcap could not compile these capture filters:",
    ...rejected.map((r) => `- ${oneLine(r.filter, 500)}: ${oneLine(r.error, 300)}`),
    "Reply with corrected capture (BPF) filters, JSON only, in the same shape.",
  ].join("\n");
}

/** Ask, keep what dumpcap compiles, retry once with its errors. */
export function suggestCaptureFilters(
  deps: SuggestDeps,
  input: CaptureFilterInput,
): Promise<{ suggestions: FilterSuggestion[]; rejected: Rejected[] }> {
  return suggestWith(deps, buildCaptureFilterPrompt(input), buildCaptureRetryPrompt);
}

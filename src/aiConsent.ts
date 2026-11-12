/**
 * The consent for the AI features that send statistics computed from the
 * capture (never packet contents): the capture summary, triage and comparison, anomaly
 * explanations and @pcap's tools. One setting, `pcapViewer.ai.allowCaptureStatistics`
 * (application-scoped), asked once with this text; allowing packet data
 * (`pcapViewer.ai.allowPacketData`) implies it. No `vscode` import: the text
 * is unit-tested against the limits it states.
 */
import { ANOMALY_LIMITS } from "./aiAnomaly";
import { COMPARE_LIMITS } from "./aiCompare";
import { SUMMARY_LIMITS } from "./aiSummary";
import { TOOL_LIMITS } from "./aiTools";

/** Exactly what the statistics-based AI features send: shown in the consent prompt (and README). */
export const STATISTICS_CONSENT =
  "Summarizing, triaging or comparing captures, explaining expert information, a TCP stream or a VoIP call, and answering @pcap questions with tools " +
  "send statistics computed from the capture by tshark to the language model (GitHub Copilot, unless you chose another " +
  "with PCAP: Choose Language Model…), never packet contents " +
  "or bytes: the capture's properties (packets, duration, size, link type); its protocol hierarchy; its top " +
  `${SUMMARY_LIMITS.maxRows} conversations and endpoints by bytes (IP addresses, ports, host names when name ` +
  "resolution is on, packet and byte counts); expert information counts and messages; packet and byte counts over " +
  `time in ${SUMMARY_LIMITS.ioBuckets} buckets; for a triage, the packet counts of fixed checks (retransmissions, ` +
  "resets, DNS and HTTP errors…) with each one's display filter and first and last packet number; " +
  "for a comparison, the same for both captures as differences: totals and rates, the checks whose counts differ, " +
  `and up to ${COMPARE_LIMITS.maxItems} protocols, flows (client address → server address and port), endpoints ` +
  "and expert messages each that are new, gone or changed; " +
  "for an explanation, the selected expert entries (with up to " +
  `${ANOMALY_LIMITS.maxFramesPerRow} packet numbers each) and their conversation, or up to ` +
  `${ANOMALY_LIMITS.maxPoints} packets of a TCP stream as sequence numbers, lengths, windows, round-trip times and ` +
  `retransmission flags, or a VoIP call's SIP message flow (up to ${ANOMALY_LIMITS.maxCallMessages} message names ` +
  "with times and addresses, the parties' SIP URIs, no message bodies or DTMF digits) with its RTP streams' " +
  "statistics; and the results of PCAP Lens's tools, which @pcap, Copilot's agent mode and the PCAP Lens agent " +
  `call (packet counts for display filters, the same statistics with up to ${TOOL_LIMITS.maxStatsRows} rows, ` +
  "the triage checks, a TCP stream's totals, a comparison with another capture file you name, and the capture " +
  `overview: its top ${TOOL_LIMITS.maxOverviewRows} addresses, protocols, TCP services, HTTP methods, status ` +
  "codes and hosts, DNS results, query types and names, and TLS versions and server names). Listing packets " +
  "(their summary lines), the session tables (HTTP requests with their paths, DNS queries with their answers, " +
  "TLS servers) and packet details also need pcapViewer.ai.allowPacketData. Addresses and host names can be private: with " +
  "pcapViewer.ai.pseudonymizeAddresses on (the default) they are replaced by stand-ins such as IP_PRIVATE_1 " +
  "before anything is sent. Your choice is saved in the " +
  "pcapViewer.ai.allowCaptureStatistics setting (user settings only).";

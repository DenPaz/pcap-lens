/**
 * Port scans and host sweeps that tshark's numbers show (backend `scans`,
 * `compare.scans`): the sentences the prompts carry, the "Found by tshark"
 * note the chat shows above an answer, and a display filter per scan. They
 * are found by the backend, not the model: models given the bare flows
 * called a scan "new services being accessed" and its resets "server
 * stability" problems. No `vscode` import: unit-tested.
 */

/** One scan of the backend's `scans` (or a capture profile's). */
export interface Scan {
  kind?: string;
  protocol?: string;
  client?: string;
  server?: string;
  port?: number;
  /** The ports (port scan) or servers (host sweep) listed: at most 50. */
  ports?: number[];
  servers?: string[];
  /** How many ports or servers there were in all. */
  targets?: number;
  packets?: number;
  /** TCP: of the targets, how many answered with a reset (closed or refused). */
  reset?: number;
}

function listed(items: readonly (string | number)[], total: number, max: number): string {
  const shown = items.slice(0, max).join(", ");
  return total > Math.min(items.length, max) ? `${shown}, …` : shown;
}

/** One scan as a sentence; `where` says which capture ("only in the after capture"). */
export function scanSentence(s: Scan, where?: string): string {
  const proto = (s.protocol ?? "").toUpperCase();
  const sweep = s.kind === "host sweep";
  const total = s.targets ?? (sweep ? s.servers?.length : s.ports?.length) ?? 0;
  const what = sweep
    ? `${s.client} reached ${proto} port ${s.port} on ${total} servers` +
      ` (${listed(s.servers ?? [], total, 8)})`
    : `${s.client} reached ${total} ${proto} ports of ${s.server}` +
      ` (${listed(s.ports ?? [], total, 20)})`;
  const reset =
    s.reset === undefined
      ? ""
      : s.reset > 0
        ? `; ${s.reset} of the ${total} ${sweep ? "servers" : "ports"} answered with a TCP reset` +
          ` (closed or refused: those resets are the scan's answers)`
        : "; none answered with a TCP reset";
  return (
    `${sweep ? "Host sweep" : "Port scan"}${where ? `, ${where}` : ""}: ${what},` +
    ` ${s.packets ?? "?"} packets, a few per connection${reset}.`
  );
}

/** A display filter for a scan's packets (the client's packets to its targets). */
export function scanFilter(scan: Scan): string | undefined {
  const { client, protocol } = scan;
  if (!client || (protocol !== "tcp" && protocol !== "udp")) {
    return undefined;
  }
  const ip = client.includes(":") ? "ipv6" : "ip";
  if (scan.kind === "host sweep") {
    return scan.port === undefined
      ? undefined
      : `${ip}.src == ${client} && ${protocol}.dstport == ${scan.port}`;
  }
  if (!scan.server) {
    return undefined;
  }
  const ports = scan.ports ?? [];
  // (tshark 4.2 refuses space-separated sets; a partial or long list adds nothing.)
  const complete = (scan.targets ?? ports.length) === ports.length;
  const portPart =
    complete && ports.length && ports.length <= 50
      ? ` && ${protocol}.dstport in {${ports.join(",")}}`
      : "";
  return `${ip}.src == ${client} && ${ip}.dst == ${scan.server}${portPart}`;
}

export interface ScanEntry {
  scan: Scan;
  /** Which capture, in a comparison ("only in the after capture"). */
  where?: string;
}

/** The prompt section: the scans as sentences under a heading (none: nothing). */
export function scanSection(entries: readonly ScanEntry[]): string[] {
  return entries.length
    ? [
        "## Scans tshark's numbers show",
        "Report each as a scan, not as new services. Resets on a scan's ports are its targets refusing the",
        "probes, not a server or network problem.",
        ...entries.map((e) => `- ${scanSentence(e.scan, e.where)}`),
        "",
      ]
    : [];
}

/**
 * What the chat shows above the model's answer: the scans tshark's numbers
 * show, whatever the model makes of them, and their filters.
 */
export function scanNote(entries: readonly ScanEntry[]): { markdown: string; filters: string[] } {
  if (!entries.length) {
    return { markdown: "", filters: [] };
  }
  const lines = entries.map((e) =>
    `- ${scanSentence(e.scan, e.where)}`.replace(/([\\`*_[\]<>])/g, "\\$1"),
  );
  const filters = [
    ...new Set(
      entries.flatMap((e) => {
        const f = scanFilter(e.scan);
        return f ? [f] : [];
      }),
    ),
  ];
  return { markdown: `**Found by tshark**\n\n${lines.join("\n")}\n\n`, filters };
}

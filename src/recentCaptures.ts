/**
 * The Recent Captures list (the PCAP Lens view in the activity bar): what is
 * remembered of each capture opened, and how it is described. Pure, so it is
 * unit-tested without VS Code.
 */
import { formatBytes, formatSeconds } from "./aiSummary";

/** At most this many captures are remembered, the most recent first. */
export const MAX_RECENT = 20;

export interface RecentCapture {
  path: string;
  /** Packets (the count when last opened; while indexing, the count so far). */
  frames: number;
  size: number;
  /** First and last packet times (epoch seconds), when known. */
  startTime: number | null;
  endTime: number | null;
  fileType: string | null;
  linkType: string | null;
  /** When it was last opened (epoch milliseconds). */
  openedAt: number;
}

/** `entry` first, without an older entry for the same path, at most `max` entries. */
export function rememberCapture(
  list: readonly RecentCapture[],
  entry: RecentCapture,
  max = MAX_RECENT,
): RecentCapture[] {
  return [entry, ...list.filter((e) => e.path !== entry.path)].slice(0, max);
}

export function forgetCapture(list: readonly RecentCapture[], path: string): RecentCapture[] {
  return list.filter((e) => e.path !== path);
}

/** The stored list, keeping only well-formed entries (globalState is user data). */
export function parseRecent(raw: unknown): RecentCapture[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw
    .filter(
      (e): e is RecentCapture =>
        typeof e === "object" &&
        e !== null &&
        typeof e.path === "string" &&
        typeof e.frames === "number" &&
        typeof e.size === "number" &&
        typeof e.openedAt === "number",
    )
    .map((e) => ({
      path: e.path,
      frames: e.frames,
      size: e.size,
      startTime: typeof e.startTime === "number" ? e.startTime : null,
      endTime: typeof e.endTime === "number" ? e.endTime : null,
      fileType: typeof e.fileType === "string" ? e.fileType : null,
      linkType: typeof e.linkType === "string" ? e.linkType : null,
      openedAt: e.openedAt,
    }))
    .slice(0, MAX_RECENT);
}

/** "just now", "5 min ago", "3 h ago", "yesterday", "4 days ago", else the date. */
export function relativeAge(ms: number, now: number): string {
  const s = Math.max(0, (now - ms) / 1000);
  if (s < 60) {
    return "just now";
  }
  if (s < 3600) {
    return `${Math.floor(s / 60)} min ago`;
  }
  if (s < 86_400) {
    return `${Math.floor(s / 3600)} h ago`;
  }
  const days = Math.floor(s / 86_400);
  if (days === 1) {
    return "yesterday";
  }
  if (days < 30) {
    return `${days} days ago`;
  }
  return new Date(ms).toISOString().slice(0, 10);
}

function packets(n: number): string {
  return `${n.toLocaleString("en-US")} packet${n === 1 ? "" : "s"}`;
}

/** The line next to the name: "1,234 packets · 2.1 MB · 3 h ago". */
export function recentDescription(entry: RecentCapture, now: number): string {
  return [packets(entry.frames), formatBytes(entry.size), relativeAge(entry.openedAt, now)].join(
    " · ",
  );
}

/** The hover's lines: path, size and format, the packets' time span, when opened. */
export function recentTooltip(entry: RecentCapture, now: number): string[] {
  const lines = [entry.path];
  const format = [entry.fileType, entry.linkType].filter(Boolean).join(", ");
  lines.push(`${packets(entry.frames)}, ${formatBytes(entry.size)}${format ? ` (${format})` : ""}`);
  if (entry.startTime !== null && entry.endTime !== null) {
    const start = new Date(entry.startTime * 1000).toISOString().replace("T", " ").slice(0, 19);
    lines.push(`From ${start} UTC, ${formatSeconds(entry.endTime - entry.startTime)}`);
  }
  lines.push(`Opened ${relativeAge(entry.openedAt, now)}`);
  return lines;
}

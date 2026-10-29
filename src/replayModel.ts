/**
 * Replay to Service (pure helpers, see docs/replay-to-service.md): the
 * presets setting, the destinations remembered per recorded target, the
 * replay options remembered between runs, and setup files (the captures,
 * destinations and options of a replay, saved as JSON to share).
 */

import * as path from "node:path";

/** Where a recorded target's traffic goes. */
export interface ReplayDestination {
  ip: string;
  port: number;
}

/** A saved mapping (`pcapViewer.replay.presets`): recorded target key → destination. */
export interface ReplayPreset {
  name: string;
  targets: Record<string, ReplayDestination>;
}

/** The panel's options kept between runs (globalState). */
export interface ReplayOptions {
  speed: number;
  /** 0: until stopped. */
  loops: number;
  scope: "all" | "filter";
  /** Several captures: one after another, or merged by their recorded times. */
  order: "sequence" | "merged";
  /** Each paced event moves by a random amount within ± this many ms. */
  jitter: number;
  /** The share of UDP datagrams left out, in percent. */
  loss: number;
}

export const MAX_PRESETS = 50;
/** Recorded targets whose last destination is remembered (most recent first). */
export const MAX_REMEMBERED = 200;
export const MAX_SPEED = 1000;
export const MAX_LOOPS = 1000;
export const MAX_JITTER_MS = 60_000;
/** Other captures in one replay (the backend's MAX_FILES). */
export const MAX_FILES = 100;
export const DEFAULT_OPTIONS: ReplayOptions = {
  speed: 1,
  loops: 1,
  scope: "all",
  order: "sequence",
  jitter: 0,
  loss: 0,
};

/** A recorded target key as replay_targets gives it: "tcp 10.20.0.5:11001", "udp [::1]:53". */
const TARGET_KEY = /^(tcp|udp) (\[[0-9A-Fa-f:.]+\]|[0-9.]+):(\d{1,5})$/;

export function isTargetKey(key: string): boolean {
  return TARGET_KEY.test(key);
}

/** Why `ip`/`port` can't be a destination, or undefined (the backend checks the rest). */
export function destinationProblem(ip: unknown, port: unknown): string | undefined {
  if (typeof ip !== "string" || !ip.trim()) {
    return "Enter an IP address or host name";
  }
  if (/\s/.test(ip.trim())) {
    return "An IP address or host name has no spaces";
  }
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) {
    return "Enter a port between 1 and 65535";
  }
  return undefined;
}

function destination(raw: unknown): ReplayDestination | undefined {
  if (!raw || typeof raw !== "object") {
    return undefined;
  }
  const { ip, port } = raw as Record<string, unknown>;
  return destinationProblem(ip, port) === undefined
    ? { ip: (ip as string).trim(), port: port as number }
    : undefined;
}

/** Recorded target key → destination, keeping only well-formed entries. */
export function normalizeDestinations(raw: unknown): Record<string, ReplayDestination> {
  const out: Record<string, ReplayDestination> = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return out;
  }
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const dest = destination(value);
    if (isTargetKey(key) && dest) {
      out[key] = dest;
    }
  }
  return out;
}

/** The presets setting, checked: named, at least one well-formed mapping, unique names. */
export function normalizePresets(raw: unknown): ReplayPreset[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const out: ReplayPreset[] = [];
  const names = new Set<string>();
  for (const item of raw) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const { name, targets } = item as Record<string, unknown>;
    if (typeof name !== "string" || !name.trim() || names.has(name.trim())) {
      continue;
    }
    const mapped = normalizeDestinations(targets);
    if (!Object.keys(mapped).length) {
      continue;
    }
    names.add(name.trim());
    out.push({ name: name.trim(), targets: mapped });
    if (out.length === MAX_PRESETS) {
      break;
    }
  }
  return out;
}

/** The presets with `preset` added, or replacing the one of the same name (in place). */
export function withPreset(list: readonly ReplayPreset[], preset: ReplayPreset): ReplayPreset[] {
  const at = list.findIndex((p) => p.name === preset.name);
  return at < 0
    ? [...list, preset].slice(0, MAX_PRESETS)
    : list.map((p, i) => (i === at ? preset : p));
}

/** The presets without the one named `name`. */
export function withoutPreset(list: readonly ReplayPreset[], name: string): ReplayPreset[] {
  return list.filter((p) => p.name !== name);
}

/** The remembered destinations with `used` first (most recent first, capped). */
export function rememberDestinations(
  previous: unknown,
  used: Record<string, ReplayDestination>,
): Record<string, ReplayDestination> {
  const merged = { ...normalizeDestinations(used) };
  for (const [key, dest] of Object.entries(normalizeDestinations(previous))) {
    if (!(key in merged)) {
      merged[key] = dest;
    }
  }
  return Object.fromEntries(Object.entries(merged).slice(0, MAX_REMEMBERED));
}

function inRange(value: unknown, min: number, max: number, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max
    ? value
    : fallback;
}

/** The options kept between runs, checked (defaults for anything missing or out of range). */
export function normalizeOptions(raw: unknown): ReplayOptions {
  const o = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const loops =
    typeof o.loops === "number" && Number.isInteger(o.loops) && o.loops >= 0 && o.loops <= MAX_LOOPS
      ? o.loops
      : DEFAULT_OPTIONS.loops;
  return {
    speed: inRange(o.speed, 0, MAX_SPEED, DEFAULT_OPTIONS.speed),
    loops,
    scope: o.scope === "filter" ? "filter" : "all",
    order: o.order === "merged" ? "merged" : "sequence",
    jitter: inRange(o.jitter, 0, MAX_JITTER_MS, DEFAULT_OPTIONS.jitter),
    loss: inRange(o.loss, 0, 100, DEFAULT_OPTIONS.loss),
  };
}

/** Capture files by name, as the viewer opens them (Add Folder… lists these). */
const CAPTURE_NAME =
  /\.(pcap|pcapng|cap|ntar|snoop|erf|pklg|btsnoop)(\.(gz|zst|lz4))?$|\.pcap\d+$/i;

export function isCaptureFileName(name: string): boolean {
  return CAPTURE_NAME.test(name);
}

/** One capture of a setup: its path and whether it is played. */
export interface SetupCapture {
  path: string;
  enabled: boolean;
}

/** A recorded target's destination in a setup, and whether it is replayed. */
export interface SetupTarget extends ReplayDestination {
  enabled: boolean;
}

/**
 * Everything a replay needs besides the open capture: the other captures in
 * order, whether the open one plays and where it goes among them, the
 * destinations and the options. Saved as a JSON file (`setupToJson`) to keep
 * next to the captures and share.
 */
export interface ReplaySetup {
  includeOpen: boolean;
  /** How many of `captures` come before the open capture (0: it plays first). */
  openAt: number;
  captures: SetupCapture[];
  targets: Record<string, SetupTarget>;
  options: ReplayOptions;
}

/** The format's name and version in a setup file. */
export const SETUP_FORMAT = "pcap-lens-replay";
export const SETUP_VERSION = 1;

/**
 * Where the open capture goes among `count` other captures: a whole number
 * from 0 (first) to `count` (last); anything else puts it first.
 */
export function openPosition(raw: unknown, count: number): number {
  return typeof raw === "number" && Number.isInteger(raw) && raw >= 0 ? Math.min(raw, count) : 0;
}

/** A path as a setup file keeps it: relative to the file's folder (forward slashes) when it can be. */
function storedPath(file: string, baseDir: string): string {
  const rel = path.relative(baseDir, file);
  return rel && !path.isAbsolute(rel) ? rel.split(path.sep).join("/") : file;
}

/** A setup as the JSON text of a file in `baseDir`. */
export function setupToJson(setup: ReplaySetup, baseDir: string): string {
  const doc = {
    format: SETUP_FORMAT,
    version: SETUP_VERSION,
    includeOpenCapture: setup.includeOpen,
    openCapturePosition: openPosition(setup.openAt, setup.captures.length),
    captures: setup.captures.map((c) => ({
      path: storedPath(c.path, baseDir),
      enabled: c.enabled,
    })),
    targets: setup.targets,
    options: normalizeOptions(setup.options),
  };
  return JSON.stringify(doc, null, 2) + "\n";
}

/**
 * A setup file's text (in `baseDir`), checked: entries that can't be used are
 * left out and named in `problems`. Relative capture paths are taken from
 * `baseDir`.
 */
export function parseSetup(
  text: string,
  baseDir: string,
): { setup: ReplaySetup; problems: string[] } | { error: string } {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    return { error: `not JSON: ${(err as Error).message}` };
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return { error: "not a replay setup (a JSON object was expected)" };
  }
  const d = doc as Record<string, unknown>;
  if (d.format !== SETUP_FORMAT) {
    return { error: `not a replay setup ("format" is not "${SETUP_FORMAT}")` };
  }
  if (typeof d.version !== "number" || d.version > SETUP_VERSION) {
    return { error: "this replay setup was saved by a newer PCAP Lens" };
  }
  const problems: string[] = [];
  const captures: SetupCapture[] = [];
  // (Counted in the file's list; entries left out before it move it up. Files
  // without it, from 0.25.2, play the open capture first.)
  const wanted = openPosition(d.openCapturePosition, Number.MAX_SAFE_INTEGER);
  if (d.openCapturePosition !== undefined && wanted !== d.openCapturePosition) {
    problems.push("openCapturePosition isn't a whole number from 0: the open capture plays first");
  }
  let openAt: number | undefined;
  for (const [i, c] of (Array.isArray(d.captures) ? d.captures : []).entries()) {
    if (i === wanted) {
      openAt = captures.length;
    }
    const item = c && typeof c === "object" ? (c as Record<string, unknown>) : {};
    if (typeof item.path !== "string" || !item.path.trim()) {
      problems.push("a capture without a path was left out");
      continue;
    }
    const full = path.resolve(baseDir, item.path.trim());
    if (captures.some((x) => x.path === full)) {
      continue;
    }
    if (captures.length === MAX_FILES) {
      problems.push(`only the first ${MAX_FILES} captures were kept`);
      break;
    }
    captures.push({ path: full, enabled: item.enabled !== false });
  }
  openAt ??= captures.length; // (past the list's end: after every capture kept)
  const targets: Record<string, SetupTarget> = {};
  const rawTargets = d.targets && typeof d.targets === "object" ? d.targets : {};
  for (const [key, value] of Object.entries(rawTargets as Record<string, unknown>)) {
    const dest = normalizeDestinations({ [key]: value })[key];
    if (!dest) {
      problems.push(`${key}: not a recorded target with an IP and port`);
      continue;
    }
    const enabled = (value as Record<string, unknown>).enabled !== false;
    targets[key] = { ...dest, enabled };
  }
  return {
    setup: {
      includeOpen: d.includeOpenCapture !== false,
      openAt,
      captures,
      targets,
      options: normalizeOptions(d.options),
    },
    problems,
  };
}

// --- results ---------------------------------------------------------------

/** Log lines a run keeps for Save Results… (the first ones; the rest are counted). */
export const MAX_SAVED_LOG = 100_000;

/** One line of a replay's log, as the backend reports it. */
export interface ReplayLogLine {
  time: number;
  level: string;
  text: string;
  target?: string;
}

/** A target's counts after a replay (replay.TargetStats). */
export interface ReplayTargetResult {
  key: string;
  to: string;
  connections: number;
  opened: number;
  refused: number;
  reset: number;
  closedByPeer: number;
  packets: number;
  bytes: number;
  dropped: number;
  received: number;
  datagrams: number;
  lost: number;
  errors: string[];
  errorCount: number;
}

/** A capture's counts after a replay (replay.SourceStats). */
export interface ReplaySourceResult {
  name: string;
  packets: number;
  bytes: number;
  lost: number;
  retransmissions: number;
  gaps: number;
}

/** One finished replay, as Save Results… writes it. */
export interface ReplayRun {
  /** The open capture's path. */
  capture: string;
  /** ISO times. */
  started: string;
  ended: string;
  options: ReplayOptions;
  /** The display filter of the open capture's packets ("" = all). */
  filter: string;
  /** Other captures played, in order, and where the open one went among them. */
  files: string[];
  includeOpen: boolean;
  openAt: number;
  stopped: boolean;
  seconds: number;
  /** Loops completed. */
  loops: number;
  targets: ReplayTargetResult[];
  sources: ReplaySourceResult[];
  log: ReplayLogLine[];
  /** Log lines past MAX_SAVED_LOG. */
  logOmitted: number;
}

export const RESULTS_FORMAT = "pcap-lens-replay-results";

/** A run as JSON (`format` pcap-lens-replay-results, version 1). */
export function resultsToJson(run: ReplayRun): string {
  return JSON.stringify({ format: RESULTS_FORMAT, version: 1, ...run }, null, 2) + "\n";
}

function size(bytes: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let n = bytes;
  let unit = 0;
  while (n >= 1000 && unit < units.length - 1) {
    n /= 1000;
    unit += 1;
  }
  return unit ? `${n.toFixed(1)} ${units[unit]}` : `${n} B`;
}

const plural = (n: number, one: string, many = `${one}s`) =>
  `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;

/** What happened to one target, in words (like the panel's Result column). */
export function targetOutcome(t: ReplayTargetResult): string {
  const parts: string[] = [];
  if (t.key.startsWith("udp")) {
    parts.push(plural(t.datagrams, "datagram"));
    if (t.lost) {
      parts.push(`${plural(t.lost, "datagram")} lost on purpose`);
    }
  } else {
    parts.push(
      `${t.opened.toLocaleString("en-US")} of ${plural(t.connections, "connection")} opened`,
    );
    if (t.refused) {
      parts.push(`${t.refused.toLocaleString("en-US")} refused`);
    }
    if (t.reset) {
      parts.push(`${t.reset.toLocaleString("en-US")} reset`);
    }
    if (t.closedByPeer) {
      parts.push(`${t.closedByPeer.toLocaleString("en-US")} closed by the service`);
    }
  }
  parts.push(`${size(t.bytes)} sent`, `${size(t.received)} received`);
  if (t.dropped) {
    parts.push(`${size(t.dropped)} not read by the service`);
  }
  if (t.errorCount) {
    parts.push(plural(t.errorCount, "error"));
  }
  return parts.join(", ");
}

/** A run as plain text: what ran, then each capture and target, then the log. */
export function resultsToText(run: ReplayRun): string {
  const o = run.options;
  const lines = [
    "PCAP Lens replay results",
    "",
    `Capture:  ${run.capture}`,
    `Started:  ${run.started}`,
    `Ended:    ${run.ended} (${run.seconds.toFixed(1)} s${run.stopped ? ", stopped" : ""})`,
    "Options:  " +
      [
        o.speed > 0 ? `speed ${o.speed}×` : "no pauses",
        o.loops === 0
          ? `until stopped (${plural(run.loops, "loop")} played)`
          : `${plural(run.loops, "loop")} of ${o.loops}`,
        run.files.length ? (o.order === "merged" ? "merged by time" : "one after another") : "",
        o.speed > 0 && o.jitter ? `jitter ±${o.jitter} ms` : "",
        o.loss ? `UDP loss ${o.loss}%` : "",
        run.filter ? `packets: ${run.filter}` : "packets: all",
      ]
        .filter(Boolean)
        .join(" · "),
    "",
    "Captures:",
  ];
  for (const s of run.sources) {
    const notes = [
      `${plural(s.packets, "packet")} sent (${size(s.bytes)})`,
      s.lost ? `${plural(s.lost, "datagram")} lost on purpose` : "",
      s.retransmissions ? `${plural(s.retransmissions, "retransmission")} skipped` : "",
      s.gaps ? `${plural(s.gaps, "gap")} in the capture` : "",
    ].filter(Boolean);
    lines.push(`  ${s.name}: ${notes.join(", ")}`);
  }
  lines.push("", "Targets:");
  for (const t of run.targets) {
    lines.push(`  ${t.key} → ${t.to}: ${targetOutcome(t)}`);
    for (const e of t.errors) {
      lines.push(`    error: ${e}`);
    }
  }
  lines.push("", "Log:");
  for (const l of run.log) {
    const target = l.target ? `${l.target}  ` : "";
    const level = l.level === "error" ? "ERROR " : "";
    lines.push(`  ${l.time.toFixed(3).padStart(10)} s  ${level}${target}${l.text}`);
  }
  if (run.logOmitted) {
    lines.push(`  (${plural(run.logOmitted, "more line")} not kept)`);
  }
  return lines.join("\n") + "\n";
}

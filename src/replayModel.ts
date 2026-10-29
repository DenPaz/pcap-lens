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
 * order, whether the open one plays, the destinations and the options. Saved
 * as a JSON file (`setupToJson`) to keep next to the captures and share.
 */
export interface ReplaySetup {
  includeOpen: boolean;
  captures: SetupCapture[];
  targets: Record<string, SetupTarget>;
  options: ReplayOptions;
}

/** The format's name and version in a setup file. */
export const SETUP_FORMAT = "pcap-lens-replay";
export const SETUP_VERSION = 1;

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
  for (const c of Array.isArray(d.captures) ? d.captures : []) {
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
      captures,
      targets,
      options: normalizeOptions(d.options),
    },
    problems,
  };
}

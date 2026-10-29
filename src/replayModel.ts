/**
 * Replay to Service (pure helpers, see docs/replay-to-service.md): the
 * presets setting, the destinations remembered per recorded target, and the
 * replay options remembered between runs.
 */

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
  loops: number;
  scope: "all" | "filter";
}

export const MAX_PRESETS = 50;
/** Recorded targets whose last destination is remembered (most recent first). */
export const MAX_REMEMBERED = 200;
export const MAX_SPEED = 1000;
export const MAX_LOOPS = 1000;
export const DEFAULT_OPTIONS: ReplayOptions = { speed: 1, loops: 1, scope: "all" };

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

/** The options kept between runs, checked (defaults for anything missing or out of range). */
export function normalizeOptions(raw: unknown): ReplayOptions {
  const o = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const speed =
    typeof o.speed === "number" && o.speed >= 0 && o.speed <= MAX_SPEED
      ? o.speed
      : DEFAULT_OPTIONS.speed;
  const loops =
    typeof o.loops === "number" && Number.isInteger(o.loops) && o.loops >= 1 && o.loops <= MAX_LOOPS
      ? o.loops
      : DEFAULT_OPTIONS.loops;
  const scope = o.scope === "filter" ? "filter" : "all";
  return { speed, loops, scope };
}

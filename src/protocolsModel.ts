/**
 * Enabled Protocols (pure): the protocols and heuristic dissectors tshark can
 * switch, the state each one is in, and the overrides to store.
 *
 * A protocol's state comes from, in order: `pcapViewer.enabledProtocols` (or
 * `pcapViewer.heuristicDissectors`) for this capture, then what the user
 * switched in Wireshark (the profile's disabled_protos, enabled_protos,
 * heuristic_protos), then tshark's default. The settings only keep what
 * differs from Wireshark's state, so a protocol switched back drops out.
 */

/** A protocol `enabled_protocols` lists (only those tshark can switch). */
export interface ListedProtocol {
  /** The filter name (`http`), what tshark's options take. */
  name: string;
  short: string;
  title: string;
  default: boolean;
}

/** A heuristic dissector `enabled_protocols` lists. */
export interface ListedHeuristic {
  /** The short name (`rtp_udp`), what tshark's options take. */
  name: string;
  /** The protocol it finds (`rtp`) and where it looks (`udp`). */
  protocol: string;
  on: string;
  title: string;
  default: boolean;
}

/** `pcapViewer.enabledProtocols` / `pcapViewer.heuristicDissectors`: name → on. */
export type Switches = Record<string, boolean>;

export interface ProtocolListing {
  protocols: ListedProtocol[];
  heuristics: ListedHeuristic[];
  /** What the user switched in Wireshark. */
  wireshark: { protocols: Switches; heuristics: Switches };
}

const NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

/** A switches setting as stored: valid names with booleans only, sorted. */
export function normalizeSwitches(raw: unknown): Switches {
  const out: Switches = {};
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    for (const [name, on] of Object.entries(raw as Record<string, unknown>).sort(([a], [b]) =>
      a.localeCompare(b),
    )) {
      if (NAME_RE.test(name) && typeof on === "boolean") {
        out[name] = on;
      }
    }
  }
  return out;
}

export function sameSwitches(a: Switches, b: Switches): boolean {
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((k) => b[k] === a[k]);
}

/** Where a protocol's state comes from. */
export type SwitchSource = "here" | "wireshark" | "default";

/** Whether `name` is on for this capture, and why. */
export function effectiveSwitch(
  name: string,
  dflt: boolean,
  wireshark: Switches,
  overrides: Switches,
): { on: boolean; source: SwitchSource } {
  if (name in overrides) {
    return { on: overrides[name], source: "here" };
  }
  if (name in wireshark) {
    return { on: wireshark[name], source: "wireshark" };
  }
  return { on: dflt, source: "default" };
}

/**
 * The overrides to store after the picker: for each listed name, the chosen
 * state when it differs from Wireshark's (else nothing); names not listed
 * (a Lua protocol whose script isn't loaded now) keep their override.
 */
export function switchOverrides(
  listed: readonly { name: string; default: boolean }[],
  wireshark: Switches,
  overrides: Switches,
  enabled: ReadonlySet<string>,
): Switches {
  const listedNames = new Set(listed.map((p) => p.name));
  const out: Switches = {};
  for (const [name, on] of Object.entries(overrides)) {
    if (!listedNames.has(name)) {
      out[name] = on;
    }
  }
  for (const p of listed) {
    const base = p.name in wireshark ? wireshark[p.name] : p.default;
    const on = enabled.has(p.name);
    if (on !== base) {
      out[p.name] = on;
    }
  }
  return normalizeSwitches(out);
}

/** The description of a picker row: its filter name and where its state comes from. */
export function switchDescription(name: string, source: SwitchSource, on: boolean): string {
  const why =
    source === "here"
      ? on
        ? "enabled here"
        : "disabled here"
      : source === "wireshark"
        ? on
          ? "enabled in Wireshark"
          : "disabled in Wireshark"
        : "";
  return why ? `${name} · ${why}` : name;
}

/** The status-bar style summary: "2 protocols disabled, 1 heuristic enabled". */
export function switchSummary(protocols: Switches, heuristics: Switches): string {
  const count = (s: Switches, on: boolean) => Object.values(s).filter((v) => v === on).length;
  const parts = [
    [count(protocols, false), "protocol", "disabled"],
    [count(protocols, true), "protocol", "enabled"],
    [count(heuristics, false), "heuristic", "disabled"],
    [count(heuristics, true), "heuristic", "enabled"],
  ] as const;
  const text = parts
    .filter(([n]) => n > 0)
    .map(([n, what, how]) => `${n} ${what}${n === 1 ? "" : "s"} ${how}`)
    .join(", ");
  return text || "Wireshark's settings";
}

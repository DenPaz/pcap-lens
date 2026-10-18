/**
 * Protocol preferences (pure): what the backend's `protocol_prefs` returns,
 * the value in effect for a capture, and checking a new value before it goes
 * into `pcapViewer.prefs` (tshark ignores an invalid enum value silently).
 */

export type PrefType =
  "bool" | "uint" | "hex" | "range" | "color" | "file" | "directory" | "string" | "enum" | "other";

/** One preference as `protocol_prefs {protocol}` returns it. */
export interface ProtocolPref {
  name: string;
  description: string;
  type: PrefType;
  choices?: string[];
  /** tshark's default. */
  default: string;
  /** The value in the user's Wireshark preferences (the default unless changed there). */
  wireshark: string;
}

/** What `pcapViewer.prefs` holds (`-o name:value`). */
export type PrefValue = string | number | boolean;
export type PrefOverrides = Record<string, PrefValue>;

/** "tcp.analyze_sequence_numbers" → "Analyze sequence numbers". */
export function prefLabel(name: string): string {
  const rest = name.includes(".") ? name.slice(name.indexOf(".") + 1) : name;
  const words = rest.replace(/[._]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** A setting's value as tshark reads it (booleans as TRUE/FALSE, like the backend's -o). */
export function prefText(value: PrefValue): string {
  return typeof value === "boolean" ? (value ? "TRUE" : "FALSE") : String(value);
}

export type PrefSource = "setting" | "wireshark" | "default";

/** The value tshark uses for this capture, and where it comes from. */
export function effectivePref(
  pref: ProtocolPref,
  overrides: PrefOverrides,
): { value: string; source: PrefSource } {
  if (Object.hasOwn(overrides, pref.name)) {
    return { value: prefText(overrides[pref.name]), source: "setting" };
  }
  if (!sameValue(pref, pref.wireshark, pref.default)) {
    return { value: pref.wireshark, source: "wireshark" };
  }
  return { value: pref.default, source: "default" };
}

/** Whether two values of `pref` mean the same (enums and booleans ignore case). */
export function sameValue(pref: ProtocolPref, a: string, b: string): boolean {
  const ci = pref.type === "bool" || pref.type === "enum" || pref.type === "hex";
  return ci ? a.trim().toLowerCase() === b.trim().toLowerCase() : a.trim() === b.trim();
}

const RANGE = /^\s*(\d+(\s*-\s*\d+)?)(\s*,\s*\d+(\s*-\s*\d+)?)*\s*$/;

/** Why `input` isn't a valid value for `pref` (undefined when it is). */
export function validatePrefValue(pref: ProtocolPref, input: string): string | undefined {
  const text = input.trim();
  if (/[\r\n]/.test(input)) {
    return "A preference value is a single line.";
  }
  switch (pref.type) {
    case "bool":
      return /^(true|false)$/i.test(text) ? undefined : "TRUE or FALSE.";
    case "uint":
      return /^\d+$/.test(text) ? undefined : "A decimal number (0 or more).";
    case "hex":
      return /^(0x)?[0-9a-f]+$/i.test(text) ? undefined : "A hexadecimal number, e.g. 0x1f.";
    case "range":
      return text === "" || RANGE.test(text)
        ? undefined
        : 'Numbers and ranges separated by commas, e.g. "1-20,30-40".';
    case "color":
      return /^[0-9a-f]{6}$/i.test(text) ? undefined : "Six hexadecimal digits, e.g. fce94f.";
    case "enum":
      return pref.choices?.some((c) => c.toLowerCase() === text.toLowerCase())
        ? undefined
        : `One of: ${(pref.choices ?? []).join(", ")}.`;
    default:
      return undefined;
  }
}

/** The value to store in `pcapViewer.prefs` for a valid `input`. */
export function prefSettingValue(pref: ProtocolPref, input: string): PrefValue {
  const text = input.trim();
  switch (pref.type) {
    case "bool":
      return text.toLowerCase() === "true";
    case "uint":
      return Number(text);
    case "enum":
      // tshark's own spelling of the choice
      return pref.choices?.find((c) => c.toLowerCase() === text.toLowerCase()) ?? text;
    default:
      return text;
  }
}

/**
 * The overrides with `name` set to `value`, or removed (undefined): an
 * override equal to what tshark would use anyway (the user's Wireshark value)
 * is removed too, so the setting only holds real changes.
 */
export function withPref(
  overrides: PrefOverrides,
  pref: ProtocolPref,
  value: PrefValue | undefined,
): PrefOverrides {
  const next = { ...overrides };
  if (value === undefined || sameValue(pref, prefText(value), pref.wireshark)) {
    delete next[pref.name];
  } else {
    next[pref.name] = value;
  }
  return next;
}

/** Whether two captures were loaded with the same preference overrides. */
export function samePrefs(a: PrefOverrides, b: PrefOverrides): boolean {
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return (
    ka.length === kb.length &&
    ka.every((k, i) => k === kb[i] && prefText(a[k]) === prefText(b[kb[i]]))
  );
}

/**
 * Extcap options (pure): an extcap helper's `--extcap-config` arguments as the
 * backend's `extcap_config` returns them, their values, checks and labels for
 * the options picker of _Start Capture…_ (commands/capture.ts).
 */

export interface ExtcapValue {
  value: string;
  display: string;
  default: boolean;
}

export interface ExtcapArg {
  number: number;
  call: string;
  display?: string;
  type: string;
  default?: string;
  tooltip?: string;
  placeholder?: string;
  required: boolean;
  group?: string;
  range?: string;
  mustexist: boolean;
  values: ExtcapValue[];
}

export type ExtcapValues = Record<string, string>;

const NUMERIC = new Set(["integer", "unsigned", "long", "double"]);
const BOOLEAN = new Set(["boolean", "boolflag"]);
/** Types whose value is picked from `values`. */
const CHOICE = new Set(["selector", "radio", "editselector", "multicheck"]);

export function isSecret(arg: ExtcapArg): boolean {
  return arg.type === "password";
}

export function isBoolean(arg: ExtcapArg): boolean {
  return BOOLEAN.has(arg.type);
}

export function isChoice(arg: ExtcapArg): boolean {
  return CHOICE.has(arg.type) && arg.values.length > 0;
}

export function argName(arg: ExtcapArg): string {
  return arg.display || arg.call.replace(/^--/, "");
}

/** What the helper would use without a value: its default, else the default choice(s). */
export function defaultValue(arg: ExtcapArg): string {
  if (arg.default !== undefined) {
    return arg.default;
  }
  if (isChoice(arg)) {
    return arg.values
      .filter((v) => v.default)
      .map((v) => v.value)
      .join(",");
  }
  return isBoolean(arg) ? "false" : "";
}

/** The values to start from: the stored ones (for options still offered), else the defaults. */
export function initialValues(args: ExtcapArg[], stored: unknown): ExtcapValues {
  const saved = stored && typeof stored === "object" ? (stored as Record<string, unknown>) : {};
  const out: ExtcapValues = {};
  for (const arg of args) {
    const value = saved[arg.call];
    out[arg.call] = typeof value === "string" && !isSecret(arg) ? value : defaultValue(arg);
  }
  return out;
}

/** What may be remembered for the next capture: everything but passwords. */
export function storableValues(args: ExtcapArg[], values: ExtcapValues): ExtcapValues {
  const out: ExtcapValues = {};
  for (const arg of args) {
    if (!isSecret(arg) && values[arg.call] !== undefined) {
      out[arg.call] = values[arg.call];
    }
  }
  return out;
}

function parseRange(range: string | undefined): [number, number] | undefined {
  const m = /^\s*(-?[\d.]+)\s*,\s*(-?[\d.]+)\s*$/.exec(range ?? "");
  return m ? [Number(m[1]), Number(m[2])] : undefined;
}

/** Why `text` won't do for `arg` (undefined: it will). Empty is fine unless required. */
export function validateValue(arg: ExtcapArg, text: string): string | undefined {
  const value = text.trim();
  if (!value) {
    return arg.required ? `${argName(arg)} is required` : undefined;
  }
  if (/[\r\n\0]/.test(text)) {
    return "A single line, please";
  }
  if (NUMERIC.has(arg.type)) {
    const n = Number(value);
    const whole = arg.type !== "double";
    if (!Number.isFinite(n) || (whole && !Number.isInteger(n))) {
      return whole ? "A whole number" : "A number";
    }
    if (arg.type === "unsigned" && n < 0) {
      return "Zero or more";
    }
    const range = parseRange(arg.range);
    if (range && (n < range[0] || n > range[1])) {
      return `From ${range[0]} to ${range[1]}`;
    }
  }
  if (isBoolean(arg) && value !== "true" && value !== "false") {
    return "true or false";
  }
  if ((arg.type === "selector" || arg.type === "radio") && arg.values.length) {
    if (!arg.values.some((v) => v.value === value)) {
      return `One of: ${arg.values.map((v) => v.display).join(", ")}`;
    }
  }
  return undefined;
}

/** The required options without a value (empty when the capture can start). */
export function missingRequired(args: ExtcapArg[], values: ExtcapValues): ExtcapArg[] {
  return args.filter((a) => a.required && !(values[a.call] ?? "").trim());
}

/** An option's value as the picker shows it (passwords hidden, choices by name). */
export function valueLabel(arg: ExtcapArg, value: string | undefined): string {
  if (!value) {
    return isSecret(arg) ? "(not set)" : arg.required ? "(required)" : "(not set)";
  }
  if (isSecret(arg)) {
    return "••••••";
  }
  if (isBoolean(arg)) {
    return value === "true" ? "On" : "Off";
  }
  if (isChoice(arg)) {
    const names = value.split(",").map((v) => arg.values.find((c) => c.value === v)?.display ?? v);
    return names.join(", ");
  }
  return value;
}

/**
 * capture_start's options for one extcap interface: every option, empty and
 * "false" ones too. tshark takes them as preferences, so one left out would
 * be the value saved in the user's Wireshark preferences instead of the one
 * shown (an empty value or a boolflag that is off isn't passed to the helper).
 */
export function captureOptions(args: ExtcapArg[], values: ExtcapValues): ExtcapValues {
  const out: ExtcapValues = {};
  for (const arg of args) {
    out[arg.call] = (values[arg.call] ?? defaultValue(arg)).trim();
  }
  return out;
}

/** The options grouped as the helper groups them ("" for the ungrouped), in its order. */
export function groupArgs(args: ExtcapArg[]): [string, ExtcapArg[]][] {
  const groups = new Map<string, ExtcapArg[]>();
  for (const arg of args) {
    const group = arg.group ?? "";
    groups.set(group, [...(groups.get(group) ?? []), arg]);
  }
  return [...groups.entries()];
}

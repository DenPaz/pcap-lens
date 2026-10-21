/**
 * Wireshark configuration profiles (pure): which one tshark uses (the
 * `pcapViewer.wiresharkProfile` setting, `-C`) and what importing one writes
 * into PCAP Lens's own settings. The backend lists and reads the profiles
 * (`wireshark_profiles`, `read_wireshark_profile`, wsprofile.py).
 */
import {
  type ColumnLayout,
  type ColumnSetting,
  type FilterButton,
  type SavedFilter,
  coloringRulesSetting,
  normalizeColumnLayout,
} from "./settingsModel";

export interface ProfileEntry {
  name: string;
  path: string;
  /** The personal configuration folder itself. */
  default: boolean;
  /** Shipped with Wireshark. */
  global: boolean;
  /** Which of the profile's configuration files exist. */
  files: string[];
}

export type ProfileColumn = { title: string; id: string } | { title: string; field: string };

export interface ProfileContents {
  name: string;
  path: string;
  coloringRules: {
    name: string;
    filter: string;
    foreground: string;
    background: string;
    enabled: boolean;
  }[];
  filterButtons: (FilterButton & { enabled: boolean })[];
  savedFilters: SavedFilter[];
  /** Capture (BPF) filters (`cfilters`; older backends leave it out). */
  captureFilters?: SavedFilter[];
  macros: { name: string; text: string }[];
  columns: ProfileColumn[];
  /** Preferences the profile sets (they apply when tshark uses it). */
  preferences: number;
  decodeAs: number;
}

// (Like the backend's: no path separators, reserved characters or control characters.)
// eslint-disable-next-line no-control-regex -- control characters are what it rules out
const NAME_RE = /^[^/\\:*?"<>|\x00-\x1f]{1,100}$/;

/** The setting's profile name, or "" (Default) for anything tshark's -C wouldn't take. */
export function normalizeProfileName(raw: unknown): string {
  if (typeof raw !== "string") {
    return "";
  }
  const name = raw.trim();
  return NAME_RE.test(name) && name !== "." && name !== ".." && name !== "Default" ? name : "";
}

const FILE_LABELS: Record<string, string> = {
  preferences: "preferences",
  colorfilters: "coloring rules",
  dfilter_buttons: "filter buttons",
  dfilters: "saved filters",
  dfilter_macros: "filter macros",
  decode_as_entries: "Decode As",
  disabled_protos: "disabled protocols",
};

/** QuickPick rows for _Use Wireshark Profile…_ and _Import from Wireshark Profile…_. */
export function profileItems(
  profiles: readonly ProfileEntry[],
  current: string,
): { label: string; description: string; detail: string; name: string }[] {
  return profiles.map((p) => {
    const name = p.default ? "" : p.name;
    const what = p.files.map((f) => FILE_LABELS[f] ?? f);
    return {
      label: name === current ? `$(check) ${p.name}` : p.name,
      description: p.default
        ? "your personal configuration"
        : p.global
          ? "shipped with Wireshark"
          : "",
      detail: what.length ? `Has ${what.join(", ")}` : "No configuration files of its own",
      name,
    };
  });
}

export type ImportKind =
  "coloringRules" | "filterButtons" | "savedFilters" | "captureFilters" | "columns";

/** What a profile can bring in, each with a count and what importing does. */
export function importChoices(
  contents: ProfileContents,
): { kind: ImportKind; label: string; detail: string }[] {
  const n = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;
  const custom = contents.columns.filter((c) => "field" in c).length;
  const enabledButtons = contents.filterButtons.filter((b) => b.enabled).length;
  const out: { kind: ImportKind; label: string; detail: string }[] = [];
  if (contents.coloringRules.length) {
    out.push({
      kind: "coloringRules",
      label: n(contents.coloringRules.length, "coloring rule", "coloring rules"),
      detail: "Replaces PCAP Lens's coloring rules (disabled ones stay disabled)",
    });
  }
  if (enabledButtons) {
    out.push({
      kind: "filterButtons",
      label: n(enabledButtons, "filter button", "filter buttons"),
      detail: "Added after yours; a button with the same filter is skipped",
    });
  }
  if (contents.savedFilters.length) {
    out.push({
      kind: "savedFilters",
      label: n(contents.savedFilters.length, "saved display filter", "saved display filters"),
      detail: "Added to your saved filters; a name you already use is skipped",
    });
  }
  const captureFilters = contents.captureFilters ?? [];
  if (captureFilters.length) {
    out.push({
      kind: "captureFilters",
      label: n(captureFilters.length, "capture filter", "capture filters"),
      detail: "Added to your saved capture filters; a name you already use is skipped",
    });
  }
  if (contents.columns.length) {
    out.push({
      kind: "columns",
      label: n(contents.columns.length, "packet list column", "packet list columns"),
      detail: `The profile's column order${custom ? `, with its ${n(custom, "custom column", "custom columns")} added` : ""}; columns it doesn't have are hidden`,
    });
  }
  return out;
}

export interface CurrentSettings {
  filterButtons: FilterButton[];
  savedFilters: SavedFilter[];
  captureFilters: SavedFilter[];
  columns: ColumnSetting[];
}

/** The setting writes importing `kind` makes, with how many entries it adds. */
export function importSettings(
  kind: ImportKind,
  contents: ProfileContents,
  current: CurrentSettings,
): { writes: { key: string; value: unknown }[]; added: number } {
  switch (kind) {
    case "coloringRules":
      return {
        writes: [{ key: "coloringRules", value: coloringRulesSetting(contents.coloringRules) }],
        added: contents.coloringRules.length,
      };
    case "filterButtons": {
      const have = new Set(current.filterButtons.map((b) => b.filter.trim()));
      const added = contents.filterButtons
        .filter((b) => b.enabled && !have.has(b.filter.trim()))
        .map((b) => ({
          label: b.label,
          filter: b.filter,
          ...(b.comment ? { comment: b.comment } : {}),
        }));
      return {
        writes: [{ key: "filterButtons", value: [...current.filterButtons, ...added] }],
        added: added.length,
      };
    }
    case "savedFilters": {
      const have = new Set(current.savedFilters.map((f) => f.name));
      const added = contents.savedFilters.filter((f) => !have.has(f.name));
      return {
        writes: [{ key: "savedFilters", value: [...current.savedFilters, ...added] }],
        added: added.length,
      };
    }
    case "captureFilters": {
      const have = new Set(current.captureFilters.map((f) => f.name));
      const added = (contents.captureFilters ?? []).filter((f) => !have.has(f.name));
      return {
        writes: [{ key: "capture.savedFilters", value: [...current.captureFilters, ...added] }],
        added: added.length,
      };
    }
    case "columns": {
      const have = new Set(current.columns.map((c) => c.field));
      const added: ColumnSetting[] = [];
      for (const c of contents.columns) {
        if ("field" in c && !have.has(c.field)) {
          have.add(c.field);
          added.push({ field: c.field, title: c.title });
        }
      }
      const columns = [...current.columns, ...added];
      const order = contents.columns.map((c) => ("field" in c ? `custom:${c.field}` : c.id));
      const all = [
        "number",
        "time",
        "source",
        "destination",
        "protocol",
        "length",
        "info",
        ...columns.map((c) => `custom:${c.field}`),
      ];
      const layout: ColumnLayout = normalizeColumnLayout({
        order: [...order, ...all.filter((id) => !order.includes(id))],
        hidden: all.filter((id) => !order.includes(id)),
      });
      return {
        writes: [
          ...(added.length ? [{ key: "columns", value: columns }] : []),
          { key: "columnLayout", value: layout },
        ],
        added: contents.columns.length,
      };
    }
  }
}
